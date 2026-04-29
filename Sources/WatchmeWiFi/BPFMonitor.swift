import Darwin
import Foundation
import WatchmeBPF
import WatchmeCore

final class PassiveBPFMonitor {
    private let interfaceName: String
    private let store: PassivePacketStore
    private let onPacketEvent: (String, [String: String]) -> Void
    private var monitor: BPFPacketMonitor?

    init(interfaceName: String, store: PassivePacketStore, onPacketEvent: @escaping (String, [String: String]) -> Void) {
        self.interfaceName = interfaceName
        self.store = store
        self.onPacketEvent = onPacketEvent
    }

    func start() -> String? {
        let monitor = BPFPacketMonitor(
            interfaceName: interfaceName,
            queueLabel: "watchme.bpf.\(interfaceName)",
            onPacket: { [weak self] packet in
                self?.handlePacket(
                    buffer: packet.frame,
                    offset: 0,
                    length: packet.frame.count,
                    timestampNanos: packet.timestampNanos
                )
            },
            onReadError: { [weak self] error in
                guard let self else {
                    return
                }
                logEvent(.warn, "bpf_read_failed", fields: ["interface": interfaceName, "error": error])
            }
        )
        if let error = monitor.start() {
            return error
        }
        self.monitor = monitor
        return nil
    }

    func stop() {
        monitor?.stop()
        monitor = nil
    }

    private func handlePacket(buffer: [UInt8], offset: Int, length: Int, timestampNanos: UInt64) {
        guard length >= 14 else {
            return
        }
        // Keep the passive path narrowly scoped to address acquisition signals.
        // Full packet capture would add noise and privacy risk without improving
        // join/roam observability.
        let etherType = readBigUInt16(buffer, offset: offset + 12)
        if etherType == 0x0800 {
            handleIPv4Packet(buffer: buffer, offset: offset + 14, packetEnd: offset + length, timestampNanos: timestampNanos)
        } else if etherType == 0x86DD {
            handleIPv6Packet(buffer: buffer, offset: offset + 14, packetEnd: offset + length, timestampNanos: timestampNanos)
        }
    }

    private func handleIPv4Packet(buffer: [UInt8], offset: Int, packetEnd: Int, timestampNanos: UInt64) {
        guard offset + 20 <= packetEnd, buffer[offset] >> 4 == 4 else {
            return
        }
        let headerLength = Int(buffer[offset] & 0x0F) * 4
        guard offset + headerLength + 8 <= packetEnd, buffer[offset + 9] == UInt8(IPPROTO_UDP) else {
            return
        }
        let udpOffset = offset + headerLength
        let sourcePort = readBigUInt16(buffer, offset: udpOffset)
        let destinationPort = readBigUInt16(buffer, offset: udpOffset + 2)
        // DHCP is the IPv4 address-acquisition signal we care about after a
        // join. Non-DHCP UDP traffic is deliberately ignored.
        guard sourcePort == 67 || sourcePort == 68 || destinationPort == 67 || destinationPort == 68 else {
            return
        }
        guard let packet = parseDHCPv4Packet(buffer: buffer, offset: udpOffset + 8, packetEnd: packetEnd) else {
            return
        }
        let observation = DHCPObservation(
            interfaceName: interfaceName,
            wallNanos: timestampNanos,
            xid: packet.xid,
            messageType: packet.messageType,
            yiaddr: packet.yiaddr,
            serverIdentifier: packet.serverIdentifier,
            leaseTimeSeconds: packet.leaseTimeSeconds
        )
        store.appendDHCP(observation)
        guard let messageType = packet.messageType else {
            return
        }
        var fields: [String: String] = [
            "interface": interfaceName,
            "dhcp.xid": String(format: "0x%08x", packet.xid),
            "dhcp.message_type": dhcpMessageTypeName(messageType),
            "packet.timestamp_epoch_ns": "\(timestampNanos)",
        ]
        setTag(&fields, "dhcp.yiaddr", packet.yiaddr)
        setTag(&fields, "dhcp.server_identifier", packet.serverIdentifier)
        if let lease = packet.leaseTimeSeconds {
            fields["dhcp.lease_time_seconds"] = "\(lease)"
        }
        logEvent(.debug, "dhcp_packet_observed", fields: fields)
        if messageType == 5 {
            onPacketEvent("wifi.rejoin.dhcp_ack", fields)
        }
    }

    private func handleIPv6Packet(buffer: [UInt8], offset: Int, packetEnd: Int, timestampNanos: UInt64) {
        guard offset + 40 <= packetEnd, buffer[offset] >> 4 == 6 else {
            return
        }
        guard buffer[offset + 6] == UInt8(IPPROTO_ICMPV6) else {
            return
        }
        let sourceIP = ipv6String(bytes: Array(buffer[(offset + 8) ..< (offset + 24)]))
        let destinationIP = ipv6String(bytes: Array(buffer[(offset + 24) ..< (offset + 40)]))
        let icmpOffset = offset + 40
        guard icmpOffset + 8 <= packetEnd else {
            return
        }
        let type = buffer[icmpOffset]
        let code = buffer[icmpOffset + 1]
        // Router Solicitation/Advertisement and Neighbor Discovery are the IPv6
        // address-acquisition signals that explain "joined but still not
        // reachable" periods. Other ICMPv6 traffic is unrelated noise here.
        guard type == 133 || type == 134 || type == 135 || type == 136 else {
            return
        }

        var targetAddress: String?
        var routerLifetimeSeconds: UInt16?
        var sourceLinkLayerAddress: String?
        var targetLinkLayerAddress: String?

        // ICMPv6 control messages have different fixed headers before their ND
        // options. Keep those offsets explicit so truncation checks remain tied
        // to the RFC packet shape rather than a shared magic number.
        if type == 134, icmpOffset + 16 <= packetEnd {
            routerLifetimeSeconds = readBigUInt16(buffer, offset: icmpOffset + 6)
            sourceLinkLayerAddress = icmpv6NDLinkLayerAddressOption(
                buffer: buffer,
                optionsOffset: icmpOffset + 16,
                packetEnd: packetEnd,
                optionType: 1
            )
        } else if type == 135 || type == 136, icmpOffset + 24 <= packetEnd {
            targetAddress = ipv6String(bytes: Array(buffer[(icmpOffset + 8) ..< (icmpOffset + 24)]))
            sourceLinkLayerAddress = icmpv6NDLinkLayerAddressOption(
                buffer: buffer,
                optionsOffset: icmpOffset + 24,
                packetEnd: packetEnd,
                optionType: 1
            )
            targetLinkLayerAddress = icmpv6NDLinkLayerAddressOption(
                buffer: buffer,
                optionsOffset: icmpOffset + 24,
                packetEnd: packetEnd,
                optionType: 2
            )
        }

        let observation = ICMPv6Observation(
            interfaceName: interfaceName,
            wallNanos: timestampNanos,
            type: type,
            code: code,
            sourceIP: sourceIP,
            destinationIP: destinationIP,
            targetAddress: targetAddress,
            routerLifetimeSeconds: routerLifetimeSeconds,
            sourceLinkLayerAddress: sourceLinkLayerAddress,
            targetLinkLayerAddress: targetLinkLayerAddress
        )
        store.appendICMPv6(observation)

        var fields: [String: String] = [
            "interface": interfaceName,
            "icmpv6.type": "\(type)",
            "icmpv6.type_name": icmpv6TypeName(type),
            "icmpv6.code": "\(code)",
            "icmpv6.source_ip": sourceIP,
            "icmpv6.destination_ip": destinationIP,
            "packet.timestamp_epoch_ns": "\(timestampNanos)",
        ]
        setTag(&fields, "icmpv6.nd.target_address", targetAddress)
        setTag(&fields, "icmpv6.nd.source_link_layer_address", sourceLinkLayerAddress)
        setTag(&fields, "icmpv6.nd.target_link_layer_address", targetLinkLayerAddress)
        if let lifetime = routerLifetimeSeconds {
            fields["icmpv6.ra.router_lifetime_seconds"] = "\(lifetime)"
        }
        logEvent(.debug, "icmpv6_control_packet_observed", fields: fields)
        if type == 134 || type == 136 {
            onPacketEvent("wifi.rejoin.\(icmpv6TypeName(type))", fields)
        }
    }
}

struct DHCPv4Packet {
    let xid: UInt32
    let messageType: UInt8?
    let yiaddr: String?
    let serverIdentifier: String?
    let leaseTimeSeconds: UInt32?
}

func parseDHCPv4Packet(buffer: [UInt8], offset: Int, packetEnd: Int) -> DHCPv4Packet? {
    guard offset + 240 <= packetEnd else {
        return nil
    }
    let hardwareType = buffer[offset + 1]
    let hardwareLength = buffer[offset + 2]
    guard hardwareType == 1, hardwareLength == 6 else {
        return nil
    }
    let xid = readBigUInt32(buffer, offset: offset + 4)
    let yiaddr = ipv4String(bytes: Array(buffer[(offset + 16) ..< (offset + 20)]))
    // Without the magic cookie the BOOTP header is still useful for xid/yiaddr,
    // but DHCP options such as message type and lease time are unavailable.
    guard readBigUInt32(buffer, offset: offset + 236) == 0x6382_5363 else {
        return DHCPv4Packet(xid: xid, messageType: nil, yiaddr: yiaddr, serverIdentifier: nil, leaseTimeSeconds: nil)
    }

    var messageType: UInt8?
    var serverIdentifier: String?
    var leaseTimeSeconds: UInt32?
    var cursor = offset + 240
    while cursor < packetEnd {
        let option = buffer[cursor]
        cursor += 1
        if option == 0 {
            // Pad options are single-byte fillers and do not carry a length.
            continue
        }
        if option == 255 {
            break
        }
        guard cursor < packetEnd else {
            break
        }
        let length = Int(buffer[cursor])
        cursor += 1
        // A truncated option means the packet was capped by BPF or malformed.
        // Return the fields parsed so far rather than failing the whole BOOTP
        // observation; xid timing is still useful for retry spans.
        guard cursor + length <= packetEnd else {
            break
        }
        switch option {
        case 53 where length >= 1:
            messageType = buffer[cursor]
        case 54 where length >= 4:
            serverIdentifier = ipv4String(bytes: Array(buffer[cursor ..< (cursor + 4)]))
        case 51 where length >= 4:
            leaseTimeSeconds = readBigUInt32(buffer, offset: cursor)
        default:
            break
        }
        cursor += length
    }

    return DHCPv4Packet(
        xid: xid,
        messageType: messageType,
        yiaddr: yiaddr,
        serverIdentifier: serverIdentifier,
        leaseTimeSeconds: leaseTimeSeconds
    )
}
