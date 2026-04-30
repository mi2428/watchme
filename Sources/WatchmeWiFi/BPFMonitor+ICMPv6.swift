import Foundation
import WatchmeBPF
import WatchmeCore

extension PassiveBPFMonitor {
    func handleICMPv6Packet(
        buffer: [UInt8],
        offset icmpOffset: Int,
        context: TransportPacketContext
    ) {
        guard icmpOffset + 8 <= context.packetEnd else {
            return
        }
        let type = buffer[icmpOffset]
        let code = buffer[icmpOffset + 1]
        if let observation = parseICMPv6EchoPacketObservation(
            buffer: buffer,
            offset: icmpOffset,
            context: context
        ), store.appendICMP(observation) {
            logActiveICMPPacket(observation)
            return
        }
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
        if type == 134, icmpOffset + 16 <= context.packetEnd {
            routerLifetimeSeconds = readBigUInt16(buffer, offset: icmpOffset + 6)
            sourceLinkLayerAddress = icmpv6NDLinkLayerAddressOption(
                buffer: buffer,
                optionsOffset: icmpOffset + 16,
                packetEnd: context.packetEnd,
                optionType: 1
            )
        } else if type == 135 || type == 136, icmpOffset + 24 <= context.packetEnd {
            targetAddress = ipv6String(bytes: Array(buffer[(icmpOffset + 8) ..< (icmpOffset + 24)]))
            sourceLinkLayerAddress = icmpv6NDLinkLayerAddressOption(
                buffer: buffer,
                optionsOffset: icmpOffset + 24,
                packetEnd: context.packetEnd,
                optionType: 1
            )
            targetLinkLayerAddress = icmpv6NDLinkLayerAddressOption(
                buffer: buffer,
                optionsOffset: icmpOffset + 24,
                packetEnd: context.packetEnd,
                optionType: 2
            )
        }

        let observation = ICMPv6Observation(
            interfaceName: interfaceName,
            wallNanos: context.timestampNanos,
            type: type,
            code: code,
            sourceIP: context.sourceIP,
            destinationIP: context.destinationIP,
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
            "icmpv6.source_ip": context.sourceIP,
            "icmpv6.destination_ip": context.destinationIP,
            "packet.timestamp_epoch_ns": "\(context.timestampNanos)",
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
