import Foundation
import WatchmeBPF

struct TransportPacketContext {
    let interfaceName: String
    let packetEnd: Int
    let timestampNanos: UInt64
    let sourceIP: String
    let destinationIP: String
}

struct ARPPacket {
    let operation: UInt16
    let senderHardwareAddress: String
    let senderProtocolAddress: String
    let targetHardwareAddress: String
    let targetProtocolAddress: String
}

func parseARPPacket(buffer: [UInt8], offset: Int, packetEnd: Int) -> ARPPacket? {
    guard offset + 28 <= packetEnd else {
        return nil
    }
    let hardwareType = readBigUInt16(buffer, offset: offset)
    let protocolType = readBigUInt16(buffer, offset: offset + 2)
    let hardwareLength = buffer[offset + 4]
    let protocolLength = buffer[offset + 5]
    guard hardwareType == 1, protocolType == 0x0800, hardwareLength == 6, protocolLength == 4 else {
        return nil
    }
    let operation = readBigUInt16(buffer, offset: offset + 6)
    guard operation == 1 || operation == 2 else {
        return nil
    }
    return ARPPacket(
        operation: operation,
        senderHardwareAddress: macAddressString(bytes: Array(buffer[(offset + 8) ..< (offset + 14)])),
        senderProtocolAddress: ipv4String(bytes: Array(buffer[(offset + 14) ..< (offset + 18)])),
        targetHardwareAddress: macAddressString(bytes: Array(buffer[(offset + 18) ..< (offset + 24)])),
        targetProtocolAddress: ipv4String(bytes: Array(buffer[(offset + 24) ..< (offset + 28)]))
    )
}

func parseDNSPacketObservation(
    buffer: [UInt8],
    offset: Int,
    context: TransportPacketContext,
    sourcePort: UInt16,
    destinationPort: UInt16
) -> DNSPacketObservation? {
    guard offset + 12 <= context.packetEnd, sourcePort == 53 || destinationPort == 53 else {
        return nil
    }
    let transactionID = readBigUInt16(buffer, offset: offset)
    let flags = readBigUInt16(buffer, offset: offset + 2)
    let isResponse = flags & 0x8000 != 0
    let questionCount = readBigUInt16(buffer, offset: offset + 4)
    let answerCount = readBigUInt16(buffer, offset: offset + 6)
    var queryName: String?
    var queryType: UInt16?
    if questionCount > 0 {
        if let parsed = parseDNSName(buffer: buffer, messageOffset: offset, cursor: offset + 12, packetEnd: context.packetEnd) {
            queryName = parsed.name
            if parsed.nextOffset + 4 <= context.packetEnd {
                queryType = readBigUInt16(buffer, offset: parsed.nextOffset)
            }
        }
    }
    return DNSPacketObservation(
        interfaceName: context.interfaceName,
        wallNanos: context.timestampNanos,
        sourceIP: context.sourceIP,
        destinationIP: context.destinationIP,
        sourcePort: sourcePort,
        destinationPort: destinationPort,
        transactionID: transactionID,
        isResponse: isResponse,
        rcode: isResponse ? Int(flags & 0x000F) : nil,
        answerCount: isResponse ? Int(answerCount) : nil,
        queryName: queryName,
        queryType: queryType
    )
}

func parseTCPPacketObservation(
    buffer: [UInt8],
    offset: Int,
    context: TransportPacketContext
) -> TCPPacketObservation? {
    guard offset + 20 <= context.packetEnd else {
        return nil
    }
    let dataOffset = Int(buffer[offset + 12] >> 4) * 4
    guard dataOffset >= 20, offset + dataOffset <= context.packetEnd else {
        return nil
    }
    let payloadOffset = offset + dataOffset
    let payloadLength = max(context.packetEnd - payloadOffset, 0)
    let prefixEnd = min(context.packetEnd, payloadOffset + 256)
    let payloadPrefix = payloadOffset < prefixEnd ? Array(buffer[payloadOffset ..< prefixEnd]) : []
    return TCPPacketObservation(
        interfaceName: context.interfaceName,
        wallNanos: context.timestampNanos,
        sourceIP: context.sourceIP,
        destinationIP: context.destinationIP,
        sourcePort: readBigUInt16(buffer, offset: offset),
        destinationPort: readBigUInt16(buffer, offset: offset + 2),
        flags: buffer[offset + 13],
        payloadLength: payloadLength,
        payloadPrefix: payloadPrefix
    )
}

func parseICMPv4PacketObservation(
    buffer: [UInt8],
    offset: Int,
    context: TransportPacketContext
) -> ICMPPacketObservation? {
    parseICMPEchoPacketObservation(buffer: buffer, offset: offset, context: context, family: .ipv4)
}

func parseICMPv6EchoPacketObservation(
    buffer: [UInt8],
    offset: Int,
    context: TransportPacketContext
) -> ICMPPacketObservation? {
    parseICMPEchoPacketObservation(buffer: buffer, offset: offset, context: context, family: .ipv6)
}

private func parseICMPEchoPacketObservation(
    buffer: [UInt8],
    offset: Int,
    context: TransportPacketContext,
    family: InternetAddressFamily
) -> ICMPPacketObservation? {
    guard offset + 8 <= context.packetEnd else {
        return nil
    }
    let type = buffer[offset]
    let echoTypes: Set<UInt8> = family == .ipv4 ? [0, 8] : [128, 129]
    guard echoTypes.contains(type) else {
        return nil
    }
    return ICMPPacketObservation(
        interfaceName: context.interfaceName,
        wallNanos: context.timestampNanos,
        family: family,
        type: type,
        code: buffer[offset + 1],
        sourceIP: context.sourceIP,
        destinationIP: context.destinationIP,
        identifier: readBigUInt16(buffer, offset: offset + 4),
        sequence: readBigUInt16(buffer, offset: offset + 6)
    )
}

func parseDNSName(
    buffer: [UInt8],
    messageOffset: Int,
    cursor startCursor: Int,
    packetEnd: Int
) -> (name: String, nextOffset: Int)? {
    var cursor = startCursor
    var labels: [String] = []
    var jumpedNextOffset: Int?
    var jumpCount = 0

    while cursor < packetEnd {
        let length = buffer[cursor]
        if length & 0xC0 == 0xC0 {
            guard cursor + 1 < packetEnd else {
                return nil
            }
            let pointer = Int(length & 0x3F) << 8 | Int(buffer[cursor + 1])
            let target = messageOffset + pointer
            guard target >= messageOffset, target < packetEnd, jumpCount < 8 else {
                return nil
            }
            if jumpedNextOffset == nil {
                jumpedNextOffset = cursor + 2
            }
            cursor = target
            jumpCount += 1
            continue
        }
        guard length & 0xC0 == 0 else {
            return nil
        }
        cursor += 1
        if length == 0 {
            return (labels.joined(separator: "."), jumpedNextOffset ?? cursor)
        }
        let labelLength = Int(length)
        guard cursor + labelLength <= packetEnd else {
            return nil
        }
        guard let label = String(bytes: buffer[cursor ..< (cursor + labelLength)], encoding: .utf8) else {
            return nil
        }
        labels.append(label)
        cursor += labelLength
    }
    return nil
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
