import Darwin
import Foundation
import WatchmeBPF

private struct BPFGatewayIPv6ICMPHeader {
    let sourceIP: String
    let destinationIP: String
    let icmpOffset: Int
    let ethernetSourceAddress: String
}

func parseBPFGatewayICMPPacket(buffer: [UInt8], offset: Int, length: Int) -> BPFGatewayICMPPacket? {
    guard length >= 14 + 20 + 8,
          offset + length <= buffer.count,
          buffer[offset + 12] == 0x08,
          buffer[offset + 13] == 0x00
    else {
        return nil
    }

    let ipOffset = offset + 14
    guard buffer[ipOffset] >> 4 == 4 else {
        return nil
    }
    let ipHeaderLength = Int(buffer[ipOffset] & 0x0F) * 4
    guard ipHeaderLength >= 20, length >= 14 + ipHeaderLength + 8, buffer[ipOffset + 9] == UInt8(IPPROTO_ICMP) else {
        return nil
    }

    let icmpOffset = ipOffset + ipHeaderLength
    return BPFGatewayICMPPacket(
        family: .ipv4,
        type: buffer[icmpOffset],
        code: buffer[icmpOffset + 1],
        sourceIP: ipv4String(bytes: Array(buffer[(ipOffset + 12) ..< (ipOffset + 16)])),
        destinationIP: ipv4String(bytes: Array(buffer[(ipOffset + 16) ..< (ipOffset + 20)])),
        identifier: readBigUInt16(buffer, offset: icmpOffset + 4),
        sequence: readBigUInt16(buffer, offset: icmpOffset + 6)
    )
}

func parseBPFGatewayICMPv6Packet(buffer: [UInt8], offset: Int, length: Int) -> BPFGatewayICMPPacket? {
    guard let parsed = parseBPFGatewayIPv6ICMPHeader(buffer: buffer, offset: offset, length: length),
          parsed.icmpOffset + 8 <= offset + length
    else {
        return nil
    }
    let type = buffer[parsed.icmpOffset]
    guard type == 128 || type == 129 else {
        return nil
    }
    return BPFGatewayICMPPacket(
        family: .ipv6,
        type: type,
        code: buffer[parsed.icmpOffset + 1],
        sourceIP: parsed.sourceIP,
        destinationIP: parsed.destinationIP,
        identifier: readBigUInt16(buffer, offset: parsed.icmpOffset + 4),
        sequence: readBigUInt16(buffer, offset: parsed.icmpOffset + 6)
    )
}

func parseBPFGatewayNeighborPacket(buffer: [UInt8], offset: Int, length: Int) -> BPFGatewayNeighborPacket? {
    guard let parsed = parseBPFGatewayIPv6ICMPHeader(buffer: buffer, offset: offset, length: length),
          parsed.icmpOffset + 8 <= offset + length
    else {
        return nil
    }
    let type = buffer[parsed.icmpOffset]
    let code = buffer[parsed.icmpOffset + 1]
    guard type == 135 || type == 136, parsed.icmpOffset + 24 <= offset + length else {
        return nil
    }
    let targetAddress = ipv6String(bytes: Array(buffer[(parsed.icmpOffset + 8) ..< (parsed.icmpOffset + 24)]))
    let sourceLinkLayerAddress = icmpv6NDLinkLayerAddressOption(
        buffer: buffer,
        optionsOffset: parsed.icmpOffset + 24,
        packetEnd: offset + length,
        optionType: 1
    )
    let targetLinkLayerAddress = icmpv6NDLinkLayerAddressOption(
        buffer: buffer,
        optionsOffset: parsed.icmpOffset + 24,
        packetEnd: offset + length,
        optionType: 2
    )
    return BPFGatewayNeighborPacket(
        type: type,
        code: code,
        sourceIP: parsed.sourceIP,
        destinationIP: parsed.destinationIP,
        targetAddress: targetAddress,
        sourceLinkLayerAddress: sourceLinkLayerAddress,
        targetLinkLayerAddress: targetLinkLayerAddress,
        ethernetSourceAddress: parsed.ethernetSourceAddress
    )
}

private func parseBPFGatewayIPv6ICMPHeader(
    buffer: [UInt8],
    offset: Int,
    length: Int
) -> BPFGatewayIPv6ICMPHeader? {
    guard length >= 14 + 40 + 8,
          offset + length <= buffer.count,
          buffer[offset + 12] == 0x86,
          buffer[offset + 13] == 0xDD
    else {
        return nil
    }
    let ipOffset = offset + 14
    guard buffer[ipOffset] >> 4 == 6, buffer[ipOffset + 6] == UInt8(IPPROTO_ICMPV6) else {
        return nil
    }
    return BPFGatewayIPv6ICMPHeader(
        sourceIP: ipv6String(bytes: Array(buffer[(ipOffset + 8) ..< (ipOffset + 24)])),
        destinationIP: ipv6String(bytes: Array(buffer[(ipOffset + 24) ..< (ipOffset + 40)])),
        icmpOffset: ipOffset + 40,
        ethernetSourceAddress: macAddressString(bytes: Array(buffer[(offset + 6) ..< (offset + 12)]))
    )
}
