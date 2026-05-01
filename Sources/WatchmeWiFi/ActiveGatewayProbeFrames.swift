import Darwin
import Foundation
import WatchmeCore

struct EthernetICMPEchoFrame {
    let sourceMAC: [UInt8]
    let destinationMAC: [UInt8]
    let sourceIP: [UInt8]
    let destinationIP: [UInt8]
    let identifier: UInt16
    let sequence: UInt16
    let payloadSize: Int
}

typealias EthernetICMPv6EchoFrame = EthernetICMPEchoFrame

private struct IPv6HeaderFields {
    let offset: Int
    let payloadLength: Int
    let nextHeader: UInt8
    let hopLimit: UInt8
    let sourceIP: [UInt8]
    let destinationIP: [UInt8]
}

func ethernetARPRequestFrame(
    sourceMAC: [UInt8],
    sourceIP: [UInt8],
    targetIP: [UInt8]
) -> [UInt8] {
    var frame = [UInt8](repeating: 0, count: 14 + 28)

    frame.replaceSubrange(0 ..< 6, with: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    frame.replaceSubrange(6 ..< 12, with: sourceMAC)
    frame[12] = 0x08
    frame[13] = 0x06

    let arpOffset = 14
    writeBigUInt16(1, to: &frame, offset: arpOffset)
    writeBigUInt16(0x0800, to: &frame, offset: arpOffset + 2)
    frame[arpOffset + 4] = 6
    frame[arpOffset + 5] = 4
    writeBigUInt16(1, to: &frame, offset: arpOffset + 6)
    frame.replaceSubrange((arpOffset + 8) ..< (arpOffset + 14), with: sourceMAC)
    frame.replaceSubrange((arpOffset + 14) ..< (arpOffset + 18), with: sourceIP)
    frame.replaceSubrange((arpOffset + 18) ..< (arpOffset + 24), with: [0, 0, 0, 0, 0, 0])
    frame.replaceSubrange((arpOffset + 24) ..< (arpOffset + 28), with: targetIP)

    return frame
}

func ethernetICMPEchoFrame(_ input: EthernetICMPEchoFrame) -> [UInt8] {
    let ipLength = 20
    let icmpLength = 8 + input.payloadSize
    var frame = [UInt8](repeating: 0, count: 14 + ipLength + icmpLength)

    frame.replaceSubrange(0 ..< 6, with: input.destinationMAC)
    frame.replaceSubrange(6 ..< 12, with: input.sourceMAC)
    frame[12] = 0x08
    frame[13] = 0x00

    let ipOffset = 14
    frame[ipOffset] = 0x45
    frame[ipOffset + 1] = 0
    writeBigUInt16(UInt16(ipLength + icmpLength), to: &frame, offset: ipOffset + 2)
    writeBigUInt16(UInt16(ProcessInfo.processInfo.processIdentifier & 0xFFFF), to: &frame, offset: ipOffset + 4)
    writeBigUInt16(0, to: &frame, offset: ipOffset + 6)
    frame[ipOffset + 8] = 64
    frame[ipOffset + 9] = UInt8(IPPROTO_ICMP)
    frame.replaceSubrange((ipOffset + 12) ..< (ipOffset + 16), with: input.sourceIP)
    frame.replaceSubrange((ipOffset + 16) ..< (ipOffset + 20), with: input.destinationIP)
    let ipChecksum = internetChecksum(Array(frame[ipOffset ..< (ipOffset + ipLength)]))
    writeBigUInt16(ipChecksum, to: &frame, offset: ipOffset + 10)

    let icmpOffset = ipOffset + ipLength
    frame[icmpOffset] = 8
    frame[icmpOffset + 1] = 0
    writeBigUInt16(input.identifier, to: &frame, offset: icmpOffset + 4)
    writeBigUInt16(input.sequence, to: &frame, offset: icmpOffset + 6)
    if input.payloadSize > 0 {
        for index in 0 ..< input.payloadSize {
            frame[icmpOffset + 8 + index] = UInt8((index + 8) & 0xFF)
        }
    }
    let icmpChecksum = internetChecksum(Array(frame[icmpOffset ..< (icmpOffset + icmpLength)]))
    writeBigUInt16(icmpChecksum, to: &frame, offset: icmpOffset + 2)

    return frame
}

func ethernetIPv6NeighborSolicitationFrame(
    sourceMAC: [UInt8],
    sourceIP: [UInt8],
    targetIP: [UInt8]
) -> [UInt8] {
    let destinationIP = solicitedNodeMulticastAddress(for: targetIP)
    let destinationMAC = solicitedNodeMulticastMAC(for: targetIP)
    let icmpLength = 32
    var frame = [UInt8](repeating: 0, count: 14 + 40 + icmpLength)

    frame.replaceSubrange(0 ..< 6, with: destinationMAC)
    frame.replaceSubrange(6 ..< 12, with: sourceMAC)
    frame[12] = 0x86
    frame[13] = 0xDD

    let ipOffset = 14
    writeIPv6Header(
        to: &frame,
        fields: IPv6HeaderFields(
            offset: ipOffset,
            payloadLength: icmpLength,
            nextHeader: UInt8(IPPROTO_ICMPV6),
            hopLimit: 255,
            sourceIP: sourceIP,
            destinationIP: destinationIP
        )
    )

    let icmpOffset = ipOffset + 40
    frame[icmpOffset] = 135
    frame[icmpOffset + 1] = 0
    frame.replaceSubrange((icmpOffset + 8) ..< (icmpOffset + 24), with: targetIP)
    frame[icmpOffset + 24] = 1
    frame[icmpOffset + 25] = 1
    frame.replaceSubrange((icmpOffset + 26) ..< (icmpOffset + 32), with: sourceMAC)

    let checksum = icmpv6Checksum(
        sourceIP: sourceIP,
        destinationIP: destinationIP,
        payload: Array(frame[icmpOffset ..< (icmpOffset + icmpLength)])
    )
    writeBigUInt16(checksum, to: &frame, offset: icmpOffset + 2)
    return frame
}

func ethernetICMPv6EchoFrame(_ input: EthernetICMPv6EchoFrame) -> [UInt8] {
    let icmpLength = 8 + input.payloadSize
    var frame = [UInt8](repeating: 0, count: 14 + 40 + icmpLength)

    frame.replaceSubrange(0 ..< 6, with: input.destinationMAC)
    frame.replaceSubrange(6 ..< 12, with: input.sourceMAC)
    frame[12] = 0x86
    frame[13] = 0xDD

    let ipOffset = 14
    writeIPv6Header(
        to: &frame,
        fields: IPv6HeaderFields(
            offset: ipOffset,
            payloadLength: icmpLength,
            nextHeader: UInt8(IPPROTO_ICMPV6),
            hopLimit: 64,
            sourceIP: input.sourceIP,
            destinationIP: input.destinationIP
        )
    )

    let icmpOffset = ipOffset + 40
    frame[icmpOffset] = 128
    frame[icmpOffset + 1] = 0
    writeBigUInt16(input.identifier, to: &frame, offset: icmpOffset + 4)
    writeBigUInt16(input.sequence, to: &frame, offset: icmpOffset + 6)
    if input.payloadSize > 0 {
        for index in 0 ..< input.payloadSize {
            frame[icmpOffset + 8 + index] = UInt8((index + 8) & 0xFF)
        }
    }
    let checksum = icmpv6Checksum(
        sourceIP: input.sourceIP,
        destinationIP: input.destinationIP,
        payload: Array(frame[icmpOffset ..< (icmpOffset + icmpLength)])
    )
    writeBigUInt16(checksum, to: &frame, offset: icmpOffset + 2)
    return frame
}

private func writeIPv6Header(
    to frame: inout [UInt8],
    fields: IPv6HeaderFields
) {
    frame[fields.offset] = 0x60
    writeBigUInt16(UInt16(fields.payloadLength), to: &frame, offset: fields.offset + 4)
    frame[fields.offset + 6] = fields.nextHeader
    frame[fields.offset + 7] = fields.hopLimit
    frame.replaceSubrange((fields.offset + 8) ..< (fields.offset + 24), with: fields.sourceIP)
    frame.replaceSubrange((fields.offset + 24) ..< (fields.offset + 40), with: fields.destinationIP)
}

private func solicitedNodeMulticastAddress(for targetIP: [UInt8]) -> [UInt8] {
    var address: [UInt8] = [
        0xFF, 0x02, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0x01,
        0xFF, 0, 0, 0,
    ]
    if targetIP.count == 16 {
        address[13] = targetIP[13]
        address[14] = targetIP[14]
        address[15] = targetIP[15]
    }
    return address
}

private func solicitedNodeMulticastMAC(for targetIP: [UInt8]) -> [UInt8] {
    guard targetIP.count == 16 else {
        return [0x33, 0x33, 0xFF, 0, 0, 0]
    }
    return [0x33, 0x33, 0xFF, targetIP[13], targetIP[14], targetIP[15]]
}

private func icmpv6Checksum(sourceIP: [UInt8], destinationIP: [UInt8], payload: [UInt8]) -> UInt16 {
    var pseudoHeader: [UInt8] = []
    pseudoHeader.append(contentsOf: sourceIP)
    pseudoHeader.append(contentsOf: destinationIP)
    pseudoHeader.append(UInt8((payload.count >> 24) & 0xFF))
    pseudoHeader.append(UInt8((payload.count >> 16) & 0xFF))
    pseudoHeader.append(UInt8((payload.count >> 8) & 0xFF))
    pseudoHeader.append(UInt8(payload.count & 0xFF))
    pseudoHeader.append(contentsOf: [0, 0, 0, UInt8(IPPROTO_ICMPV6)])
    pseudoHeader.append(contentsOf: payload)
    return internetChecksum(pseudoHeader)
}

func gatewayIPv6SourceAddress(interfaceState: NativeInterfaceState, gateway: String) -> String? {
    let normalizedGateway = normalizedIPv6Scope(gateway)
    if normalizedGateway.hasPrefix("fe80:") {
        return interfaceState.ipv6LinkLocalAddresses.first
    }
    return interfaceState.ipv6Addresses.first ?? interfaceState.ipv6LinkLocalAddresses.first
}

func parseIPv4Address(_ value: String) -> [UInt8]? {
    let parts = value.split(separator: ".")
    guard parts.count == 4 else {
        return nil
    }
    var bytes: [UInt8] = []
    for part in parts {
        guard let byte = UInt8(part) else {
            return nil
        }
        bytes.append(byte)
    }
    return bytes
}

func parseIPv6Address(_ value: String) -> [UInt8]? {
    var address = in6_addr()
    let normalized = normalizedIPv6Scope(value)
    guard inet_pton(AF_INET6, normalized, &address) == 1 else {
        return nil
    }
    return withUnsafeBytes(of: address) { Array($0) }
}

func parseMACAddress(_ value: String) -> [UInt8]? {
    let parts = value.split(separator: ":")
    guard parts.count == 6 else {
        return nil
    }
    var bytes: [UInt8] = []
    for part in parts {
        guard let byte = UInt8(part, radix: 16) else {
            return nil
        }
        bytes.append(byte)
    }
    return bytes
}

private func writeBigUInt16(_ value: UInt16, to buffer: inout [UInt8], offset: Int) {
    buffer[offset] = UInt8(value >> 8)
    buffer[offset + 1] = UInt8(value & 0x00FF)
}

func gatewayJitterNanos(attempts: [ActiveGatewayProbeAttempt]) -> UInt64 {
    let durations = attempts
        .sorted { $0.sequence < $1.sequence }
        .filter(\.reachable)
        .map(\.durationNanos)
    guard durations.count > 1 else {
        return 0
    }
    var previous = durations[0]
    var totalDifference: UInt64 = 0
    for duration in durations.dropFirst() {
        totalDifference += previous > duration ? previous - duration : duration - previous
        previous = duration
    }
    return totalDifference / UInt64(durations.count - 1)
}

func aggregateGatewayString(_ values: [String]) -> String {
    let nonEmpty = values.filter { !$0.isEmpty }
    guard let first = nonEmpty.first else {
        return "unknown"
    }
    return nonEmpty.allSatisfy { $0 == first } ? first : "mixed"
}

func formatGatewayProbeDouble(_ value: Double) -> String {
    String(format: "%.6f", value)
}
