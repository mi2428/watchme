import Darwin
import Foundation
import WatchmeCore

struct ActiveICMPProbeResult {
    let target: String
    let family: InternetAddressFamily
    let remoteIP: String
    let identifier: UInt16?
    let sequence: UInt16?
    let ok: Bool
    let outcome: String
    let error: String?
    let timing: ActiveProbeTiming

    var startWallNanos: UInt64 {
        timing.startWallNanos
    }

    var finishedWallNanos: UInt64 {
        timing.finishedWallNanos
    }

    var durationNanos: UInt64 {
        timing.durationNanos
    }

    var timingSource: String {
        timing.timingSource
    }

    var timestampSource: String {
        timing.timestampSource
    }
}

private struct ICMPFailureContext {
    let target: String
    let family: InternetAddressFamily
    let remoteIP: String
    let identifier: UInt16?
    let sequence: UInt16?
    let startWallNanos: UInt64
}

func runInternetICMPProbe(
    target: String,
    family: InternetAddressFamily,
    remoteIP: String?,
    timeout: TimeInterval,
    interfaceName: String?,
    packetStore: PassivePacketStore? = nil
) -> ActiveICMPProbeResult {
    let host = normalizedProbeHost(target)
    let startWallNanos = wallClockNanos()
    guard let remoteIP, !remoteIP.isEmpty else {
        return failedICMPProbe(
            context: ICMPFailureContext(
                target: host,
                family: family,
                remoteIP: "none",
                identifier: nil,
                sequence: nil,
                startWallNanos: startWallNanos
            ),
            outcome: "no_address",
            timingSource: noAddressTimingSource,
            error: "no \(family.metricValue) address was available for ICMP probe"
        )
    }

    let echo = icmpEchoPacket(family: family)
    let request = ActiveICMPProbeRequest(
        family: family,
        remoteIP: remoteIP,
        identifier: echo.identifier,
        sequence: echo.sequence,
        interfaceName: interfaceName,
        startWallNanos: startWallNanos,
        timeout: timeout
    )
    packetStore?.registerActiveICMPProbe(request)
    defer {
        packetStore?.unregisterActiveICMPProbe(request)
    }

    do {
        try sendICMPEchoRequest(packet: echo.data, family: family, remoteIP: remoteIP, interfaceName: interfaceName)
    } catch {
        return failedICMPProbe(
            context: ICMPFailureContext(
                target: host,
                family: family,
                remoteIP: remoteIP,
                identifier: echo.identifier,
                sequence: echo.sequence,
                startWallNanos: startWallNanos
            ),
            outcome: "send_failed",
            timingSource: networkFrameworkTimingSource,
            error: error.localizedDescription
        )
    }

    if let exchange = packetStore?.icmpExchange(for: request, wait: timeout) {
        let timing = exchange.timing
        return ActiveICMPProbeResult(
            target: host,
            family: family,
            remoteIP: remoteIP,
            identifier: exchange.request.identifier,
            sequence: exchange.request.sequence,
            ok: true,
            outcome: "reply",
            error: nil,
            timing: timing
        )
    }

    return failedICMPProbe(
        context: ICMPFailureContext(
            target: host,
            family: family,
            remoteIP: remoteIP,
            identifier: echo.identifier,
            sequence: echo.sequence,
            startWallNanos: startWallNanos
        ),
        outcome: "timeout",
        timingSource: wallClockDeadlineTimingSource,
        error: "ICMP echo reply was not observed before timeout"
    )
}

private func failedICMPProbe(
    context: ICMPFailureContext,
    outcome: String,
    timingSource: String,
    error: String
) -> ActiveICMPProbeResult {
    let finishedWallNanos = wallClockNanos()
    return ActiveICMPProbeResult(
        target: context.target,
        family: context.family,
        remoteIP: context.remoteIP,
        identifier: context.identifier,
        sequence: context.sequence,
        ok: false,
        outcome: outcome,
        error: error,
        timing: ActiveProbeTiming(
            startWallNanos: context.startWallNanos,
            finishedWallNanos: finishedWallNanos,
            timingSource: timingSource,
            timestampSource: wallClockTimestampSource
        )
    )
}

private func sendICMPEchoRequest(packet: [UInt8], family: InternetAddressFamily, remoteIP: String, interfaceName: String?) throws {
    let socketFamily = family == .ipv4 ? AF_INET : AF_INET6
    let protocolNumber = family == .ipv4 ? IPPROTO_ICMP : IPPROTO_ICMPV6
    let fd = socket(socketFamily, SOCK_DGRAM, protocolNumber)
    guard fd >= 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EACCES)
    }
    defer {
        close(fd)
    }
    try bindSocket(fd, family: family, interfaceName: interfaceName)
    let sent: ssize_t
    switch family {
    case .ipv4:
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        inet_pton(AF_INET, remoteIP, &address.sin_addr)
        sent = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                sendto(fd, packet, packet.count, 0, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    case .ipv6:
        var address = sockaddr_in6()
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        address.sin6_family = sa_family_t(AF_INET6)
        inet_pton(AF_INET6, remoteIP, &address.sin6_addr)
        sent = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                sendto(fd, packet, packet.count, 0, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
    }
    guard sent == packet.count else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}

private func bindSocket(_ fd: Int32, family: InternetAddressFamily, interfaceName: String?) throws {
    guard let interfaceName, !interfaceName.isEmpty else {
        return
    }
    var interfaceIndex = if_nametoindex(interfaceName)
    guard interfaceIndex > 0 else {
        throw POSIXError(.ENXIO)
    }
    let level = family == .ipv4 ? IPPROTO_IP : IPPROTO_IPV6
    let option = family == .ipv4 ? IP_BOUND_IF : IPV6_BOUND_IF
    let optionLength = socklen_t(MemoryLayout.size(ofValue: interfaceIndex))
    let result = withUnsafePointer(to: &interfaceIndex) { pointer in
        setsockopt(fd, level, option, pointer, optionLength)
    }
    guard result == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EINVAL)
    }
}

private struct ICMPEchoPacket {
    let data: [UInt8]
    let identifier: UInt16
    let sequence: UInt16
}

private func icmpEchoPacket(family: InternetAddressFamily) -> ICMPEchoPacket {
    let identifier = UInt16.random(in: 0 ... UInt16.max)
    let sequence = UInt16.random(in: 0 ... UInt16.max)
    var packet: [UInt8] = [
        family == .ipv4 ? 8 : 128,
        0,
        0,
        0,
        UInt8(identifier >> 8),
        UInt8(identifier & 0x00FF),
        UInt8(sequence >> 8),
        UInt8(sequence & 0x00FF),
    ]
    packet.append(contentsOf: Array("watchme".utf8))
    if family == .ipv4 {
        let checksum = internetChecksum(packet)
        packet[2] = UInt8(checksum >> 8)
        packet[3] = UInt8(checksum & 0x00FF)
    }
    return ICMPEchoPacket(data: packet, identifier: identifier, sequence: sequence)
}

func internetChecksum(_ bytes: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    var index = 0
    while index + 1 < bytes.count {
        sum += UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
        index += 2
    }
    if index < bytes.count {
        sum += UInt32(bytes[index]) << 8
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return UInt16(~sum & 0xFFFF)
}
