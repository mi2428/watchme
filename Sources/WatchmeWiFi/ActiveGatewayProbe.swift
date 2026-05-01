import Darwin
import Foundation
import WatchmeBPF
import WatchmeCore

struct ActiveGatewayProbeAttempt {
    let sequence: Int
    let identifier: UInt16?
    let icmpSequence: UInt16?
    let reachable: Bool
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

struct ActiveGatewayARPResult {
    let gateway: String
    let family: InternetAddressFamily
    let protocolName: String
    let sourceIP: String?
    let sourceHardwareAddress: String?
    let gatewayHardwareAddress: String?
    let ok: Bool
    let outcome: String
    let error: String?
    let timing: ActiveProbeTiming

    init(
        gateway: String,
        family: InternetAddressFamily = .ipv4,
        protocolName: String = "arp",
        sourceIP: String?,
        sourceHardwareAddress: String?,
        gatewayHardwareAddress: String?,
        ok: Bool,
        outcome: String,
        error: String?,
        timing: ActiveProbeTiming
    ) {
        self.gateway = gateway
        self.family = family
        self.protocolName = protocolName
        self.sourceIP = sourceIP
        self.sourceHardwareAddress = sourceHardwareAddress
        self.gatewayHardwareAddress = gatewayHardwareAddress
        self.ok = ok
        self.outcome = outcome
        self.error = error
        self.timing = timing
    }

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

struct ActiveGatewayProbeResult {
    let gateway: String
    let family: InternetAddressFamily
    let attempts: [ActiveGatewayProbeAttempt]
    let burstIntervalSeconds: TimeInterval
    let arpResolution: ActiveGatewayARPResult?

    init(
        gateway: String,
        family: InternetAddressFamily = .ipv4,
        attempts: [ActiveGatewayProbeAttempt],
        burstIntervalSeconds: TimeInterval,
        arpResolution: ActiveGatewayARPResult? = nil
    ) {
        self.gateway = gateway
        self.family = family
        self.attempts = attempts.sorted { $0.sequence < $1.sequence }
        self.burstIntervalSeconds = burstIntervalSeconds
        self.arpResolution = arpResolution
    }

    var probeCount: Int {
        attempts.count
    }

    var reachableCount: Int {
        attempts.filter(\.reachable).count
    }

    var lostCount: Int {
        max(probeCount - reachableCount, 0)
    }

    var lossRatio: Double {
        guard probeCount > 0 else {
            return 1.0
        }
        return Double(lostCount) / Double(probeCount)
    }

    var jitterNanos: UInt64 {
        gatewayJitterNanos(attempts: attempts)
    }

    var reachable: Bool {
        reachableCount > 0
    }

    var pathOK: Bool {
        (arpResolution?.ok ?? true) && reachable
    }

    var outcome: String {
        if let arpResolution, !arpResolution.ok {
            return "\(arpResolution.protocolName)_\(arpResolution.outcome)"
        }
        guard !attempts.isEmpty else {
            return "no_samples"
        }
        if reachableCount == 0 {
            return "loss"
        }
        if lostCount > 0 {
            return "partial_loss"
        }
        let outcomes = Set(attempts.map(\.outcome))
        return outcomes.count == 1 ? (outcomes.first ?? "unknown") : "mixed"
    }

    var error: String? {
        if let arpResolution, !arpResolution.ok, let error = arpResolution.error, !error.isEmpty {
            return error
        }
        if let latestError = latestAttempt?.error, !latestError.isEmpty {
            return latestError
        }
        return attempts.first { !($0.error ?? "").isEmpty }?.error
    }

    var startWallNanos: UInt64 {
        ([arpResolution?.startWallNanos].compactMap(\.self) + attempts.map(\.startWallNanos)).min() ?? 0
    }

    var finishedWallNanos: UInt64 {
        ([arpResolution?.finishedWallNanos].compactMap(\.self) + attempts.map(\.finishedWallNanos)).max()
            ?? max(startWallNanos + 1000, 1000)
    }

    var burstDurationNanos: UInt64 {
        guard let start = attempts.map(\.startWallNanos).min(),
              let finished = attempts.map(\.finishedWallNanos).max()
        else {
            return 0
        }
        return max(finished >= start ? finished - start : 0, 1000)
    }

    var durationNanos: UInt64 {
        averageReachableDurationNanos ?? latestAttempt?.durationNanos ?? arpResolution?.durationNanos ?? burstDurationNanos
    }

    var timingSource: String {
        aggregateGatewayString(attempts.map(\.timingSource) + [arpResolution?.timingSource].compactMap(\.self))
    }

    var timestampSource: String {
        aggregateGatewayString(attempts.map(\.timestampSource) + [arpResolution?.timestampSource].compactMap(\.self))
    }

    var latestAttempt: ActiveGatewayProbeAttempt? {
        attempts.max { $0.sequence < $1.sequence }
    }

    var gatewayHardwareAddress: String? {
        arpResolution?.gatewayHardwareAddress
    }

    private var averageReachableDurationNanos: UInt64? {
        let durations = attempts.filter(\.reachable).map(\.durationNanos)
        guard !durations.isEmpty else {
            return nil
        }
        let sum = durations.reduce(UInt64(0), +)
        return sum / UInt64(durations.count)
    }
}

func runGatewayICMPProbe(
    gateway: String,
    timeout: TimeInterval,
    interfaceName: String?,
    packetStore: PassivePacketStore? = nil,
    burstCount: Int = WiFiDefaults.gatewayProbeBurstCount,
    burstInterval: TimeInterval = WiFiDefaults.gatewayProbeBurstInterval,
    useDirectBPF: Bool = true
) -> ActiveGatewayProbeResult {
    let count = max(burstCount, 1)
    let interval = max(burstInterval, 0)
    if useDirectBPF {
        let arpResolution = runBPFGatewayARPResolution(
            gateway: gateway,
            timeout: timeout,
            interfaceName: interfaceName
        )
        guard arpResolution.ok,
              let gatewayHardwareAddress = arpResolution.gatewayHardwareAddress,
              !gatewayHardwareAddress.isEmpty
        else {
            return ActiveGatewayProbeResult(
                gateway: gateway,
                attempts: [],
                burstIntervalSeconds: interval,
                arpResolution: arpResolution
            )
        }
        let attempts = runProbeBurst(count: count, interval: interval) { sequence in
            runBPFGatewayICMPAttempt(
                sequence: sequence,
                gateway: gateway,
                gatewayHardwareAddress: gatewayHardwareAddress,
                timeout: timeout,
                interfaceName: interfaceName
            )
        }
        return ActiveGatewayProbeResult(
            gateway: gateway,
            attempts: attempts,
            burstIntervalSeconds: interval,
            arpResolution: arpResolution
        )
    }

    let attempts = runProbeBurst(count: count, interval: interval) { sequence in
        let result = runInternetICMPProbe(
            target: gateway,
            family: .ipv4,
            remoteIP: gateway,
            timeout: timeout,
            interfaceName: interfaceName,
            packetStore: packetStore
        )
        return gatewayAttempt(sequence: sequence, result: result)
    }

    return ActiveGatewayProbeResult(
        gateway: gateway,
        attempts: attempts,
        burstIntervalSeconds: interval
    )
}

func runGatewayICMPv6Probe(
    gateway: String,
    timeout: TimeInterval,
    interfaceName: String?,
    packetStore: PassivePacketStore? = nil,
    burstCount: Int = WiFiDefaults.gatewayProbeBurstCount,
    burstInterval: TimeInterval = WiFiDefaults.gatewayProbeBurstInterval,
    useDirectBPF: Bool = true
) -> ActiveGatewayProbeResult {
    let count = max(burstCount, 1)
    let interval = max(burstInterval, 0)
    if useDirectBPF {
        let ndpResolution = runBPFGatewayNDPResolution(
            gateway: gateway,
            timeout: timeout,
            interfaceName: interfaceName
        )
        guard ndpResolution.ok,
              let gatewayHardwareAddress = ndpResolution.gatewayHardwareAddress,
              !gatewayHardwareAddress.isEmpty
        else {
            return ActiveGatewayProbeResult(
                gateway: gateway,
                family: .ipv6,
                attempts: [],
                burstIntervalSeconds: interval,
                arpResolution: ndpResolution
            )
        }
        let attempts = runProbeBurst(count: count, interval: interval) { sequence in
            runBPFGatewayICMPv6Attempt(
                sequence: sequence,
                gateway: gateway,
                gatewayHardwareAddress: gatewayHardwareAddress,
                timeout: timeout,
                interfaceName: interfaceName
            )
        }
        return ActiveGatewayProbeResult(
            gateway: gateway,
            family: .ipv6,
            attempts: attempts,
            burstIntervalSeconds: interval,
            arpResolution: ndpResolution
        )
    }

    let attempts = runProbeBurst(count: count, interval: interval) { sequence in
        let result = runInternetICMPProbe(
            target: gateway,
            family: .ipv6,
            remoteIP: gateway,
            timeout: timeout,
            interfaceName: interfaceName,
            packetStore: packetStore
        )
        return gatewayAttempt(sequence: sequence, result: result)
    }

    return ActiveGatewayProbeResult(
        gateway: gateway,
        family: .ipv6,
        attempts: attempts,
        burstIntervalSeconds: interval
    )
}

private func runBPFGatewayARPResolution(
    gateway: String,
    timeout: TimeInterval,
    interfaceName: String?
) -> ActiveGatewayARPResult {
    let startWallNanos = wallClockNanos()
    guard let interfaceName, !interfaceName.isEmpty else {
        return failedGatewayARPResolution(
            gateway: gateway,
            sourceIP: nil,
            sourceHardwareAddress: nil,
            startWallNanos: startWallNanos,
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface was not available for BPF gateway ARP probe"
        )
    }
    let interfaceState = nativeInterfaceState(interfaceName: interfaceName)
    guard let localIP = interfaceState.ipv4Addresses.first else {
        return failedGatewayARPResolution(
            gateway: gateway,
            sourceIP: nil,
            sourceHardwareAddress: interfaceState.macAddress,
            startWallNanos: startWallNanos,
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface \(interfaceName) had no IPv4 address for BPF gateway ARP probe"
        )
    }
    guard let sourceMAC = interfaceState.macAddress,
          let sourceMACBytes = parseMACAddress(sourceMAC),
          let sourceIPBytes = parseIPv4Address(localIP),
          let gatewayIPBytes = parseIPv4Address(gateway)
    else {
        return failedGatewayARPResolution(
            gateway: gateway,
            sourceIP: localIP,
            sourceHardwareAddress: interfaceState.macAddress,
            startWallNanos: startWallNanos,
            outcome: "preflight_failed",
            timingSource: networkFrameworkTimingSource,
            error: "BPF gateway ARP probe could not parse interface or gateway addresses"
        )
    }

    let openResult = openBPFDevice()
    guard let fd = openResult.fd else {
        return failedGatewayARPResolution(
            gateway: gateway,
            sourceIP: localIP,
            sourceHardwareAddress: sourceMAC,
            startWallNanos: startWallNanos,
            outcome: "bpf_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: openResult.error ?? "could not open /dev/bpf for gateway ARP probe"
        )
    }
    defer {
        close(fd)
    }

    var bpfTags: [String: String] = [:]
    guard configureBPF(fd: fd, interfaceName: interfaceName, tags: &bpfTags) else {
        return failedGatewayARPResolution(
            gateway: gateway,
            sourceIP: localIP,
            sourceHardwareAddress: sourceMAC,
            startWallNanos: startWallNanos,
            outcome: "bpf_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: bpfTags["bpf.error"] ?? "could not configure BPF for gateway ARP probe"
        )
    }

    let frame = ethernetARPRequestFrame(
        sourceMAC: sourceMACBytes,
        sourceIP: sourceIPBytes,
        targetIP: gatewayIPBytes
    )
    let requestWriteWallNanos = wallClockNanos()
    let sent = frame.withUnsafeBytes { frameBuffer in
        write(fd, frameBuffer.baseAddress, frameBuffer.count)
    }
    guard sent == frame.count else {
        return failedGatewayARPResolution(
            gateway: gateway,
            sourceIP: localIP,
            sourceHardwareAddress: sourceMAC,
            startWallNanos: startWallNanos,
            outcome: "send_failed",
            timingSource: networkFrameworkTimingSource,
            error: "BPF gateway ARP write failed: \(posixErrorString())"
        )
    }

    let result = readBPFGatewayARPReply(
        fd: fd,
        bufferLength: Int(bpfTags["bpf.buffer_length"] ?? "4096") ?? 4096,
        timeout: timeout,
        localIP: localIP,
        gateway: gateway
    )
    guard result.ok,
          let replyNanos = result.replyWallNanos,
          let gatewayHardwareAddress = result.gatewayHardwareAddress
    else {
        return failedGatewayARPResolution(
            gateway: gateway,
            sourceIP: localIP,
            sourceHardwareAddress: sourceMAC,
            startWallNanos: result.requestWallNanos ?? requestWriteWallNanos,
            outcome: "timeout",
            timingSource: wallClockDeadlineTimingSource,
            error: result.error ?? "BPF gateway ARP reply timed out"
        )
    }

    let timing = gatewayARPRequestToReplyTiming(
        requestPacketWallNanos: result.requestWallNanos,
        requestWriteWallNanos: requestWriteWallNanos,
        replyWallNanos: replyNanos
    )
    return ActiveGatewayARPResult(
        gateway: gateway,
        sourceIP: localIP,
        sourceHardwareAddress: macAddressString(bytes: sourceMACBytes),
        gatewayHardwareAddress: gatewayHardwareAddress,
        ok: true,
        outcome: "reply",
        error: nil,
        timing: timing
    )
}

private func runBPFGatewayNDPResolution(
    gateway: String,
    timeout: TimeInterval,
    interfaceName: String?
) -> ActiveGatewayARPResult {
    let startWallNanos = wallClockNanos()
    guard let interfaceName, !interfaceName.isEmpty else {
        return failedGatewayARPResolution(
            gateway: gateway,
            family: .ipv6,
            protocolName: "ndp",
            sourceIP: nil,
            sourceHardwareAddress: nil,
            startWallNanos: startWallNanos,
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface was not available for BPF gateway NDP probe"
        )
    }
    let interfaceState = nativeInterfaceState(interfaceName: interfaceName)
    guard let localIP = gatewayIPv6SourceAddress(interfaceState: interfaceState, gateway: gateway) else {
        return failedGatewayARPResolution(
            gateway: gateway,
            family: .ipv6,
            protocolName: "ndp",
            sourceIP: nil,
            sourceHardwareAddress: interfaceState.macAddress,
            startWallNanos: startWallNanos,
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface \(interfaceName) had no IPv6 address for BPF gateway NDP probe"
        )
    }
    guard let sourceMAC = interfaceState.macAddress,
          let sourceMACBytes = parseMACAddress(sourceMAC),
          let sourceIPBytes = parseIPv6Address(localIP),
          let gatewayIPBytes = parseIPv6Address(gateway)
    else {
        return failedGatewayARPResolution(
            gateway: gateway,
            family: .ipv6,
            protocolName: "ndp",
            sourceIP: localIP,
            sourceHardwareAddress: interfaceState.macAddress,
            startWallNanos: startWallNanos,
            outcome: "preflight_failed",
            timingSource: networkFrameworkTimingSource,
            error: "BPF gateway NDP probe could not parse interface or gateway addresses"
        )
    }

    let openResult = openBPFDevice()
    guard let fd = openResult.fd else {
        return failedGatewayARPResolution(
            gateway: gateway,
            family: .ipv6,
            protocolName: "ndp",
            sourceIP: localIP,
            sourceHardwareAddress: sourceMAC,
            startWallNanos: startWallNanos,
            outcome: "bpf_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: openResult.error ?? "could not open /dev/bpf for gateway NDP probe"
        )
    }
    defer {
        close(fd)
    }

    var bpfTags: [String: String] = [:]
    guard configureBPF(fd: fd, interfaceName: interfaceName, tags: &bpfTags) else {
        return failedGatewayARPResolution(
            gateway: gateway,
            family: .ipv6,
            protocolName: "ndp",
            sourceIP: localIP,
            sourceHardwareAddress: sourceMAC,
            startWallNanos: startWallNanos,
            outcome: "bpf_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: bpfTags["bpf.error"] ?? "could not configure BPF for gateway NDP probe"
        )
    }

    let frame = ethernetIPv6NeighborSolicitationFrame(
        sourceMAC: sourceMACBytes,
        sourceIP: sourceIPBytes,
        targetIP: gatewayIPBytes
    )
    let requestWriteWallNanos = wallClockNanos()
    let sent = frame.withUnsafeBytes { frameBuffer in
        write(fd, frameBuffer.baseAddress, frameBuffer.count)
    }
    guard sent == frame.count else {
        return failedGatewayARPResolution(
            gateway: gateway,
            family: .ipv6,
            protocolName: "ndp",
            sourceIP: localIP,
            sourceHardwareAddress: sourceMAC,
            startWallNanos: startWallNanos,
            outcome: "send_failed",
            timingSource: networkFrameworkTimingSource,
            error: "BPF gateway NDP write failed: \(posixErrorString())"
        )
    }

    let result = readBPFGatewayNeighborAdvertisement(
        fd: fd,
        bufferLength: Int(bpfTags["bpf.buffer_length"] ?? "4096") ?? 4096,
        timeout: timeout,
        localIP: localIP,
        gateway: gateway
    )
    guard result.ok,
          let replyNanos = result.replyWallNanos,
          let gatewayHardwareAddress = result.gatewayHardwareAddress
    else {
        return failedGatewayARPResolution(
            gateway: gateway,
            family: .ipv6,
            protocolName: "ndp",
            sourceIP: localIP,
            sourceHardwareAddress: sourceMAC,
            startWallNanos: result.requestWallNanos ?? requestWriteWallNanos,
            outcome: "timeout",
            timingSource: wallClockDeadlineTimingSource,
            error: result.error ?? "BPF gateway NDP reply timed out"
        )
    }

    let timing = gatewayARPRequestToReplyTiming(
        requestPacketWallNanos: result.requestWallNanos,
        requestWriteWallNanos: requestWriteWallNanos,
        replyWallNanos: replyNanos
    )
    return ActiveGatewayARPResult(
        gateway: gateway,
        family: .ipv6,
        protocolName: "ndp",
        sourceIP: localIP,
        sourceHardwareAddress: macAddressString(bytes: sourceMACBytes),
        gatewayHardwareAddress: gatewayHardwareAddress,
        ok: true,
        outcome: "reply",
        error: nil,
        timing: timing
    )
}

func gatewayARPRequestToReplyTiming(
    requestPacketWallNanos: UInt64?,
    requestWriteWallNanos: UInt64,
    replyWallNanos: UInt64
) -> ActiveProbeTiming {
    if let requestPacketWallNanos {
        return .bpfPacket(start: requestPacketWallNanos, finished: replyWallNanos)
    }
    return ActiveProbeTiming(
        startWallNanos: requestWriteWallNanos,
        finishedWallNanos: replyWallNanos,
        timingSource: wallClockPacketBoundaryTimingSource,
        timestampSource: wallClockTimestampSource
    )
}

private func runBPFGatewayICMPAttempt(
    sequence: Int,
    gateway: String,
    gatewayHardwareAddress: String,
    timeout: TimeInterval,
    interfaceName: String?
) -> ActiveGatewayProbeAttempt {
    let startWallNanos = wallClockNanos()
    let identifier = UInt16(ProcessInfo.processInfo.processIdentifier & 0xFFFF)
    let icmpSequence = UInt16((wallClockNanos() + UInt64(sequence)) & UInt64(UInt16.max))
    guard let interfaceName, !interfaceName.isEmpty else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface was not available for BPF gateway probe"
        )
    }
    let interfaceState = nativeInterfaceState(interfaceName: interfaceName)
    guard let localIP = interfaceState.ipv4Addresses.first else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface \(interfaceName) had no IPv4 address for BPF gateway probe"
        )
    }
    guard let sourceMAC = interfaceState.macAddress,
          let sourceMACBytes = parseMACAddress(sourceMAC),
          let gatewayMACBytes = parseMACAddress(gatewayHardwareAddress),
          let sourceIPBytes = parseIPv4Address(localIP),
          let gatewayIPBytes = parseIPv4Address(gateway)
    else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "preflight_failed",
            timingSource: networkFrameworkTimingSource,
            error: "BPF gateway probe could not parse interface or gateway addresses"
        )
    }

    let openResult = openBPFDevice()
    guard let fd = openResult.fd else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "bpf_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: openResult.error ?? "could not open /dev/bpf for gateway probe"
        )
    }
    defer {
        close(fd)
    }

    var bpfTags: [String: String] = [:]
    guard configureBPF(fd: fd, interfaceName: interfaceName, tags: &bpfTags) else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "bpf_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: bpfTags["bpf.error"] ?? "could not configure BPF for gateway probe"
        )
    }

    let frame = ethernetICMPEchoFrame(
        sourceMAC: sourceMACBytes,
        destinationMAC: gatewayMACBytes,
        sourceIP: sourceIPBytes,
        destinationIP: gatewayIPBytes,
        identifier: identifier,
        sequence: icmpSequence,
        payloadSize: 56
    )
    let sent = frame.withUnsafeBytes { frameBuffer in
        write(fd, frameBuffer.baseAddress, frameBuffer.count)
    }
    guard sent == frame.count else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "send_failed",
            timingSource: networkFrameworkTimingSource,
            error: "BPF gateway ICMP write failed: \(posixErrorString())"
        )
    }

    let result = readBPFGatewayICMPReply(
        fd: fd,
        bufferLength: Int(bpfTags["bpf.buffer_length"] ?? "4096") ?? 4096,
        timeout: timeout,
        localIP: localIP,
        gateway: gateway,
        identifier: identifier,
        sequence: icmpSequence,
        startWallNanos: startWallNanos
    )
    guard result.ok, let replyNanos = result.replyWallNanos else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "timeout",
            timingSource: wallClockDeadlineTimingSource,
            error: result.error ?? "BPF gateway ICMP echo timed out"
        )
    }

    let timing = result.requestWallNanos.map {
        ActiveProbeTiming.bpfPacket(start: $0, finished: replyNanos)
    } ?? .networkFramework(start: startWallNanos, finished: wallClockNanos())
    return ActiveGatewayProbeAttempt(
        sequence: sequence,
        identifier: identifier,
        icmpSequence: icmpSequence,
        reachable: true,
        outcome: "reply",
        error: nil,
        timing: timing
    )
}

private func runBPFGatewayICMPv6Attempt(
    sequence: Int,
    gateway: String,
    gatewayHardwareAddress: String,
    timeout: TimeInterval,
    interfaceName: String?
) -> ActiveGatewayProbeAttempt {
    let startWallNanos = wallClockNanos()
    let identifier = UInt16(ProcessInfo.processInfo.processIdentifier & 0xFFFF)
    let icmpSequence = UInt16((wallClockNanos() + UInt64(sequence)) & UInt64(UInt16.max))
    guard let interfaceName, !interfaceName.isEmpty else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface was not available for BPF IPv6 gateway probe"
        )
    }
    let interfaceState = nativeInterfaceState(interfaceName: interfaceName)
    guard let localIP = gatewayIPv6SourceAddress(interfaceState: interfaceState, gateway: gateway) else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface \(interfaceName) had no IPv6 address for BPF IPv6 gateway probe"
        )
    }
    guard let sourceMAC = interfaceState.macAddress,
          let sourceMACBytes = parseMACAddress(sourceMAC),
          let gatewayMACBytes = parseMACAddress(gatewayHardwareAddress),
          let sourceIPBytes = parseIPv6Address(localIP),
          let gatewayIPBytes = parseIPv6Address(gateway)
    else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "preflight_failed",
            timingSource: networkFrameworkTimingSource,
            error: "BPF IPv6 gateway probe could not parse interface or gateway addresses"
        )
    }

    let openResult = openBPFDevice()
    guard let fd = openResult.fd else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "bpf_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: openResult.error ?? "could not open /dev/bpf for IPv6 gateway probe"
        )
    }
    defer {
        close(fd)
    }

    var bpfTags: [String: String] = [:]
    guard configureBPF(fd: fd, interfaceName: interfaceName, tags: &bpfTags) else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "bpf_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: bpfTags["bpf.error"] ?? "could not configure BPF for IPv6 gateway probe"
        )
    }

    let frame = ethernetICMPv6EchoFrame(
        sourceMAC: sourceMACBytes,
        destinationMAC: gatewayMACBytes,
        sourceIP: sourceIPBytes,
        destinationIP: gatewayIPBytes,
        identifier: identifier,
        sequence: icmpSequence,
        payloadSize: 56
    )
    let sent = frame.withUnsafeBytes { frameBuffer in
        write(fd, frameBuffer.baseAddress, frameBuffer.count)
    }
    guard sent == frame.count else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "send_failed",
            timingSource: networkFrameworkTimingSource,
            error: "BPF gateway ICMPv6 write failed: \(posixErrorString())"
        )
    }

    let result = readBPFGatewayICMPv6Reply(
        fd: fd,
        bufferLength: Int(bpfTags["bpf.buffer_length"] ?? "4096") ?? 4096,
        timeout: timeout,
        localIP: localIP,
        gateway: gateway,
        identifier: identifier,
        sequence: icmpSequence,
        startWallNanos: startWallNanos
    )
    guard result.ok, let replyNanos = result.replyWallNanos else {
        return failedGatewayAttempt(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            outcome: "timeout",
            timingSource: wallClockDeadlineTimingSource,
            error: result.error ?? "BPF gateway ICMPv6 echo timed out"
        )
    }

    let timing = result.requestWallNanos.map {
        ActiveProbeTiming.bpfPacket(start: $0, finished: replyNanos)
    } ?? .networkFramework(start: startWallNanos, finished: wallClockNanos())
    return ActiveGatewayProbeAttempt(
        sequence: sequence,
        identifier: identifier,
        icmpSequence: icmpSequence,
        reachable: true,
        outcome: "reply",
        error: nil,
        timing: timing
    )
}

private func failedGatewayARPResolution(
    gateway: String,
    family: InternetAddressFamily = .ipv4,
    protocolName: String = "arp",
    sourceIP: String?,
    sourceHardwareAddress: String?,
    startWallNanos: UInt64,
    outcome: String,
    timingSource: String,
    error: String
) -> ActiveGatewayARPResult {
    ActiveGatewayARPResult(
        gateway: gateway,
        family: family,
        protocolName: protocolName,
        sourceIP: sourceIP,
        sourceHardwareAddress: sourceHardwareAddress,
        gatewayHardwareAddress: nil,
        ok: false,
        outcome: outcome,
        error: error,
        timing: ActiveProbeTiming(
            startWallNanos: startWallNanos,
            finishedWallNanos: wallClockNanos(),
            timingSource: timingSource,
            timestampSource: wallClockTimestampSource
        )
    )
}

private func gatewayAttempt(sequence: Int, result: ActiveICMPProbeResult) -> ActiveGatewayProbeAttempt {
    ActiveGatewayProbeAttempt(
        sequence: sequence,
        identifier: result.identifier,
        icmpSequence: result.sequence,
        reachable: result.ok,
        outcome: result.ok ? "reply" : result.outcome,
        error: result.error,
        timing: result.timing
    )
}

private func failedGatewayAttempt(
    sequence: Int,
    identifier: UInt16?,
    icmpSequence: UInt16?,
    startWallNanos: UInt64,
    outcome: String,
    timingSource: String,
    error: String
) -> ActiveGatewayProbeAttempt {
    ActiveGatewayProbeAttempt(
        sequence: sequence,
        identifier: identifier,
        icmpSequence: icmpSequence,
        reachable: false,
        outcome: outcome,
        error: error,
        timing: ActiveProbeTiming(
            startWallNanos: startWallNanos,
            finishedWallNanos: wallClockNanos(),
            timingSource: timingSource,
            timestampSource: wallClockTimestampSource
        )
    )
}

private struct BPFGatewayARPReadResult {
    let ok: Bool
    let error: String?
    let requestWallNanos: UInt64?
    let replyWallNanos: UInt64?
    let gatewayHardwareAddress: String?
}

private typealias BPFGatewayNDPReadResult = BPFGatewayARPReadResult

private struct BPFGatewayICMPReadResult {
    let ok: Bool
    let error: String?
    let requestWallNanos: UInt64?
    let replyWallNanos: UInt64?
}

struct BPFGatewayICMPPacket {
    let family: InternetAddressFamily
    let type: UInt8
    let code: UInt8
    let sourceIP: String
    let destinationIP: String
    let identifier: UInt16
    let sequence: UInt16
}

struct BPFGatewayNeighborPacket {
    let type: UInt8
    let code: UInt8
    let sourceIP: String
    let destinationIP: String
    let targetAddress: String?
    let sourceLinkLayerAddress: String?
    let targetLinkLayerAddress: String?
    let ethernetSourceAddress: String
}

private func readBPFGatewayARPReply(
    fd: Int32,
    bufferLength: Int,
    timeout: TimeInterval,
    localIP: String,
    gateway: String
) -> BPFGatewayARPReadResult {
    let started = DispatchTime.now().uptimeNanoseconds
    let timeoutNanos = UInt64(max(timeout, 0.001) * 1_000_000_000)
    var requestWallNanos: UInt64?
    var pollDescriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
    var readBuffer = [UInt8](repeating: 0, count: max(bufferLength, 4096))

    while true {
        let elapsedNanos = DispatchTime.now().uptimeNanoseconds - started
        guard elapsedNanos < timeoutNanos else {
            return BPFGatewayARPReadResult(
                ok: false,
                error: "BPF gateway ARP reply timed out",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil,
                gatewayHardwareAddress: nil
            )
        }
        let remainingMillis = max(1, Int((timeoutNanos - elapsedNanos) / 1_000_000))

        pollDescriptor.revents = 0
        let ready = poll(&pollDescriptor, 1, Int32(remainingMillis))
        if ready == 0 {
            return BPFGatewayARPReadResult(
                ok: false,
                error: "BPF gateway ARP reply timed out",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil,
                gatewayHardwareAddress: nil
            )
        }
        guard ready > 0 else {
            return BPFGatewayARPReadResult(
                ok: false,
                error: "BPF gateway ARP poll failed: \(posixErrorString())",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil,
                gatewayHardwareAddress: nil
            )
        }

        let bytesRead = readBuffer.withUnsafeMutableBytes { rawBuffer in
            read(fd, rawBuffer.baseAddress, rawBuffer.count)
        }
        guard bytesRead > 0 else {
            return BPFGatewayARPReadResult(
                ok: false,
                error: "BPF gateway ARP read failed: \(posixErrorString())",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil,
                gatewayHardwareAddress: nil
            )
        }

        var offset = 0
        while offset + 20 <= bytesRead {
            let caplen = Int(readLittleUInt32(readBuffer, offset: offset + bpfHeaderCaplenOffset))
            let headerLength = Int(readLittleUInt16(readBuffer, offset: offset + bpfHeaderHeaderLengthOffset))
            guard headerLength > 0, caplen > 0 else {
                break
            }

            let packetOffset = offset + headerLength
            if packetOffset + caplen <= bytesRead,
               caplen >= 14 + 28,
               readBuffer[packetOffset + 12] == 0x08,
               readBuffer[packetOffset + 13] == 0x06,
               let packet = parseARPPacket(
                   buffer: readBuffer,
                   offset: packetOffset + 14,
                   packetEnd: packetOffset + caplen
               )
            {
                let packetWallNanos = bpfTimestampNanos(buffer: readBuffer, offset: offset) ?? wallClockNanos()
                if packet.operation == 1,
                   packet.senderProtocolAddress == localIP,
                   packet.targetProtocolAddress == gateway
                {
                    requestWallNanos = requestWallNanos ?? packetWallNanos
                } else if packet.operation == 2,
                          packet.senderProtocolAddress == gateway,
                          packet.targetProtocolAddress == localIP
                {
                    return BPFGatewayARPReadResult(
                        ok: true,
                        error: nil,
                        requestWallNanos: requestWallNanos,
                        replyWallNanos: packetWallNanos,
                        gatewayHardwareAddress: packet.senderHardwareAddress
                    )
                }
            }

            let advance = bpfWordAlign(headerLength + caplen)
            guard advance > 0 else {
                break
            }
            offset += advance
        }
    }
}

private func readBPFGatewayNeighborAdvertisement(
    fd: Int32,
    bufferLength: Int,
    timeout: TimeInterval,
    localIP: String,
    gateway: String
) -> BPFGatewayNDPReadResult {
    let normalizedLocalIP = normalizedIPv6Scope(localIP)
    let normalizedGateway = normalizedIPv6Scope(gateway)
    let started = DispatchTime.now().uptimeNanoseconds
    let timeoutNanos = UInt64(max(timeout, 0.001) * 1_000_000_000)
    var requestWallNanos: UInt64?
    var pollDescriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
    var readBuffer = [UInt8](repeating: 0, count: max(bufferLength, 4096))

    while true {
        let elapsedNanos = DispatchTime.now().uptimeNanoseconds - started
        guard elapsedNanos < timeoutNanos else {
            return BPFGatewayNDPReadResult(
                ok: false,
                error: "BPF gateway NDP reply timed out",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil,
                gatewayHardwareAddress: nil
            )
        }
        let remainingMillis = max(1, Int((timeoutNanos - elapsedNanos) / 1_000_000))

        pollDescriptor.revents = 0
        let ready = poll(&pollDescriptor, 1, Int32(remainingMillis))
        if ready == 0 {
            return BPFGatewayNDPReadResult(
                ok: false,
                error: "BPF gateway NDP reply timed out",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil,
                gatewayHardwareAddress: nil
            )
        }
        guard ready > 0 else {
            return BPFGatewayNDPReadResult(
                ok: false,
                error: "BPF gateway NDP poll failed: \(posixErrorString())",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil,
                gatewayHardwareAddress: nil
            )
        }

        let bytesRead = readBuffer.withUnsafeMutableBytes { rawBuffer in
            read(fd, rawBuffer.baseAddress, rawBuffer.count)
        }
        guard bytesRead > 0 else {
            return BPFGatewayNDPReadResult(
                ok: false,
                error: "BPF gateway NDP read failed: \(posixErrorString())",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil,
                gatewayHardwareAddress: nil
            )
        }

        var offset = 0
        while offset + 20 <= bytesRead {
            let caplen = Int(readLittleUInt32(readBuffer, offset: offset + bpfHeaderCaplenOffset))
            let headerLength = Int(readLittleUInt16(readBuffer, offset: offset + bpfHeaderHeaderLengthOffset))
            guard headerLength > 0, caplen > 0 else {
                break
            }

            let packetOffset = offset + headerLength
            if packetOffset + caplen <= bytesRead,
               let packet = parseBPFGatewayNeighborPacket(buffer: readBuffer, offset: packetOffset, length: caplen)
            {
                let packetWallNanos = bpfTimestampNanos(buffer: readBuffer, offset: offset) ?? wallClockNanos()
                if packet.type == 135,
                   normalizedIPv6Scope(packet.sourceIP) == normalizedLocalIP,
                   packet.targetAddress.map(normalizedIPv6Scope) == normalizedGateway
                {
                    requestWallNanos = requestWallNanos ?? packetWallNanos
                } else if packet.type == 136,
                          packet.targetAddress.map(normalizedIPv6Scope) == normalizedGateway
                {
                    return BPFGatewayNDPReadResult(
                        ok: true,
                        error: nil,
                        requestWallNanos: requestWallNanos,
                        replyWallNanos: packetWallNanos,
                        gatewayHardwareAddress: packet.targetLinkLayerAddress ?? packet.ethernetSourceAddress
                    )
                }
            }

            let advance = bpfWordAlign(headerLength + caplen)
            guard advance > 0 else {
                break
            }
            offset += advance
        }
    }
}

private func readBPFGatewayICMPReply(
    fd: Int32,
    bufferLength: Int,
    timeout: TimeInterval,
    localIP: String,
    gateway: String,
    identifier: UInt16,
    sequence: UInt16,
    startWallNanos: UInt64
) -> BPFGatewayICMPReadResult {
    let started = DispatchTime.now().uptimeNanoseconds
    let timeoutNanos = UInt64(max(timeout, 0.001) * 1_000_000_000)
    var requestWallNanos: UInt64?
    var pollDescriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
    var readBuffer = [UInt8](repeating: 0, count: max(bufferLength, 4096))

    while true {
        let elapsedNanos = DispatchTime.now().uptimeNanoseconds - started
        guard elapsedNanos < timeoutNanos else {
            return BPFGatewayICMPReadResult(
                ok: false,
                error: "BPF gateway ICMP echo timed out",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil
            )
        }
        let remainingMillis = max(1, Int((timeoutNanos - elapsedNanos) / 1_000_000))

        pollDescriptor.revents = 0
        let ready = poll(&pollDescriptor, 1, Int32(remainingMillis))
        if ready == 0 {
            return BPFGatewayICMPReadResult(
                ok: false,
                error: "BPF gateway ICMP echo timed out",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil
            )
        }
        guard ready > 0 else {
            return BPFGatewayICMPReadResult(
                ok: false,
                error: "BPF gateway ICMP poll failed: \(posixErrorString())",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil
            )
        }

        let bytesRead = readBuffer.withUnsafeMutableBytes { rawBuffer in
            read(fd, rawBuffer.baseAddress, rawBuffer.count)
        }
        guard bytesRead > 0 else {
            return BPFGatewayICMPReadResult(
                ok: false,
                error: "BPF gateway ICMP read failed: \(posixErrorString())",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil
            )
        }

        var offset = 0
        while offset + 20 <= bytesRead {
            let caplen = Int(readLittleUInt32(readBuffer, offset: offset + bpfHeaderCaplenOffset))
            let headerLength = Int(readLittleUInt16(readBuffer, offset: offset + bpfHeaderHeaderLengthOffset))
            guard headerLength > 0, caplen > 0 else {
                break
            }

            let packetOffset = offset + headerLength
            if packetOffset + caplen <= bytesRead,
               let packet = parseBPFGatewayICMPPacket(buffer: readBuffer, offset: packetOffset, length: caplen),
               packet.identifier == identifier,
               packet.sequence == sequence
            {
                let packetWallNanos = bpfTimestampNanos(buffer: readBuffer, offset: offset) ?? wallClockNanos()
                if packet.type == 8, packet.sourceIP == localIP, packet.destinationIP == gateway {
                    requestWallNanos = requestWallNanos ?? packetWallNanos
                } else if packet.type == 0, packet.sourceIP == gateway, packet.destinationIP == localIP {
                    return BPFGatewayICMPReadResult(
                        ok: true,
                        error: nil,
                        requestWallNanos: requestWallNanos ?? startWallNanos,
                        replyWallNanos: packetWallNanos
                    )
                } else if packet.sourceIP == gateway || packet.destinationIP == gateway {
                    return BPFGatewayICMPReadResult(
                        ok: false,
                        error: "Unexpected gateway ICMP type \(packet.type) code \(packet.code)",
                        requestWallNanos: requestWallNanos,
                        replyWallNanos: packetWallNanos
                    )
                }
            }

            let advance = bpfWordAlign(headerLength + caplen)
            guard advance > 0 else {
                break
            }
            offset += advance
        }
    }
}

private func readBPFGatewayICMPv6Reply(
    fd: Int32,
    bufferLength: Int,
    timeout: TimeInterval,
    localIP: String,
    gateway: String,
    identifier: UInt16,
    sequence: UInt16,
    startWallNanos: UInt64
) -> BPFGatewayICMPReadResult {
    let normalizedLocalIP = normalizedIPv6Scope(localIP)
    let normalizedGateway = normalizedIPv6Scope(gateway)
    let started = DispatchTime.now().uptimeNanoseconds
    let timeoutNanos = UInt64(max(timeout, 0.001) * 1_000_000_000)
    var requestWallNanos: UInt64?
    var pollDescriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
    var readBuffer = [UInt8](repeating: 0, count: max(bufferLength, 4096))

    while true {
        let elapsedNanos = DispatchTime.now().uptimeNanoseconds - started
        guard elapsedNanos < timeoutNanos else {
            return BPFGatewayICMPReadResult(
                ok: false,
                error: "BPF gateway ICMPv6 echo timed out",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil
            )
        }
        let remainingMillis = max(1, Int((timeoutNanos - elapsedNanos) / 1_000_000))

        pollDescriptor.revents = 0
        let ready = poll(&pollDescriptor, 1, Int32(remainingMillis))
        if ready == 0 {
            return BPFGatewayICMPReadResult(
                ok: false,
                error: "BPF gateway ICMPv6 echo timed out",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil
            )
        }
        guard ready > 0 else {
            return BPFGatewayICMPReadResult(
                ok: false,
                error: "BPF gateway ICMPv6 poll failed: \(posixErrorString())",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil
            )
        }

        let bytesRead = readBuffer.withUnsafeMutableBytes { rawBuffer in
            read(fd, rawBuffer.baseAddress, rawBuffer.count)
        }
        guard bytesRead > 0 else {
            return BPFGatewayICMPReadResult(
                ok: false,
                error: "BPF gateway ICMPv6 read failed: \(posixErrorString())",
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil
            )
        }

        var offset = 0
        while offset + 20 <= bytesRead {
            let caplen = Int(readLittleUInt32(readBuffer, offset: offset + bpfHeaderCaplenOffset))
            let headerLength = Int(readLittleUInt16(readBuffer, offset: offset + bpfHeaderHeaderLengthOffset))
            guard headerLength > 0, caplen > 0 else {
                break
            }

            let packetOffset = offset + headerLength
            if packetOffset + caplen <= bytesRead,
               let packet = parseBPFGatewayICMPv6Packet(buffer: readBuffer, offset: packetOffset, length: caplen),
               packet.identifier == identifier,
               packet.sequence == sequence
            {
                let packetWallNanos = bpfTimestampNanos(buffer: readBuffer, offset: offset) ?? wallClockNanos()
                if packet.type == 128,
                   normalizedIPv6Scope(packet.sourceIP) == normalizedLocalIP,
                   normalizedIPv6Scope(packet.destinationIP) == normalizedGateway
                {
                    requestWallNanos = requestWallNanos ?? packetWallNanos
                } else if packet.type == 129,
                          normalizedIPv6Scope(packet.sourceIP) == normalizedGateway,
                          normalizedIPv6Scope(packet.destinationIP) == normalizedLocalIP
                {
                    return BPFGatewayICMPReadResult(
                        ok: true,
                        error: nil,
                        requestWallNanos: requestWallNanos ?? startWallNanos,
                        replyWallNanos: packetWallNanos
                    )
                } else if normalizedIPv6Scope(packet.sourceIP) == normalizedGateway
                    || normalizedIPv6Scope(packet.destinationIP) == normalizedGateway
                {
                    return BPFGatewayICMPReadResult(
                        ok: false,
                        error: "Unexpected gateway ICMPv6 type \(packet.type) code \(packet.code)",
                        requestWallNanos: requestWallNanos,
                        replyWallNanos: packetWallNanos
                    )
                }
            }

            let advance = bpfWordAlign(headerLength + caplen)
            guard advance > 0 else {
                break
            }
            offset += advance
        }
    }
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
) -> (
    sourceIP: String,
    destinationIP: String,
    icmpOffset: Int,
    ethernetSourceAddress: String
)? {
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
    return (
        sourceIP: ipv6String(bytes: Array(buffer[(ipOffset + 8) ..< (ipOffset + 24)])),
        destinationIP: ipv6String(bytes: Array(buffer[(ipOffset + 24) ..< (ipOffset + 40)])),
        icmpOffset: ipOffset + 40,
        ethernetSourceAddress: macAddressString(bytes: Array(buffer[(offset + 6) ..< (offset + 12)]))
    )
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

func ethernetICMPEchoFrame(
    sourceMAC: [UInt8],
    destinationMAC: [UInt8],
    sourceIP: [UInt8],
    destinationIP: [UInt8],
    identifier: UInt16,
    sequence: UInt16,
    payloadSize: Int
) -> [UInt8] {
    let ipLength = 20
    let icmpLength = 8 + payloadSize
    var frame = [UInt8](repeating: 0, count: 14 + ipLength + icmpLength)

    frame.replaceSubrange(0 ..< 6, with: destinationMAC)
    frame.replaceSubrange(6 ..< 12, with: sourceMAC)
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
    frame.replaceSubrange((ipOffset + 12) ..< (ipOffset + 16), with: sourceIP)
    frame.replaceSubrange((ipOffset + 16) ..< (ipOffset + 20), with: destinationIP)
    let ipChecksum = internetChecksum(Array(frame[ipOffset ..< (ipOffset + ipLength)]))
    writeBigUInt16(ipChecksum, to: &frame, offset: ipOffset + 10)

    let icmpOffset = ipOffset + ipLength
    frame[icmpOffset] = 8
    frame[icmpOffset + 1] = 0
    writeBigUInt16(identifier, to: &frame, offset: icmpOffset + 4)
    writeBigUInt16(sequence, to: &frame, offset: icmpOffset + 6)
    if payloadSize > 0 {
        for index in 0 ..< payloadSize {
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
        offset: ipOffset,
        payloadLength: icmpLength,
        nextHeader: UInt8(IPPROTO_ICMPV6),
        hopLimit: 255,
        sourceIP: sourceIP,
        destinationIP: destinationIP
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

func ethernetICMPv6EchoFrame(
    sourceMAC: [UInt8],
    destinationMAC: [UInt8],
    sourceIP: [UInt8],
    destinationIP: [UInt8],
    identifier: UInt16,
    sequence: UInt16,
    payloadSize: Int
) -> [UInt8] {
    let icmpLength = 8 + payloadSize
    var frame = [UInt8](repeating: 0, count: 14 + 40 + icmpLength)

    frame.replaceSubrange(0 ..< 6, with: destinationMAC)
    frame.replaceSubrange(6 ..< 12, with: sourceMAC)
    frame[12] = 0x86
    frame[13] = 0xDD

    let ipOffset = 14
    writeIPv6Header(
        to: &frame,
        offset: ipOffset,
        payloadLength: icmpLength,
        nextHeader: UInt8(IPPROTO_ICMPV6),
        hopLimit: 64,
        sourceIP: sourceIP,
        destinationIP: destinationIP
    )

    let icmpOffset = ipOffset + 40
    frame[icmpOffset] = 128
    frame[icmpOffset + 1] = 0
    writeBigUInt16(identifier, to: &frame, offset: icmpOffset + 4)
    writeBigUInt16(sequence, to: &frame, offset: icmpOffset + 6)
    if payloadSize > 0 {
        for index in 0 ..< payloadSize {
            frame[icmpOffset + 8 + index] = UInt8((index + 8) & 0xFF)
        }
    }
    let checksum = icmpv6Checksum(
        sourceIP: sourceIP,
        destinationIP: destinationIP,
        payload: Array(frame[icmpOffset ..< (icmpOffset + icmpLength)])
    )
    writeBigUInt16(checksum, to: &frame, offset: icmpOffset + 2)
    return frame
}

private func writeIPv6Header(
    to frame: inout [UInt8],
    offset: Int,
    payloadLength: Int,
    nextHeader: UInt8,
    hopLimit: UInt8,
    sourceIP: [UInt8],
    destinationIP: [UInt8]
) {
    frame[offset] = 0x60
    writeBigUInt16(UInt16(payloadLength), to: &frame, offset: offset + 4)
    frame[offset + 6] = nextHeader
    frame[offset + 7] = hopLimit
    frame.replaceSubrange((offset + 8) ..< (offset + 24), with: sourceIP)
    frame.replaceSubrange((offset + 24) ..< (offset + 40), with: destinationIP)
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

private func gatewayIPv6SourceAddress(interfaceState: NativeInterfaceState, gateway: String) -> String? {
    let normalizedGateway = normalizedIPv6Scope(gateway)
    if normalizedGateway.hasPrefix("fe80:") {
        return interfaceState.ipv6LinkLocalAddresses.first
    }
    return interfaceState.ipv6Addresses.first ?? interfaceState.ipv6LinkLocalAddresses.first
}

private func parseIPv4Address(_ value: String) -> [UInt8]? {
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

private func parseIPv6Address(_ value: String) -> [UInt8]? {
    var address = in6_addr()
    let normalized = normalizedIPv6Scope(value)
    guard inet_pton(AF_INET6, normalized, &address) == 1 else {
        return nil
    }
    return withUnsafeBytes(of: address) { Array($0) }
}

private func parseMACAddress(_ value: String) -> [UInt8]? {
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

private func gatewayJitterNanos(attempts: [ActiveGatewayProbeAttempt]) -> UInt64 {
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

private func aggregateGatewayString(_ values: [String]) -> String {
    let nonEmpty = values.filter { !$0.isEmpty }
    guard let first = nonEmpty.first else {
        return "unknown"
    }
    return nonEmpty.allSatisfy { $0 == first } ? first : "mixed"
}

func formatGatewayProbeDouble(_ value: Double) -> String {
    String(format: "%.6f", value)
}
