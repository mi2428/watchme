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

    var icmpTimingSource: String {
        aggregateGatewayString(attempts.map(\.timingSource))
    }

    var icmpTimestampSource: String {
        aggregateGatewayString(attempts.map(\.timestampSource))
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
