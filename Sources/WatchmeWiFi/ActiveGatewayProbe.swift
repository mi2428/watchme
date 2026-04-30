import Foundation
import WatchmeCore

let defaultGatewayProbeBurstCount = 4
let defaultGatewayProbeBurstInterval: TimeInterval = 0.05

struct ActiveGatewayProbeAttempt {
    let sequence: Int
    let identifier: UInt16?
    let icmpSequence: UInt16?
    let reachable: Bool
    let outcome: String
    let error: String?
    let timing: ActiveProbeTiming

    init(
        sequence: Int,
        identifier: UInt16?,
        icmpSequence: UInt16?,
        reachable: Bool,
        outcome: String,
        error: String?,
        timing: ActiveProbeTiming
    ) {
        self.sequence = sequence
        self.identifier = identifier
        self.icmpSequence = icmpSequence
        self.reachable = reachable
        self.outcome = outcome
        self.error = error
        self.timing = timing
    }

    init(
        sequence: Int,
        identifier: UInt16?,
        icmpSequence: UInt16?,
        reachable: Bool,
        outcome: String,
        error: String?,
        startWallNanos: UInt64,
        finishedWallNanos: UInt64,
        durationNanos _: UInt64,
        timingSource: String,
        timestampSource: String
    ) {
        self.init(
            sequence: sequence,
            identifier: identifier,
            icmpSequence: icmpSequence,
            reachable: reachable,
            outcome: outcome,
            error: error,
            timing: ActiveProbeTiming(
                startWallNanos: startWallNanos,
                finishedWallNanos: finishedWallNanos,
                timingSource: timingSource,
                timestampSource: timestampSource
            )
        )
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

    init(
        gateway: String,
        family: InternetAddressFamily = .ipv4,
        attempts: [ActiveGatewayProbeAttempt],
        burstIntervalSeconds: TimeInterval
    ) {
        self.gateway = gateway
        self.family = family
        self.attempts = attempts.sorted { $0.sequence < $1.sequence }
        self.burstIntervalSeconds = burstIntervalSeconds
    }

    init(
        gateway: String,
        family: InternetAddressFamily = .ipv4,
        reachable: Bool,
        outcome: String,
        error: String?,
        startWallNanos: UInt64,
        finishedWallNanos: UInt64,
        durationNanos _: UInt64,
        timingSource: String,
        timestampSource: String
    ) {
        self.init(
            gateway: gateway,
            family: family,
            attempts: [
                ActiveGatewayProbeAttempt(
                    sequence: 1,
                    identifier: nil,
                    icmpSequence: nil,
                    reachable: reachable,
                    outcome: outcome,
                    error: error,
                    timing: ActiveProbeTiming(
                        startWallNanos: startWallNanos,
                        finishedWallNanos: finishedWallNanos,
                        timingSource: timingSource,
                        timestampSource: timestampSource
                    )
                ),
            ],
            burstIntervalSeconds: 0
        )
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

    var outcome: String {
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
        if let latestError = latestAttempt?.error, !latestError.isEmpty {
            return latestError
        }
        return attempts.first { !($0.error ?? "").isEmpty }?.error
    }

    var startWallNanos: UInt64 {
        attempts.map(\.startWallNanos).min() ?? 0
    }

    var finishedWallNanos: UInt64 {
        attempts.map(\.finishedWallNanos).max() ?? max(startWallNanos + 1000, 1000)
    }

    var burstDurationNanos: UInt64 {
        max(finishedWallNanos >= startWallNanos ? finishedWallNanos - startWallNanos : 0, 1000)
    }

    var durationNanos: UInt64 {
        averageReachableDurationNanos ?? latestAttempt?.durationNanos ?? burstDurationNanos
    }

    var timingSource: String {
        aggregateGatewayString(attempts.map(\.timingSource))
    }

    var timestampSource: String {
        aggregateGatewayString(attempts.map(\.timestampSource))
    }

    var latestAttempt: ActiveGatewayProbeAttempt? {
        attempts.max { $0.sequence < $1.sequence }
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
    burstCount: Int = defaultGatewayProbeBurstCount,
    burstInterval: TimeInterval = defaultGatewayProbeBurstInterval
) -> ActiveGatewayProbeResult {
    let count = max(burstCount, 1)
    let interval = max(burstInterval, 0)
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
