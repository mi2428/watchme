import Foundation

protocol WiFiAgentClock {
    var now: Date { get }
    func wallClockNanos() -> UInt64
}

struct SystemWiFiAgentClock: WiFiAgentClock {
    var now: Date {
        Date()
    }

    func wallClockNanos() -> UInt64 {
        UInt64(now.timeIntervalSince1970 * 1_000_000_000)
    }
}

protocol WiFiTraceScheduler {
    func async(_ work: @escaping () -> Void)
    func asyncAfter(delay: TimeInterval, _ work: @escaping () -> Void)
}

struct DispatchWiFiTraceScheduler: WiFiTraceScheduler {
    let queue: DispatchQueue

    func async(_ work: @escaping () -> Void) {
        queue.async(execute: work)
    }

    func asyncAfter(delay: TimeInterval, _ work: @escaping () -> Void) {
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }
}

struct WiFiTraceEmission {
    let reason: String
    let eventTags: [String: String]
    let consumePacketSpans: Bool
    let includeConnectivityCheck: Bool
    let connectivityReadinessTimeout: TimeInterval
}

extension WiFiAgent {
    func emitScheduledTrace(_ emission: WiFiTraceEmission) {
        if let traceEmissionHandler {
            traceEmissionHandler(emission)
            return
        }
        emitTrace(
            reason: emission.reason,
            eventTags: emission.eventTags,
            consumePacketSpans: emission.consumePacketSpans,
            includeConnectivityCheck: emission.includeConnectivityCheck,
            connectivityReadinessTimeout: emission.connectivityReadinessTimeout
        )
    }
}
