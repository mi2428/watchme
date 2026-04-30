import Foundation
import Network
import WatchmeCore

struct ActiveTCPProbeResult {
    let target: String
    let family: InternetAddressFamily
    let remoteIP: String
    let port: UInt16
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

private struct TCPProbeFailureContext {
    let target: String
    let family: InternetAddressFamily
    let remoteIP: String
    let port: UInt16
    let startWallNanos: UInt64
}

private final class TCPConnectState {
    let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var completed = false
    var outcome = "unknown"
    var errorMessage: String?
    var completedWallNanos: UInt64?

    func complete(outcome newOutcome: String, error: String? = nil) {
        lock.lock()
        defer {
            lock.unlock()
        }
        guard !completed else {
            return
        }
        outcome = newOutcome
        errorMessage = error
        completedWallNanos = completedWallNanos ?? wallClockNanos()
        completed = true
        semaphore.signal()
    }

    func result() -> (outcome: String, error: String?, completedWallNanos: UInt64) {
        lock.lock()
        defer {
            lock.unlock()
        }
        return (outcome, errorMessage, completedWallNanos ?? wallClockNanos())
    }
}

func runInternetTCPProbe(
    target: String,
    family: InternetAddressFamily,
    remoteIP: String?,
    port: UInt16 = 80,
    timeout: TimeInterval,
    interfaceName: String?,
    packetStore: PassivePacketStore? = nil
) -> ActiveTCPProbeResult {
    let host = normalizedProbeHost(target)
    let startWallNanos = wallClockNanos()
    guard let remoteIP, !remoteIP.isEmpty else {
        return failedTCPProbe(
            context: TCPProbeFailureContext(
                target: host,
                family: family,
                remoteIP: "none",
                port: port,
                startWallNanos: startWallNanos
            ),
            outcome: "no_address",
            timingSource: noAddressTimingSource,
            error: "no \(family.metricValue) address was available for TCP probe"
        )
    }
    guard let interface = requiredProbeInterface(named: interfaceName, timeout: timeout) else {
        return failedTCPProbe(
            context: TCPProbeFailureContext(
                target: host,
                family: family,
                remoteIP: remoteIP,
                port: port,
                startWallNanos: startWallNanos
            ),
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface \(interfaceName ?? "unknown") was not available to Network.framework"
        )
    }

    let request = ActiveTCPProbeRequest(
        target: host,
        remoteIP: remoteIP,
        port: port,
        interfaceName: interfaceName,
        startWallNanos: startWallNanos,
        timeout: timeout
    )
    packetStore?.registerActiveTCPProbe(request)
    defer {
        packetStore?.unregisterActiveTCPProbe(request)
    }

    let connect = performTCPConnect(remoteIP: remoteIP, port: port, selectedInterface: interface, timeout: timeout)
    let packetExchange = packetStore?.tcpConnectExchange(for: request, finishedWallNanos: connect.completedWallNanos)
    let timing = packetExchange?.timing ?? .networkFramework(start: startWallNanos, finished: connect.completedWallNanos)
    let outcome = packetExchange?.outcome ?? connect.outcome
    return ActiveTCPProbeResult(
        target: host,
        family: family,
        remoteIP: remoteIP,
        port: port,
        ok: outcome == "connected",
        outcome: outcome,
        error: connect.error,
        timing: timing
    )
}

private func failedTCPProbe(
    context: TCPProbeFailureContext,
    outcome: String,
    timingSource: String,
    error: String
) -> ActiveTCPProbeResult {
    let finishedWallNanos = wallClockNanos()
    return ActiveTCPProbeResult(
        target: context.target,
        family: context.family,
        remoteIP: context.remoteIP,
        port: context.port,
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

private func performTCPConnect(
    remoteIP: String,
    port: UInt16,
    selectedInterface: NWInterface,
    timeout: TimeInterval
) -> (outcome: String, error: String?, completedWallNanos: UInt64) {
    let parameters = NWParameters.tcp
    parameters.requiredInterface = selectedInterface
    let connection = NWConnection(
        host: NWEndpoint.Host(remoteIP),
        port: NWEndpoint.Port(rawValue: port)!,
        using: parameters
    )
    let queue = DispatchQueue(label: "watchme.internet_tcp.\(randomHex(bytes: 4))")
    let state = TCPConnectState()

    connection.stateUpdateHandler = { connectionState in
        switch connectionState {
        case .ready:
            state.complete(outcome: "connected")
        case let .failed(error):
            state.complete(outcome: isConnectionRefused(error) ? "refused" : "failed", error: error.localizedDescription)
        case .cancelled:
            state.complete(outcome: "cancelled", error: "connection cancelled")
        default:
            break
        }
    }
    connection.start(queue: queue)

    if state.semaphore.wait(timeout: .now() + timeout) == .timedOut {
        state.complete(outcome: "timeout", error: "TCP connect probe timed out")
    }
    connection.cancel()

    return state.result()
}
