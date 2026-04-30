import Foundation
import Network
import WatchmeCore

struct ActiveGatewayProbeResult {
    let gateway: String
    let port: UInt16
    let reachable: Bool
    let connectSuccess: Bool
    let outcome: String
    let error: String?
    let startWallNanos: UInt64
    let finishedWallNanos: UInt64
    let durationNanos: UInt64
}

func runGatewayTCPConnectProbe(
    gateway: String,
    port: UInt16 = 53,
    timeout: TimeInterval,
    interfaceName: String?
) -> ActiveGatewayProbeResult {
    let startWallNanos = wallClockNanos()
    guard let interface = requiredProbeInterface(named: interfaceName, timeout: timeout) else {
        return failedGatewayProbe(
            gateway: gateway,
            port: port,
            startWallNanos: startWallNanos,
            outcome: "interface_unavailable",
            error: "Wi-Fi interface \(interfaceName ?? "unknown") was not available to Network.framework"
        )
    }

    let parameters = NWParameters.tcp
    parameters.requiredInterface = interface
    let connection = NWConnection(
        host: NWEndpoint.Host(gateway),
        port: NWEndpoint.Port(rawValue: port) ?? NWEndpoint.Port(rawValue: 53)!,
        using: parameters
    )
    let queue = DispatchQueue(label: "watchme.gateway_probe.\(randomHex(bytes: 4))")
    let semaphore = DispatchSemaphore(value: 0)
    let completionLock = NSLock()
    var completed = false
    var reachable = false
    var connectSuccess = false
    var outcome = "unknown"
    var errorMessage: String?
    var completedWallNanos: UInt64?

    func complete(outcome newOutcome: String, reachable isReachable: Bool, connectOK: Bool, error: String? = nil) {
        completionLock.lock()
        defer { completionLock.unlock() }
        guard !completed else {
            return
        }
        reachable = isReachable
        connectSuccess = connectOK
        outcome = newOutcome
        errorMessage = error
        completedWallNanos = wallClockNanos()
        completed = true
        semaphore.signal()
    }

    connection.stateUpdateHandler = { state in
        switch state {
        case .ready:
            complete(outcome: "connected", reachable: true, connectOK: true)
        case let .failed(error):
            // TCP refusal proves the first hop answered even though no service
            // accepted the connection, so it is still useful as reachability.
            if isConnectionRefused(error) {
                complete(outcome: "refused", reachable: true, connectOK: false, error: error.localizedDescription)
            } else {
                complete(outcome: "failed", reachable: false, connectOK: false, error: error.localizedDescription)
            }
        case .cancelled:
            complete(outcome: "cancelled", reachable: false, connectOK: false, error: "connection cancelled")
        default:
            break
        }
    }
    connection.start(queue: queue)

    if semaphore.wait(timeout: .now() + timeout) == .timedOut {
        complete(outcome: "timeout", reachable: false, connectOK: false, error: "gateway TCP connect timed out")
    }
    connection.cancel()

    let finishedWallNanos = completedWallNanos ?? wallClockNanos()
    return ActiveGatewayProbeResult(
        gateway: gateway,
        port: port,
        reachable: reachable,
        connectSuccess: connectSuccess,
        outcome: outcome,
        error: errorMessage,
        startWallNanos: startWallNanos,
        finishedWallNanos: finishedWallNanos,
        durationNanos: max(finishedWallNanos - startWallNanos, 1000)
    )
}

private func failedGatewayProbe(
    gateway: String,
    port: UInt16,
    startWallNanos: UInt64,
    outcome: String,
    error: String
) -> ActiveGatewayProbeResult {
    let finishedWallNanos = wallClockNanos()
    return ActiveGatewayProbeResult(
        gateway: gateway,
        port: port,
        reachable: false,
        connectSuccess: false,
        outcome: outcome,
        error: error,
        startWallNanos: startWallNanos,
        finishedWallNanos: finishedWallNanos,
        durationNanos: max(finishedWallNanos - startWallNanos, 1000)
    )
}

func isConnectionRefused(_ error: NWError) -> Bool {
    if case let .posix(code) = error {
        return code == .ECONNREFUSED
    }
    return false
}
