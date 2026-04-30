import Foundation
import Network
import WatchmeCore

struct ActiveInternetHTTPProbeResult {
    let target: String
    let family: InternetAddressFamily
    let remoteIP: String
    let ok: Bool
    let outcome: String
    let statusCode: Int?
    let error: String?
    let startWallNanos: UInt64
    let finishedWallNanos: UInt64
    let durationNanos: UInt64
    let timingSource: String
    let timestampSource: String
}

private struct PlainHTTPExchangeResult {
    let statusCode: Int?
    let outcome: String
    let error: String?
    let requestWallNanos: UInt64?
    let responseWallNanos: UInt64?
    let completedWallNanos: UInt64
}

private struct HTTPFailureContext {
    let target: String
    let family: InternetAddressFamily
    let remoteIP: String
    let startWallNanos: UInt64
}

private final class PlainHTTPExchangeState {
    let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var completed = false
    var requestWallNanos: UInt64?
    var responseWallNanos: UInt64?
    var completedWallNanos: UInt64?
    var statusCode: Int?
    var outcome = "unknown"
    var errorMessage: String?

    func complete(outcome newOutcome: String, error: String? = nil) {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else {
            return
        }
        outcome = newOutcome
        errorMessage = error
        completedWallNanos = completedWallNanos ?? responseWallNanos ?? wallClockNanos()
        completed = true
        semaphore.signal()
    }

    func exchange() -> PlainHTTPExchangeResult {
        lock.lock()
        defer { lock.unlock() }
        return PlainHTTPExchangeResult(
            statusCode: statusCode,
            outcome: outcome,
            error: errorMessage,
            requestWallNanos: requestWallNanos,
            responseWallNanos: responseWallNanos,
            completedWallNanos: completedWallNanos ?? wallClockNanos()
        )
    }
}

func runInternetHTTPProbe(
    target: String,
    family: InternetAddressFamily,
    remoteIP: String?,
    timeout: TimeInterval,
    interfaceName: String?,
    packetStore: PassivePacketStore? = nil
) -> ActiveInternetHTTPProbeResult {
    let host = normalizedProbeHost(target)
    let startWallNanos = wallClockNanos()
    guard let remoteIP, !remoteIP.isEmpty else {
        return failedHTTPProbe(
            context: HTTPFailureContext(target: host, family: family, remoteIP: "none", startWallNanos: startWallNanos),
            outcome: "no_address",
            timingSource: noAddressTimingSource,
            error: "no \(family.metricValue) address was available for HTTP probe"
        )
    }
    guard let interface = requiredProbeInterface(named: interfaceName, timeout: timeout) else {
        return failedHTTPProbe(
            context: HTTPFailureContext(target: host, family: family, remoteIP: remoteIP, startWallNanos: startWallNanos),
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface \(interfaceName ?? "unknown") was not available to Network.framework"
        )
    }

    let request = ActiveHTTPProbeRequest(
        target: host,
        remoteIP: remoteIP,
        port: 80,
        interfaceName: interfaceName,
        startWallNanos: startWallNanos,
        timeout: timeout
    )
    packetStore?.registerActiveHTTPProbe(request)
    defer {
        packetStore?.unregisterActiveHTTPProbe(request)
    }

    let exchange = performPlainHTTPHeadExchange(
        host: host,
        remoteIP: remoteIP,
        selectedInterface: interface,
        timeout: timeout
    )
    let packetExchange = packetStore?.httpExchange(for: request, finishedWallNanos: exchange.completedWallNanos)
    let fallbackStart = exchange.requestWallNanos ?? startWallNanos
    let fallbackFinished = exchange.responseWallNanos ?? exchange.completedWallNanos
    let timing = packetExchange?.timing ?? .networkFramework(start: fallbackStart, finished: fallbackFinished)
    let statusCode = exchange.statusCode ?? packetExchange?.statusCode
    let ok = statusCode.map { (200 ..< 500).contains($0) } ?? false
    return ActiveInternetHTTPProbeResult(
        target: host,
        family: family,
        remoteIP: remoteIP,
        ok: ok,
        outcome: ok ? "response" : exchange.outcome,
        statusCode: statusCode,
        error: exchange.error,
        startWallNanos: timing.startWallNanos,
        finishedWallNanos: timing.finishedWallNanos,
        durationNanos: timing.durationNanos,
        timingSource: timing.timingSource,
        timestampSource: timing.timestampSource
    )
}

private func failedHTTPProbe(
    context: HTTPFailureContext,
    outcome: String,
    timingSource: String,
    error: String
) -> ActiveInternetHTTPProbeResult {
    let finishedWallNanos = wallClockNanos()
    return ActiveInternetHTTPProbeResult(
        target: context.target,
        family: context.family,
        remoteIP: context.remoteIP,
        ok: false,
        outcome: outcome,
        statusCode: nil,
        error: error,
        startWallNanos: context.startWallNanos,
        finishedWallNanos: finishedWallNanos,
        durationNanos: max(finishedWallNanos - context.startWallNanos, 1000),
        timingSource: timingSource,
        timestampSource: wallClockTimestampSource
    )
}

private func performPlainHTTPHeadExchange(
    host: String,
    remoteIP: String,
    selectedInterface: NWInterface,
    timeout: TimeInterval
) -> PlainHTTPExchangeResult {
    let parameters = NWParameters.tcp
    parameters.requiredInterface = selectedInterface
    let connection = NWConnection(
        host: NWEndpoint.Host(remoteIP),
        port: NWEndpoint.Port(rawValue: 80)!,
        using: parameters
    )
    let queue = DispatchQueue(label: "watchme.internet_http.\(randomHex(bytes: 4))")
    let state = PlainHTTPExchangeState()

    connection.stateUpdateHandler = { connectionState in
        switch connectionState {
        case .ready:
            state.requestWallNanos = wallClockNanos()
            connection.send(
                content: httpHeadRequestBytes(path: "/", host: host),
                completion: .contentProcessed { error in
                    if let error {
                        state.complete(outcome: "send_failed", error: error.localizedDescription)
                        return
                    }
                    receivePlainHTTPResponse(connection: connection, state: state)
                }
            )
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
        state.complete(outcome: "timeout", error: "HTTP probe timed out")
    }
    connection.cancel()

    return state.exchange()
}

private func receivePlainHTTPResponse(connection: NWConnection, state: PlainHTTPExchangeState) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, isComplete, error in
        if let error {
            state.complete(outcome: "receive_failed", error: error.localizedDescription)
            return
        }
        if let data, !data.isEmpty {
            state.responseWallNanos = wallClockNanos()
            state.statusCode = parseHTTPStatusCode(data)
            state.complete(outcome: "response")
            return
        }
        if isComplete {
            state.complete(outcome: "closed", error: "connection closed before response bytes")
            return
        }
        receivePlainHTTPResponse(connection: connection, state: state)
    }
}

func httpHeadRequestBytes(path: String, host: String) -> Data {
    let normalizedPath = path.isEmpty ? "/" : path
    let request = """
    HEAD \(normalizedPath) HTTP/1.1\r
    Host: \(host)\r
    User-Agent: watchme/0.1\r
    Accept: */*\r
    Connection: close\r
    \r

    """
    return Data(request.utf8)
}
