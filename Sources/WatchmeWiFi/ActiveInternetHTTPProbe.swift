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
        timing: timing
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
        timing: ActiveProbeTiming(
            startWallNanos: context.startWallNanos,
            finishedWallNanos: finishedWallNanos,
            timingSource: timingSource,
            timestampSource: wallClockTimestampSource
        )
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
    // HTTP response timing has two boundaries: request write and first response
    // byte. The completion is first-writer-wins; the request timestamp gets a
    // tiny lock because timeout can read it while the ready callback writes it.
    let completion = SynchronousCompletion<PlainHTTPExchangeResult>()
    let requestStartLock = NSLock()
    var requestWallNanos: UInt64?

    func setRequestWallNanos(_ value: UInt64) {
        requestStartLock.lock()
        requestWallNanos = value
        requestStartLock.unlock()
    }

    func currentRequestWallNanos() -> UInt64? {
        requestStartLock.lock()
        defer {
            requestStartLock.unlock()
        }
        return requestWallNanos
    }

    connection.stateUpdateHandler = { connectionState in
        switch connectionState {
        case .ready:
            let requestStarted = wallClockNanos()
            setRequestWallNanos(requestStarted)
            connection.send(
                content: httpHeadRequestBytes(path: "/", host: host),
                completion: .contentProcessed { error in
                    if let error {
                        completion.complete(plainHTTPExchangeResult(
                            outcome: "send_failed",
                            error: error.localizedDescription,
                            requestWallNanos: requestStarted
                        ))
                        return
                    }
                    receivePlainHTTPResponse(
                        connection: connection,
                        completion: completion,
                        requestWallNanos: requestStarted
                    )
                }
            )
        case let .failed(error):
            completion.complete(plainHTTPExchangeResult(
                outcome: isConnectionRefused(error) ? "refused" : "failed",
                error: error.localizedDescription,
                requestWallNanos: currentRequestWallNanos()
            ))
        case .cancelled:
            completion.complete(plainHTTPExchangeResult(
                outcome: "cancelled",
                error: "connection cancelled",
                requestWallNanos: currentRequestWallNanos()
            ))
        default:
            break
        }
    }
    connection.start(queue: queue)

    let result = completion.wait(
        timeout: timeout,
        timeoutValue: plainHTTPExchangeResult(
            outcome: "timeout",
            error: "HTTP probe timed out",
            requestWallNanos: currentRequestWallNanos()
        )
    )
    connection.cancel()
    return result
}

private func receivePlainHTTPResponse(
    connection: NWConnection,
    completion: SynchronousCompletion<PlainHTTPExchangeResult>,
    requestWallNanos: UInt64
) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, isComplete, error in
        if let error {
            completion.complete(plainHTTPExchangeResult(
                outcome: "receive_failed",
                error: error.localizedDescription,
                requestWallNanos: requestWallNanos
            ))
            return
        }
        if let data, !data.isEmpty {
            let responseWallNanos = wallClockNanos()
            completion.complete(plainHTTPExchangeResult(
                statusCode: parseHTTPStatusCode(data),
                outcome: "response",
                requestWallNanos: requestWallNanos,
                responseWallNanos: responseWallNanos
            ))
            return
        }
        if isComplete {
            completion.complete(plainHTTPExchangeResult(
                outcome: "closed",
                error: "connection closed before response bytes",
                requestWallNanos: requestWallNanos
            ))
            return
        }
        receivePlainHTTPResponse(connection: connection, completion: completion, requestWallNanos: requestWallNanos)
    }
}

private func plainHTTPExchangeResult(
    statusCode: Int? = nil,
    outcome: String,
    error: String? = nil,
    requestWallNanos: UInt64?,
    responseWallNanos: UInt64? = nil
) -> PlainHTTPExchangeResult {
    PlainHTTPExchangeResult(
        statusCode: statusCode,
        outcome: outcome,
        error: error,
        requestWallNanos: requestWallNanos,
        responseWallNanos: responseWallNanos,
        completedWallNanos: responseWallNanos ?? wallClockNanos()
    )
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
