import Foundation
import Network
import Security
import WatchmeCore
import WatchmeTelemetry

final class HTTPMetricsDelegate: NSObject, URLSessionTaskDelegate {
    private let lock = NSLock()
    private var taskMetrics: URLSessionTaskMetrics?

    func urlSession(_: URLSession, task _: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        lock.lock()
        taskMetrics = metrics
        lock.unlock()
    }

    func metrics() -> URLSessionTaskMetrics? {
        lock.lock()
        defer { lock.unlock() }
        return taskMetrics
    }
}

struct ActiveProbeResult {
    let target: String
    let url: URL
    let ok: Bool
    let statusCode: Int?
    let error: String?
    let startWallNanos: UInt64
    let durationNanos: UInt64
    let childSpans: [SpanEvent]
}

private struct HTTPHeadExchange {
    let readyWallNanos: UInt64?
    let responseWallNanos: UInt64?
    let statusCode: Int?
    let errorMessage: String?
}

private struct ProbeSpanContext {
    let target: String
    let url: URL
    let interfaceName: String?
    let selectedInterface: NWInterface?
    let portValue: UInt16
    let startWallNanos: UInt64
    let durationNanos: UInt64
    let exchange: HTTPHeadExchange
    let ok: Bool
}

func runHTTPHeadProbe(target: String, timeout: TimeInterval, interfaceName: String?) -> ActiveProbeResult {
    let url = normalizedTargetURL(target)
    let startWallNanos = wallClockNanos()
    guard let host = url.host else {
        return failedProbe(target: target, url: url, startWallNanos: startWallNanos, error: "target URL has no host")
    }

    let selectedInterface: NWInterface?
    if let interfaceName, !interfaceName.isEmpty {
        guard let interface = requiredProbeInterface(named: interfaceName, timeout: timeout) else {
            return failedProbe(
                target: target,
                url: url,
                startWallNanos: startWallNanos,
                error: "Wi-Fi interface \(interfaceName) was not available to Network.framework"
            )
        }
        selectedInterface = interface
    } else {
        selectedInterface = nil
    }

    let portValue = UInt16(url.port ?? 443)
    let exchange = performHTTPHeadExchange(
        url: url,
        host: host,
        portValue: portValue,
        selectedInterface: selectedInterface,
        timeout: timeout
    )
    let endWallNanos = exchange.responseWallNanos ?? wallClockNanos()
    let durationNanos = max(endWallNanos - startWallNanos, 1000)
    let ok = exchange.statusCode.map { (200 ..< 500).contains($0) } ?? false

    return ActiveProbeResult(
        target: target,
        url: url,
        ok: ok,
        statusCode: exchange.statusCode,
        error: exchange.errorMessage,
        startWallNanos: startWallNanos,
        durationNanos: durationNanos,
        childSpans: probeChildSpans(
            ProbeSpanContext(
                target: target,
                url: url,
                interfaceName: interfaceName,
                selectedInterface: selectedInterface,
                portValue: portValue,
                startWallNanos: startWallNanos,
                durationNanos: durationNanos,
                exchange: exchange,
                ok: ok
            )
        )
    )
}

private func failedProbe(target: String, url: URL, startWallNanos: UInt64, error: String) -> ActiveProbeResult {
    ActiveProbeResult(
        target: target,
        url: url,
        ok: false,
        statusCode: nil,
        error: error,
        startWallNanos: startWallNanos,
        durationNanos: max(wallClockNanos() - startWallNanos, 1000),
        childSpans: []
    )
}

private func requiredProbeInterface(named interfaceName: String?, timeout: TimeInterval) -> NWInterface? {
    guard let interfaceName, !interfaceName.isEmpty else {
        return nil
    }
    // The active probe must validate the Wi-Fi path itself, not the system
    // default route. On Macs with Ethernet or VPN as default, this prevents a
    // successful non-Wi-Fi route from hiding Wi-Fi join failures.
    return networkInterface(named: interfaceName, timeout: min(1.0, timeout))
}

private func performHTTPHeadExchange(
    url: URL,
    host: String,
    portValue: UInt16,
    selectedInterface: NWInterface?,
    timeout: TimeInterval
) -> HTTPHeadExchange {
    let tlsOptions = NWProtocolTLS.Options()
    sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, host)
    let parameters = NWParameters(tls: tlsOptions)
    parameters.requiredInterface = selectedInterface

    // Use Network.framework directly so connection timing and interface binding
    // stay inside the process; the agent must not shell out to curl or ifconfig.
    let port = NWEndpoint.Port(rawValue: portValue) ?? .https
    let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
    let queue = DispatchQueue(label: "watchme.http_head.\(randomHex(bytes: 4))")
    let semaphore = DispatchSemaphore(value: 0)
    let completionLock = NSLock()
    var completed = false
    var readyWallNanos: UInt64?
    var responseWallNanos: UInt64?
    var statusCode: Int?
    var errorMessage: String?

    func complete(_ error: String? = nil) {
        completionLock.lock()
        defer { completionLock.unlock() }
        guard !completed else {
            return
        }
        if let error {
            errorMessage = error
        }
        completed = true
        semaphore.signal()
    }

    func receiveResponse() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, isComplete, error in
            if let error {
                complete(error.localizedDescription)
                return
            }
            if let data, !data.isEmpty {
                responseWallNanos = wallClockNanos()
                statusCode = parseHTTPStatusCode(data)
                complete()
                return
            }
            if isComplete {
                complete("connection closed before response bytes")
                return
            }
            receiveResponse()
        }
    }

    connection.stateUpdateHandler = { state in
        switch state {
        case .ready:
            readyWallNanos = wallClockNanos()
            connection.send(
                content: httpHeadRequestBytes(url: url, host: host),
                completion: .contentProcessed { error in
                    if let error {
                        complete(error.localizedDescription)
                        return
                    }
                    receiveResponse()
                }
            )
        case let .failed(error):
            complete(error.localizedDescription)
        case .cancelled:
            complete("connection cancelled")
        default:
            break
        }
    }
    connection.start(queue: queue)

    if semaphore.wait(timeout: .now() + timeout + 1) == .timedOut {
        complete("HTTP HEAD timed out")
    }
    connection.cancel()

    return HTTPHeadExchange(
        readyWallNanos: readyWallNanos,
        responseWallNanos: responseWallNanos,
        statusCode: statusCode,
        errorMessage: errorMessage
    )
}

private func probeChildSpans(_ context: ProbeSpanContext) -> [SpanEvent] {
    var childSpans: [SpanEvent] = []
    var commonTags: [String: String] = [
        "net.peer.name": context.url.host ?? context.target,
        "net.peer.port": "\(context.portValue)",
        "probe.target": context.target,
        "url.scheme": context.url.scheme ?? "",
        "active_probe.interface": context.interfaceName ?? "",
        "active_probe.required_interface": context.selectedInterface?.name ?? "",
    ]
    if let readyWallNanos = context.exchange.readyWallNanos {
        var tags = commonTags
        tags["span.source"] = "network_framework"
        tags["network.framework.phase"] = "dns_tcp_tls_connect"
        childSpans.append(
            SpanEvent(
                name: "probe.network.connect",
                startWallNanos: context.startWallNanos,
                durationNanos: max(readyWallNanos - context.startWallNanos, 1000),
                tags: tags,
                statusOK: true
            )
        )
    }

    commonTags["span.source"] = "network_framework_active_probe"
    commonTags["http.request.method"] = "HEAD"
    if let statusCode = context.exchange.statusCode {
        commonTags["http.response.status_code"] = "\(statusCode)"
    }
    if let errorMessage = context.exchange.errorMessage {
        commonTags["error"] = clipped(errorMessage, limit: 240)
    }
    childSpans.append(
        SpanEvent(
            name: "probe.http.head",
            startWallNanos: context.startWallNanos,
            durationNanos: context.durationNanos,
            tags: commonTags,
            statusOK: context.ok
        )
    )
    return childSpans
}

func networkInterface(named name: String?, timeout: TimeInterval) -> NWInterface? {
    guard let name, !name.isEmpty else {
        return nil
    }
    // NWPathMonitor is asynchronous even for a simple interface lookup, so keep
    // this bounded. A missing interface is a useful probe failure, not a reason
    // to block the whole trace.
    let monitor = NWPathMonitor()
    let queue = DispatchQueue(label: "watchme.network_interface_lookup")
    let semaphore = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var selected: NWInterface?
    monitor.pathUpdateHandler = { path in
        lock.lock()
        selected = path.availableInterfaces.first { $0.name == name }
        lock.unlock()
        semaphore.signal()
    }
    monitor.start(queue: queue)
    _ = semaphore.wait(timeout: .now() + timeout)
    monitor.cancel()
    lock.lock()
    defer { lock.unlock() }
    return selected
}

func httpHeadRequestBytes(url: URL, host: String) -> Data {
    var path = url.path.isEmpty ? "/" : url.path
    if let query = url.query, !query.isEmpty {
        path += "?\(query)"
    }
    // A raw Network.framework connection gives us deterministic interface
    // binding and timing, so construct the minimal HTTP/1.1 request here rather
    // than relying on URLSession's routing decisions.
    let request = """
    HEAD \(path) HTTP/1.1\r
    Host: \(host)\r
    User-Agent: watchme/0.1\r
    Accept: */*\r
    Connection: close\r
    \r

    """
    return Data(request.utf8)
}

func parseHTTPStatusCode(_ data: Data) -> Int? {
    // The active probe only needs the status line. Cap the decoded prefix so a
    // misbehaving endpoint cannot turn response parsing into unbounded work.
    guard let text = String(data: data.prefix(256), encoding: .utf8),
          let firstLine = text.components(separatedBy: "\r\n").first
    else {
        return nil
    }
    let parts = firstLine.split(separator: " ")
    guard parts.count >= 2 else {
        return nil
    }
    return Int(parts[1])
}

func spanEventsFromURLMetrics(_ metrics: URLSessionTaskMetrics?, target: String, url: URL) -> [SpanEvent] {
    guard let transaction = metrics?.transactionMetrics.last else {
        return []
    }
    var events: [SpanEvent] = []
    let baseTags: [String: String] = [
        "span.source": "urlsession_task_metrics",
        "net.peer.name": url.host ?? target,
        "probe.target": target,
    ]

    func append(name: String, start: Date?, end: Date?, extra: [String: String] = [:]) {
        guard let start, let end, end >= start else {
            return
        }
        var tags = baseTags
        tags.merge(extra) { _, new in new }
        events.append(
            SpanEvent(
                name: name,
                startWallNanos: dateToWallNanos(start),
                durationNanos: max(dateToWallNanos(end) - dateToWallNanos(start), 1000),
                tags: tags,
                statusOK: true
            )
        )
    }

    append(name: "probe.dns.resolve", start: transaction.domainLookupStartDate, end: transaction.domainLookupEndDate)
    append(name: "probe.tcp.connect", start: transaction.connectStartDate, end: transaction.connectEndDate)
    append(name: "probe.tls.handshake", start: transaction.secureConnectionStartDate, end: transaction.secureConnectionEndDate)
    append(name: "probe.http.request_to_first_byte", start: transaction.requestStartDate, end: transaction.responseStartDate)
    return events
}
