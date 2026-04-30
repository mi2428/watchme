import Foundation
import OpenTelemetryApi
import OpenTelemetryProtocolExporterHttp
import OpenTelemetrySdk
import WatchmeCore

public struct PrometheusMetric {
    public enum MetricType: String {
        case gauge
        case counter
    }

    public let name: String
    public let help: String
    public let type: MetricType
    public let labels: [String: String]
    public let value: Double

    public init(name: String, help: String, type: MetricType, labels: [String: String], value: Double) {
        self.name = name
        self.help = help
        self.type = type
        self.labels = labels
        self.value = value
    }
}

public enum PrometheusTextEncoder {
    public static func encode(_ metrics: [PrometheusMetric]) -> String {
        var lines: [String] = []
        var described = Set<String>()
        for metric in metrics {
            // Pushgateway accepts the Prometheus 0.0.4 text format; HELP/TYPE
            // must be emitted once per metric family, before the first sample.
            if !described.contains(metric.name) {
                lines.append("# HELP \(metric.name) \(metric.help)")
                lines.append("# TYPE \(metric.name) \(metric.type.rawValue)")
                described.insert(metric.name)
            }
            lines.append("\(metric.name)\(prometheusLabels(metric.labels)) \(formatPrometheusValue(metric.value))")
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }

    private static func formatPrometheusValue(_ value: Double) -> String {
        // Keep integer gauges readable while still emitting deterministic
        // decimal text for rates and timestamps. Prometheus accepts either
        // spelling, but stable formatting keeps tests and diffs meaningful.
        if value.rounded() == value {
            return String(Int64(value))
        }
        return String(format: "%.6f", value)
    }
}

public struct MetricPushResult {
    public let ok: Bool
    public let endpoint: URL
    public let statusCode: Int
    public let error: String?
}

public protocol MetricSink {
    func push(job: String, instance: String, body: String, timeout: TimeInterval) -> MetricPushResult
}

public final class PushgatewayMetricSink: MetricSink {
    private let baseURL: URL
    private let pathPrefix: String

    public init(baseURL: URL, pathPrefix: String = "") {
        self.baseURL = baseURL
        self.pathPrefix = pathPrefix
    }

    public func push(job: String, instance: String, body: String, timeout: TimeInterval) -> MetricPushResult {
        let endpoint = pushgatewayEndpointURL(baseURL: baseURL, pathPrefix: pathPrefix, job: job, instance: instance)
        var request = URLRequest(url: endpoint)
        request.httpMethod = "PUT"
        request.timeoutInterval = timeout
        request.setValue("text/plain; version=0.0.4; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = body.data(using: .utf8)

        let semaphore = DispatchSemaphore(value: 0)
        var ok = false
        var statusCode = 0
        var errorMessage: String?

        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error {
                errorMessage = error.localizedDescription
            }
            if let http = response as? HTTPURLResponse {
                statusCode = http.statusCode
                ok = (200 ..< 300).contains(http.statusCode)
            }
            semaphore.signal()
        }.resume()

        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            errorMessage = "push timed out"
        }

        return MetricPushResult(ok: ok, endpoint: endpoint, statusCode: statusCode, error: errorMessage)
    }
}

func pushgatewayEndpointURL(baseURL: URL, pathPrefix: String = "", job: String, instance: String) -> URL {
    let encodedJob = pathEscape(job)
    let encodedInstance = pathEscape(instance)
    var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)!
    let basePrefix = components.percentEncodedPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    let configuredPrefix = pushgatewayPathPrefix(pathPrefix)
    let prefix = [basePrefix, configuredPrefix].filter { !$0.isEmpty }.joined(separator: "/")
    // Use percentEncodedPath because Pushgateway grouping keys are path
    // segments. A job or instance can legally contain "/", and that slash must
    // stay encoded as data rather than being interpreted as a path separator.
    let pathPrefix = prefix.isEmpty ? "" : "/\(prefix)"
    components.percentEncodedPath = "\(pathPrefix)/metrics/job/\(encodedJob)/instance/\(encodedInstance)"
    return components.url!
}

private func pushgatewayPathPrefix(_ rawPrefix: String) -> String {
    rawPrefix
        .split(separator: "/", omittingEmptySubsequences: true)
        .map { pathEscape(String($0)) }
        .joined(separator: "/")
}

public final class TelemetryClient {
    private let serviceName: String
    private let metricsSink: MetricSink
    private let traces: OTelTraceExporter
    private let metricsTimeout: TimeInterval

    public init(serviceName: String, tracesEndpoint: URL, metricsSink: MetricSink, metricsTimeout: TimeInterval = 5) {
        self.serviceName = serviceName
        self.metricsSink = metricsSink
        self.metricsTimeout = metricsTimeout
        traces = OTelTraceExporter(serviceName: serviceName, endpoint: tracesEndpoint)
    }

    public func pushMetrics(job: String, fields: [String: String], metrics: [PrometheusMetric]) -> Bool {
        let instance = Host.current().localizedName ?? "macos"
        let body = PrometheusTextEncoder.encode(metrics)
        let result = metricsSink.push(job: job, instance: instance, body: body, timeout: metricsTimeout)
        var logFields = fields
        logFields["metrics_push_endpoint_url"] = result.endpoint.absoluteString
        logFields["status_code"] = "\(result.statusCode)"
        if let error = result.error {
            logFields["error"] = error
        }
        logEvent(result.ok ? .debug : .warn, result.ok ? "\(job)_metrics_pushed" : "\(job)_metrics_push_failed", fields: logFields)
        return result.ok
    }

    public func exportTrace(records: TraceBatch) -> String {
        traces.export(records)
    }
}

public struct TraceSpanRecord {
    public let id: String
    public let parentId: String?
    public let name: String
    public let startWallNanos: UInt64
    public let durationNanos: UInt64
    public let tags: [String: String]
    public let statusOK: Bool

    public init(
        id: String,
        parentId: String?,
        name: String,
        startWallNanos: UInt64,
        durationNanos: UInt64,
        tags: [String: String],
        statusOK: Bool
    ) {
        self.id = id
        self.parentId = parentId
        self.name = name
        self.startWallNanos = startWallNanos
        self.durationNanos = durationNanos
        self.tags = tags
        self.statusOK = statusOK
    }
}

public struct TraceBatch {
    public let rootName: String
    public let rootTags: [String: String]
    public let rootStartWallNanos: UInt64
    public let rootDurationNanos: UInt64
    public let spans: [TraceSpanRecord]

    public init(
        rootName: String,
        rootTags: [String: String],
        rootStartWallNanos: UInt64,
        rootDurationNanos: UInt64,
        spans: [TraceSpanRecord]
    ) {
        self.rootName = rootName
        self.rootTags = rootTags
        self.rootStartWallNanos = rootStartWallNanos
        self.rootDurationNanos = rootDurationNanos
        self.spans = spans
    }
}

public struct SpanEvent {
    public let name: String
    public let startWallNanos: UInt64
    public let durationNanos: UInt64
    public let tags: [String: String]
    public let statusOK: Bool

    public init(name: String, startWallNanos: UInt64, durationNanos: UInt64, tags: [String: String], statusOK: Bool) {
        self.name = name
        self.startWallNanos = startWallNanos
        self.durationNanos = durationNanos
        self.tags = tags
        self.statusOK = statusOK
    }
}

public final class TraceRecorder {
    public let traceId = randomHex(bytes: 16)
    private let rootSpanId = randomHex(bytes: 8)
    private let rootStartWallNanos = wallClockNanos()
    private var spans: [TraceSpanRecord] = []
    private let lock = NSLock()

    public init() {}

    public func newSpanId() -> String {
        randomHex(bytes: 8)
    }

    @discardableResult
    public func recordSpan(
        name: String,
        id explicitId: String? = nil,
        startWallNanos: UInt64,
        durationNanos: UInt64,
        parentId: String? = nil,
        tags inputTags: [String: String] = [:],
        statusOK: Bool = true
    ) -> String {
        let spanId = explicitId ?? newSpanId()
        var tags = inputTags
        // The local model can be exported to OTLP or logged directly. Store the
        // status in tags as well as on the final Span so terminal logs and
        // backend traces agree when a probe fails.
        tags["otel.status_code"] = statusOK ? "OK" : "ERROR"
        if tags["span.source"] == nil {
            tags["span.source"] = "watchme"
        }

        let span = TraceSpanRecord(
            id: spanId,
            parentId: parentId ?? rootSpanId,
            name: name,
            startWallNanos: startWallNanos,
            durationNanos: max(1000, durationNanos),
            tags: tags,
            statusOK: statusOK
        )

        lock.lock()
        spans.append(span)
        lock.unlock()

        var logFields: [String: String] = [
            "trace_id": traceId,
            "span": name,
            "span_id": spanId,
            "duration_ms": String(format: "%.3f", Double(span.durationNanos) / 1_000_000.0),
            "status": statusOK ? "ok" : "error",
        ]
        for (key, value) in tags {
            logFields["attr.\(key)"] = clipped(value, limit: 240)
        }
        logEvent(.debug, "span_finished", fields: logFields)
        return spanId
    }

    public func recordEvent(_ event: SpanEvent, parentId: String? = nil, tags extraTags: [String: String] = [:]) {
        var tags = event.tags
        // Packet parsers own protocol-specific attributes. Extra Wi-Fi tags are
        // context, so they only fill gaps and do not overwrite packet evidence.
        tags.merge(extraTags) { current, _ in current }
        recordSpan(
            name: event.name,
            startWallNanos: event.startWallNanos,
            durationNanos: event.durationNanos,
            parentId: parentId,
            tags: tags,
            statusOK: event.statusOK
        )
    }

    public func finish(rootName: String, rootTags: [String: String]) -> TraceBatch {
        lock.lock()
        let children = spans
        lock.unlock()

        let rootStart: UInt64
        let rootDuration: UInt64
        if children.isEmpty {
            rootStart = rootStartWallNanos
            rootDuration = max(1000, wallClockNanos() - rootStartWallNanos)
        } else {
            // Passive BPF spans may start before the CoreWLAN/SystemConfiguration
            // callback that triggered export. Expand the root span so Tempo shows
            // the whole rejoin window rather than clipping the packet history.
            rootStart = min(rootStartWallNanos, children.map(\.startWallNanos).min() ?? rootStartWallNanos)
            let last = max(wallClockNanos(), children.map { $0.startWallNanos + $0.durationNanos }.max() ?? rootStartWallNanos)
            rootDuration = max(1000, last - rootStart)
        }

        var tags = rootTags
        tags["trace.kind"] = "wifi_observability"
        tags["host.name"] = Host.current().localizedName ?? "unknown"
        tags["os.type"] = "macOS"

        return TraceBatch(
            rootName: rootName,
            rootTags: tags,
            rootStartWallNanos: rootStart,
            rootDurationNanos: rootDuration,
            spans: children.sorted { $0.startWallNanos < $1.startWallNanos }
        )
    }
}

final class OTelTraceExporter {
    private let endpoint: URL
    private let exporter: OtlpHttpTraceExporter
    private let provider: TracerProviderSdk
    private let tracer: Tracer

    init(serviceName: String, endpoint: URL) {
        self.endpoint = endpoint
        exporter = OtlpHttpTraceExporter(endpoint: endpoint, httpClient: BlockingHTTPClient(timeout: 10))
        let resource = Resource(attributes: [
            "service.name": AttributeValue.string(serviceName),
            "os.type": AttributeValue.string("macOS"),
        ])
        let provider = TracerProviderBuilder()
            .with(resource: resource)
            .add(spanProcessor: SimpleSpanProcessor(spanExporter: exporter))
            .build()
        self.provider = provider
        tracer = provider.get(instrumentationName: "watchme", instrumentationVersion: "0.1.0")
    }

    func export(_ batch: TraceBatch) -> String {
        let root = tracer.spanBuilder(spanName: batch.rootName)
            .setNoParent()
            .setSpanKind(spanKind: .internal)
            .setStartTime(time: dateFromWallNanos(batch.rootStartWallNanos))
            .startSpan()
        root.setAttributes(attributeValues(batch.rootTags))

        let traceId = root.context.traceId.hexString
        var spanById: [String: Span] = ["root": root]

        for record in batch.spans {
            // Packet-window traces can contain synthetic phase spans and packet
            // spans; this map preserves explicit parent relationships while
            // falling back to the root if a referenced parent was pruned.
            let parent = record.parentId.flatMap { spanById[$0] } ?? root
            let span = tracer.spanBuilder(spanName: record.name)
                .setParent(parent)
                .setStartTime(time: dateFromWallNanos(record.startWallNanos))
                .startSpan()
            span.setAttributes(attributeValues(record.tags))
            span.status = record.statusOK ? .ok : .error(description: record.tags["error"] ?? "span failed")
            span.end(time: dateFromWallNanos(record.startWallNanos + record.durationNanos))
            spanById[record.id] = span
        }

        root.status = .ok
        root.end(time: dateFromWallNanos(batch.rootStartWallNanos + batch.rootDurationNanos))
        provider.forceFlush()
        _ = exporter.flush()
        return traceId
    }
}

final class BlockingHTTPClient: HTTPClient {
    private let session: URLSession
    private let timeout: TimeInterval

    init(timeout: TimeInterval) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.urlCache = nil
        session = URLSession(configuration: configuration)
        self.timeout = timeout
    }

    func send(request: URLRequest, completion: @escaping (Result<HTTPURLResponse, Error>) -> Void) {
        // The exporter API is callback-based, but watchme emits traces from a
        // serial agent path and needs completion before logging "trace_sent".
        // Blocking here keeps lifecycle semantics simple without shelling out.
        let semaphore = DispatchSemaphore(value: 0)
        var output: Result<HTTPURLResponse, Error>?
        let task = session.dataTask(with: request) { data, response, error in
            if let error {
                output = .failure(error)
            } else if let http = response as? HTTPURLResponse {
                output = .success(http)
            } else {
                output = .failure(
                    WatchmeError
                        .invalidArgument("Failed to receive HTTPURLResponse: \(String(describing: response)), bytes=\(data?.count ?? 0)")
                )
            }
            semaphore.signal()
        }
        task.resume()
        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            task.cancel()
            output = .failure(WatchmeError.invalidArgument("OTLP HTTP export timed out"))
        }
        completion(output ?? .failure(WatchmeError.invalidArgument("OTLP HTTP export did not complete")))
    }
}

func prometheusLabels(_ labels: [String: String]) -> String {
    guard !labels.isEmpty else {
        return ""
    }
    return "{"
        + labels.keys.sorted().map { key in
            "\(key)=\"\(prometheusEscape(labels[key] ?? ""))\""
        }.joined(separator: ",") + "}"
}

func prometheusEscape(_ value: String) -> String {
    value
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\n", with: "\\n")
        .replacingOccurrences(of: "\"", with: "\\\"")
}

func pathEscape(_ value: String) -> String {
    var allowed = CharacterSet.urlPathAllowed
    allowed.remove(charactersIn: "/")
    return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
}

func attributeValues(_ tags: [String: String]) -> [String: AttributeValue] {
    tags.reduce(into: [:]) { result, entry in
        result[entry.key] = .string(entry.value)
    }
}
