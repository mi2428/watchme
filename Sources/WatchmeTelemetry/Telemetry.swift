import Foundation
import OpenTelemetryApi
import OpenTelemetryProtocolExporterHttp
import OpenTelemetrySdk
import WatchmeCore

public struct MetricSample {
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

public struct MetricExportResult {
    public let ok: Bool
    public let endpoint: URL
    public let error: String?
}

public final class TelemetryClient {
    private let traces: OTelTraceExporter
    private let metrics: OTelMetricExporter

    public init(serviceName: String, tracesEndpoint: URL, metricsEndpoint: URL, metricsTimeout: TimeInterval = 5) {
        traces = OTelTraceExporter(serviceName: serviceName, endpoint: tracesEndpoint)
        metrics = OTelMetricExporter(serviceName: serviceName, endpoint: metricsEndpoint, timeout: metricsTimeout)
    }

    public func exportMetrics(name: String, fields: [String: String], metrics samples: [MetricSample]) -> Bool {
        let result = metrics.export(samples)
        var logFields = fields
        logFields["metrics_endpoint_url"] = result.endpoint.absoluteString
        logFields["metric_sample_count"] = "\(samples.count)"
        if let error = result.error {
            logFields["error"] = error
        }
        logEvent(result.ok ? .debug : .warn, result.ok ? "\(name)_metrics_exported" : "\(name)_metrics_export_failed", fields: logFields)
        return result.ok
    }

    public func exportTrace(records: TraceBatch) -> String {
        traces.export(records)
    }
}

final class OTelMetricExporter {
    private let endpoint: URL
    private let exporter: OtlpHttpMetricExporter
    private let provider: MeterProviderSdk
    private let meter: MeterSdk
    private let lock = NSLock()
    private var gauges: [String: DoubleGaugeSdk] = [:]
    private var counters: [String: DoubleCounterSdk] = [:]
    private var previousCounterValues: [String: Double] = [:]

    init(serviceName: String, endpoint: URL, timeout: TimeInterval) {
        self.endpoint = endpoint
        exporter = OtlpHttpMetricExporter(endpoint: endpoint, httpClient: BlockingHTTPClient(timeout: timeout))
        let reader = PeriodicMetricReaderBuilder(exporter: exporter)
            .setInterval(timeInterval: 86_400)
            .build()
        let resource = Resource(attributes: [
            "service.name": AttributeValue.string(serviceName),
            "host.name": AttributeValue.string(Host.current().localizedName ?? "unknown"),
            "os.type": AttributeValue.string("macOS"),
        ])
        provider = MeterProviderSdk.builder()
            .setResource(resource: resource)
            .registerMetricReader(reader: reader)
            .build()
        meter = provider.get(name: "watchme")
    }

    func export(_ samples: [MetricSample]) -> MetricExportResult {
        lock.lock()
        defer { lock.unlock() }

        for sample in samples {
            switch sample.type {
            case .gauge:
                recordGauge(sample)
            case .counter:
                recordCounter(sample)
            }
        }

        let providerResult = provider.forceFlush()
        let exporterResult = exporter.flush()
        let ok = providerResult == .success && exporterResult == .success
        return MetricExportResult(
            ok: ok,
            endpoint: endpoint,
            error: ok ? nil : "OTLP metric export failed"
        )
    }

    private func recordGauge(_ sample: MetricSample) {
        let gauge = gauges[sample.name] ?? meter.gaugeBuilder(name: sample.name)
            .setDescription(sample.help)
            .build()
        gauges[sample.name] = gauge
        gauge.record(value: sample.value, attributes: metricAttributes(sample.labels))
    }

    private func recordCounter(_ sample: MetricSample) {
        let key = metricSeriesKey(name: sample.name, labels: sample.labels)
        let previous = previousCounterValues[key]
        let delta = previous.map { sample.value >= $0 ? sample.value - $0 : sample.value } ?? sample.value
        previousCounterValues[key] = sample.value
        guard delta > 0 || previous == nil else {
            return
        }

        var counter = counters[sample.name] ?? meter.counterBuilder(name: sample.name)
            .ofDoubles()
            .setDescription(sample.help)
            .build()
        counter.add(value: delta, attributes: metricAttributes(sample.labels))
        counters[sample.name] = counter
    }
}

func metricSeriesKey(name: String, labels: [String: String]) -> String {
    let labelKey = labels.keys.sorted().map { "\($0)=\(labels[$0] ?? "")" }.joined(separator: "\u{1f}")
    return "\(name)\u{1e}\(labelKey)"
}

func metricAttributes(_ labels: [String: String]) -> [String: AttributeValue] {
    labels.reduce(into: [:]) { result, entry in
        result[entry.key] = .string(entry.value)
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
                if (200 ..< 300).contains(http.statusCode) {
                    output = .success(http)
                } else {
                    output = .failure(WatchmeError.invalidArgument("OTLP HTTP export failed with status \(http.statusCode)"))
                }
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

func attributeValues(_ tags: [String: String]) -> [String: AttributeValue] {
    tags.reduce(into: [:]) { result, entry in
        result[entry.key] = .string(entry.value)
    }
}
