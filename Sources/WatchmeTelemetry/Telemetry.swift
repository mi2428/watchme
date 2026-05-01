import Foundation
import OpenTelemetryApi
import OpenTelemetryProtocolExporterHttp
import OpenTelemetrySdk
import WatchmeCore

/// One metric data point before it is encoded as OTLP JSON.
public struct MetricSample {
    /// Supported metric encodings.
    public enum MetricType: String {
        case gauge
        case counter
    }

    /// Metric name emitted to OTLP.
    public let name: String
    /// Human-readable metric description.
    public let help: String
    /// Gauge or monotonic counter.
    public let type: MetricType
    /// Metric attributes.
    public let labels: [String: String]
    /// Source value before counter normalization.
    public let value: Double

    public init(name: String, help: String, type: MetricType, labels: [String: String], value: Double) {
        self.name = name
        self.help = help
        self.type = type
        self.labels = labels
        self.value = value
    }
}

/// Result of a metric export attempt.
public struct MetricExportResult {
    public let ok: Bool
    public let endpoint: URL
    public let error: String?
    public let samples: [MetricExportedSample]
}

/// Metric sample after exporter-side normalization.
public struct MetricExportedSample {
    public let name: String
    public let type: MetricSample.MetricType
    public let labels: [String: String]
    public let value: Double
}

/// Result of a trace export attempt.
public struct TraceExportResult {
    public let traceId: String
    public let ok: Bool
    public let endpoint: URL
    public let error: String?
}

/// OpenTelemetry client used by collectors.
public final class TelemetryClient {
    private let traces: OTelTraceExporter
    private let metrics: OTelMetricExporter

    public init(
        serviceName: String,
        tracesEndpoint: URL,
        metricsEndpoint: URL,
        metricsTimeout: TimeInterval = WatchmeDefaults.metricsTimeout
    ) {
        traces = OTelTraceExporter(serviceName: serviceName, endpoint: tracesEndpoint)
        metrics = OTelMetricExporter(serviceName: serviceName, endpoint: metricsEndpoint, timeout: metricsTimeout)
    }

    /// Exports metrics and logs the export outcome.
    public func exportMetrics(name: String, fields: [String: String], metrics samples: [MetricSample]) -> Bool {
        let result = metrics.export(samples)
        var logFields = fields
        logFields["metric_export_name"] = name
        logFields["metrics_endpoint_url"] = result.endpoint.absoluteString
        logFields["metric_sample_count"] = "\(result.samples.count)"
        if let error = result.error {
            logFields["error"] = error
        }
        logEvent(result.ok ? .info : .warn, result.ok ? "metrics_exported" : "metrics_export_failed", fields: logFields)
        if result.ok {
            logMetricSamples(result.samples, exportName: name, endpoint: result.endpoint, fields: fields)
        }
        return result.ok
    }

    /// Exports a trace batch through OTLP/HTTP.
    public func exportTrace(records: TraceBatch) -> TraceExportResult {
        traces.export(records)
    }
}

private func logMetricSamples(
    _ samples: [MetricExportedSample],
    exportName: String,
    endpoint: URL,
    fields: [String: String]
) {
    for (index, sample) in samples.enumerated() {
        var logFields = fields
        logFields["metric_export_name"] = exportName
        logFields["metrics_endpoint_url"] = endpoint.absoluteString
        logFields["metric_sample_index"] = "\(index)"
        logFields["metric_sample_count"] = "\(samples.count)"
        logFields["metric_name"] = sample.name
        logFields["metric_type"] = sample.type.rawValue
        logFields["metric_value"] = formatMetricLogValue(sample.value)
        logFields["metric_labels"] = formatMetricLogLabels(sample.labels)
        for key in sample.labels.keys.sorted() {
            logFields["metric_label.\(logFieldKeyComponent(key))"] = sample.labels[key] ?? ""
        }
        logEvent(.debug, "metric_sample_exported", fields: logFields)
    }
}

private func formatMetricLogLabels(_ labels: [String: String]) -> String {
    labels.keys.sorted().map { key in
        "\(key)=\(labels[key] ?? "")"
    }.joined(separator: ",")
}

private func formatMetricLogValue(_ value: Double) -> String {
    guard value.isFinite else {
        return "\(value)"
    }
    return String(format: "%.15g", value)
}

private func logFieldKeyComponent(_ key: String) -> String {
    String(key.map { character in
        character.isLetter || character.isNumber || character == "." || character == "_" || character == "-" ? character : "_"
    })
}

/// Collector-neutral span model before conversion to OpenTelemetry SDK spans.
public struct TraceSpanRecord {
    /// Stable local span identifier used for parent mapping.
    public let id: String
    /// Optional local parent span identifier.
    public let parentId: String?
    /// Span name.
    public let name: String
    /// Span start time in wall-clock nanoseconds.
    public let startWallNanos: UInt64
    /// Span duration in nanoseconds.
    public let durationNanos: UInt64
    /// Span attributes.
    public let tags: [String: String]
    /// Whether the span should be exported with OK status.
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

/// A root trace and all child spans ready for export.
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

/// Packet or probe event that can be recorded as a span.
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

/// Thread-safe collector-local trace builder.
public final class TraceRecorder {
    /// Local trace identifier used by structured logs before OTLP export.
    public let traceId = randomHex(bytes: 16)
    private let rootSpanId = randomHex(bytes: 8)
    private let rootStartWallNanos = wallClockNanos()
    private var spans: [TraceSpanRecord] = []
    private let lock = NSLock()

    public init() {}

    /// Generates a local span identifier.
    public func newSpanId() -> String {
        randomHex(bytes: 8)
    }

    /// Records a child span in the local trace model.
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

    /// Records a `SpanEvent`, preserving packet parser attributes over context tags.
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

    /// Finishes the trace and expands the root to include any earlier packet spans.
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
            // the whole attachment packet history rather than clipping it.
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
    private let httpClient: OTelHTTPClientAdapter

    convenience init(serviceName: String, endpoint: URL) {
        self.init(serviceName: serviceName, endpoint: endpoint, httpClient: BlockingHTTPClient(timeout: 10))
    }

    init(serviceName: String, endpoint: URL, httpClient: OTLPTraceHTTPClient) {
        self.endpoint = endpoint
        let adapter = OTelHTTPClientAdapter(client: httpClient)
        self.httpClient = adapter
        exporter = OtlpHttpTraceExporter(endpoint: endpoint, httpClient: adapter)
        let resource = Resource(attributes: [
            "service.name": AttributeValue.string(serviceName),
            "os.type": AttributeValue.string("macOS"),
        ])
        let provider = TracerProviderBuilder()
            .with(resource: resource)
            .add(spanProcessor: SimpleSpanProcessor(spanExporter: exporter))
            .build()
        self.provider = provider
        tracer = provider.get(instrumentationName: "watchme", instrumentationVersion: WatchmeVersion.current.packageVersion)
    }

    func export(_ batch: TraceBatch) -> TraceExportResult {
        let root = tracer.spanBuilder(spanName: batch.rootName)
            .setNoParent()
            .setSpanKind(spanKind: .internal)
            .setStartTime(time: dateFromWallNanos(batch.rootStartWallNanos))
            .startSpan()
        root.setAttributes(attributeValues(batch.rootTags))

        let traceId = root.context.traceId.hexString
        var spanById: [String: Span] = ["root": root]

        for record in batch.spans {
            // Network attachment traces can contain synthetic phase spans and
            // packet spans; this map preserves explicit parent relationships
            // while falling back to the root if a referenced parent was pruned.
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
        let exporterResult = exporter.flush()
        let ok = exporterResult == .success
        return TraceExportResult(
            traceId: traceId,
            ok: ok,
            endpoint: endpoint,
            error: ok ? nil : "OTLP trace export failed"
        )
    }
}
