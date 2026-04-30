import Foundation
import WatchmeCore

final class OTelMetricExporter {
    private let endpoint: URL
    private let serviceName: String
    private let httpClient: OTLPHTTPTransport
    private let startWallNanos = wallClockNanos()
    private let lock = NSLock()
    private var previousCounterValues: [String: Double] = [:]
    private var counterTotals: [String: Double] = [:]

    convenience init(serviceName: String, endpoint: URL, timeout: TimeInterval) {
        self.init(serviceName: serviceName, endpoint: endpoint, httpClient: BlockingHTTPClient(timeout: timeout))
    }

    init(serviceName: String, endpoint: URL, httpClient: OTLPHTTPTransport) {
        self.endpoint = endpoint
        self.serviceName = serviceName
        self.httpClient = httpClient
    }

    func export(_ samples: [MetricSample]) -> MetricExportResult {
        lock.lock()
        defer { lock.unlock() }

        let (payload, emittedSamples) = metricPayload(samples)
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = payload
        let result = httpClient.sendSynchronously(request: request)
        let ok = result.isSuccess
        return MetricExportResult(
            ok: ok,
            endpoint: endpoint,
            error: ok ? nil : result.errorDescription ?? "OTLP metric export failed",
            samples: emittedSamples
        )
    }

    private func metricPayload(_ samples: [MetricSample]) -> (Data, [MetricExportedSample]) {
        let timeUnixNano = "\(wallClockNanos())"
        var metricsByKey: [String: [String: Any]] = [:]
        var order: [String] = []
        var emittedSamples: [MetricExportedSample] = []

        for sample in samples {
            let value: Double = switch sample.type {
            case .gauge:
                sample.value
            case .counter:
                recordCounterTotal(sample)
            }
            emittedSamples.append(MetricExportedSample(name: sample.name, type: sample.type, labels: sample.labels, value: value))

            let key = "\(sample.name)\u{1e}\(sample.help)\u{1e}\(sample.type.rawValue)"
            if metricsByKey[key] == nil {
                order.append(key)
                metricsByKey[key] = [
                    "name": sample.name,
                    "description": sample.help,
                    sample.type.otlpJSONField: sample.type.emptyOTLPJSONMetric,
                ]
            }
            var metric = metricsByKey[key] ?? [:]
            var container = metric[sample.type.otlpJSONField] as? [String: Any] ?? sample.type.emptyOTLPJSONMetric
            var dataPoints = container["dataPoints"] as? [[String: Any]] ?? []
            dataPoints.append(dataPoint(sample: sample, value: value, timeUnixNano: timeUnixNano))
            container["dataPoints"] = dataPoints
            metric[sample.type.otlpJSONField] = container
            metricsByKey[key] = metric
        }

        let body: [String: Any] = [
            "resourceMetrics": [
                [
                    "resource": [
                        "attributes": [
                            otlpStringAttribute(key: "service.name", value: serviceName),
                            otlpStringAttribute(key: "host.name", value: Host.current().localizedName ?? "unknown"),
                            otlpStringAttribute(key: "os.type", value: "macOS"),
                        ],
                    ],
                    "scopeMetrics": [
                        [
                            "scope": [
                                "name": "watchme",
                            ],
                            "metrics": order.compactMap { metricsByKey[$0] },
                        ],
                    ],
                ],
            ],
        ]
        return ((try? JSONSerialization.data(withJSONObject: body)) ?? Data(), emittedSamples)
    }

    private func recordCounterTotal(_ sample: MetricSample) -> Double {
        let key = metricSeriesKey(name: sample.name, labels: sample.labels)
        let previous = previousCounterValues[key]
        let delta = previous.map { sample.value >= $0 ? sample.value - $0 : sample.value } ?? sample.value
        previousCounterValues[key] = sample.value
        let total = (counterTotals[key] ?? 0) + max(delta, 0)
        counterTotals[key] = total
        return total
    }

    private func dataPoint(sample: MetricSample, value: Double, timeUnixNano: String) -> [String: Any] {
        var point: [String: Any] = [
            "attributes": sample.labels.keys.sorted().map { key in
                otlpStringAttribute(key: key, value: sample.labels[key] ?? "")
            },
            "asDouble": value,
            "timeUnixNano": timeUnixNano,
        ]
        if sample.type == .counter {
            point["startTimeUnixNano"] = "\(startWallNanos)"
        }
        return point
    }
}

protocol OTLPHTTPTransport {
    func sendSynchronously(request: URLRequest) -> Result<HTTPURLResponse, Error>
}

private extension MetricSample.MetricType {
    var otlpJSONField: String {
        switch self {
        case .gauge:
            "gauge"
        case .counter:
            "sum"
        }
    }

    var emptyOTLPJSONMetric: [String: Any] {
        switch self {
        case .gauge:
            ["dataPoints": []]
        case .counter:
            [
                "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                "isMonotonic": true,
                "dataPoints": [],
            ]
        }
    }
}

private func otlpStringAttribute(key: String, value: String) -> [String: Any] {
    [
        "key": key,
        "value": [
            "stringValue": value,
        ],
    ]
}

func metricSeriesKey(name: String, labels: [String: String]) -> String {
    let labelKey = labels.keys.sorted().map { "\($0)=\(labels[$0] ?? "")" }.joined(separator: "\u{1f}")
    return "\(name)\u{1e}\(labelKey)"
}
