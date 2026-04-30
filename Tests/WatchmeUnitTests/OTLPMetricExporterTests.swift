@testable import WatchmeTelemetry
import XCTest

final class OTLPMetricExporterTests: XCTestCase {
    func testExporterBuildsOTLPJSONMetricRequest() throws {
        let transport = RecordingOTLPHTTPTransport()
        let exporter = try OTelMetricExporter(
            serviceName: "watchme-test",
            endpoint: XCTUnwrap(URL(string: "http://collector.example/v1/metrics")),
            httpClient: transport
        )

        let result = exporter.export([
            MetricSample(
                name: "watchme_test_memory_bytes",
                help: "Memory bytes.",
                type: .gauge,
                labels: ["state": "free"],
                value: 1024
            ),
            MetricSample(
                name: "watchme_test_cpu_time_seconds_total",
                help: "CPU time.",
                type: .counter,
                labels: ["mode": "user"],
                value: 7
            ),
        ])

        XCTAssertTrue(result.ok)
        let request = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(request.url?.absoluteString, "http://collector.example/v1/metrics")
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")

        let metrics = try metricPayloadMetrics(from: request)
        let names = Set(metrics.compactMap { $0["name"] as? String })
        XCTAssertEqual(names, ["watchme_test_memory_bytes", "watchme_test_cpu_time_seconds_total"])
        XCTAssertEqual(
            dataPointValue(metricName: "watchme_test_memory_bytes", field: "gauge", in: metrics),
            1024
        )
        XCTAssertEqual(
            dataPointValue(metricName: "watchme_test_cpu_time_seconds_total", field: "sum", in: metrics),
            7
        )
        let resourceAttributes = try metricPayloadResourceAttributes(from: request)
        XCTAssertEqual(resourceAttributes["service.name"], "watchme-test")
        XCTAssertEqual(resourceAttributes["os.type"], "macOS")
    }

    func testCounterSamplesRemainMonotonicAcrossSourceReset() throws {
        let transport = RecordingOTLPHTTPTransport()
        let exporter = try OTelMetricExporter(
            serviceName: "watchme-test",
            endpoint: XCTUnwrap(URL(string: "http://collector.example/v1/metrics")),
            httpClient: transport
        )

        for value in [10.0, 12.0, 4.0] {
            _ = exporter.export([
                MetricSample(
                    name: "watchme_test_counter_total",
                    help: "Counter.",
                    type: .counter,
                    labels: ["kind": "unit"],
                    value: value
                ),
            ])
        }

        let request = try XCTUnwrap(transport.requests.last)
        let metrics = try metricPayloadMetrics(from: request)
        XCTAssertEqual(dataPointValue(metricName: "watchme_test_counter_total", field: "sum", in: metrics), 16)
    }
}

private final class RecordingOTLPHTTPTransport: OTLPHTTPTransport {
    var requests: [URLRequest] = []

    func sendSynchronously(request: URLRequest) -> Result<HTTPURLResponse, Error> {
        requests.append(request)
        return .success(HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!)
    }
}

private func metricPayloadMetrics(from request: URLRequest) throws -> [[String: Any]] {
    let body = try XCTUnwrap(request.httpBody)
    let object = try JSONSerialization.jsonObject(with: body) as? [String: Any]
    let resourceMetrics = try XCTUnwrap(object?["resourceMetrics"] as? [[String: Any]])
    let scopeMetrics = try XCTUnwrap(resourceMetrics.first?["scopeMetrics"] as? [[String: Any]])
    return try XCTUnwrap(scopeMetrics.first?["metrics"] as? [[String: Any]])
}

private func metricPayloadResourceAttributes(from request: URLRequest) throws -> [String: String] {
    let body = try XCTUnwrap(request.httpBody)
    let object = try JSONSerialization.jsonObject(with: body) as? [String: Any]
    let resourceMetrics = try XCTUnwrap(object?["resourceMetrics"] as? [[String: Any]])
    let resource = try XCTUnwrap(resourceMetrics.first?["resource"] as? [String: Any])
    let attributes = try XCTUnwrap(resource["attributes"] as? [[String: Any]])
    return stringAttributes(attributes)
}

private func dataPointValue(metricName: String, field: String, in metrics: [[String: Any]]) -> Double? {
    guard
        let metric = metrics.first(where: { $0["name"] as? String == metricName }),
        let container = metric[field] as? [String: Any],
        let points = container["dataPoints"] as? [[String: Any]],
        let value = points.first?["asDouble"] as? Double
    else {
        return nil
    }
    return value
}

private func stringAttributes(_ attributes: [[String: Any]]) -> [String: String] {
    attributes.reduce(into: [:]) { result, attribute in
        guard
            let key = attribute["key"] as? String,
            let value = attribute["value"] as? [String: Any],
            let stringValue = value["stringValue"] as? String
        else {
            return
        }
        result[key] = stringValue
    }
}
