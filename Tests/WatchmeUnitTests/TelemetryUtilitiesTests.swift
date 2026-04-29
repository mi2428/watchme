@testable import WatchmeCore
@testable import WatchmeTelemetry
import XCTest

final class TelemetryUtilitiesTests: XCTestCase {
    override func setUp() {
        super.setUp()
        logger.minimumLevel = .error
    }

    func testPushgatewayEndpointPreservesPrefixAndEscapesGroupingKeys() throws {
        let baseURL = try XCTUnwrap(URL(string: "http://127.0.0.1:9091/proxy/api"))

        let endpoint = pushgatewayEndpointURL(baseURL: baseURL, job: "watchme/wifi", instance: "mac 1/en0")

        XCTAssertEqual(
            endpoint.absoluteString,
            "http://127.0.0.1:9091/proxy/api/metrics/job/watchme%2Fwifi/instance/mac%201%2Fen0"
        )
    }

    func testTraceRecorderSortsSpansAndAddsDefaultTraceTags() {
        let recorder = TraceRecorder()

        recorder.recordSpan(name: "later", startWallNanos: 2000, durationNanos: 0)
        recorder.recordSpan(name: "earlier", startWallNanos: 1000, durationNanos: 500, tags: ["span.source": "test"])

        let batch = recorder.finish(rootName: "wifi.test", rootTags: ["reason": "unit"])

        XCTAssertEqual(batch.spans.map(\.name), ["earlier", "later"])
        XCTAssertEqual(batch.spans.first?.durationNanos, 1000)
        XCTAssertEqual(batch.spans.first?.tags["span.source"], "test")
        XCTAssertEqual(batch.spans.last?.tags["span.source"], "watchme")
        XCTAssertEqual(batch.rootTags["trace.kind"], "wifi_observability")
        XCTAssertEqual(batch.rootTags["reason"], "unit")
    }
}
