@testable import WatchmeCore
@testable import WatchmeTelemetry
import XCTest

final class TelemetryUtilitiesTests: XCTestCase {
    override func setUp() {
        super.setUp()
        logger.minimumLevel = .error
    }

    func testMetricSeriesKeySortsLabels() {
        XCTAssertEqual(
            metricSeriesKey(name: "watchme.test", labels: ["z": "last", "a": "first"]),
            metricSeriesKey(name: "watchme.test", labels: ["a": "first", "z": "last"])
        )
        XCTAssertNotEqual(
            metricSeriesKey(name: "watchme.test", labels: ["a": "first"]),
            metricSeriesKey(name: "watchme.test", labels: ["a": "second"])
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
