@testable import WatchmeCore
@testable import WatchmeSelf
import XCTest

final class SelfCollectorConfigTests: XCTestCase {
    func testParseNamespacedMetricsInterval() throws {
        let otlpURL = try XCTUnwrap(URL(string: "http://collector.example:4318/otlp"))
        let config = try SelfConfig.parse([
            "\(SelfCLI.Option.metricsInterval.name)=2.5",
        ], otlpURL: otlpURL)

        XCTAssertEqual(config.otlpURL.absoluteString, "http://collector.example:4318/otlp")
        XCTAssertEqual(config.traceEndpointURL.absoluteString, "http://collector.example:4318/otlp/v1/traces")
        XCTAssertEqual(config.metricEndpointURL.absoluteString, "http://collector.example:4318/otlp/v1/metrics")
        XCTAssertEqual(config.metricsInterval, 2.5)
    }

    func testDefaultMetricsInterval() throws {
        let config = try SelfConfig.parse([], otlpURL: WatchmeDefaults.otlpURL)

        XCTAssertEqual(config.metricsInterval, SelfDefaults.metricsInterval)
    }

    func testRejectsUnknownAndInvalidArguments() throws {
        let otlpURL = WatchmeDefaults.otlpURL

        XCTAssertThrowsError(try SelfConfig.parse([SelfCLI.Option.metricsInterval.name, "0"], otlpURL: otlpURL))
        XCTAssertThrowsError(try SelfConfig.parse([SelfCLI.Option.metricsInterval.name, "-1"], otlpURL: otlpURL))
        XCTAssertThrowsError(try SelfConfig.parse([SelfCLI.Option.metricsInterval.name], otlpURL: otlpURL))
        XCTAssertThrowsError(try SelfConfig.parse(["--unknown"], otlpURL: otlpURL))
    }
}
