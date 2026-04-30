@testable import WatchmeCore
@testable import WatchmeSystem
import XCTest

final class SystemConfigTests: XCTestCase {
    func testParseOnceAndTelemetryOptions() throws {
        let config = try SystemConfig.parse([
            "once",
            "--collector.url", "http://collector.example:4318/otlp",
            "--metrics.interval=2.5",
            "--log.level", "info",
        ])

        XCTAssertTrue(config.once)
        XCTAssertEqual(config.collectorURL.absoluteString, "http://collector.example:4318/otlp")
        XCTAssertEqual(config.traceEndpointURL.absoluteString, "http://collector.example:4318/otlp/v1/traces")
        XCTAssertEqual(config.metricEndpointURL.absoluteString, "http://collector.example:4318/otlp/v1/metrics")
        XCTAssertEqual(config.metricsInterval, 2.5)
        XCTAssertEqual(config.logLevel, .info)
    }

    func testDefaultModeIsLongRunningAgent() throws {
        let config = try SystemConfig.parse(["--log.level", "warn"])

        XCTAssertFalse(config.once)
        XCTAssertEqual(config.collectorURL.absoluteString, "http://127.0.0.1:4318")
        XCTAssertEqual(config.traceEndpointURL.absoluteString, "http://127.0.0.1:4318/v1/traces")
        XCTAssertEqual(config.metricEndpointURL.absoluteString, "http://127.0.0.1:4318/v1/metrics")
        XCTAssertEqual(config.metricsInterval, 5)
        XCTAssertEqual(config.logLevel, .warn)
    }

    func testUsageShowsOnlySystemOptions() {
        let usage = systemUsageText()

        XCTAssertTrue(usage.contains("watchme system [options]"))
        XCTAssertTrue(usage.contains("watchme system once [options]"))
        XCTAssertTrue(usage.contains("--collector.url URL"))
        XCTAssertTrue(usage.contains("--metrics.interval seconds"))
        XCTAssertTrue(usage.contains("--log.level level"))
        XCTAssertFalse(usage.contains("--traces.interval"))
        XCTAssertFalse(usage.contains("--probe.internet.target"))
    }

    func testParseRejectsInvalidArguments() {
        XCTAssertThrowsError(try SystemConfig.parse(["--collector.url", "http://127.0.0.1:4318?debug=1"]))
        XCTAssertThrowsError(try SystemConfig.parse(["--metrics.interval", "0"]))
        XCTAssertThrowsError(try SystemConfig.parse(["--metrics.interval", "-1"]))
        XCTAssertThrowsError(try SystemConfig.parse(["--metrics.interval"]))
        XCTAssertThrowsError(try SystemConfig.parse(["--log.level", "verbose"]))
        XCTAssertThrowsError(try SystemConfig.parse(["--once"]))
        XCTAssertThrowsError(try SystemConfig.parse(["agent"]))
        XCTAssertThrowsError(try SystemConfig.parse(["run"]))
        XCTAssertThrowsError(try SystemConfig.parse(["watch"]))
        XCTAssertThrowsError(try SystemConfig.parse(["--unknown"]))
    }
}
