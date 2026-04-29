@testable import WatchmeCore
@testable import WatchmeWiFi
import XCTest

final class WiFiConfigTests: XCTestCase {
    func testParseOnceAndTelemetryOptions() throws {
        let config = try WiFiConfig.parse([
            "once",
            "--collector", "http://collector.example:4318/v1/traces",
            "--pushgateway", "http://pushgateway.example:9091/base",
            "--metrics-interval", "2.5",
            "--active-interval", "30",
            "--trigger-cooldown", "0",
            "--timeout", "3",
            "--bpf-span-max-age", "90",
            "--no-bpf",
            "--target", "https://example.com/health",
            "-t", "www.apple.com",
            "--log-level", "info",
        ])

        XCTAssertTrue(config.once)
        XCTAssertEqual(config.collectorURL.absoluteString, "http://collector.example:4318/v1/traces")
        XCTAssertEqual(config.pushgatewayURL.absoluteString, "http://pushgateway.example:9091/base")
        XCTAssertEqual(config.metricsInterval, 2.5)
        XCTAssertEqual(config.activeInterval, 30)
        XCTAssertEqual(config.triggerCooldown, 0)
        XCTAssertEqual(config.timeout, 3)
        XCTAssertEqual(config.bpfSpanMaxAge, 90)
        XCTAssertFalse(config.bpfEnabled)
        XCTAssertEqual(config.targets, ["https://example.com/health", "www.apple.com"])
        XCTAssertEqual(config.logLevel, .info)
    }

    func testAgentAliasesDoNotForceOnceMode() throws {
        for alias in ["agent", "run", "watch"] {
            let config = try WiFiConfig.parse([alias, "--log-level", "warn"])
            XCTAssertFalse(config.once)
            XCTAssertEqual(config.logLevel, .warn)
        }
    }

    func testParseRejectsInvalidArguments() {
        XCTAssertThrowsError(try WiFiConfig.parse(["--metrics-interval", "0"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--target"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--unknown"]))
    }
}
