@testable import WatchmeCore
@testable import WatchmeWiFi
import XCTest

final class WiFiConfigTests: XCTestCase {
    func testParseOnceAndTelemetryOptions() throws {
        let config = try WiFiConfig.parse([
            "once",
            "--traces.url", "http://collector.example:4318/v1/traces",
            "--metrics.push.url=http://pushgateway.example:9091",
            "--metrics.push.prefix", "/base",
            "--metrics.interval", "2.5",
            "--traces.interval=30",
            "--traces.cooldown", "0",
            "--probe.http.timeout", "3",
            "--probe.bpf.span-max-age=90",
            "--probe.bpf.enabled", "false",
            "--probe.http.target", "https://example.com/health",
            "--probe.http.target=www.apple.com",
            "--log.level", "info",
        ])

        XCTAssertTrue(config.once)
        XCTAssertEqual(config.tracesURL.absoluteString, "http://collector.example:4318/v1/traces")
        XCTAssertEqual(config.metricsPushURL.absoluteString, "http://pushgateway.example:9091")
        XCTAssertEqual(config.metricsPushPrefix, "/base")
        XCTAssertEqual(config.metricsInterval, 2.5)
        XCTAssertEqual(config.activeInterval, 30)
        XCTAssertEqual(config.triggerCooldown, 0)
        XCTAssertEqual(config.probeHTTPTimeout, 3)
        XCTAssertEqual(config.bpfSpanMaxAge, 90)
        XCTAssertFalse(config.bpfEnabled)
        XCTAssertEqual(config.probeHTTPTargets, ["https://example.com/health", "www.apple.com"])
        XCTAssertEqual(config.logLevel, .info)
    }

    func testDefaultModeIsLongRunningAgent() throws {
        let config = try WiFiConfig.parse(["--log.level", "warn"])

        XCTAssertFalse(config.once)
        XCTAssertFalse(config.authorizeLocation)
        XCTAssertEqual(config.logLevel, .warn)
    }

    func testParseLocationAuthorizationMode() throws {
        let config = try WiFiConfig.parse(["authorize-only"])

        XCTAssertTrue(config.authorizeLocation)
        XCTAssertFalse(config.once)
        XCTAssertEqual(config.probeHTTPTimeout, 5)
    }

    func testParseRejectsInvalidArguments() {
        XCTAssertThrowsError(try WiFiConfig.parse(["--metrics.interval", "0"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--probe.http.target"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--probe.bpf.enabled", "maybe"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--bpf.enabled", "false"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--bpf.span-max-age", "90"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--once"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["agent"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["run"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["watch"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["location-authorize"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["authorize-location"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["authorize-only", "--probe.http.timeout", "12"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["authorize-only", "--log.level", "debug"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--unknown"]))
    }
}
