@testable import WatchmeCore
@testable import WatchmeWiFi
import XCTest

final class WiFiConfigTests: XCTestCase {
    func testParseOnceAndTelemetryOptions() throws {
        let config = try WiFiConfig.parse([
            "once",
            "--traces.url", "http://collector.example:4318/v1/traces",
            "--metrics.url=http://collector.example:4318/v1/metrics",
            "--metrics.interval", "2.5",
            "--traces.interval=30",
            "--traces.cooldown", "0",
            "--probe.internet.timeout", "3",
            "--probe.internet.family", "ipv6",
            "--probe.internet.dns", "false",
            "--probe.internet.icmp", "true",
            "--probe.internet.http", "false",
            "--probe.gateway.count", "6",
            "--probe.gateway.interval=0.1",
            "--probe.bpf.span-max-age=90",
            "--probe.bpf.enabled", "false",
            "--probe.internet.target", "example.com",
            "--probe.internet.target=www.apple.com",
            "--log.level", "info",
        ])

        XCTAssertTrue(config.once)
        XCTAssertEqual(config.tracesURL.absoluteString, "http://collector.example:4318/v1/traces")
        XCTAssertEqual(config.metricsURL.absoluteString, "http://collector.example:4318/v1/metrics")
        XCTAssertEqual(config.metricsInterval, 2.5)
        XCTAssertEqual(config.activeInterval, 30)
        XCTAssertEqual(config.triggerCooldown, 0)
        XCTAssertEqual(config.probeInternetTimeout, 3)
        XCTAssertEqual(config.probeInternetFamily, .ipv6)
        XCTAssertFalse(config.probeInternetDNS)
        XCTAssertTrue(config.probeInternetICMP)
        XCTAssertFalse(config.probeInternetHTTP)
        XCTAssertEqual(config.probeGatewayBurstCount, 6)
        XCTAssertEqual(config.probeGatewayBurstInterval, 0.1)
        XCTAssertEqual(config.bpfSpanMaxAge, 90)
        XCTAssertFalse(config.bpfEnabled)
        XCTAssertEqual(config.probeInternetTargets, ["example.com", "www.apple.com"])
        XCTAssertEqual(config.logLevel, .info)
    }

    func testDefaultModeIsLongRunningAgent() throws {
        let config = try WiFiConfig.parse(["--log.level", "warn"])

        XCTAssertFalse(config.once)
        XCTAssertFalse(config.authorizeLocation)
        XCTAssertEqual(config.probeInternetTargets, ["example.com", "www.cloudflare.com"])
        XCTAssertEqual(config.probeInternetFamily, .dual)
        XCTAssertEqual(config.logLevel, .warn)
    }

    func testParseLocationAuthorizationMode() throws {
        let config = try WiFiConfig.parse(["authorize-only"])

        XCTAssertTrue(config.authorizeLocation)
        XCTAssertFalse(config.once)
        XCTAssertEqual(config.probeInternetTimeout, 5)
    }

    func testParseRejectsInvalidArguments() {
        XCTAssertThrowsError(try WiFiConfig.parse(["--metrics.interval", "0"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--probe.internet.target"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--probe.internet.family", "both"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--probe.internet.icmp", "maybe"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--probe.gateway.count", "0"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--probe.gateway.interval", "-0.1"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--probe.bpf.enabled", "maybe"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--bpf.enabled", "false"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--bpf.span-max-age", "90"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--once"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["agent"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["run"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["watch"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["location-authorize"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["authorize-location"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["authorize-only", "--probe.internet.timeout", "12"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["authorize-only", "--log.level", "debug"]))
        XCTAssertThrowsError(try WiFiConfig.parse(["--unknown"]))
    }
}
