@testable import WatchmeWiFi
import XCTest

final class WiFiCollectorConfigTests: XCTestCase {
    func testParseNamespacedTelemetryOptions() throws {
        let otlpURL = try XCTUnwrap(URL(string: "http://collector.example:4318/otlp"))
        let config = try WiFiConfig.parse([
            "--wifi.metrics.interval", "2.5",
            "--wifi.traces.interval=30",
            "--wifi.traces.cooldown", "0",
            "--wifi.probe.internet.timeout", "3",
            "--wifi.probe.internet.family", "ipv6",
            "--wifi.probe.internet.dns", "false",
            "--wifi.probe.internet.icmp", "true",
            "--wifi.probe.internet.http", "false",
            "--wifi.probe.gateway.count", "6",
            "--wifi.probe.gateway.interval=0.1",
            "--wifi.probe.bpf.span-max-age=90",
            "--wifi.probe.bpf.enabled", "false",
            "--wifi.probe.internet.target", "example.com",
            "--wifi.probe.internet.target=www.apple.com",
        ], otlpURL: otlpURL)

        XCTAssertEqual(config.otlpURL.absoluteString, "http://collector.example:4318/otlp")
        XCTAssertEqual(config.traceEndpointURL.absoluteString, "http://collector.example:4318/otlp/v1/traces")
        XCTAssertEqual(config.metricEndpointURL.absoluteString, "http://collector.example:4318/otlp/v1/metrics")
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
    }

    func testDefaultConfiguration() throws {
        let config = try WiFiConfig.parse([], otlpURL: XCTUnwrap(URL(string: "http://127.0.0.1:4318")))

        XCTAssertEqual(config.probeInternetTargets, ["example.com", "www.cloudflare.com"])
        XCTAssertEqual(config.probeInternetFamily, .dual)
        XCTAssertEqual(config.metricsInterval, 5)
        XCTAssertEqual(config.activeInterval, 60)
    }

    func testAuthorizationTimeoutParserOnlyAllowsTimeout() throws {
        XCTAssertEqual(try WiFiCollectorFactory.authorizationTimeout(arguments: []), 5)
        XCTAssertEqual(
            try WiFiCollectorFactory.authorizationTimeout(arguments: ["--wifi.probe.internet.timeout", "12"]),
            12
        )

        XCTAssertThrowsError(try WiFiCollectorFactory.authorizationTimeout(arguments: ["--wifi.metrics.interval", "1"]))
        XCTAssertThrowsError(try WiFiCollectorFactory.authorizationTimeout(arguments: ["--wifi.probe.internet.timeout", "0"]))
    }

    func testRejectsUnknownAndInvalidArguments() throws {
        let otlpURL = try XCTUnwrap(URL(string: "http://127.0.0.1:4318"))

        XCTAssertThrowsError(try WiFiConfig.parse(["--wifi.metrics.interval", "0"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse(["--wifi.probe.internet.target"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse(["--wifi.probe.internet.family", "both"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse(["--wifi.probe.internet.icmp", "maybe"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse(["--wifi.probe.gateway.count", "0"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse(["--wifi.probe.gateway.interval", "-0.1"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse(["--wifi.probe.bpf.enabled", "maybe"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse(["--wifi.unknown"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse(["--unknown"], otlpURL: otlpURL))
    }
}
