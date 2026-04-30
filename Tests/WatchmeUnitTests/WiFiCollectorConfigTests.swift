@testable import WatchmeCore
@testable import WatchmeWiFi
import XCTest

final class WiFiCollectorConfigTests: XCTestCase {
    func testParseNamespacedTelemetryOptions() throws {
        let otlpURL = try XCTUnwrap(URL(string: "http://collector.example:4318/otlp"))
        let config = try WiFiConfig.parse([
            WiFiCLI.Option.metricsInterval.name, "2.5",
            "\(WiFiCLI.Option.traceInterval.name)=30",
            WiFiCLI.Option.triggerCooldown.name, "0",
            WiFiCLI.Option.internetTimeout.name, "3",
            WiFiCLI.Option.internetFamily.name, "ipv6",
            WiFiCLI.Option.internetDNS.name, "false",
            WiFiCLI.Option.internetICMP.name, "true",
            WiFiCLI.Option.internetTCP.name, "false",
            WiFiCLI.Option.internetHTTP.name, "false",
            WiFiCLI.Option.gatewayCount.name, "6",
            "\(WiFiCLI.Option.gatewayInterval.name)=0.1",
            "\(WiFiCLI.Option.bpfSpanMaxAge.name)=90",
            WiFiCLI.Option.bpfEnabled.name, "false",
            WiFiCLI.Option.internetTarget.name, "example.com",
            "\(WiFiCLI.Option.internetTarget.name)=www.apple.com",
        ], otlpURL: otlpURL)

        XCTAssertEqual(config.otlpURL.absoluteString, "http://collector.example:4318/otlp")
        XCTAssertEqual(config.traceEndpointURL.absoluteString, "http://collector.example:4318/otlp/v1/traces")
        XCTAssertEqual(config.metricEndpointURL.absoluteString, "http://collector.example:4318/otlp/v1/metrics")
        XCTAssertEqual(config.metricsInterval, 2.5)
        XCTAssertEqual(config.traceInterval, 30)
        XCTAssertEqual(config.triggerCooldown, 0)
        XCTAssertEqual(config.probeInternetTimeout, 3)
        XCTAssertEqual(config.probeInternetFamily, .ipv6)
        XCTAssertFalse(config.probeInternetDNS)
        XCTAssertTrue(config.probeInternetICMP)
        XCTAssertFalse(config.probeInternetTCP)
        XCTAssertFalse(config.probeInternetHTTP)
        XCTAssertEqual(config.probeGatewayBurstCount, 6)
        XCTAssertEqual(config.probeGatewayBurstInterval, 0.1)
        XCTAssertEqual(config.bpfSpanMaxAge, 90)
        XCTAssertFalse(config.bpfEnabled)
        XCTAssertEqual(config.probeInternetTargets, ["example.com", "www.apple.com"])
    }

    func testDefaultConfiguration() throws {
        let config = try WiFiConfig.parse([], otlpURL: WatchmeDefaults.otlpURL)

        XCTAssertEqual(config.probeInternetTargets, WiFiDefaults.probeInternetTargets)
        XCTAssertEqual(config.probeInternetFamily, WiFiDefaults.probeInternetFamily)
        XCTAssertEqual(config.metricsInterval, WiFiDefaults.metricsInterval)
        XCTAssertEqual(config.traceInterval, WiFiDefaults.traceInterval)
    }

    func testAuthorizationTimeoutParserOnlyAllowsTimeout() throws {
        XCTAssertEqual(try WiFiCollectorFactory.authorizationTimeout(arguments: []), WiFiDefaults.probeInternetTimeout)
        XCTAssertEqual(
            try WiFiCollectorFactory.authorizationTimeout(arguments: [WiFiCLI.Option.internetTimeout.name, "12"]),
            12
        )

        XCTAssertThrowsError(try WiFiCollectorFactory.authorizationTimeout(arguments: [WiFiCLI.Option.metricsInterval.name, "1"]))
        XCTAssertThrowsError(try WiFiCollectorFactory.authorizationTimeout(arguments: [WiFiCLI.Option.internetTimeout.name, "0"]))
    }

    func testRejectsUnknownAndInvalidArguments() throws {
        let otlpURL = WatchmeDefaults.otlpURL

        XCTAssertThrowsError(try WiFiConfig.parse([WiFiCLI.Option.metricsInterval.name, "0"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse([WiFiCLI.Option.internetTarget.name], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse([WiFiCLI.Option.internetFamily.name, "both"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse([WiFiCLI.Option.internetICMP.name, "maybe"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse([WiFiCLI.Option.gatewayCount.name, "0"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse([WiFiCLI.Option.gatewayInterval.name, "-0.1"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse([WiFiCLI.Option.bpfEnabled.name, "maybe"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse(["--\(WiFiCollectorFactory.name).unknown"], otlpURL: otlpURL))
        XCTAssertThrowsError(try WiFiConfig.parse(["--unknown"], otlpURL: otlpURL))
    }
}
