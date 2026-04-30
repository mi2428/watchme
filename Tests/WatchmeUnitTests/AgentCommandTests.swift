@testable import WatchmeAgent
@testable import WatchmeCore
@testable import WatchmeSystem
@testable import WatchmeWiFi
import XCTest

final class AgentCommandTests: XCTestCase {
    private let factories: [any WatchmeCollectorFactory.Type] = [
        SystemCollectorFactory.self,
        WiFiCollectorFactory.self,
    ]

    func testDefaultAgentEnablesOnlySystemCollector() throws {
        let config = try AgentConfig.parse([], factories: factories)

        XCTAssertEqual(config.mode, .longRunning)
        XCTAssertEqual(config.enabledCollectors, ["system"])
        XCTAssertEqual(config.otlpURL.absoluteString, "http://127.0.0.1:4318")
        XCTAssertEqual(config.logLevel, .debug)

        let collectors = try config.makeCollectors(factories: factories)
        XCTAssertEqual(collectorNames(collectors), ["system"])
    }

    func testParseOnceWithBothCollectorsAndNamespacedOptions() throws {
        let config = try AgentConfig.parse([
            "once",
            "--collector.system",
            "--collector.wifi",
            "--otlp.url", "http://collector.example:4318/base",
            "--log.level", "info",
            "--system.metrics.interval", "2.5",
            "--wifi.metrics.interval=3",
            "--wifi.probe.internet.icmp", "false",
        ], factories: factories)

        XCTAssertEqual(config.mode, .once)
        XCTAssertEqual(config.enabledCollectors, ["system", "wifi"])
        XCTAssertEqual(config.otlpURL.absoluteString, "http://collector.example:4318/base")
        XCTAssertEqual(config.logLevel, .info)
        XCTAssertEqual(config.collectorArguments["system"], ["--system.metrics.interval", "2.5"])
        XCTAssertEqual(config.collectorArguments["wifi"], ["--wifi.metrics.interval=3", "--wifi.probe.internet.icmp", "false"])

        let collectors = try config.makeCollectors(factories: factories)
        XCTAssertEqual(collectorNames(collectors), ["system", "wifi"])
    }

    func testParseAuthorizationMode() throws {
        let config = try AgentConfig.parse([
            "authorize-location",
            "--wifi.probe.internet.timeout", "9",
        ], factories: factories)

        XCTAssertEqual(config.mode, .authorizeLocation)
        XCTAssertEqual(config.wifiAuthorizationTimeout, 9)
        XCTAssertTrue(try config.makeCollectors(factories: factories).isEmpty)
    }

    func testUsageShowsCollectorBasedCLI() {
        let usage = agentUsageText()

        XCTAssertTrue(usage.contains("watchme agent [options]"))
        XCTAssertTrue(usage.contains("watchme agent once [options]"))
        XCTAssertTrue(usage.contains("watchme agent authorize-location [options]"))
        XCTAssertTrue(usage.contains("--collector.system"))
        XCTAssertTrue(usage.contains("--collector.wifi"))
        XCTAssertTrue(usage.contains("--otlp.url URL"))
        XCTAssertTrue(usage.contains("--system.metrics.interval seconds"))
        XCTAssertTrue(usage.contains("--wifi.probe.internet.target host"))
    }

    func testRejectsUnknownAndAmbiguousOptions() {
        let registry = CommandRegistry(commands: [AgentCommand.self])

        XCTAssertThrowsError(try registry.parse(["watchme", "unknown"]))
        XCTAssertThrowsError(try AgentConfig.parse(["--collector.unknown"], factories: factories))
        XCTAssertThrowsError(try AgentConfig.parse(["--unknown"], factories: factories))
        XCTAssertThrowsError(try AgentConfig.parse(["--wifi.metrics.interval", "1"], factories: factories))
        XCTAssertThrowsError(try AgentConfig.parse(["--collector.wifi=false"], factories: factories))
        XCTAssertThrowsError(try AgentConfig.parse(["authorize-location", "--collector.wifi"], factories: factories))
        XCTAssertThrowsError(try AgentConfig.parse(["authorize-location", "--system.metrics.interval", "1"], factories: factories))
    }

    private func collectorNames(_ collectors: [any WatchmeCollector]) -> [String] {
        var names: [String] = []
        for collector in collectors {
            names.append(collector.name)
        }
        return names
    }
}
