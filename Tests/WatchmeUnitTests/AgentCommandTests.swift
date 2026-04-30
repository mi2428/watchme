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
        XCTAssertEqual(config.enabledCollectors, [SystemCollectorFactory.name])
        XCTAssertEqual(config.otlpURL.absoluteString, WatchmeDefaults.otlpURLString)
        XCTAssertEqual(config.logLevel, WatchmeDefaults.logLevel)

        let collectors = try config.makeCollectors(factories: factories)
        XCTAssertEqual(collectorNames(collectors), [SystemCollectorFactory.name])
    }

    func testParseOnceWithBothCollectorsAndNamespacedOptions() throws {
        let config = try AgentConfig.parse([
            WatchmeCLI.Mode.once,
            WatchmeCLI.Collector.option(SystemCollectorFactory.name),
            WatchmeCLI.Collector.option(WiFiCollectorFactory.name),
            WatchmeCLI.Option.otlpURL.name, "http://collector.example:4318/base",
            WatchmeCLI.Option.logLevel.name, "info",
            SystemCLI.Option.metricsInterval.name, "2.5",
            "\(WiFiCLI.Option.metricsInterval.name)=3",
            WiFiCLI.Option.internetICMP.name, "false",
        ], factories: factories)

        XCTAssertEqual(config.mode, .once)
        XCTAssertEqual(config.enabledCollectors, [SystemCollectorFactory.name, WiFiCollectorFactory.name])
        XCTAssertEqual(config.otlpURL.absoluteString, "http://collector.example:4318/base")
        XCTAssertEqual(config.logLevel, .info)
        XCTAssertEqual(config.collectorArguments[SystemCollectorFactory.name], [SystemCLI.Option.metricsInterval.name, "2.5"])
        XCTAssertEqual(
            config.collectorArguments[WiFiCollectorFactory.name],
            ["\(WiFiCLI.Option.metricsInterval.name)=3", WiFiCLI.Option.internetICMP.name, "false"]
        )

        let collectors = try config.makeCollectors(factories: factories)
        XCTAssertEqual(collectorNames(collectors), [SystemCollectorFactory.name, WiFiCollectorFactory.name])
    }

    func testParseAuthorizationMode() throws {
        let config = try AgentConfig.parse([
            WatchmeCLI.Mode.authorizeLocation,
            WiFiCLI.Option.internetTimeout.name, "9",
        ], factories: factories)

        XCTAssertEqual(config.mode, .authorizeLocation)
        XCTAssertEqual(config.wifiAuthorizationTimeout, 9)
        XCTAssertTrue(try config.makeCollectors(factories: factories).isEmpty)
    }

    func testUsageShowsCollectorBasedCLI() {
        let usage = agentUsageText()

        XCTAssertTrue(usage.contains(WatchmeCLI.displayName))
        XCTAssertTrue(usage.contains("\(WatchmeCLI.Command.executable) \(AgentCommand.name) [options]"))
        XCTAssertTrue(usage.contains("\(WatchmeCLI.Command.executable) \(AgentCommand.name) \(WatchmeCLI.Mode.once) [options]"))
        XCTAssertTrue(usage
            .contains("\(WatchmeCLI.Command.executable) \(AgentCommand.name) \(WatchmeCLI.Mode.authorizeLocation) [options]"))
        XCTAssertTrue(usage.contains(WatchmeCLI.Collector.option(SystemCollectorFactory.name)))
        XCTAssertTrue(usage.contains(WatchmeCLI.Collector.option(WiFiCollectorFactory.name)))
        XCTAssertTrue(usage.contains(WatchmeCLI.Option.otlpURL.usage))
        XCTAssertTrue(usage.contains(SystemCLI.Option.metricsInterval.usage))
        XCTAssertTrue(usage.contains(WiFiCLI.Option.internetTarget.usage))
        XCTAssertTrue(usage.contains("`\(WatchmeCLI.Command.executable) \(AgentCommand.name)` starts \(WatchmeCLI.displayName)"))
    }

    func testRejectsUnknownAndAmbiguousOptions() {
        let registry = CommandRegistry(commands: [AgentCommand.self])

        XCTAssertThrowsError(try registry.parse([WatchmeCLI.Command.executable, "unknown"]))
        XCTAssertThrowsError(try AgentConfig.parse(["\(WatchmeCLI.Collector.prefix)unknown"], factories: factories))
        XCTAssertThrowsError(try AgentConfig.parse(["--unknown"], factories: factories))
        XCTAssertThrowsError(try AgentConfig.parse([WiFiCLI.Option.metricsInterval.name, "1"], factories: factories))
        XCTAssertThrowsError(
            try AgentConfig.parse(["\(WatchmeCLI.Collector.option(WiFiCollectorFactory.name))=false"], factories: factories)
        )
        XCTAssertThrowsError(
            try AgentConfig.parse([
                WatchmeCLI.Mode.authorizeLocation,
                WatchmeCLI.Collector.option(WiFiCollectorFactory.name),
            ], factories: factories)
        )
        XCTAssertThrowsError(
            try AgentConfig.parse([
                WatchmeCLI.Mode.authorizeLocation,
                SystemCLI.Option.metricsInterval.name, "1",
            ], factories: factories)
        )
    }

    private func collectorNames(_ collectors: [any WatchmeCollector]) -> [String] {
        var names: [String] = []
        for collector in collectors {
            names.append(collector.name)
        }
        return names
    }
}
