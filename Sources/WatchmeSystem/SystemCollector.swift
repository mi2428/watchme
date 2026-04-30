import Darwin
import Foundation
import WatchmeCore
import WatchmeTelemetry

private let defaultSystemOTLPURL = URL(string: "http://127.0.0.1:4318")!

public enum SystemCollectorFactory: WatchmeCollectorFactory {
    public static let name = "system"
    public static let summary = "Collect CPU, memory, and disk metrics."

    public static func makeCollector(arguments: [String], context: CollectorBuildContext) throws -> any WatchmeCollector {
        let config = try SystemConfig.parse(arguments, otlpURL: context.otlpURL)
        let telemetry = TelemetryClient(
            serviceName: "watchme-macos",
            tracesEndpoint: config.traceEndpointURL,
            metricsEndpoint: config.metricEndpointURL
        )
        return SystemAgent(config: config, telemetry: telemetry)
    }

    public static func usageRows() -> [(String, String)] {
        [
            ("--system.metrics.interval seconds", "System metric collection interval. Default: 5"),
        ]
    }
}

struct SystemConfig {
    var otlpURL: URL = defaultSystemOTLPURL
    var metricsInterval: TimeInterval = 5

    static func parse(_ arguments: [String], otlpURL: URL) throws -> SystemConfig {
        var parser = SystemConfigParser(arguments: arguments, config: SystemConfig(otlpURL: otlpURL))
        return try parser.parse()
    }

    var traceEndpointURL: URL {
        otlpEndpointURL(baseURL: otlpURL, path: "v1/traces")
    }

    var metricEndpointURL: URL {
        otlpEndpointURL(baseURL: otlpURL, path: "v1/metrics")
    }
}

private struct SystemConfigParser {
    let arguments: [String]
    var config: SystemConfig
    var index = 0

    mutating func parse() throws -> SystemConfig {
        while index < arguments.count {
            try consumeOption()
            index += 1
        }
        return config
    }

    private mutating func consumeOption() throws {
        let (argument, inlineValue) = splitInlineValue(arguments[index])
        switch argument {
        case "--system.metrics.interval":
            try applyMetricsInterval(argument, inlineValue: inlineValue)
        default:
            throw WatchmeError.invalidArgument("Unknown system collector argument: \(argument)")
        }
    }

    private mutating func applyMetricsInterval(_ argument: String, inlineValue: String?) throws {
        let rawValue = try requireValue(argument, inlineValue: inlineValue)
        guard let value = TimeInterval(rawValue), value > 0 else {
            throw WatchmeError.invalidArgument("Invalid system metrics interval")
        }
        config.metricsInterval = value
    }

    private mutating func requireValue(_ argument: String, inlineValue: String?) throws -> String {
        try requireOptionValue(arguments: arguments, index: &index, argument: argument, inlineValue: inlineValue)
    }
}
