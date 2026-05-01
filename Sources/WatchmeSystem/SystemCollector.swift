import Darwin
import Foundation
import WatchmeCore
import WatchmeTelemetry

enum SystemDefaults {
    static let metricsInterval: TimeInterval = 5
}

enum SystemCLI {
    enum Option {
        static let metricsInterval = CLIOption(
            "--system.metrics.interval",
            valueName: "seconds",
            help: "System metric collection interval. Default: \(formatCLIDefault(SystemDefaults.metricsInterval))"
        )
    }
}

public enum SystemCollectorFactory: WatchmeCollectorFactory {
    public static let name = "system"
    public static let summary = "Collect host CPU, memory, disk, network, filesystem, and uptime metrics."

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
            SystemCLI.Option.metricsInterval.usageRow,
        ]
    }
}

struct SystemConfig {
    var otlpURL = WatchmeDefaults.otlpURL
    var metricsInterval = SystemDefaults.metricsInterval

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
        case SystemCLI.Option.metricsInterval.name:
            try applyMetricsInterval(argument, inlineValue: inlineValue)
        default:
            throw WatchmeError.invalidArgument("Unknown system collector argument: \(argument)")
        }
    }

    private mutating func applyMetricsInterval(_ argument: String, inlineValue: String?) throws {
        let rawValue = try requireValue(argument, inlineValue: inlineValue)
        config.metricsInterval = try positiveTimeIntervalValue(rawValue, name: "system metrics interval")
    }

    private mutating func requireValue(_ argument: String, inlineValue: String?) throws -> String {
        try requireOptionValue(arguments: arguments, index: &index, argument: argument, inlineValue: inlineValue)
    }
}
