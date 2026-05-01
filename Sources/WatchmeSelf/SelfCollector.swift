import Foundation
import WatchmeCore
import WatchmeTelemetry

enum SelfDefaults {
    static let metricsInterval: TimeInterval = 5
}

enum SelfCLI {
    enum Option {
        static let metricsInterval = CLIOption(
            "--self.metrics.interval",
            valueName: "seconds",
            help: "Self metric collection interval. Default: \(formatCLIDefault(SelfDefaults.metricsInterval))"
        )
    }
}

public enum SelfCollectorFactory: WatchmeCollectorFactory {
    public static let name = "self"
    public static let summary = "Collect WatchMe process self metrics."

    public static func makeCollector(arguments: [String], context: CollectorBuildContext) throws -> any WatchmeCollector {
        let config = try SelfConfig.parse(arguments, otlpURL: context.otlpURL)
        let telemetry = TelemetryClient(
            serviceName: "watchme-macos",
            tracesEndpoint: config.traceEndpointURL,
            metricsEndpoint: config.metricEndpointURL
        )
        return SelfAgent(config: config, telemetry: telemetry)
    }

    public static func usageRows() -> [(String, String)] {
        [
            SelfCLI.Option.metricsInterval.usageRow,
        ]
    }
}

struct SelfConfig {
    var otlpURL = WatchmeDefaults.otlpURL
    var metricsInterval = SelfDefaults.metricsInterval

    static func parse(_ arguments: [String], otlpURL: URL) throws -> SelfConfig {
        var parser = SelfConfigParser(arguments: arguments, config: SelfConfig(otlpURL: otlpURL))
        return try parser.parse()
    }

    var traceEndpointURL: URL {
        otlpEndpointURL(baseURL: otlpURL, path: "v1/traces")
    }

    var metricEndpointURL: URL {
        otlpEndpointURL(baseURL: otlpURL, path: "v1/metrics")
    }
}

private struct SelfConfigParser {
    let arguments: [String]
    var config: SelfConfig
    var index = 0

    mutating func parse() throws -> SelfConfig {
        while index < arguments.count {
            try consumeOption()
            index += 1
        }
        return config
    }

    private mutating func consumeOption() throws {
        let (argument, inlineValue) = splitInlineValue(arguments[index])
        switch argument {
        case SelfCLI.Option.metricsInterval.name:
            try applyMetricsInterval(argument, inlineValue: inlineValue)
        default:
            throw WatchmeError.invalidArgument("Unknown self collector argument: \(argument)")
        }
    }

    private mutating func applyMetricsInterval(_ argument: String, inlineValue: String?) throws {
        let rawValue = try requireValue(argument, inlineValue: inlineValue)
        config.metricsInterval = try positiveTimeIntervalValue(rawValue, name: "self metrics interval")
    }

    private mutating func requireValue(_ argument: String, inlineValue: String?) throws -> String {
        try requireOptionValue(arguments: arguments, index: &index, argument: argument, inlineValue: inlineValue)
    }
}
