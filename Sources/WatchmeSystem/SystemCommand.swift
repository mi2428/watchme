import Darwin
import Foundation
import WatchmeCore
import WatchmeTelemetry

public struct SystemCommand: WatchmeSubcommand {
    public static let name = "system"
    public static let summary = "Collect CPU, memory, and disk metrics."

    private let config: SystemConfig

    public init(arguments: [String]) throws {
        config = try SystemConfig.parse(arguments)
    }

    public func run() -> Int32 {
        logger.minimumLevel = config.logLevel

        let telemetry = TelemetryClient(
            serviceName: "watchme-macos",
            tracesEndpoint: config.traceEndpointURL,
            metricsEndpoint: config.metricEndpointURL
        )
        let agent = SystemAgent(config: config, telemetry: telemetry)
        if config.once {
            return agent.runOnce()
        }
        agent.run()
        return 0
    }

    public static func printUsage() {
        printSystemUsage()
    }
}

struct SystemConfig {
    var once = false
    var collectorURL = defaultSystemCollectorURL
    var metricsInterval: TimeInterval = 5
    var logLevel: LogLevel = .debug

    static func parse(_ arguments: [String]) throws -> SystemConfig {
        var parser = SystemConfigParser(arguments: arguments)
        return try parser.parse()
    }

    var traceEndpointURL: URL {
        collectorEndpointURL(baseURL: collectorURL, path: "v1/traces")
    }

    var metricEndpointURL: URL {
        collectorEndpointURL(baseURL: collectorURL, path: "v1/metrics")
    }
}

private let defaultSystemCollectorURL = URL(string: "http://127.0.0.1:4318")!

private struct SystemConfigParser {
    let arguments: [String]
    var config = SystemConfig()
    var index = 0

    mutating func parse() throws -> SystemConfig {
        consumeLeadingMode()
        while index < arguments.count {
            try consumeOption()
            index += 1
        }
        return config
    }

    private mutating func consumeLeadingMode() {
        guard index < arguments.count else {
            return
        }
        switch arguments[index] {
        case "once":
            config.once = true
            index += 1
        case "help", "--help", "-h":
            printSystemUsage()
            exit(0)
        default:
            break
        }
    }

    private mutating func consumeOption() throws {
        let (argument, inlineValue) = splitInlineValue(arguments[index])
        switch argument {
        case "--collector.url":
            try applyCollectorURL(argument, inlineValue: inlineValue)
        case "--metrics.interval":
            try applyMetricsInterval(argument, inlineValue: inlineValue)
        case "--log.level":
            try applyLogLevel(argument, inlineValue: inlineValue)
        case "--help", "-h":
            try rejectInlineValue(argument, inlineValue)
            printSystemUsage()
            exit(0)
        default:
            throw WatchmeError.invalidArgument("Unknown system argument: \(argument)")
        }
    }

    private mutating func applyCollectorURL(_ argument: String, inlineValue: String?) throws {
        config.collectorURL = try validatedCollectorURL(requireValue(argument, inlineValue: inlineValue), argument: argument)
    }

    private mutating func applyMetricsInterval(_ argument: String, inlineValue: String?) throws {
        let rawValue = try requireValue(argument, inlineValue: inlineValue)
        guard let value = TimeInterval(rawValue), value > 0 else {
            throw WatchmeError.invalidArgument("Invalid metrics interval")
        }
        config.metricsInterval = value
    }

    private mutating func applyLogLevel(_ argument: String, inlineValue: String?) throws {
        let value = try requireValue(argument, inlineValue: inlineValue).lowercased()
        guard let level = LogLevel(rawValue: value) else {
            throw WatchmeError.invalidArgument("Invalid log level: \(value)")
        }
        config.logLevel = level
    }

    private mutating func requireValue(_ argument: String, inlineValue: String?) throws -> String {
        try requireOptionValue(arguments: arguments, index: &index, argument: argument, inlineValue: inlineValue)
    }
}

func printSystemUsage() {
    print(systemUsageText())
}

func systemUsageText() -> String {
    let commands = formatUsageRows([
        ("watchme system [options]", "Run the long-running system metrics agent."),
        ("watchme system once [options]", "Export one CPU, memory, and disk metrics snapshot."),
    ])
    let options = formatUsageRows([
        ("--collector.url URL", "OTLP/HTTP collector endpoint. Default: http://127.0.0.1:4318"),
        ("--metrics.interval seconds", "System metric collection interval. Default: 5"),
        ("--log.level level", "debug, info, warn, or error. Default: debug"),
    ])

    return """
    WatchMe System - macOS host metrics agent

    Commands:
    \(commands)

    Options:
    \(options)
    """
}
