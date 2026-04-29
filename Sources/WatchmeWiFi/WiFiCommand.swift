import Darwin
import Foundation
import WatchmeCore
import WatchmeTelemetry

public struct WiFiCommand: WatchmeSubcommand {
    public static let name = "wifi"
    public static let summary = "Collect Wi-Fi metrics and traces."

    private let config: WiFiConfig

    public init(arguments: [String]) throws {
        config = try WiFiConfig.parse(arguments)
    }

    public func run() -> Int32 {
        logger.minimumLevel = config.logLevel

        if config.authorizeLocation {
            return requestWiFiLocationAuthorization(timeout: config.timeout)
        }

        let telemetry = TelemetryClient(
            serviceName: "watchme-macos",
            tracesEndpoint: config.collectorURL,
            metricsSink: PushgatewayMetricSink(baseURL: config.pushgatewayURL, timeout: config.timeout),
            metricsTimeout: config.timeout
        )
        let agent = WiFiAgent(config: config, telemetry: telemetry)
        if config.once {
            return agent.runOnce()
        }
        agent.run()
        return 0
    }

    public static func printUsage() {
        printWiFiUsage()
    }
}

struct WiFiConfig {
    var once = false
    var authorizeLocation = false
    var collectorURL = URL(string: "http://127.0.0.1:4318/v1/traces")!
    var pushgatewayURL = URL(string: "http://127.0.0.1:9091")!
    var metricsInterval: TimeInterval = 5
    var activeInterval: TimeInterval = 60
    var triggerCooldown: TimeInterval = 2
    var timeout: TimeInterval = 5
    var bpfEnabled = true
    var bpfSpanMaxAge: TimeInterval = 180
    var targets = ["www.apple.com", "www.cloudflare.com"]
    var logLevel: LogLevel = .debug

    static func parse(_ arguments: [String]) throws -> WiFiConfig {
        var parser = WiFiConfigParser(arguments: arguments)
        return try parser.parse()
    }
}

private struct WiFiConfigParser {
    let arguments: [String]
    var config = WiFiConfig()
    var explicitTargets: [String] = []
    var index = 0

    mutating func parse() throws -> WiFiConfig {
        consumeLeadingMode()
        while index < arguments.count {
            try consumeOption()
            index += 1
        }
        if !explicitTargets.isEmpty {
            config.targets = explicitTargets
        }
        return config
    }

    private mutating func consumeLeadingMode() {
        guard index < arguments.count else {
            return
        }
        switch arguments[index] {
        case "authorize-location", "location-authorize":
            config.authorizeLocation = true
            index += 1
        case "once":
            config.once = true
            index += 1
        case "agent", "run", "watch":
            index += 1
        case "help", "--help", "-h":
            printWiFiUsage()
            exit(0)
        default:
            break
        }
    }

    private mutating func consumeOption() throws {
        let argument = arguments[index]
        switch argument {
        case "--once":
            config.once = true
        case "--no-bpf":
            config.bpfEnabled = false
        case "--target", "-t":
            try explicitTargets.append(requireValue(for: argument))
        case "--collector", "--pushgateway":
            try applyURL(argument)
        case "--metrics-interval", "--active-interval", "--trigger-cooldown", "--timeout", "--bpf-span-max-age":
            try applyTimeInterval(argument)
        case "--log-level":
            try applyLogLevel(argument)
        case "--help", "-h":
            printWiFiUsage()
            exit(0)
        default:
            throw WatchmeError.invalidArgument("Unknown wifi argument: \(argument)")
        }
    }

    private mutating func applyURL(_ argument: String) throws {
        let value = try requireValue(for: argument)
        guard let url = URL(string: value) else {
            throw WatchmeError.invalidArgument("Invalid URL for \(argument): \(value)")
        }
        switch argument {
        case "--collector":
            config.collectorURL = url
        case "--pushgateway":
            config.pushgatewayURL = url
        default:
            break
        }
    }

    private mutating func applyTimeInterval(_ argument: String) throws {
        let rawValue = try requireValue(for: argument)
        guard let value = TimeInterval(rawValue) else {
            throw WatchmeError.invalidArgument("Invalid value for \(argument): \(rawValue)")
        }
        switch argument {
        case "--metrics-interval":
            config.metricsInterval = try positive(value, name: "metrics interval")
        case "--active-interval":
            config.activeInterval = try positive(value, name: "active interval")
        case "--trigger-cooldown":
            config.triggerCooldown = try nonNegative(value, name: "trigger cooldown")
        case "--timeout":
            config.timeout = try positive(value, name: "timeout")
        case "--bpf-span-max-age":
            config.bpfSpanMaxAge = try positive(value, name: "BPF span max age")
        default:
            break
        }
    }

    private mutating func applyLogLevel(_ argument: String) throws {
        let value = try requireValue(for: argument).lowercased()
        guard let level = LogLevel(rawValue: value) else {
            throw WatchmeError.invalidArgument("Invalid log level: \(value)")
        }
        config.logLevel = level
    }

    private mutating func requireValue(for argument: String) throws -> String {
        guard index + 1 < arguments.count else {
            throw WatchmeError.invalidArgument("Missing value for \(argument)")
        }
        index += 1
        return arguments[index]
    }

    private func positive(_ value: TimeInterval, name: String) throws -> TimeInterval {
        guard value > 0 else {
            throw WatchmeError.invalidArgument("Invalid \(name)")
        }
        return value
    }

    private func nonNegative(_ value: TimeInterval, name: String) throws -> TimeInterval {
        guard value >= 0 else {
            throw WatchmeError.invalidArgument("Invalid \(name)")
        }
        return value
    }
}

func printWiFiUsage() {
    print(
        """
        WatchMe Wi-Fi - macOS Wi-Fi O11y agent

        Usage:
          watchme wifi [agent] [options]
          watchme wifi once [options]
          watchme wifi authorize-location [options]
          watchme wifi --once [options]

        Options:
          --collector URL             OTLP/HTTP trace endpoint. Default: http://127.0.0.1:4318/v1/traces
          --pushgateway URL           Pushgateway base URL. Default: http://127.0.0.1:9091
          --metrics-interval seconds  Wi-Fi metric collection interval. Default: 5
          --active-interval seconds   Active trace interval. Default: 60
          --trigger-cooldown seconds  Minimum seconds between event traces. Default: 2
          --timeout seconds           Active probe HTTP timeout. Default: 5
          --target, -t host-or-url    Active HTTP HEAD target. Can be repeated.
          --no-bpf                    Disable DHCP/RS/RA/NDP passive BPF watcher.
          --bpf-span-max-age seconds  Packet span lookback window. Default: 180
          --log-level level           debug, info, warn, or error. Default: debug
          --once                      Push one metric snapshot and send one active trace, then exit.

        Location authorization:
          Build an app bundle, then run:
            open .build/watchme-app/WatchMe.app --args wifi authorize-location
        """
    )
}
