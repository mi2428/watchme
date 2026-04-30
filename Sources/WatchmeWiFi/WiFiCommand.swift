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
            return requestWiFiLocationAuthorization(timeout: config.probeInternetTimeout)
        }

        let telemetry = TelemetryClient(
            serviceName: "watchme-macos",
            tracesEndpoint: config.tracesURL,
            metricsEndpoint: config.metricsURL,
            metricsTimeout: config.probeInternetTimeout
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
    var tracesURL = URL(string: "http://127.0.0.1:4318/v1/traces")!
    var metricsURL = URL(string: "http://127.0.0.1:4318/v1/metrics")!
    var metricsInterval: TimeInterval = 5
    var activeInterval: TimeInterval = 60
    var triggerCooldown: TimeInterval = 2
    var probeInternetTimeout: TimeInterval = 5
    var probeInternetFamily: InternetProbeFamily = .dual
    var probeInternetDNS = true
    var probeInternetICMP = true
    var probeInternetHTTP = true
    var probeInternetTargets = ["example.com", "www.cloudflare.com"]
    var probeGatewayBurstCount = defaultGatewayProbeBurstCount
    var probeGatewayBurstInterval = defaultGatewayProbeBurstInterval
    var bpfEnabled = true
    var bpfSpanMaxAge: TimeInterval = 180
    var logLevel: LogLevel = .debug

    static func parse(_ arguments: [String]) throws -> WiFiConfig {
        var parser = WiFiConfigParser(arguments: arguments)
        return try parser.parse()
    }
}

private struct WiFiConfigParser {
    let arguments: [String]
    var config = WiFiConfig()
    var explicitInternetTargets: [String] = []
    var index = 0

    mutating func parse() throws -> WiFiConfig {
        consumeLeadingMode()
        if config.authorizeLocation {
            guard index == arguments.count else {
                throw WatchmeError.invalidArgument("authorize-only does not accept options")
            }
            return config
        }
        while index < arguments.count {
            try consumeOption()
            index += 1
        }
        if !explicitInternetTargets.isEmpty {
            _ = try uniqueInternetProbeTargets(explicitInternetTargets)
            config.probeInternetTargets = explicitInternetTargets
        }
        return config
    }

    private mutating func consumeLeadingMode() {
        guard index < arguments.count else {
            return
        }
        switch arguments[index] {
        case "authorize-only":
            config.authorizeLocation = true
            index += 1
        case "once":
            config.once = true
            index += 1
        case "help", "--help", "-h":
            printWiFiUsage()
            exit(0)
        default:
            break
        }
    }

    private mutating func consumeOption() throws {
        let (argument, inlineValue) = splitInlineValue(arguments[index])
        switch argument {
        case "--probe.internet.target":
            try explicitInternetTargets.append(requireValue(for: argument, inlineValue: inlineValue))
        case "--probe.internet.family":
            try applyInternetFamily(argument, inlineValue: inlineValue)
        case "--probe.gateway.count":
            try applyGatewayBurstCount(argument, inlineValue: inlineValue)
        case "--traces.url", "--metrics.url":
            try applyURL(argument, inlineValue: inlineValue)
        case "--metrics.interval", "--traces.interval", "--traces.cooldown", "--probe.internet.timeout", "--probe.gateway.interval",
             "--probe.bpf.span-max-age":
            try applyTimeInterval(argument, inlineValue: inlineValue)
        case "--probe.internet.dns", "--probe.internet.icmp", "--probe.internet.http", "--probe.bpf.enabled":
            try applyBoolOption(argument, inlineValue: inlineValue)
        case "--log.level":
            try applyLogLevel(argument, inlineValue: inlineValue)
        case "--help", "-h":
            try rejectInlineValue(argument, inlineValue)
            printWiFiUsage()
            exit(0)
        default:
            throw WatchmeError.invalidArgument("Unknown wifi argument: \(argument)")
        }
    }

    private func splitInlineValue(_ argument: String) -> (option: String, inlineValue: String?) {
        guard let equals = argument.firstIndex(of: "=") else {
            return (argument, nil)
        }
        return (String(argument[..<equals]), String(argument[argument.index(after: equals)...]))
    }

    private func rejectInlineValue(_ argument: String, _ inlineValue: String?) throws {
        guard inlineValue == nil else {
            throw WatchmeError.invalidArgument("\(argument) does not accept a value")
        }
    }

    private mutating func applyURL(_ argument: String, inlineValue: String?) throws {
        let value = try requireValue(for: argument, inlineValue: inlineValue)
        guard
            let url = URL(string: value),
            let scheme = url.scheme?.lowercased(),
            ["http", "https"].contains(scheme),
            url.host != nil
        else {
            throw WatchmeError.invalidArgument("Invalid URL for \(argument): \(value)")
        }
        switch argument {
        case "--traces.url":
            config.tracesURL = url
        case "--metrics.url":
            config.metricsURL = url
        default:
            break
        }
    }

    private mutating func applyTimeInterval(_ argument: String, inlineValue: String?) throws {
        let rawValue = try requireValue(for: argument, inlineValue: inlineValue)
        guard let value = TimeInterval(rawValue) else {
            throw WatchmeError.invalidArgument("Invalid value for \(argument): \(rawValue)")
        }
        switch argument {
        case "--metrics.interval":
            config.metricsInterval = try positive(value, name: "metrics interval")
        case "--traces.interval":
            config.activeInterval = try positive(value, name: "active interval")
        case "--traces.cooldown":
            config.triggerCooldown = try nonNegative(value, name: "trigger cooldown")
        case "--probe.internet.timeout":
            config.probeInternetTimeout = try positive(value, name: "internet probe timeout")
        case "--probe.gateway.interval":
            config.probeGatewayBurstInterval = try nonNegative(value, name: "gateway probe burst interval")
        case "--probe.bpf.span-max-age":
            config.bpfSpanMaxAge = try positive(value, name: "BPF span max age")
        default:
            break
        }
    }

    private mutating func applyGatewayBurstCount(_ argument: String, inlineValue: String?) throws {
        let rawValue = try requireValue(for: argument, inlineValue: inlineValue)
        guard let value = Int(rawValue), value > 0 else {
            throw WatchmeError.invalidArgument("Invalid gateway probe burst count: \(rawValue)")
        }
        config.probeGatewayBurstCount = value
    }

    private mutating func applyInternetFamily(_ argument: String, inlineValue: String?) throws {
        let value = try requireValue(for: argument, inlineValue: inlineValue).lowercased()
        guard let family = InternetProbeFamily(rawValue: value) else {
            throw WatchmeError.invalidArgument("Invalid internet probe family for \(argument): \(value)")
        }
        config.probeInternetFamily = family
    }

    private mutating func applyLogLevel(_ argument: String, inlineValue: String?) throws {
        let value = try requireValue(for: argument, inlineValue: inlineValue).lowercased()
        guard let level = LogLevel(rawValue: value) else {
            throw WatchmeError.invalidArgument("Invalid log level: \(value)")
        }
        config.logLevel = level
    }

    private mutating func applyBoolOption(_ argument: String, inlineValue: String?) throws {
        let rawValue = try requireValue(for: argument, inlineValue: inlineValue).lowercased()
        let value: Bool
        switch rawValue {
        case "1", "true", "yes", "on":
            value = true
        case "0", "false", "no", "off":
            value = false
        default:
            throw WatchmeError.invalidArgument("Invalid boolean for \(argument): \(rawValue)")
        }
        switch argument {
        case "--probe.internet.dns":
            config.probeInternetDNS = value
        case "--probe.internet.icmp":
            config.probeInternetICMP = value
        case "--probe.internet.http":
            config.probeInternetHTTP = value
        case "--probe.bpf.enabled":
            config.bpfEnabled = value
        default:
            break
        }
    }

    private mutating func requireValue(for argument: String, inlineValue: String?) throws -> String {
        if let inlineValue {
            guard !inlineValue.isEmpty else {
                throw WatchmeError.invalidArgument("Missing value for \(argument)")
            }
            return inlineValue
        }
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
    let commands = usageRows([
        ("watchme wifi [options]", "Run the long-running Wi-Fi observability agent."),
        ("watchme wifi once [options]", "Export one metrics snapshot and send one active trace."),
        ("watchme wifi authorize-only", "Request Location authorization for the app-bundled CLI."),
    ])
    let options = usageRows([
        ("--metrics.url URL", "OTLP/HTTP metrics endpoint. Default: http://127.0.0.1:4318/v1/metrics"),
        ("--metrics.interval seconds", "Wi-Fi metric collection interval. Default: 5"),
        ("--traces.url URL", "OTLP/HTTP trace endpoint. Default: http://127.0.0.1:4318/v1/traces"),
        ("--traces.interval seconds", "Active trace interval. Default: 60"),
        ("--traces.cooldown seconds", "Minimum seconds between event traces. Default: 2"),
        ("--probe.internet.target host", "Internet probe host. Can be repeated. Default: example.com, www.cloudflare.com"),
        ("--probe.internet.family value", "ipv4, ipv6, or dual. Default: dual"),
        ("--probe.internet.timeout sec", "Internet probe timeout. Default: 5"),
        ("--probe.internet.dns bool", "Enable internet DNS probe. Default: true"),
        ("--probe.internet.icmp bool", "Enable internet ICMP probe. Default: true"),
        ("--probe.internet.http bool", "Enable internet plain HTTP probe. Default: true"),
        ("--probe.gateway.count n", "Gateway ICMP probes per burst. Default: 4"),
        ("--probe.gateway.interval sec", "Delay between gateway burst probes. Default: 0.05"),
        ("--probe.bpf.enabled bool", "Enable passive BPF probe for DHCP/RS/RA/NDP. Default: true"),
        ("--probe.bpf.span-max-age sec", "Passive probe packet span lookback window. Default: 180"),
        ("--log.level level", "debug, info, warn, or error. Default: debug"),
    ])

    print(
        """
        WatchMe Wi-Fi - macOS observability agent

        Commands:
        \(commands)

        Options:
        \(options)

        NOTE:
          On first run, execute:

            $ watchme wifi authorize-only

          Press 'Allow' in the macOS Preferences popup.
        """
    )
}

private func usageRows(_ rows: [(String, String)], leftColumnWidth: Int = 34) -> String {
    rows
        .map { left, right in
            let separator = String(repeating: " ", count: max(leftColumnWidth - left.count, 2))
            return "  \(left)\(separator)\(right)"
        }
        .joined(separator: "\n")
}
