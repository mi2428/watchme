import Darwin
import Foundation
import WatchmeCore
import WatchmeTelemetry

enum WiFiCLI {
    enum Option {
        static let metricsInterval = CLIOption(
            "--wifi.metrics.interval",
            valueName: "seconds",
            help: "Wi-Fi metric collection interval. Default: \(formatCLIDefault(WiFiDefaults.metricsInterval))"
        )
        static let traceInterval = CLIOption(
            "--wifi.traces.interval",
            valueName: "seconds",
            help: "Connectivity trace interval. Default: \(formatCLIDefault(WiFiDefaults.traceInterval))"
        )
        static let triggerCooldown = CLIOption(
            "--wifi.traces.cooldown",
            valueName: "seconds",
            help: "Minimum seconds between event traces. Default: \(formatCLIDefault(WiFiDefaults.triggerCooldown))"
        )
        static let bpfEnabled = CLIOption(
            "--wifi.probe.bpf.enabled",
            valueName: "bool",
            help: "Enable passive BPF probe for DHCP/RS/RA/NDP. Default: \(WiFiDefaults.bpfEnabled)"
        )
        static let bpfSpanMaxAge = CLIOption(
            "--wifi.probe.bpf.span-max-age",
            valueName: "sec",
            help: "Passive probe packet span lookback window. Default: \(formatCLIDefault(WiFiDefaults.bpfSpanMaxAge))"
        )
        static let gatewayCount = CLIOption(
            "--wifi.probe.gateway.count",
            valueName: "n",
            help: "Gateway ICMP probes per burst. Default: \(WiFiDefaults.gatewayProbeBurstCount)"
        )
        static let gatewayInterval = CLIOption(
            "--wifi.probe.gateway.interval",
            valueName: "sec",
            help: "Delay between gateway burst probes. Default: \(formatCLIDefault(WiFiDefaults.gatewayProbeBurstInterval))"
        )
        static let internetTarget = CLIOption(
            "--wifi.probe.internet.target",
            valueName: "host",
            help: "Internet probe host. Can be repeated. Default: \(WiFiDefaults.probeInternetTargets.joined(separator: ", "))"
        )
        static let internetFamily = CLIOption(
            "--wifi.probe.internet.family",
            valueName: "value",
            help: "ipv4, ipv6, or dual. Default: \(WiFiDefaults.probeInternetFamily.rawValue)"
        )
        static let internetTimeout = CLIOption(
            "--wifi.probe.internet.timeout",
            valueName: "sec",
            help: "Internet probe timeout. Default: \(formatCLIDefault(WiFiDefaults.probeInternetTimeout))"
        )
        static let internetDNS = CLIOption(
            "--wifi.probe.internet.dns",
            valueName: "bool",
            help: "Enable internet DNS probe. Default: \(WiFiDefaults.probeInternetDNS)"
        )
        static let internetICMP = CLIOption(
            "--wifi.probe.internet.icmp",
            valueName: "bool",
            help: "Enable internet ICMP probe. Default: \(WiFiDefaults.probeInternetICMP)"
        )
        static let internetTCP = CLIOption(
            "--wifi.probe.internet.tcp",
            valueName: "bool",
            help: "Enable internet TCP connect probe. Default: \(WiFiDefaults.probeInternetTCP)"
        )
        static let internetHTTP = CLIOption(
            "--wifi.probe.internet.http",
            valueName: "bool",
            help: "Enable internet plain HTTP probe. Default: \(WiFiDefaults.probeInternetHTTP)"
        )
    }

    static let usageOptions = [
        Option.metricsInterval,
        Option.traceInterval,
        Option.triggerCooldown,
        Option.bpfEnabled,
        Option.bpfSpanMaxAge,
        Option.gatewayCount,
        Option.gatewayInterval,
        Option.internetTarget,
        Option.internetFamily,
        Option.internetTimeout,
        Option.internetDNS,
        Option.internetICMP,
        Option.internetTCP,
        Option.internetHTTP,
    ]

    static let timeIntervalOptionNames = Set([
        Option.metricsInterval.name,
        Option.traceInterval.name,
        Option.triggerCooldown.name,
        Option.internetTimeout.name,
        Option.gatewayInterval.name,
        Option.bpfSpanMaxAge.name,
    ])

    static let boolOptionNames = Set([
        Option.internetDNS.name,
        Option.internetICMP.name,
        Option.internetTCP.name,
        Option.internetHTTP.name,
        Option.bpfEnabled.name,
    ])
}

public enum WiFiCollectorFactory: WatchmeCollectorFactory {
    public static let name = "wifi"
    public static let summary = "Collect Wi-Fi metrics and traces."

    public static func makeCollector(arguments: [String], context: CollectorBuildContext) throws -> any WatchmeCollector {
        let config = try WiFiConfig.parse(arguments, otlpURL: context.otlpURL)
        let telemetry = TelemetryClient(
            serviceName: "watchme-macos",
            tracesEndpoint: config.traceEndpointURL,
            metricsEndpoint: config.metricEndpointURL,
            metricsTimeout: config.probeInternetTimeout
        )
        return WiFiAgent(config: config, telemetry: telemetry)
    }

    public static func authorizeLocation(timeout: TimeInterval) -> Int32 {
        requestWiFiLocationAuthorization(timeout: timeout)
    }

    public static func authorizationTimeout(arguments: [String]) throws -> TimeInterval {
        var timeout = WiFiDefaults.probeInternetTimeout
        var index = 0
        while index < arguments.count {
            let (argument, inlineValue) = splitInlineValue(arguments[index])
            guard argument == WiFiCLI.Option.internetTimeout.name else {
                throw WatchmeError.invalidArgument("authorize-location only accepts \(WiFiCLI.Option.internetTimeout.name)")
            }
            let rawValue = try requireOptionValue(arguments: arguments, index: &index, argument: argument, inlineValue: inlineValue)
            guard let value = TimeInterval(rawValue), value > 0 else {
                throw WatchmeError.invalidArgument("Invalid internet probe timeout")
            }
            timeout = value
            index += 1
        }
        return timeout
    }

    public static func usageRows() -> [(String, String)] {
        WiFiCLI.usageOptions.map(\.usageRow)
    }
}

struct WiFiConfig {
    var otlpURL = WatchmeDefaults.otlpURL
    var metricsInterval = WiFiDefaults.metricsInterval
    var traceInterval = WiFiDefaults.traceInterval
    var triggerCooldown = WiFiDefaults.triggerCooldown
    var probeInternetTimeout = WiFiDefaults.probeInternetTimeout
    var probeInternetFamily = WiFiDefaults.probeInternetFamily
    var probeInternetDNS = WiFiDefaults.probeInternetDNS
    var probeInternetICMP = WiFiDefaults.probeInternetICMP
    var probeInternetTCP = WiFiDefaults.probeInternetTCP
    var probeInternetHTTP = WiFiDefaults.probeInternetHTTP
    var probeInternetTargets = WiFiDefaults.probeInternetTargets
    var probeGatewayBurstCount = WiFiDefaults.gatewayProbeBurstCount
    var probeGatewayBurstInterval = WiFiDefaults.gatewayProbeBurstInterval
    var bpfEnabled = WiFiDefaults.bpfEnabled
    var bpfSpanMaxAge = WiFiDefaults.bpfSpanMaxAge
    var associationTraceDelay = WiFiDefaults.associationTraceDelay
    var associationTraceReadinessTimeout = WiFiDefaults.associationTraceReadinessTimeout
    var connectivityReadinessPollInterval = WiFiDefaults.connectivityReadinessPollInterval
    var packetWindowTraceDelay = WiFiDefaults.packetWindowTraceDelay
    var packetWindowSuppressionAfterAssociation = WiFiDefaults.packetWindowSuppressionAfterAssociation

    static func parse(_ arguments: [String], otlpURL: URL) throws -> WiFiConfig {
        var parser = WiFiConfigParser(arguments: arguments, config: WiFiConfig(otlpURL: otlpURL))
        return try parser.parse()
    }

    var traceEndpointURL: URL {
        otlpEndpointURL(baseURL: otlpURL, path: "v1/traces")
    }

    var metricEndpointURL: URL {
        otlpEndpointURL(baseURL: otlpURL, path: "v1/metrics")
    }
}

private struct WiFiConfigParser {
    let arguments: [String]
    var config: WiFiConfig
    var explicitInternetTargets: [String] = []
    var index = 0

    mutating func parse() throws -> WiFiConfig {
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

    private mutating func consumeOption() throws {
        let (argument, inlineValue) = splitInlineValue(arguments[index])
        switch argument {
        case WiFiCLI.Option.internetTarget.name:
            try explicitInternetTargets.append(requireValue(argument, inlineValue: inlineValue))
        case WiFiCLI.Option.internetFamily.name:
            try applyInternetFamily(argument, inlineValue: inlineValue)
        case WiFiCLI.Option.gatewayCount.name:
            try applyGatewayBurstCount(argument, inlineValue: inlineValue)
        case _ where WiFiCLI.timeIntervalOptionNames.contains(argument):
            try applyTimeInterval(argument, inlineValue: inlineValue)
        case _ where WiFiCLI.boolOptionNames.contains(argument):
            try applyBoolOption(argument, inlineValue: inlineValue)
        default:
            throw WatchmeError.invalidArgument("Unknown wifi collector argument: \(argument)")
        }
    }

    private mutating func applyTimeInterval(_ argument: String, inlineValue: String?) throws {
        let rawValue = try requireValue(argument, inlineValue: inlineValue)
        guard let value = TimeInterval(rawValue) else {
            throw WatchmeError.invalidArgument("Invalid value for \(argument): \(rawValue)")
        }
        switch argument {
        case WiFiCLI.Option.metricsInterval.name:
            config.metricsInterval = try positive(value, name: "Wi-Fi metrics interval")
        case WiFiCLI.Option.traceInterval.name:
            config.traceInterval = try positive(value, name: "Wi-Fi trace interval")
        case WiFiCLI.Option.triggerCooldown.name:
            config.triggerCooldown = try nonNegative(value, name: "Wi-Fi trigger cooldown")
        case WiFiCLI.Option.internetTimeout.name:
            config.probeInternetTimeout = try positive(value, name: "internet probe timeout")
        case WiFiCLI.Option.gatewayInterval.name:
            config.probeGatewayBurstInterval = try nonNegative(value, name: "gateway probe burst interval")
        case WiFiCLI.Option.bpfSpanMaxAge.name:
            config.bpfSpanMaxAge = try positive(value, name: "BPF span max age")
        default:
            break
        }
    }

    private mutating func applyGatewayBurstCount(_ argument: String, inlineValue: String?) throws {
        let rawValue = try requireValue(argument, inlineValue: inlineValue)
        guard let value = Int(rawValue), value > 0 else {
            throw WatchmeError.invalidArgument("Invalid gateway probe burst count: \(rawValue)")
        }
        config.probeGatewayBurstCount = value
    }

    private mutating func applyInternetFamily(_ argument: String, inlineValue: String?) throws {
        let value = try requireValue(argument, inlineValue: inlineValue).lowercased()
        guard let family = InternetProbeFamily(rawValue: value) else {
            throw WatchmeError.invalidArgument("Invalid internet probe family for \(argument): \(value)")
        }
        config.probeInternetFamily = family
    }

    private mutating func applyBoolOption(_ argument: String, inlineValue: String?) throws {
        let rawValue = try requireValue(argument, inlineValue: inlineValue).lowercased()
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
        case WiFiCLI.Option.internetDNS.name:
            config.probeInternetDNS = value
        case WiFiCLI.Option.internetICMP.name:
            config.probeInternetICMP = value
        case WiFiCLI.Option.internetTCP.name:
            config.probeInternetTCP = value
        case WiFiCLI.Option.internetHTTP.name:
            config.probeInternetHTTP = value
        case WiFiCLI.Option.bpfEnabled.name:
            config.bpfEnabled = value
        default:
            break
        }
    }

    private mutating func requireValue(_ argument: String, inlineValue: String?) throws -> String {
        try requireOptionValue(arguments: arguments, index: &index, argument: argument, inlineValue: inlineValue)
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
