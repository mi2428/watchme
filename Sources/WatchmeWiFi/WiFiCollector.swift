import Darwin
import Foundation
import WatchmeCore
import WatchmeTelemetry

private let defaultWiFiOTLPURL = URL(string: "http://127.0.0.1:4318")!

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
        var timeout: TimeInterval = 5
        var index = 0
        while index < arguments.count {
            let (argument, inlineValue) = splitInlineValue(arguments[index])
            guard argument == "--wifi.probe.internet.timeout" else {
                throw WatchmeError.invalidArgument("authorize-location only accepts --wifi.probe.internet.timeout")
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
        [
            ("--wifi.metrics.interval seconds", "Wi-Fi metric collection interval. Default: 5"),
            ("--wifi.traces.interval seconds", "Active trace interval. Default: 60"),
            ("--wifi.traces.cooldown seconds", "Minimum seconds between event traces. Default: 2"),
            ("--wifi.probe.bpf.enabled bool", "Enable passive BPF probe for DHCP/RS/RA/NDP. Default: true"),
            ("--wifi.probe.bpf.span-max-age sec", "Passive probe packet span lookback window. Default: 180"),
            ("--wifi.probe.gateway.count n", "Gateway ICMP probes per burst. Default: 4"),
            ("--wifi.probe.gateway.interval sec", "Delay between gateway burst probes. Default: 0.05"),
            ("--wifi.probe.internet.target host", "Internet probe host. Can be repeated. Default: example.com, www.cloudflare.com"),
            ("--wifi.probe.internet.family value", "ipv4, ipv6, or dual. Default: dual"),
            ("--wifi.probe.internet.timeout sec", "Internet probe timeout. Default: 5"),
            ("--wifi.probe.internet.dns bool", "Enable internet DNS probe. Default: true"),
            ("--wifi.probe.internet.icmp bool", "Enable internet ICMP probe. Default: true"),
            ("--wifi.probe.internet.http bool", "Enable internet plain HTTP probe. Default: true"),
        ]
    }
}

struct WiFiConfig {
    var otlpURL: URL = defaultWiFiOTLPURL
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
        case "--wifi.probe.internet.target":
            try explicitInternetTargets.append(requireValue(argument, inlineValue: inlineValue))
        case "--wifi.probe.internet.family":
            try applyInternetFamily(argument, inlineValue: inlineValue)
        case "--wifi.probe.gateway.count":
            try applyGatewayBurstCount(argument, inlineValue: inlineValue)
        case "--wifi.metrics.interval", "--wifi.traces.interval", "--wifi.traces.cooldown", "--wifi.probe.internet.timeout",
             "--wifi.probe.gateway.interval", "--wifi.probe.bpf.span-max-age":
            try applyTimeInterval(argument, inlineValue: inlineValue)
        case "--wifi.probe.internet.dns", "--wifi.probe.internet.icmp", "--wifi.probe.internet.http", "--wifi.probe.bpf.enabled":
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
        case "--wifi.metrics.interval":
            config.metricsInterval = try positive(value, name: "Wi-Fi metrics interval")
        case "--wifi.traces.interval":
            config.activeInterval = try positive(value, name: "Wi-Fi active interval")
        case "--wifi.traces.cooldown":
            config.triggerCooldown = try nonNegative(value, name: "Wi-Fi trigger cooldown")
        case "--wifi.probe.internet.timeout":
            config.probeInternetTimeout = try positive(value, name: "internet probe timeout")
        case "--wifi.probe.gateway.interval":
            config.probeGatewayBurstInterval = try nonNegative(value, name: "gateway probe burst interval")
        case "--wifi.probe.bpf.span-max-age":
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
        case "--wifi.probe.internet.dns":
            config.probeInternetDNS = value
        case "--wifi.probe.internet.icmp":
            config.probeInternetICMP = value
        case "--wifi.probe.internet.http":
            config.probeInternetHTTP = value
        case "--wifi.probe.bpf.enabled":
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
