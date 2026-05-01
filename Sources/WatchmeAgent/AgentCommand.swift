import Darwin
import Foundation
import WatchmeCore
import WatchmeSelf
import WatchmeSystem
import WatchmeWiFi

public struct AgentCommand: WatchmeCommand {
    public static let name = WatchmeCLI.Command.agent
    public static let summary = "Run one or more observability collectors."

    private static let collectorFactories: [any WatchmeCollectorFactory.Type] = [
        SystemCollectorFactory.self,
        SelfCollectorFactory.self,
        WiFiCollectorFactory.self,
    ]

    private let config: AgentConfig
    private let collectors: [any WatchmeCollector]

    public init(arguments: [String]) throws {
        config = try AgentConfig.parse(arguments, factories: Self.collectorFactories)
        collectors = try config.makeCollectors(factories: Self.collectorFactories)
    }

    public func run() -> Int32 {
        logger.minimumLevel = config.logLevel

        if config.mode == .authorizeLocation {
            return WiFiCollectorFactory.authorizeLocation(timeout: config.wifiAuthorizationTimeout)
        }

        if config.mode == .once {
            var status: Int32 = 0
            for collector in collectors {
                let collectorStatus = collector.runOnce()
                if status == 0, collectorStatus != 0 {
                    status = collectorStatus
                }
            }
            return status
        }

        let enabledCollectorNames = collectors.reduce(into: [String]()) { names, collector in
            names.append(collector.name)
        }

        logEvent(
            .info,
            "agent_started",
            fields: [
                "collectors": enabledCollectorNames.joined(separator: ","),
                "otlp_url": config.otlpURL.absoluteString,
            ]
        )

        for collector in collectors {
            collector.start()
        }

        let shutdown = DispatchSemaphore(value: 0)
        let stopLock = NSLock()
        var stopped = false
        let signalQueue = DispatchQueue(label: "watchme.agent.signals")
        let sigint = DispatchSource.makeSignalSource(signal: SIGINT, queue: signalQueue)
        let sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: signalQueue)
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)

        let stop: (String) -> Void = { signalName in
            stopLock.lock()
            if stopped {
                stopLock.unlock()
                return
            }
            stopped = true
            stopLock.unlock()
            logEvent(.info, "agent_stopping", fields: ["signal": signalName])
            for collector in collectors.reversed() {
                collector.stop()
            }
            shutdown.signal()
        }
        sigint.setEventHandler { stop("SIGINT") }
        sigterm.setEventHandler { stop("SIGTERM") }
        sigint.resume()
        sigterm.resume()

        shutdown.wait()
        return 0
    }

    public static func printUsage() {
        print(agentUsageText())
    }
}

enum AgentMode: Equatable {
    case longRunning
    case once
    case authorizeLocation
}

struct AgentConfig {
    var mode: AgentMode = .longRunning
    var otlpURL = WatchmeDefaults.otlpURL
    var logLevel = WatchmeDefaults.logLevel
    var enabledCollectors: [String] = []
    var collectorArguments: [String: [String]] = [:]
    var wifiAuthorizationTimeout: TimeInterval = 0

    static func parse(_ arguments: [String], factories: [any WatchmeCollectorFactory.Type]) throws -> AgentConfig {
        var parser = AgentConfigParser(arguments: arguments, factories: factories)
        return try parser.parse()
    }

    func makeCollectors(factories: [any WatchmeCollectorFactory.Type]) throws -> [any WatchmeCollector] {
        guard mode != .authorizeLocation else {
            return []
        }
        return try enabledCollectors.map { name in
            guard let factory = factories.first(where: { $0.name == name }) else {
                throw WatchmeError.invalidArgument("Unknown collector: \(name)")
            }
            return try factory.makeCollector(arguments: collectorArguments[name] ?? [], context: CollectorBuildContext(otlpURL: otlpURL))
        }
    }
}

private struct AgentConfigParser {
    let arguments: [String]
    let factories: [any WatchmeCollectorFactory.Type]
    var config = AgentConfig()
    var index = 0
    var explicitlySelectedCollectors = false

    var collectorNames: Set<String> {
        var names = Set<String>()
        for factory in factories {
            names.insert(factory.name)
        }
        return names
    }

    var defaultCollectorNames: [String] {
        var names: [String] = []
        for factory in factories {
            names.append(factory.name)
        }
        return names
    }

    mutating func parse() throws -> AgentConfig {
        consumeLeadingMode()
        while index < arguments.count {
            try consumeOption()
            index += 1
        }
        try finalizeCollectors()
        try finalizeAuthorization()
        return config
    }

    private mutating func consumeLeadingMode() {
        guard index < arguments.count else {
            return
        }
        switch arguments[index] {
        case WatchmeCLI.Mode.once:
            config.mode = .once
            index += 1
        case WatchmeCLI.Mode.authorizeLocation:
            config.mode = .authorizeLocation
            index += 1
        case WatchmeCLI.Command.help, WatchmeCLI.Option.help, WatchmeCLI.Option.shortHelp:
            print(agentUsageText())
            exit(0)
        default:
            break
        }
    }

    private mutating func consumeOption() throws {
        let (argument, inlineValue) = splitInlineValue(arguments[index])
        switch argument {
        case WatchmeCLI.Option.otlpURL.name:
            try applyOTLPURL(argument, inlineValue: inlineValue)
        case WatchmeCLI.Option.logLevel.name:
            try applyLogLevel(argument, inlineValue: inlineValue)
        case WatchmeCLI.Option.help, WatchmeCLI.Option.shortHelp:
            try rejectInlineValue(argument, inlineValue)
            print(agentUsageText())
            exit(0)
        default:
            if argument.hasPrefix(WatchmeCLI.Collector.prefix) {
                try enableCollector(argument, inlineValue: inlineValue)
            } else if let collectorName = collectorName(forNamespacedOption: argument) {
                try appendCollectorOption(collectorName: collectorName)
            } else {
                throw WatchmeError.invalidArgument("Unknown `watchme agent` argument: \(argument)")
            }
        }
    }

    private mutating func applyOTLPURL(_ argument: String, inlineValue: String?) throws {
        config.otlpURL = try validatedOTLPURL(requireValue(argument, inlineValue: inlineValue), argument: argument)
    }

    private mutating func applyLogLevel(_ argument: String, inlineValue: String?) throws {
        let value = try requireValue(argument, inlineValue: inlineValue).lowercased()
        guard let level = LogLevel(rawValue: value) else {
            throw WatchmeError.invalidArgument("Invalid log level: \(value)")
        }
        config.logLevel = level
    }

    private mutating func enableCollector(_ argument: String, inlineValue: String?) throws {
        try rejectInlineValue(argument, inlineValue)
        let name = String(argument.dropFirst(WatchmeCLI.Collector.prefix.count))
        guard collectorNames.contains(name) else {
            throw WatchmeError.invalidArgument("Unknown collector: \(name)")
        }
        explicitlySelectedCollectors = true
        if !config.enabledCollectors.contains(name) {
            config.enabledCollectors.append(name)
        }
    }

    private func collectorName(forNamespacedOption argument: String) -> String? {
        guard argument.hasPrefix("--") else {
            return nil
        }
        let option = String(argument.dropFirst(2))
        guard let dot = option.firstIndex(of: ".") else {
            return nil
        }
        let name = String(option[..<dot])
        return collectorNames.contains(name) ? name : nil
    }

    private mutating func appendCollectorOption(collectorName: String) throws {
        var tokens = [arguments[index]]
        if splitInlineValue(arguments[index]).inlineValue == nil {
            guard index + 1 < arguments.count else {
                throw WatchmeError.invalidArgument("Missing value for \(arguments[index])")
            }
            index += 1
            tokens.append(arguments[index])
        }
        config.collectorArguments[collectorName, default: []].append(contentsOf: tokens)
    }

    private mutating func finalizeCollectors() throws {
        if config.mode == .authorizeLocation {
            return
        }
        if config.enabledCollectors.isEmpty {
            config.enabledCollectors = defaultCollectorNames
        }
        for collectorName in config.collectorArguments.keys where !config.enabledCollectors.contains(collectorName) {
            throw WatchmeError.invalidArgument("--\(collectorName).* options require \(WatchmeCLI.Collector.option(collectorName))")
        }
        if explicitlySelectedCollectors, config.enabledCollectors.isEmpty {
            throw WatchmeError.invalidArgument("At least one collector must be enabled")
        }
    }

    private mutating func finalizeAuthorization() throws {
        guard config.mode == .authorizeLocation else {
            return
        }
        if explicitlySelectedCollectors {
            throw WatchmeError
                .invalidArgument("\(WatchmeCLI.Mode.authorizeLocation) does not accept \(WatchmeCLI.Collector.wildcard) options")
        }
        let nonWiFiArguments = config.collectorArguments.keys.filter { $0 != WiFiCollectorFactory.name }
        guard nonWiFiArguments.isEmpty else {
            throw WatchmeError.invalidArgument("authorize-location only accepts Wi-Fi options")
        }
        config.wifiAuthorizationTimeout = try WiFiCollectorFactory.authorizationTimeout(
            arguments: config.collectorArguments[WiFiCollectorFactory.name] ?? []
        )
    }

    private mutating func requireValue(_ argument: String, inlineValue: String?) throws -> String {
        try requireOptionValue(arguments: arguments, index: &index, argument: argument, inlineValue: inlineValue)
    }
}

public func agentUsageText() -> String {
    let factories: [any WatchmeCollectorFactory.Type] = [
        SystemCollectorFactory.self,
        SelfCollectorFactory.self,
        WiFiCollectorFactory.self,
    ]
    let collectorRows = formatUsageRows(
        factories.map { (WatchmeCLI.Collector.option($0.name), $0.summary) },
        leftColumnWidth: 38
    )
    let commonOptions = formatUsageRows([
        WatchmeCLI.Option.otlpURL.usageRow,
        WatchmeCLI.Option.logLevel.usageRow,
    ], leftColumnWidth: 38)
    let systemOptions = formatUsageRows(SystemCollectorFactory.usageRows(), leftColumnWidth: 38)
    let selfOptions = formatUsageRows(SelfCollectorFactory.usageRows(), leftColumnWidth: 38)
    let wifiOptions = formatUsageRows(WiFiCollectorFactory.usageRows(), leftColumnWidth: 38)
    let defaultCollectors = factories
        .map { "`\(WatchmeCLI.Collector.option($0.name))`" }
        .joined(separator: ", ")

    return """
    \(WatchmeCLI.displayName) - macOS observability

    Usage:
      \(WatchmeCLI.Command.executable) \(AgentCommand.name) [options]
      \(WatchmeCLI.Command.executable) \(AgentCommand.name) \(WatchmeCLI.Mode.once) [options]
      \(WatchmeCLI.Command.executable) \(AgentCommand.name) \(WatchmeCLI.Mode.authorizeLocation) [options]
      \(WatchmeCLI.Command.executable) \(AgentCommand.name) \(WatchmeCLI.Option.help)

    Collectors:
    \(collectorRows)

    Common Options:
    \(commonOptions)

    System Options:
    \(systemOptions)

    Self Options:
    \(selfOptions)

    Wi-Fi Options:
    \(wifiOptions)

    Defaults:
      `\(WatchmeCLI.Command.executable) \(AgentCommand.name)` starts \(WatchmeCLI.displayName) with all collectors: \(defaultCollectors).
      Pass one or more `\(WatchmeCLI.Collector.wildcard)` options to run only those collectors.
    """
}
