import Foundation

public enum WatchmeDefaults {
    public static let otlpURLString = "http://127.0.0.1:4318"
    public static let otlpURL = URL(string: otlpURLString)!
    public static let logLevel: LogLevel = .debug
    public static let metricsTimeout: TimeInterval = 5
}

public struct CLIOption: Equatable {
    public let name: String
    public let valueName: String?
    public let help: String

    public init(_ name: String, valueName: String? = nil, help: String) {
        self.name = name
        self.valueName = valueName
        self.help = help
    }

    public var usage: String {
        guard let valueName else {
            return name
        }
        return "\(name) \(valueName)"
    }

    public var usageRow: (String, String) {
        (usage, help)
    }
}

public enum WatchmeCLI {
    public enum Command {
        public static let executable = "watchme"
        public static let agent = "agent"
        public static let help = "help"
    }

    public enum Mode {
        public static let once = "once"
        public static let authorizeLocation = "authorize-location"
    }

    public enum Option {
        public static let help = "--help"
        public static let shortHelp = "-h"
        public static let otlpURL = CLIOption(
            "--otlp.url",
            valueName: "URL",
            help: "OTLP/HTTP collector endpoint. Default: \(WatchmeDefaults.otlpURLString)"
        )
        public static let logLevel = CLIOption(
            "--log.level",
            valueName: "level",
            help: "debug, info, warn, or error. Default: \(WatchmeDefaults.logLevel.rawValue)"
        )
    }

    public enum Collector {
        public static let prefix = "--collector."
        public static let wildcard = "--collector.*"

        public static func option(_ name: String) -> String {
            "\(prefix)\(name)"
        }
    }
}

public func formatCLIDefault(_ value: TimeInterval) -> String {
    let integerValue = Int(value)
    if value == TimeInterval(integerValue) {
        return "\(integerValue)"
    }
    return "\(value)"
}
