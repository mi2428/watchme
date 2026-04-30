import Darwin
import Foundation

public enum LogLevel: String, Comparable {
    case debug
    case info
    case warn
    case error

    private var rank: Int {
        switch self {
        case .debug: 10
        case .info: 20
        case .warn: 30
        case .error: 40
        }
    }

    public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool {
        lhs.rank < rhs.rank
    }
}

public final class StructuredLogger {
    public var minimumLevel: LogLevel = .debug
    private let lock = NSLock()
    private let formatter = ISO8601DateFormatter()

    public init() {}

    public func log(_ level: LogLevel, _ message: String, fields: [String: String] = [:]) {
        guard level >= minimumLevel else {
            return
        }

        lock.lock()
        defer { lock.unlock() }

        var parts = [
            "time=\(logfmt(formatter.string(from: Date())))",
            "level=\(level.rawValue)",
            "msg=\(logfmtQuoted(logMessageText(message)))",
        ]
        for key in fields.keys.sorted() {
            if let value = fields[key] {
                parts.append("\(key)=\(logfmt(value))")
            }
        }
        print(parts.joined(separator: " "))
        fflush(stdout)
    }
}

public let logger = StructuredLogger()

public func logEvent(_ level: LogLevel, _ message: String, fields: [String: String] = [:]) {
    logger.log(level, message, fields: fields)
}
