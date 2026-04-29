import Foundation

public func setTag(_ tags: inout [String: String], _ key: String, _ value: String?) {
    guard let value, !value.isEmpty else {
        return
    }
    tags[key] = value
}

public func clipped(_ value: String, limit: Int) -> String {
    if value.count <= limit {
        return value
    }
    return String(value.prefix(limit)) + "..."
}

public func logfmt(_ value: String) -> String {
    if value.isEmpty {
        return "\"\""
    }
    let needsQuoting = value.contains { character in
        character.isWhitespace || character == "\"" || character == "="
    }
    guard needsQuoting else {
        return value
    }
    return "\""
        + value
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\n", with: "\\n") + "\""
}

public func randomHex(bytes: Int) -> String {
    (0 ..< bytes).map { _ in String(format: "%02x", UInt8.random(in: 0 ... 255)) }.joined()
}

public func wallClockNanos() -> UInt64 {
    UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
}

public func dateToWallNanos(_ date: Date) -> UInt64 {
    UInt64(date.timeIntervalSince1970 * 1_000_000_000)
}

public func dateFromWallNanos(_ nanos: UInt64) -> Date {
    Date(timeIntervalSince1970: Double(nanos) / 1_000_000_000.0)
}
