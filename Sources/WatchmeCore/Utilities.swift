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

public func dateFromWallNanos(_ nanos: UInt64) -> Date {
    Date(timeIntervalSince1970: Double(nanos) / 1_000_000_000.0)
}

public func splitInlineValue(_ argument: String) -> (option: String, inlineValue: String?) {
    guard let equals = argument.firstIndex(of: "=") else {
        return (argument, nil)
    }
    return (String(argument[..<equals]), String(argument[argument.index(after: equals)...]))
}

public func rejectInlineValue(_ argument: String, _ inlineValue: String?) throws {
    guard inlineValue == nil else {
        throw WatchmeError.invalidArgument("\(argument) does not accept a value")
    }
}

public func requireOptionValue(
    arguments: [String],
    index: inout Int,
    argument: String,
    inlineValue: String?
) throws -> String {
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

public func validatedOTLPURL(_ value: String, argument: String) throws -> URL {
    guard
        let url = URL(string: value),
        let scheme = url.scheme?.lowercased(),
        ["http", "https"].contains(scheme),
        url.host != nil,
        url.query == nil,
        url.fragment == nil
    else {
        throw WatchmeError.invalidArgument("Invalid URL for \(argument): \(value)")
    }
    return url
}

public func formatUsageRows(_ rows: [(String, String)], leftColumnWidth: Int = 34) -> String {
    rows
        .map { left, right in
            let separator = String(repeating: " ", count: max(leftColumnWidth - left.count, 2))
            return "  \(left)\(separator)\(right)"
        }
        .joined(separator: "\n")
}

public func otlpEndpointURL(baseURL: URL, path: String) -> URL {
    var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)!
    let basePath = components.percentEncodedPath
        .split(separator: "/", omittingEmptySubsequences: true)
        .map(String.init)
        .joined(separator: "/")
    let endpointPath = path
        .split(separator: "/", omittingEmptySubsequences: true)
        .map(String.init)
        .joined(separator: "/")
    let joined = [basePath, endpointPath].filter { !$0.isEmpty }.joined(separator: "/")
    components.percentEncodedPath = joined.isEmpty ? "" : "/\(joined)"
    return components.url!
}
