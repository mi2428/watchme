import Foundation
import WatchmeCore

enum InternetProbeFamily: String, CaseIterable {
    case ipv4
    case ipv6
    case dual

    var metricValue: String {
        rawValue
    }

    var concreteFamilies: [InternetAddressFamily] {
        switch self {
        case .ipv4:
            [.ipv4]
        case .ipv6:
            [.ipv6]
        case .dual:
            [.ipv4, .ipv6]
        }
    }
}

enum InternetAddressFamily: String, CaseIterable {
    case ipv4
    case ipv6

    var metricValue: String {
        rawValue
    }

    var dnsRecordType: DNSRecordType {
        switch self {
        case .ipv4:
            .a
        case .ipv6:
            .aaaa
        }
    }

    var addressByteCount: Int {
        switch self {
        case .ipv4:
            4
        case .ipv6:
            16
        }
    }
}

enum DNSRecordType: UInt16 {
    case a = 1
    case aaaa = 28

    var name: String {
        switch self {
        case .a:
            "A"
        case .aaaa:
            "AAAA"
        }
    }

    var family: InternetAddressFamily {
        switch self {
        case .a:
            .ipv4
        case .aaaa:
            .ipv6
        }
    }
}

struct InternetProbeTarget: Hashable {
    let host: String

    init(_ value: String) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw WatchmeError.invalidArgument("Internet probe target must not be empty")
        }
        if let url = URL(string: trimmed), url.scheme != nil {
            guard let host = url.host, !host.isEmpty else {
                throw WatchmeError.invalidArgument("Invalid internet probe target: \(value)")
            }
            self.host = normalizedProbeHost(host)
            return
        }
        host = normalizedProbeHost(trimmed)
    }
}

func normalizedProbeHost(_ value: String) -> String {
    value
        .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        .lowercased()
}

func uniqueInternetProbeTargets(_ values: [String]) throws -> [InternetProbeTarget] {
    var seen = Set<String>()
    var targets: [InternetProbeTarget] = []
    for value in values {
        let target = try InternetProbeTarget(value)
        guard !seen.contains(target.host) else {
            continue
        }
        seen.insert(target.host)
        targets.append(target)
    }
    return targets
}
