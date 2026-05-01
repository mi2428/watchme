import Foundation
import WatchmeCore
import WatchmeTelemetry

extension PassivePacketStore {
    func recentPacketSpans(
        interfaceName: String?,
        ipv4Gateway: String?,
        maxAge: TimeInterval,
        since: UInt64? = nil,
        consume: Bool,
        includeConsumed: ((SpanEvent) -> Bool)? = nil,
        localHardwareAddress: String? = nil,
        localIPv4Addresses: [String] = [],
        localIPv6Addresses: [String] = [],
        ipv6Gateway: String? = nil
    ) -> [SpanEvent] {
        let now = wallClockNanos()
        let maxAgeNanos = UInt64(maxAge * 1_000_000_000)
        let ageCutoff = now > maxAgeNanos ? now - maxAgeNanos : 0
        let cutoff = max(ageCutoff, since ?? 0)
        let localContext = PassivePacketSpanLocalContext(
            hardwareAddress: localHardwareAddress,
            ipv4Addresses: localIPv4Addresses,
            ipv6Addresses: localIPv6Addresses,
            ipv4Gateway: ipv4Gateway,
            ipv6Gateway: ipv6Gateway
        )
        lock.lock()
        let dhcpSnapshot = dhcp.filter { $0.wallNanos >= cutoff && (interfaceName == nil || $0.interfaceName == interfaceName) }
        let icmpv6Snapshot = icmpv6.filter {
            $0.wallNanos >= cutoff
                && (interfaceName == nil || $0.interfaceName == interfaceName)
                && localContext.includes($0)
        }
        let arpSnapshot = arp.filter {
            $0.wallNanos >= cutoff
                && (interfaceName == nil || $0.interfaceName == interfaceName)
                && localContext.includes($0)
        }
        var spans = buildDHCPSpans(dhcpSnapshot)
            + buildICMPv6Spans(icmpv6Snapshot)
            + buildARPSpans(arpSnapshot, ipv4Gateway: ipv4Gateway, allowedTargets: localContext.arpSpanTargets)
        spans.sort { $0.startWallNanos < $1.startWallNanos }
        if consume {
            // Event-triggered traces should not repeatedly attach the same packet-derived spans.
            spans = spans.filter { span in
                let key = spanKey(span)
                if emittedKeys.contains(key) {
                    return includeConsumed?(span) == true
                }
                emittedKeys.insert(key)
                return true
            }
        }
        lock.unlock()
        return spans
    }
}

struct PassivePacketSpanLocalContext {
    let hardwareAddress: String?
    let ipv4Addresses: Set<String>
    let ipv6Addresses: Set<String>
    let ipv4Gateway: String?
    let ipv6Gateway: String?

    init(
        hardwareAddress: String?,
        ipv4Addresses: [String],
        ipv6Addresses: [String],
        ipv4Gateway: String?,
        ipv6Gateway: String?
    ) {
        self.hardwareAddress = hardwareAddress?.lowercased()
        self.ipv4Addresses = Set(ipv4Addresses.filter { !$0.isEmpty })
        self.ipv6Addresses = Set(ipv6Addresses.map(normalizedIPv6Scope).filter { !$0.isEmpty })
        self.ipv4Gateway = ipv4Gateway
        self.ipv6Gateway = ipv6Gateway.map(normalizedIPv6Scope)
    }

    var arpSpanTargets: Set<String>? {
        var targets = ipv4Addresses
        if let ipv4Gateway, !ipv4Gateway.isEmpty {
            targets.insert(ipv4Gateway)
        }
        return targets.isEmpty ? nil : targets
    }

    func includes(_ observation: ARPObservation) -> Bool {
        guard hasIPv4LocalContext else {
            if let ipv4Gateway {
                return observation.targetProtocolAddress == ipv4Gateway || observation.senderProtocolAddress == ipv4Gateway
            }
            return true
        }
        if let hardwareAddress {
            let senderMAC = observation.senderHardwareAddress.lowercased()
            let targetMAC = observation.targetHardwareAddress.lowercased()
            if senderMAC == hardwareAddress || targetMAC == hardwareAddress {
                return true
            }
            return ipv4Addresses.contains(observation.senderProtocolAddress)
        }
        return ipv4Addresses.contains(observation.senderProtocolAddress)
            || ipv4Addresses.contains(observation.targetProtocolAddress)
    }

    func includes(_ observation: ICMPv6Observation) -> Bool {
        guard hasIPv6LocalContext else {
            return true
        }
        let sourceIP = normalizedIPv6Scope(observation.sourceIP)
        let destinationIP = normalizedIPv6Scope(observation.destinationIP)
        let targetAddress = observation.targetAddress.map(normalizedIPv6Scope)

        switch observation.type {
        case 133:
            return sourceIP == "::" || ipv6Addresses.contains(sourceIP) || ipv6Addresses.contains(destinationIP)
        case 134:
            guard let ipv6Gateway else {
                return true
            }
            return sourceIP == ipv6Gateway
        case 135, 136:
            if let targetAddress, ipv6Addresses.contains(targetAddress) {
                return true
            }
            guard let ipv6Gateway else {
                return false
            }
            return targetAddress == ipv6Gateway
        default:
            guard let ipv6Gateway else {
                return ipv6Addresses.contains(sourceIP) || ipv6Addresses.contains(destinationIP)
            }
            return sourceIP == ipv6Gateway || destinationIP == ipv6Gateway
        }
    }

    private var hasIPv4LocalContext: Bool {
        hardwareAddress != nil || !ipv4Addresses.isEmpty
    }

    private var hasIPv6LocalContext: Bool {
        !ipv6Addresses.isEmpty || ipv6Gateway != nil
    }
}
