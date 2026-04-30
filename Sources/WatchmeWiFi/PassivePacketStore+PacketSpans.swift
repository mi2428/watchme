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
        includeConsumed: ((SpanEvent) -> Bool)? = nil
    ) -> [SpanEvent] {
        let now = wallClockNanos()
        let maxAgeNanos = UInt64(maxAge * 1_000_000_000)
        let ageCutoff = now > maxAgeNanos ? now - maxAgeNanos : 0
        let cutoff = max(ageCutoff, since ?? 0)
        lock.lock()
        let dhcpSnapshot = dhcp.filter { $0.wallNanos >= cutoff && (interfaceName == nil || $0.interfaceName == interfaceName) }
        let icmpv6Snapshot = icmpv6.filter { $0.wallNanos >= cutoff && (interfaceName == nil || $0.interfaceName == interfaceName) }
        let arpSnapshot = arp.filter {
            $0.wallNanos >= cutoff
                && (interfaceName == nil || $0.interfaceName == interfaceName)
                && (ipv4Gateway == nil || $0.targetProtocolAddress == ipv4Gateway || $0.senderProtocolAddress == ipv4Gateway)
        }
        var spans = buildDHCPSpans(dhcpSnapshot) + buildICMPv6Spans(icmpv6Snapshot) + buildARPSpans(arpSnapshot, ipv4Gateway: ipv4Gateway)
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
