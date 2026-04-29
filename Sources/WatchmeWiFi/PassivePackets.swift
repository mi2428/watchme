import Foundation
import WatchmeCore
import WatchmeTelemetry

struct DHCPObservation {
    let interfaceName: String
    let wallNanos: UInt64
    let xid: UInt32
    let messageType: UInt8?
    let yiaddr: String?
    let serverIdentifier: String?
    let leaseTimeSeconds: UInt32?
}

struct ICMPv6Observation {
    let interfaceName: String
    let wallNanos: UInt64
    let type: UInt8
    let code: UInt8
    let sourceIP: String
    let destinationIP: String
    let targetAddress: String?
    let routerLifetimeSeconds: UInt16?
    let sourceLinkLayerAddress: String?
    let targetLinkLayerAddress: String?
}

final class PassivePacketStore {
    private let lock = NSLock()
    private var dhcp: [DHCPObservation] = []
    private var icmpv6: [ICMPv6Observation] = []
    private var emittedKeys = Set<String>()

    func appendDHCP(_ observation: DHCPObservation) {
        lock.lock()
        dhcp.append(observation)
        pruneLocked()
        lock.unlock()
    }

    func appendICMPv6(_ observation: ICMPv6Observation) {
        lock.lock()
        icmpv6.append(observation)
        pruneLocked()
        lock.unlock()
    }

    func recentPacketSpans(interfaceName: String?, maxAge: TimeInterval, consume: Bool) -> [SpanEvent] {
        let cutoff = wallClockNanos() - UInt64(maxAge * 1_000_000_000)
        lock.lock()
        let dhcpSnapshot = dhcp.filter { $0.wallNanos >= cutoff && (interfaceName == nil || $0.interfaceName == interfaceName) }
        let icmpv6Snapshot = icmpv6.filter { $0.wallNanos >= cutoff && (interfaceName == nil || $0.interfaceName == interfaceName) }
        var spans = buildDHCPSpans(dhcpSnapshot) + buildICMPv6Spans(icmpv6Snapshot)
        spans.sort { $0.startWallNanos < $1.startWallNanos }
        if consume {
            // Event-triggered traces should not repeatedly attach the same
            // packet-derived spans. Active interval traces can still inspect the
            // full recent window by calling with consume=false.
            spans = spans.filter { span in
                let key = spanKey(span)
                if emittedKeys.contains(key) {
                    return false
                }
                emittedKeys.insert(key)
                return true
            }
        }
        lock.unlock()
        return spans
    }

    private func pruneLocked() {
        let cutoff = wallClockNanos() - UInt64(600 * 1_000_000_000)
        dhcp.removeAll { $0.wallNanos < cutoff }
        icmpv6.removeAll { $0.wallNanos < cutoff }
        if emittedKeys.count > 5000 {
            emittedKeys.removeAll()
        }
    }
}

func buildDHCPSpans(_ observations: [DHCPObservation]) -> [SpanEvent] {
    var spans: [SpanEvent] = []
    let grouped = Dictionary(grouping: observations, by: \.xid)

    for (xid, values) in grouped {
        // DHCP transaction IDs are the only reliable join key visible in a
        // passive capture. Grouping by xid avoids pairing retries from one lease
        // attempt with the ACK from another.
        let sorted = values.sorted { $0.wallNanos < $1.wallNanos }
        let discovers = sorted.filter { $0.messageType == 1 }
        let offers = sorted.filter { $0.messageType == 2 }
        let requests = sorted.filter { $0.messageType == 3 }
        let acks = sorted.filter { $0.messageType == 5 }

        // Repeated DISCOVER/REQUEST packets are useful spans by themselves:
        // they show link-layer recovery or DHCP server latency before success.
        for gap in retryGaps(discovers.map(\.wallNanos)) {
            spans.append(
                packetSpan(
                    "packet.dhcp.discover_retry_gap",
                    start: gap.start,
                    end: gap.end,
                    tags: dhcpTags(xid: xid, event: "discover_retry_gap", interfaceName: sorted.first?.interfaceName)
                )
            )
        }
        for gap in retryGaps(requests.map(\.wallNanos)) {
            spans.append(
                packetSpan(
                    "packet.dhcp.request_retry_gap",
                    start: gap.start,
                    end: gap.end,
                    tags: dhcpTags(xid: xid, event: "request_retry_gap", interfaceName: sorted.first?.interfaceName)
                )
            )
        }
        if let offer = offers.first, let discover = latest(beforeOrAt: offer.wallNanos, in: discovers) {
            var tags = dhcpTags(xid: xid, event: "discover_to_offer", interfaceName: offer.interfaceName)
            setTag(&tags, "dhcp.server_identifier", offer.serverIdentifier)
            spans.append(packetSpan("packet.dhcp.discover_to_offer", start: discover.wallNanos, end: offer.wallNanos, tags: tags))
        }
        if let ack = acks.first, let request = latest(beforeOrAt: ack.wallNanos, in: requests) {
            var tags = dhcpTags(xid: xid, event: "request_to_ack", interfaceName: ack.interfaceName)
            setTag(&tags, "dhcp.yiaddr", ack.yiaddr)
            setTag(&tags, "dhcp.server_identifier", ack.serverIdentifier)
            if let lease = ack.leaseTimeSeconds {
                tags["dhcp.lease_time_seconds"] = "\(lease)"
            }
            spans.append(packetSpan("packet.dhcp.request_to_ack", start: request.wallNanos, end: ack.wallNanos, tags: tags))
        }
    }
    return spans
}

func buildICMPv6Spans(_ observations: [ICMPv6Observation]) -> [SpanEvent] {
    var spans: [SpanEvent] = []
    let sorted = observations.sorted { $0.wallNanos < $1.wallNanos }
    let solicitations = sorted.filter { $0.type == 133 }
    let advertisements = sorted.filter { $0.type == 134 }
    let neighborSolicitations = sorted.filter { $0.type == 135 && $0.targetAddress != nil }
    let neighborAdvertisements = sorted.filter { $0.type == 136 && $0.targetAddress != nil }

    for gap in retryGaps(solicitations.map(\.wallNanos)) {
        spans.append(
            packetSpan(
                "packet.icmpv6.router_solicitation_retry_gap",
                start: gap.start,
                end: gap.end,
                tags: ["packet.protocol": "icmpv6", "icmpv6.type": "133", "packet.event": "router_solicitation_retry_gap"]
            )
        )
    }

    for ra in advertisements {
        // Pair only close RS->RA exchanges. Older solicitations can remain in
        // the rolling store and should not be treated as causal for a later RA.
        guard let rs = latest(beforeOrAt: ra.wallNanos, in: solicitations),
              ra.wallNanos - rs.wallNanos <= UInt64(3 * 1_000_000_000)
        else {
            continue
        }
        var tags: [String: String] = [
            "packet.protocol": "icmpv6",
            "packet.event": "router_solicitation_to_advertisement",
            "icmpv6.rs.source_ip": rs.sourceIP,
            "icmpv6.ra.source_ip": ra.sourceIP,
            "icmpv6.ra.destination_ip": ra.destinationIP,
            "network.interface": ra.interfaceName,
        ]
        if let lifetime = ra.routerLifetimeSeconds {
            tags["icmpv6.ra.router_lifetime_seconds"] = "\(lifetime)"
        }
        setTag(&tags, "icmpv6.ra.source_link_layer_address", ra.sourceLinkLayerAddress)
        spans.append(packetSpan("packet.icmpv6.router_solicitation_to_advertisement", start: rs.wallNanos, end: ra.wallNanos, tags: tags))
        break
    }

    spans.append(contentsOf: buildNeighborDiscoverySpans(solicitations: neighborSolicitations, advertisements: neighborAdvertisements))

    return spans
}

func buildNeighborDiscoverySpans(
    solicitations: [ICMPv6Observation],
    advertisements: [ICMPv6Observation]
) -> [SpanEvent] {
    var spans: [SpanEvent] = []
    let groupedNS = Dictionary(grouping: solicitations) { $0.targetAddress ?? "" }
    let groupedNA = Dictionary(grouping: advertisements) { $0.targetAddress ?? "" }
    for (target, attempts) in groupedNS {
        // Neighbor Discovery is keyed by the IPv6 target address, not by source
        // host. During rejoin the default router address is the stable value we
        // need to measure resolution delay.
        guard !target.isEmpty, let replies = groupedNA[target] else {
            continue
        }
        let sortedAttempts = attempts.sorted { $0.wallNanos < $1.wallNanos }
        spans.append(contentsOf: neighborRetrySpans(target: target, attempts: sortedAttempts))
        if let resolution = neighborResolutionSpan(target: target, attempts: sortedAttempts, replies: replies) {
            spans.append(resolution)
        }
    }
    return spans
}

private func neighborRetrySpans(target: String, attempts: [ICMPv6Observation]) -> [SpanEvent] {
    // Neighbor Solicitation retries often explain post-DHCP reachability delay,
    // especially when the default router cache is cold after rejoin.
    retryGaps(attempts.map(\.wallNanos)).map { gap in
        packetSpan(
            "packet.icmpv6.default_router_neighbor_solicitation_retry_gap",
            start: gap.start,
            end: gap.end,
            tags: [
                "packet.protocol": "icmpv6",
                "packet.event": "neighbor_solicitation_retry_gap",
                "icmpv6.nd.target_address": target,
            ]
        )
    }
}

private func neighborResolutionSpan(
    target: String,
    attempts: [ICMPv6Observation],
    replies: [ICMPv6Observation]
) -> SpanEvent? {
    guard let reply = replies.sorted(by: { $0.wallNanos < $1.wallNanos }).first,
          let request = latest(beforeOrAt: reply.wallNanos, in: attempts)
    else {
        return nil
    }
    var tags: [String: String] = [
        "packet.protocol": "icmpv6",
        "packet.event": "default_router_neighbor_resolution",
        "icmpv6.nd.target_address": target,
        "network.interface": reply.interfaceName,
    ]
    setTag(&tags, "icmpv6.nd.target_link_layer_address", reply.targetLinkLayerAddress)
    setTag(&tags, "icmpv6.nd.source_link_layer_address", reply.sourceLinkLayerAddress)
    return packetSpan("packet.icmpv6.default_router_neighbor_resolution", start: request.wallNanos, end: reply.wallNanos, tags: tags)
}
