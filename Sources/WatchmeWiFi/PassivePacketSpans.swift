import Foundation
import WatchmeCore
import WatchmeTelemetry

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
    let ipv6DefaultRouters = Set(
        advertisements
            .filter { ($0.routerLifetimeSeconds ?? 0) > 0 }
            .map(\.sourceIP)
    )

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

    spans.append(
        contentsOf: buildNeighborDiscoverySpans(
            solicitations: neighborSolicitations,
            advertisements: neighborAdvertisements,
            retryTargets: ipv6DefaultRouters
        )
    )

    return spans
}

func buildARPSpans(_ observations: [ARPObservation], ipv4Gateway: String?, allowedTargets: Set<String>? = nil) -> [SpanEvent] {
    var spans: [SpanEvent] = []
    let requestsByTarget = Dictionary(grouping: observations.filter(\.isRequest), by: \.targetProtocolAddress)
    let repliesBySender = Dictionary(grouping: observations.filter(\.isReply), by: \.senderProtocolAddress)

    for (target, requests) in requestsByTarget where !target.isEmpty {
        if let allowedTargets, !allowedTargets.contains(target) {
            continue
        }
        if allowedTargets == nil, let ipv4Gateway, target != ipv4Gateway {
            continue
        }
        let sortedRequests = requests.sorted { $0.wallNanos < $1.wallNanos }
        for gap in retryGaps(sortedRequests.map(\.wallNanos)) {
            spans.append(
                packetSpan(
                    "packet.arp.request_retry_gap",
                    start: gap.start,
                    end: gap.end,
                    tags: arpTags(target: target, event: "request_retry_gap", ipv4Gateway: ipv4Gateway, observation: sortedRequests.first)
                )
            )
        }
        guard let reply = repliesBySender[target]?.sorted(by: { $0.wallNanos < $1.wallNanos }).first,
              let request = latestARPRequest(beforeOrAt: reply.wallNanos, in: sortedRequests)
        else {
            continue
        }
        spans.append(
            packetSpan(
                "packet.arp.request_to_reply",
                start: request.wallNanos,
                end: reply.wallNanos,
                tags: arpTags(target: target, event: "request_to_reply", ipv4Gateway: ipv4Gateway, observation: reply)
            )
        )
    }
    return spans
}

private func arpTags(target: String, event: String, ipv4Gateway: String?, observation: ARPObservation?) -> [String: String] {
    var tags: [String: String] = [
        "packet.protocol": "arp",
        "packet.event": event,
        "arp.target_ip": target,
    ]
    setTag(&tags, "network.interface", observation?.interfaceName)
    setTag(&tags, "arp.sender_ip", observation?.senderProtocolAddress)
    setTag(&tags, "arp.sender_mac", observation?.senderHardwareAddress)
    setTag(&tags, "arp.target_mac", observation?.targetHardwareAddress)
    if let ipv4Gateway, target == ipv4Gateway {
        tags["network.gateway"] = ipv4Gateway
        tags["arp.target_role"] = "gateway"
    } else {
        tags["arp.target_role"] = "ipv4_neighbor"
    }
    return tags
}

private func latestARPRequest(beforeOrAt end: UInt64, in values: [ARPObservation]) -> ARPObservation? {
    values.last { $0.wallNanos <= end }
}

func buildNeighborDiscoverySpans(
    solicitations: [ICMPv6Observation],
    advertisements: [ICMPv6Observation],
    retryTargets: Set<String> = []
) -> [SpanEvent] {
    var spans: [SpanEvent] = []
    let groupedNS = Dictionary(grouping: solicitations) { $0.targetAddress ?? "" }
    let groupedNA = Dictionary(grouping: advertisements) { $0.targetAddress ?? "" }
    for (target, attempts) in groupedNS {
        // Neighbor Discovery is keyed by the IPv6 target address, not by source
        // host, so retries and replies for the same target stay paired.
        guard !target.isEmpty, let replies = groupedNA[target] else {
            continue
        }
        let sortedAttempts = attempts.sorted { $0.wallNanos < $1.wallNanos }
        if retryTargets.contains(target) {
            spans.append(contentsOf: neighborRetrySpans(target: target, attempts: sortedAttempts))
        }
        if let resolution = neighborResolutionSpan(target: target, attempts: sortedAttempts, replies: replies) {
            spans.append(resolution)
        }
    }
    return spans
}

private func neighborRetrySpans(target: String, attempts: [ICMPv6Observation]) -> [SpanEvent] {
    // Neighbor Solicitation retries often explain post-DHCP reachability delay.
    retryGaps(attempts.map(\.wallNanos)).map { gap in
        packetSpan(
            "packet.icmpv6.neighbor_solicitation_retry_gap",
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
        "packet.event": "neighbor_solicitation_to_advertisement",
        "icmpv6.nd.target_address": target,
        "network.interface": reply.interfaceName,
    ]
    setTag(&tags, "icmpv6.nd.target_link_layer_address", reply.targetLinkLayerAddress)
    setTag(&tags, "icmpv6.nd.source_link_layer_address", reply.sourceLinkLayerAddress)
    return packetSpan("packet.icmpv6.neighbor_solicitation_to_advertisement", start: request.wallNanos, end: reply.wallNanos, tags: tags)
}
