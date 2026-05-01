import Foundation
import WatchmeCore

extension WiFiAgent {
    func activeGatewayTags(result: ActiveGatewayProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags = activeProbeBaseTags(
            snapshot: snapshot,
            timingSource: result.icmpTimingSource,
            timestampSource: result.icmpTimestampSource,
            spanSource: "darwin_icmp_gateway_probe"
        )
        tags.merge([
            "probe.target": result.gateway,
            "probe.gateway.target": result.gateway,
            "network.family": result.family.metricValue,
            "network.peer.address": result.gateway,
            "network.wifi_gateway": result.gateway,
            "network.gateway_probe.protocol": "icmp",
            "network.gateway_probe.outcome": result.outcome,
            "network.gateway_probe.reachable": result.reachable ? "true" : "false",
            "network.gateway_probe.probe_count": "\(result.probeCount)",
            "network.gateway_probe.reply_count": "\(result.reachableCount)",
            "network.gateway_probe.lost_count": "\(result.lostCount)",
            "network.gateway_probe.loss_ratio": formatGatewayProbeDouble(result.lossRatio),
            "network.gateway_probe.jitter_seconds": formatGatewayProbeDouble(seconds(fromDurationNanos: result.jitterNanos)),
            "network.gateway_probe.burst_interval_seconds": formatGatewayProbeDouble(result.burstIntervalSeconds),
            "probe.gateway.icmp.span_kind": "burst",
            "probe.gateway.icmp.echo_span_count": "\(result.attempts.count)",
            "icmp.outcome": result.outcome,
        ]) { _, new in new }
        if let gatewayHardwareAddress = result.gatewayHardwareAddress {
            tags["network.wifi_gateway_hwaddr"] = gatewayHardwareAddress
        }
        addErrorTag(&tags, error: result.error)
        return tags
    }

    func activeGatewayAttemptTags(
        result: ActiveGatewayProbeResult,
        attempt: ActiveGatewayProbeAttempt,
        snapshot: WiFiSnapshot
    ) -> [String: String] {
        var tags = activeProbeBaseTags(
            snapshot: snapshot,
            timingSource: attempt.timingSource,
            timestampSource: attempt.timestampSource,
            spanSource: "darwin_icmp_gateway_probe"
        )
        tags.merge([
            "probe.target": result.gateway,
            "probe.gateway.target": result.gateway,
            "network.family": result.family.metricValue,
            "network.peer.address": result.gateway,
            "network.wifi_gateway": result.gateway,
            "network.gateway_probe.protocol": "icmp",
            "network.gateway_probe.outcome": attempt.outcome,
            "network.gateway_probe.reachable": attempt.reachable ? "true" : "false",
            "network.gateway_probe.attempt_sequence": "\(attempt.sequence)",
            "icmp.outcome": attempt.outcome,
        ]) { _, new in new }
        if let identifier = attempt.identifier {
            tags["icmp.identifier"] = String(format: "0x%04x", identifier)
        }
        if let sequence = attempt.icmpSequence {
            tags["icmp.sequence"] = "\(sequence)"
        }
        if let gatewayHardwareAddress = result.gatewayHardwareAddress {
            tags["network.wifi_gateway_hwaddr"] = gatewayHardwareAddress
        }
        addPacketTimingTags(
            &tags,
            timingSource: attempt.timingSource,
            event: result.family == .ipv6 ? "icmpv6_echo_request_to_reply" : "icmp_echo_request_to_reply"
        )
        addErrorTag(&tags, error: attempt.error)
        return tags
    }

    func activeGatewayARPTags(result: ActiveGatewayARPResult, snapshot: WiFiSnapshot) -> [String: String] {
        activeGatewayResolutionTags(result: result, snapshot: snapshot)
    }

    func activeGatewayResolutionTags(result: ActiveGatewayARPResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags = activeProbeBaseTags(
            snapshot: snapshot,
            timingSource: result.timingSource,
            timestampSource: result.timestampSource,
            spanSource: result.family == .ipv6 ? "darwin_bpf_gateway_ndp_probe" : "darwin_bpf_gateway_arp_probe"
        )
        tags.merge(gatewayResolutionProtocolTags(result)) { _, new in new }
        if result.family == .ipv4, result.gatewayHardwareAddress != nil {
            tags["arp.sender_ip"] = result.gateway
            setTag(&tags, "arp.sender_mac", result.gatewayHardwareAddress)
            setTag(&tags, "arp.target_mac", result.sourceHardwareAddress)
        }
        setTag(&tags, "network.wifi_gateway_hwaddr", result.gatewayHardwareAddress)
        setTag(&tags, "active_probe.source_ip", result.sourceIP)
        addPacketTimingTags(
            &tags,
            timingSource: result.timingSource,
            event: result.family == .ipv6 ? "neighbor_solicitation_to_advertisement" : "arp_request_to_reply"
        )
        addErrorTag(&tags, error: result.error)
        return tags
    }

    private func gatewayResolutionProtocolTags(_ result: ActiveGatewayARPResult) -> [String: String] {
        if result.family == .ipv6 {
            var tags: [String: String] = [
                "network.family": InternetAddressFamily.ipv6.metricValue,
                "network.wifi_gateway": result.gateway,
                "network.gateway": result.gateway,
                "network.gateway_probe.protocol": "ndp",
                "network.gateway_ndp.outcome": result.outcome,
                "network.gateway_ndp.resolved": result.ok ? "true" : "false",
                "packet.protocol": "icmpv6",
                "icmpv6.nd.target_address": result.gateway,
            ]
            setTag(&tags, "icmpv6.nd.target_link_layer_address", result.gatewayHardwareAddress)
            return tags
        }
        return [
            "network.family": InternetAddressFamily.ipv4.metricValue,
            "network.wifi_gateway": result.gateway,
            "network.gateway": result.gateway,
            "network.gateway_probe.protocol": "arp",
            "network.gateway_arp.outcome": result.outcome,
            "network.gateway_arp.resolved": result.ok ? "true" : "false",
            "packet.protocol": "arp",
            "arp.target_ip": result.gateway,
            "arp.target_role": "gateway",
        ]
    }
}
