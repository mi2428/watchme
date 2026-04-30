import Foundation
import WatchmeCore
import WatchmeTelemetry

extension WiFiAgent {
    func recordInternetProbeResults(
        _ results: ActiveInternetProbeResults,
        phaseId: String,
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        for result in results.dns {
            metricState.recordDNSProbe(result)
            recorder.recordSpan(
                name: "probe.internet.dns.resolve",
                id: recorder.newSpanId(),
                startWallNanos: result.startWallNanos,
                durationNanos: result.durationNanos,
                parentId: phaseId,
                tags: activeDNSTags(result: result, snapshot: snapshot),
                statusOK: result.ok
            )
            logInternetDNSResult(result, traceId: recorder.traceId)
        }
        for result in results.icmp {
            metricState.recordICMPProbe(result)
            recorder.recordSpan(
                name: "probe.internet.icmp.echo",
                id: recorder.newSpanId(),
                startWallNanos: result.startWallNanos,
                durationNanos: result.durationNanos,
                parentId: phaseId,
                tags: activeICMPTags(result: result, snapshot: snapshot),
                statusOK: result.ok
            )
            logInternetICMPResult(result, traceId: recorder.traceId)
        }
        for result in results.http {
            metricState.recordInternetHTTPProbe(result)
            recorder.recordSpan(
                name: "probe.internet.http.head",
                id: recorder.newSpanId(),
                startWallNanos: result.startWallNanos,
                durationNanos: result.durationNanos,
                parentId: phaseId,
                tags: activeInternetHTTPTags(result: result, snapshot: snapshot),
                statusOK: result.ok
            )
            logInternetHTTPResult(result, traceId: recorder.traceId)
        }
    }

    func recordGatewayProbeResult(
        _ result: ActiveGatewayProbeResult,
        phaseId: String,
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        metricState.recordGatewayProbe(result)
        recorder.recordSpan(
            name: "probe.gateway.icmp.echo",
            id: recorder.newSpanId(),
            startWallNanos: result.startWallNanos,
            durationNanos: result.burstDurationNanos,
            parentId: phaseId,
            tags: activeGatewayTags(result: result, snapshot: snapshot),
            statusOK: result.reachable
        )
        logEvent(
            result.lossRatio == 0 ? .debug : .warn, "active_gateway_probe_completed",
            fields: [
                "trace_id": recorder.traceId,
                "gateway": result.gateway,
                "outcome": result.outcome,
                "reachable": result.reachable ? "true" : "false",
                "probe_count": "\(result.probeCount)",
                "reply_count": "\(result.reachableCount)",
                "lost_count": "\(result.lostCount)",
                "loss_ratio": formatGatewayProbeDouble(result.lossRatio),
                "jitter_seconds": formatGatewayProbeDouble(seconds(fromDurationNanos: result.jitterNanos)),
                "burst_interval_seconds": formatGatewayProbeDouble(result.burstIntervalSeconds),
                "timing_source": result.timingSource,
                "error": result.error ?? "",
            ]
        )
    }

    func activeDNSTags(result: ActiveDNSProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags = activeProbeBaseTags(
            snapshot: snapshot,
            timingSource: result.timingSource,
            timestampSource: result.timestampSource,
            spanSource: "network_framework_internet_dns_probe"
        )
        tags.merge([
            "probe.target": result.target,
            "probe.internet.target": result.target,
            "network.family": result.family.metricValue,
            "dns.resolver": result.resolver,
            "dns.transport": result.transport,
            "dns.question.type": result.recordType.name,
            "dns.answer_count": result.answerCount.map(String.init) ?? "",
            "dns.address_count": "\(result.addresses.count)",
            "dns.addresses": result.addresses.joined(separator: ","),
        ]) { _, new in new }
        if let rcode = result.rcode {
            tags["dns.rcode"] = "\(rcode)"
        }
        addPacketTimingTags(&tags, timingSource: result.timingSource, event: "dns_query_to_response")
        addErrorTag(&tags, error: result.error)
        return tags
    }

    func activeICMPTags(result: ActiveICMPProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags = activeProbeBaseTags(
            snapshot: snapshot,
            timingSource: result.timingSource,
            timestampSource: result.timestampSource,
            spanSource: "darwin_icmp_socket"
        )
        tags.merge([
            "probe.target": result.target,
            "probe.internet.target": result.target,
            "network.family": result.family.metricValue,
            "network.peer.address": result.remoteIP,
            "icmp.outcome": result.outcome,
        ]) { _, new in new }
        addPacketTimingTags(&tags, timingSource: result.timingSource, event: "icmp_echo_request_to_reply")
        if let identifier = result.identifier {
            tags["icmp.identifier"] = String(format: "0x%04x", identifier)
        }
        if let sequence = result.sequence {
            tags["icmp.sequence"] = "\(sequence)"
        }
        addErrorTag(&tags, error: result.error)
        return tags
    }

    func activeInternetHTTPTags(result: ActiveInternetHTTPProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags = activeProbeBaseTags(
            snapshot: snapshot,
            timingSource: result.timingSource,
            timestampSource: result.timestampSource,
            spanSource: "network_framework_plain_http_probe"
        )
        tags.merge([
            "probe.target": result.target,
            "probe.internet.target": result.target,
            "network.family": result.family.metricValue,
            "network.peer.address": result.remoteIP,
            "net.peer.port": "80",
            "url.scheme": "http",
            "http.request.method": "HEAD",
            "http.outcome": result.outcome,
        ]) { _, new in new }
        if let statusCode = result.statusCode {
            tags["http.response.status_code"] = "\(statusCode)"
        }
        addPacketTimingTags(&tags, timingSource: result.timingSource, event: "http_request_to_first_response_byte")
        addErrorTag(&tags, error: result.error)
        return tags
    }

    func logInternetDNSResult(_ result: ActiveDNSProbeResult, traceId: String) {
        logEvent(
            result.ok ? .debug : .warn, "active_internet_dns_probe_completed",
            fields: [
                "trace_id": traceId,
                "target": result.target,
                "network.family": result.family.metricValue,
                "resolver": result.resolver,
                "record_type": result.recordType.name,
                "transport": result.transport,
                "status": result.ok ? "ok" : "error",
                "rcode": result.rcode.map(String.init) ?? "",
                "answers": result.answerCount.map(String.init) ?? "",
                "addresses": result.addresses.joined(separator: ","),
                "timing_source": result.timingSource,
                "error": result.error ?? "",
            ]
        )
    }

    func logInternetICMPResult(_ result: ActiveICMPProbeResult, traceId: String) {
        logEvent(
            result.ok ? .debug : .warn, "active_internet_icmp_probe_completed",
            fields: [
                "trace_id": traceId,
                "target": result.target,
                "network.family": result.family.metricValue,
                "remote_ip": result.remoteIP,
                "outcome": result.outcome,
                "status": result.ok ? "ok" : "error",
                "timing_source": result.timingSource,
                "icmp.identifier": result.identifier.map { String(format: "0x%04x", $0) } ?? "",
                "icmp.sequence": result.sequence.map(String.init) ?? "",
                "error": result.error ?? "",
            ]
        )
    }

    func logInternetHTTPResult(_ result: ActiveInternetHTTPProbeResult, traceId: String) {
        logEvent(
            result.ok ? .debug : .warn, "active_internet_http_probe_completed",
            fields: [
                "trace_id": traceId,
                "target": result.target,
                "network.family": result.family.metricValue,
                "remote_ip": result.remoteIP,
                "outcome": result.outcome,
                "status": result.ok ? "ok" : "error",
                "status_code": result.statusCode.map(String.init) ?? "",
                "timing_source": result.timingSource,
                "error": result.error ?? "",
            ]
        )
    }

    func activeGatewayTags(result: ActiveGatewayProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags = activeProbeBaseTags(
            snapshot: snapshot,
            timingSource: result.timingSource,
            timestampSource: result.timestampSource,
            spanSource: "darwin_icmp_gateway_probe"
        )
        tags.merge([
            "network.family": result.family.metricValue,
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
        ]) { _, new in new }
        addPacketTimingTags(&tags, timingSource: result.timingSource, event: "icmp_echo_request_to_reply")
        addErrorTag(&tags, error: result.error)
        return tags
    }

    private func activeProbeBaseTags(
        snapshot: WiFiSnapshot,
        timingSource: String,
        timestampSource: String,
        spanSource: String
    ) -> [String: String] {
        [
            "span.source": spanSource,
            "active_probe.interface": snapshot.interfaceName ?? "",
            "active_probe.required_interface": snapshot.interfaceName ?? "",
            "probe.timing_source": timingSource,
            "probe.timestamp_source": timestampSource,
            "wifi.essid": snapshot.ssid ?? "unknown",
            "wifi.bssid": snapshot.bssid ?? "unknown",
        ]
    }

    private func addPacketTimingTags(_ tags: inout [String: String], timingSource: String, event: String) {
        guard timingSource == bpfPacketTimingSource else {
            return
        }
        tags["packet.event"] = event
        tags["packet.timestamp_source"] = bpfHeaderTimestampSource
        tags["packet.timestamp_resolution"] = "microsecond"
    }

    private func addErrorTag(_ tags: inout [String: String], error: String?) {
        guard let error else {
            return
        }
        tags["error"] = clipped(error, limit: 240)
    }
}
