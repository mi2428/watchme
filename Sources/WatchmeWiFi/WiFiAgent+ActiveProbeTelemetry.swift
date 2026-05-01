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
        for lane in results.lanes {
            metricState.recordInternetPathProbe(lane)
            let laneId = recorder.newSpanId()
            let laneStart = parentSpanStart(before: lane.startWallNanos)
            recorder.recordSpan(
                name: internetProbePathSpanName(family: lane.family),
                id: laneId,
                startWallNanos: laneStart,
                durationNanos: lane.finishedWallNanos - laneStart,
                parentId: phaseId,
                tags: activeInternetLaneTags(result: lane, snapshot: snapshot),
                statusOK: lane.ok
            )
            for result in lane.dns {
                recordInternetDNSResult(result, parentId: laneId, recorder: recorder, snapshot: snapshot)
            }
            if let result = lane.icmp {
                recordInternetICMPResult(result, parentId: laneId, recorder: recorder, snapshot: snapshot)
            }
            if let result = lane.tcp {
                recordInternetTCPResult(result, parentId: laneId, recorder: recorder, snapshot: snapshot)
            }
            if let result = lane.http {
                recordInternetHTTPResult(result, parentId: laneId, recorder: recorder, snapshot: snapshot)
            }
        }
    }

    private func recordInternetDNSResult(
        _ result: ActiveDNSProbeResult,
        parentId: String,
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        metricState.recordDNSProbe(result)
        recorder.recordSpan(
            name: "probe.internet.dns.resolve",
            id: recorder.newSpanId(),
            startWallNanos: result.startWallNanos,
            durationNanos: result.durationNanos,
            parentId: parentId,
            tags: activeDNSTags(result: result, snapshot: snapshot),
            statusOK: result.ok
        )
        logInternetDNSResult(result, traceId: recorder.traceId)
    }

    private func recordInternetICMPResult(
        _ result: ActiveICMPProbeResult,
        parentId: String,
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        metricState.recordICMPProbe(result)
        recorder.recordSpan(
            name: "probe.internet.icmp.echo",
            id: recorder.newSpanId(),
            startWallNanos: result.startWallNanos,
            durationNanos: result.durationNanos,
            parentId: parentId,
            tags: activeICMPTags(result: result, snapshot: snapshot),
            statusOK: result.ok
        )
        logInternetICMPResult(result, traceId: recorder.traceId)
    }

    private func recordInternetTCPResult(
        _ result: ActiveTCPProbeResult,
        parentId: String,
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        metricState.recordInternetTCPProbe(result)
        recorder.recordSpan(
            name: "probe.internet.tcp.connect",
            id: recorder.newSpanId(),
            startWallNanos: result.startWallNanos,
            durationNanos: result.durationNanos,
            parentId: parentId,
            tags: activeTCPTags(result: result, snapshot: snapshot),
            statusOK: result.ok
        )
        logInternetTCPResult(result, traceId: recorder.traceId)
    }

    private func recordInternetHTTPResult(
        _ result: ActiveInternetHTTPProbeResult,
        parentId: String,
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        metricState.recordInternetHTTPProbe(result)
        recorder.recordSpan(
            name: "probe.internet.http.head",
            id: recorder.newSpanId(),
            startWallNanos: result.startWallNanos,
            durationNanos: result.durationNanos,
            parentId: parentId,
            tags: activeInternetHTTPTags(result: result, snapshot: snapshot),
            statusOK: result.ok
        )
        logInternetHTTPResult(result, traceId: recorder.traceId)
    }

    func activeInternetLaneTags(result: ActiveInternetProbeLaneResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags = activeProbeBaseTags(
            snapshot: snapshot,
            timingSource: "composite",
            timestampSource: wallClockTimestampSource,
            spanSource: "watchme_connectivity_check"
        )
        let checkStatuses = internetProbeCheckStatuses(result)
        let okChecks = internetProbeChecks(with: "ok", in: checkStatuses)
        let failedChecks = internetProbeChecks(with: "error", in: checkStatuses)
        tags.merge([
            "probe.target": result.target,
            "probe.internet.target": result.target,
            "network.family": result.family.metricValue,
            "network.peer.address": result.remoteIP,
            "probe.internet.dns.span_count": "\(result.dns.count)",
            "probe.internet.icmp.span_count": result.icmp == nil ? "0" : "1",
            "probe.internet.tcp.span_count": result.tcp == nil ? "0" : "1",
            "probe.internet.http.span_count": result.http == nil ? "0" : "1",
            "probe.internet.path.status": result.ok ? "ok" : "error",
            "probe.internet.checks.summary": internetProbeCheckSummary(checkStatuses),
            "probe.internet.checks.ok": okChecks.joined(separator: ","),
            "probe.internet.checks.failed": failedChecks.joined(separator: ","),
        ]) { _, new in new }
        for checkStatus in checkStatuses {
            tags["probe.internet.check.\(checkStatus.key).status"] = checkStatus.status
        }
        return tags
    }

    private struct InternetProbeCheckStatus {
        let key: String
        let label: String
        let status: String
    }

    private func internetProbeCheckStatuses(_ result: ActiveInternetProbeLaneResult) -> [InternetProbeCheckStatus] {
        var statuses: [InternetProbeCheckStatus] = []
        if !result.dns.isEmpty {
            statuses.append(InternetProbeCheckStatus(
                key: "dns",
                label: "DNS",
                status: result.dns.allSatisfy(\.ok) ? "ok" : "error"
            ))
        }
        if let icmp = result.icmp {
            statuses.append(InternetProbeCheckStatus(
                key: "icmp",
                label: "ICMP",
                status: icmp.ok ? "ok" : "error"
            ))
        }
        if let tcp = result.tcp {
            statuses.append(InternetProbeCheckStatus(
                key: "tcp",
                label: "TCP",
                status: tcp.ok ? "ok" : "error"
            ))
        }
        if let http = result.http {
            statuses.append(InternetProbeCheckStatus(
                key: "http",
                label: "HTTP",
                status: http.ok ? "ok" : "error"
            ))
        }
        return statuses
    }

    private func internetProbeChecks(
        with status: String,
        in statuses: [InternetProbeCheckStatus]
    ) -> [String] {
        statuses.filter { $0.status == status }.map(\.label)
    }

    private func internetProbeCheckSummary(_ statuses: [InternetProbeCheckStatus]) -> String {
        statuses.map { "\($0.label)=\($0.status)" }.joined(separator: ",")
    }

    private func parentSpanStart(before firstChildStart: UInt64) -> UInt64 {
        firstChildStart > 1000 ? firstChildStart - 1000 : firstChildStart
    }

    private func internetProbePathSpanName(family: InternetAddressFamily) -> String {
        "probe.internet.path.\(family.metricValue)"
    }

    private func gatewayProbePathSpanName(family: InternetAddressFamily) -> String {
        "probe.gateway.path.\(family.metricValue)"
    }

    func recordGatewayProbeResult(
        _ result: ActiveGatewayProbeResult,
        phaseId: String,
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        metricState.recordGatewayProbe(result)
        let pathId = recorder.newSpanId()
        let pathStart = parentSpanStart(before: result.startWallNanos)
        recorder.recordSpan(
            name: gatewayProbePathSpanName(family: result.family),
            id: pathId,
            startWallNanos: pathStart,
            durationNanos: result.finishedWallNanos - pathStart,
            parentId: phaseId,
            tags: activeGatewayPathTags(result: result, snapshot: snapshot),
            statusOK: result.pathOK
        )
        if let arpResolution = result.arpResolution {
            recorder.recordSpan(
                name: gatewayResolutionSpanName(result: arpResolution),
                id: recorder.newSpanId(),
                startWallNanos: arpResolution.startWallNanos,
                durationNanos: arpResolution.durationNanos,
                parentId: pathId,
                tags: activeGatewayResolutionTags(result: arpResolution, snapshot: snapshot),
                statusOK: arpResolution.ok
            )
        }
        if !result.attempts.isEmpty {
            let burstId = recorder.newSpanId()
            recorder.recordSpan(
                name: "probe.gateway.icmp.burst",
                id: burstId,
                startWallNanos: result.attempts.map(\.startWallNanos).min() ?? result.startWallNanos,
                durationNanos: result.burstDurationNanos,
                parentId: pathId,
                tags: activeGatewayTags(result: result, snapshot: snapshot),
                statusOK: result.reachable
            )
            for attempt in result.attempts {
                recorder.recordSpan(
                    name: "probe.gateway.icmp.echo",
                    id: recorder.newSpanId(),
                    startWallNanos: attempt.startWallNanos,
                    durationNanos: attempt.durationNanos,
                    parentId: burstId,
                    tags: activeGatewayAttemptTags(result: result, attempt: attempt, snapshot: snapshot),
                    statusOK: attempt.reachable
                )
            }
        }
        logEvent(
            result.pathOK ? .debug : .warn, "active_gateway_probe_completed",
            fields: [
                "trace_id": recorder.traceId,
                "gateway": result.gateway,
                "network.family": result.family.metricValue,
                "gateway_hwaddr": result.gatewayHardwareAddress ?? "",
                "resolution_protocol": result.arpResolution?.protocolName ?? "",
                "resolution_outcome": result.arpResolution?.outcome ?? "",
                "resolution_resolved": result.arpResolution.map { $0.ok ? "true" : "false" } ?? "",
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

    func activeGatewayPathTags(result: ActiveGatewayProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags = activeProbeBaseTags(
            snapshot: snapshot,
            timingSource: "composite",
            timestampSource: wallClockTimestampSource,
            spanSource: "watchme_connectivity_check"
        )
        tags.merge([
            "probe.gateway.path.status": result.pathOK ? "ok" : "error",
            "probe.gateway.arp.span_count": result.family == .ipv4 && result.arpResolution != nil ? "1" : "0",
            "probe.gateway.ndp.span_count": result.family == .ipv6 && result.arpResolution != nil ? "1" : "0",
            "probe.gateway.icmp.span_count": "\(result.attempts.count)",
            "probe.gateway.icmp.echo_span_count": "\(result.attempts.count)",
            "probe.gateway.icmp.burst_span_count": result.attempts.isEmpty ? "0" : "1",
            "network.family": result.family.metricValue,
            "network.wifi_gateway": result.gateway,
            "network.gateway_probe.reachable": result.reachable ? "true" : "false",
            "network.gateway_probe.outcome": result.outcome,
            "network.gateway_probe.probe_count": "\(result.probeCount)",
            "network.gateway_probe.reply_count": "\(result.reachableCount)",
            "network.gateway_probe.lost_count": "\(result.lostCount)",
            "network.gateway_probe.loss_ratio": formatGatewayProbeDouble(result.lossRatio),
        ]) { _, new in new }
        if let gatewayHardwareAddress = result.gatewayHardwareAddress {
            tags["network.wifi_gateway_hwaddr"] = gatewayHardwareAddress
        }
        if let resolution = result.arpResolution {
            tags["network.gateway_probe.resolution_protocol"] = resolution.protocolName
        }
        addErrorTag(&tags, error: result.error)
        return tags
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
            "probe.internet.http.scheme": "http",
            "probe.internet.http.method": "HEAD",
            "probe.internet.http.outcome": result.outcome,
        ]) { _, new in new }
        if let statusCode = result.statusCode {
            tags["probe.internet.http.status_code"] = "\(statusCode)"
        }
        addPacketTimingTags(&tags, timingSource: result.timingSource, event: "http_request_to_first_response_byte")
        addErrorTag(&tags, error: result.error)
        return tags
    }

    func activeTCPTags(result: ActiveTCPProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags = activeProbeBaseTags(
            snapshot: snapshot,
            timingSource: result.timingSource,
            timestampSource: result.timestampSource,
            spanSource: "network_framework_tcp_probe"
        )
        tags.merge([
            "probe.target": result.target,
            "probe.internet.target": result.target,
            "network.family": result.family.metricValue,
            "network.peer.address": result.remoteIP,
            "net.peer.port": "\(result.port)",
            "tcp.outcome": result.outcome,
        ]) { _, new in new }
        addPacketTimingTags(&tags, timingSource: result.timingSource, event: "tcp_syn_to_response")
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

    func logInternetTCPResult(_ result: ActiveTCPProbeResult, traceId: String) {
        logEvent(
            result.ok ? .debug : .warn, "active_internet_tcp_probe_completed",
            fields: [
                "trace_id": traceId,
                "target": result.target,
                "network.family": result.family.metricValue,
                "remote_ip": result.remoteIP,
                "remote_port": "\(result.port)",
                "outcome": result.outcome,
                "status": result.ok ? "ok" : "error",
                "timing_source": result.timingSource,
                "error": result.error ?? "",
            ]
        )
    }

    private func gatewayResolutionSpanName(result: ActiveGatewayARPResult) -> String {
        result.family == .ipv6
            ? "probe.gateway.ndp.neighbor_solicitation_to_advertisement"
            : "probe.gateway.arp.request_to_reply"
    }
}
