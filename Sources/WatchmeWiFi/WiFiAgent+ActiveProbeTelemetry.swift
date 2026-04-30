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
            name: "probe.gateway.tcp_connect",
            id: recorder.newSpanId(),
            startWallNanos: result.startWallNanos,
            durationNanos: result.durationNanos,
            parentId: phaseId,
            tags: activeGatewayTags(result: result, snapshot: snapshot),
            statusOK: result.reachable
        )
        logEvent(
            result.reachable ? .debug : .warn, "active_gateway_probe_completed",
            fields: [
                "trace_id": recorder.traceId,
                "gateway": result.gateway,
                "port": "\(result.port)",
                "outcome": result.outcome,
                "reachable": result.reachable ? "true" : "false",
                "connect_success": result.connectSuccess ? "true" : "false",
                "timing_source": result.timingSource,
                "error": result.error ?? "",
            ]
        )
    }

    func activeDNSTags(result: ActiveDNSProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags: [String: String] = [
            "span.source": "network_framework_internet_dns_probe",
            "active_probe.interface": snapshot.interfaceName ?? "",
            "active_probe.required_interface": snapshot.interfaceName ?? "",
            "probe.target": result.target,
            "probe.internet.target": result.target,
            "probe.timing_source": result.timingSource,
            "probe.timestamp_source": result.timestampSource,
            "network.family": result.family.metricValue,
            "dns.resolver": result.resolver,
            "dns.transport": result.transport,
            "dns.question.type": result.recordType.name,
            "dns.answer_count": result.answerCount.map(String.init) ?? "",
            "dns.address_count": "\(result.addresses.count)",
            "dns.addresses": result.addresses.joined(separator: ","),
            "wifi.essid": snapshot.ssid ?? "unknown",
            "wifi.bssid": snapshot.bssid ?? "unknown",
        ]
        if let rcode = result.rcode {
            tags["dns.rcode"] = "\(rcode)"
        }
        if result.timingSource == bpfPacketTimingSource {
            tags["packet.event"] = "dns_query_to_response"
            tags["packet.timestamp_source"] = bpfHeaderTimestampSource
            tags["packet.timestamp_resolution"] = "microsecond"
        }
        if let error = result.error {
            tags["error"] = clipped(error, limit: 240)
        }
        return tags
    }

    func activeICMPTags(result: ActiveICMPProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags: [String: String] = [
            "span.source": "darwin_icmp_socket",
            "active_probe.interface": snapshot.interfaceName ?? "",
            "active_probe.required_interface": snapshot.interfaceName ?? "",
            "probe.target": result.target,
            "probe.internet.target": result.target,
            "probe.timing_source": result.timingSource,
            "probe.timestamp_source": result.timestampSource,
            "network.family": result.family.metricValue,
            "network.peer.address": result.remoteIP,
            "icmp.outcome": result.outcome,
            "wifi.essid": snapshot.ssid ?? "unknown",
            "wifi.bssid": snapshot.bssid ?? "unknown",
        ]
        if result.timingSource == bpfPacketTimingSource {
            tags["packet.event"] = "icmp_echo_request_to_reply"
            tags["packet.timestamp_source"] = bpfHeaderTimestampSource
            tags["packet.timestamp_resolution"] = "microsecond"
        }
        if let identifier = result.identifier {
            tags["icmp.identifier"] = String(format: "0x%04x", identifier)
        }
        if let sequence = result.sequence {
            tags["icmp.sequence"] = "\(sequence)"
        }
        if let error = result.error {
            tags["error"] = clipped(error, limit: 240)
        }
        return tags
    }

    func activeInternetHTTPTags(result: ActiveInternetHTTPProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags: [String: String] = [
            "span.source": "network_framework_plain_http_probe",
            "active_probe.interface": snapshot.interfaceName ?? "",
            "active_probe.required_interface": snapshot.interfaceName ?? "",
            "probe.target": result.target,
            "probe.internet.target": result.target,
            "probe.timing_source": result.timingSource,
            "probe.timestamp_source": result.timestampSource,
            "network.family": result.family.metricValue,
            "network.peer.address": result.remoteIP,
            "net.peer.port": "80",
            "url.scheme": "http",
            "http.request.method": "HEAD",
            "http.outcome": result.outcome,
            "wifi.essid": snapshot.ssid ?? "unknown",
            "wifi.bssid": snapshot.bssid ?? "unknown",
        ]
        if let statusCode = result.statusCode {
            tags["http.response.status_code"] = "\(statusCode)"
        }
        if result.timingSource == bpfPacketTimingSource {
            tags["packet.event"] = "http_request_to_first_response_byte"
            tags["packet.timestamp_source"] = bpfHeaderTimestampSource
            tags["packet.timestamp_resolution"] = "microsecond"
        }
        if let error = result.error {
            tags["error"] = clipped(error, limit: 240)
        }
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
        var tags: [String: String] = [
            "span.source": "network_framework_gateway_probe",
            "active_probe.interface": snapshot.interfaceName ?? "",
            "active_probe.required_interface": snapshot.interfaceName ?? "",
            "probe.timing_source": result.timingSource,
            "probe.timestamp_source": result.timestampSource,
            "network.wifi_gateway": result.gateway,
            "network.gateway_probe.port": "\(result.port)",
            "network.gateway_probe.outcome": result.outcome,
            "network.gateway_probe.reachable": result.reachable ? "true" : "false",
            "network.gateway_probe.connect_success": result.connectSuccess ? "true" : "false",
            "wifi.essid": snapshot.ssid ?? "unknown",
            "wifi.bssid": snapshot.bssid ?? "unknown",
        ]
        if result.timingSource == bpfPacketTimingSource {
            tags["packet.event"] = "tcp_syn_to_response"
            tags["packet.timestamp_source"] = bpfHeaderTimestampSource
            tags["packet.timestamp_resolution"] = "microsecond"
        }
        if let error = result.error {
            tags["error"] = clipped(error, limit: 240)
        }
        return tags
    }
}
