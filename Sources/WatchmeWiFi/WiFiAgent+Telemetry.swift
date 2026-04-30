import Foundation
import WatchmeCore
import WatchmeTelemetry

extension WiFiAgent {
    func triggerTrace(reason: String, eventTags: [String: String], force: Bool, includeActive: Bool) {
        triggerQueue.async {
            let now = Date()
            guard force || now.timeIntervalSince(self.lastTrigger) >= self.config.triggerCooldown else {
                logEvent(
                    .debug, "trace_trigger_suppressed",
                    fields: [
                        "reason": reason,
                        "cooldown_seconds": "\(self.config.triggerCooldown)",
                    ]
                )
                return
            }
            self.lastTrigger = now
            logEvent(.info, "trace_trigger_accepted", fields: ["reason": reason, "force": force ? "true" : "false"])
            self.emitTrace(reason: reason, eventTags: eventTags, consumePacketSpans: true, includeActive: includeActive)
        }
    }

    func schedulePacketWindowTrace(sourceReason: String, eventTags: [String: String], delay: TimeInterval) {
        packetWindowVersion += 1
        let version = packetWindowVersion
        logEvent(
            .debug, "packet_window_trace_scheduled",
            fields: [
                "source_reason": sourceReason,
                "delay_seconds": String(format: "%.1f", delay),
            ]
        )
        triggerQueue.asyncAfter(deadline: .now() + delay) {
            // DHCP and IPv6 control packets usually arrive after the CoreWLAN
            // callback. Delay briefly so the packet-window trace contains the
            // address acquisition sequence instead of only the trigger event.
            guard version == self.packetWindowVersion else {
                return
            }
            var tags = eventTags
            tags["packet.window.source_reason"] = sourceReason
            tags["packet.window.delay_seconds"] = String(format: "%.1f", delay)
            self.emitTrace(reason: "wifi.rejoin.packet_window", eventTags: tags, consumePacketSpans: false, includeActive: true)
        }
    }

    func startBPFIfNeeded(interfaceName: String?) {
        guard config.bpfEnabled else {
            return
        }
        guard let interfaceName, !interfaceName.isEmpty else {
            return
        }
        if bpfInterface == interfaceName {
            return
        }
        bpfMonitor?.stop()
        let monitor = PassiveBPFMonitor(interfaceName: interfaceName, store: packetStore) { [weak self] reason, tags in
            self?.triggerQueue.async {
                var eventTags = tags
                eventTags["agent.observation"] = reason
                self?.schedulePacketWindowTrace(sourceReason: reason, eventTags: eventTags, delay: 1.25)
            }
        }
        if let error = monitor.start() {
            logEvent(.warn, "bpf_monitor_start_failed", fields: ["interface": interfaceName, "error": error])
            bpfMonitor = nil
            bpfInterface = nil
            return
        }
        bpfMonitor = monitor
        bpfInterface = interfaceName
        logEvent(.info, "bpf_monitor_started", fields: ["interface": interfaceName, "profiles": "dhcp,icmpv6_control"])
    }

    func logIdentityStatus(_ snapshot: WiFiSnapshot) {
        let signature = [
            snapshot.interfaceName ?? "unknown",
            snapshot.identityStatus,
            snapshot.ssid ?? "unknown",
            snapshot.bssid ?? "unknown",
        ].joined(separator: "|")
        guard signature != lastIdentityStatusLogSignature else {
            return
        }
        lastIdentityStatusLogSignature = signature

        // SSID/BSSID are gated by macOS Location Services. Emit one explicit
        // state-change log so redacted labels are visible without flooding every
        // metrics tick.
        if snapshot.identityAvailable {
            logEvent(
                .info, "wifi_identity_available",
                fields: [
                    "interface": snapshot.interfaceName ?? "unknown",
                    "essid": snapshot.ssid ?? "unknown",
                    "bssid": snapshot.bssid ?? "unknown",
                ]
            )
            return
        }
        logEvent(
            .warn, "wifi_identity_unavailable",
            fields: [
                "status": snapshot.identityStatus,
                "interface": snapshot.interfaceName ?? "unknown",
                "associated": snapshot.isAssociated ? "true" : "false",
                "impact": "essid_bssid_labels_are_unknown",
                "likely_reason": "macos_location_services_corewlan_gate",
            ]
        )
    }

    func emitTrace(reason: String, eventTags: [String: String], consumePacketSpans: Bool, includeActive: Bool) {
        let traceStarted = wallClockNanos()
        let snapshot = captureLatestSnapshot()
        logIdentityStatus(snapshot)
        _ = pushMetrics(snapshot: snapshot)
        let recorder = TraceRecorder()

        logEvent(
            .info, "trace_started",
            fields: [
                "trace_id": recorder.traceId,
                "reason": reason,
                "include_active": includeActive ? "true" : "false",
            ]
        )

        var rootTags = snapshot.traceTags
        rootTags.merge(eventTags) { _, new in new }
        rootTags["reason"] = reason
        rootTags["traces.url"] = config.tracesURL.absoluteString
        rootTags["metrics.push.url"] = config.metricsPushURL.absoluteString
        rootTags["metrics.push.prefix"] = config.metricsPushPrefix
        rootTags["bpf.enabled"] = config.bpfEnabled ? "true" : "false"

        let packetSpans = packetStore.recentPacketSpans(
            interfaceName: snapshot.interfaceName,
            maxAge: config.bpfSpanMaxAge,
            consume: consumePacketSpans
        )
        if !packetSpans.isEmpty, let window = spanWindow(packetSpans) {
            recordPacketWindow(packetSpans, window: window, recorder: recorder, snapshot: snapshot)
        }

        if includeActive {
            recordActiveValidation(recorder: recorder, snapshot: snapshot)
            _ = pushMetrics(snapshot: snapshot)
        }

        let rootName = traceRootName(reason)
        rootTags["trace.root_name"] = rootName
        rootTags["trace.start_epoch_ns"] = "\(traceStarted)"
        let batch = recorder.finish(rootName: rootName, rootTags: rootTags)
        let otelTraceId = telemetry.exportTrace(records: batch)
        logEvent(
            .info, "trace_sent",
            fields: [
                "trace_id": otelTraceId,
                "local_trace_id": recorder.traceId,
                "reason": reason,
                "spans": "\(batch.spans.count + 1)",
                "traces_url": config.tracesURL.absoluteString,
            ]
        )
    }

    func pushMetrics(snapshot: WiFiSnapshot) -> Bool {
        telemetry.pushMetrics(
            job: "watchme_wifi",
            fields: snapshot.traceTags,
            metrics: WiFiMetricBuilder.metrics(snapshot: snapshot, state: metricState)
        )
    }

    private func recordPacketWindow(
        _ packetSpans: [SpanEvent],
        window: (start: UInt64, duration: UInt64),
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        let phaseId = recorder.newSpanId()
        for span in packetSpans {
            recorder.recordEvent(
                span, parentId: phaseId,
                tags: [
                    "wifi.essid": snapshot.ssid ?? "unknown",
                    "wifi.bssid": snapshot.bssid ?? "unknown",
                ]
            )
        }
        recorder.recordSpan(
            name: "phase.wifi_rejoin_packets",
            id: phaseId,
            startWallNanos: window.start,
            durationNanos: window.duration,
            tags: [
                "phase.name": "wifi_rejoin_packets",
                "phase.source": "continuous_bpf",
                "phase.packet_span_count": "\(packetSpans.count)",
            ]
        )
    }

    private func recordActiveValidation(recorder: TraceRecorder, snapshot: WiFiSnapshot) {
        let phaseId = recorder.newSpanId()
        let phaseStart = wallClockNanos()
        let networkState = currentWiFiServiceNetworkState(interfaceName: snapshot.interfaceName)
        var routeTags = defaultRouteTags()
        routeTags.merge(networkState.traceTags) { _, new in new }

        for target in config.probeHTTPTargets {
            recordActiveTarget(target, phaseId: phaseId, routeTags: routeTags, recorder: recorder, snapshot: snapshot)
        }
        recordActiveDNSProbes(phaseId: phaseId, networkState: networkState, recorder: recorder, snapshot: snapshot)
        recordActiveGatewayProbe(phaseId: phaseId, networkState: networkState, recorder: recorder, snapshot: snapshot)

        recorder.recordSpan(
            name: "phase.active_validation",
            id: phaseId,
            startWallNanos: phaseStart,
            durationNanos: max(wallClockNanos() - phaseStart, 1000),
            tags: [
                "phase.name": "active_validation",
                "phase.source": "network_framework_active_probe",
                "phase.validation_scope": "http_head_targets,dns_targets,gateway_tcp",
                "probe.targets": config.probeHTTPTargets.joined(separator: ","),
                "probe.dns_resolvers": networkState.dnsServers.joined(separator: ","),
                "probe.gateway": networkState.routerIPv4 ?? "",
            ]
        )
    }

    private func recordActiveTarget(
        _ target: String,
        phaseId: String,
        routeTags: [String: String],
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        let targetSpanId = recorder.newSpanId()
        let result = runHTTPHeadProbe(target: target, timeout: config.probeHTTPTimeout, interfaceName: snapshot.interfaceName)
        metricState.recordHTTPProbe(result)
        for child in result.childSpans {
            recorder.recordEvent(
                child, parentId: targetSpanId,
                tags: [
                    "probe.target": target,
                    "wifi.essid": snapshot.ssid ?? "unknown",
                    "wifi.bssid": snapshot.bssid ?? "unknown",
                ]
            )
        }
        recorder.recordSpan(
            name: "target.probe",
            id: targetSpanId,
            startWallNanos: result.startWallNanos,
            durationNanos: result.durationNanos,
            parentId: phaseId,
            tags: activeTargetTags(target: target, result: result, routeTags: routeTags, snapshot: snapshot),
            statusOK: result.ok
        )
        logEvent(
            result.ok ? .debug : .warn, "active_probe_completed",
            fields: [
                "trace_id": recorder.traceId,
                "target": target,
                "url": result.url.absoluteString,
                "status": result.ok ? "ok" : "error",
                "status_code": result.statusCode.map(String.init) ?? "",
                "error": result.error ?? "",
            ]
        )
    }

    private func activeTargetTags(
        target: String,
        result: ActiveProbeResult,
        routeTags: [String: String],
        snapshot: WiFiSnapshot
    ) -> [String: String] {
        var tags: [String: String] = [
            "span.source": "active_probe",
            "active_probe.interface": snapshot.interfaceName ?? "",
            "active_probe.required_interface": snapshot.interfaceName ?? "",
            "probe.target": target,
            "url.full": result.url.absoluteString,
            "target.probe.child_span_count": "\(result.childSpans.count)",
        ]
        tags.merge(routeTags) { _, new in new }
        if let statusCode = result.statusCode {
            tags["http.response.status_code"] = "\(statusCode)"
        }
        if let error = result.error {
            tags["error"] = clipped(error, limit: 240)
        }
        return tags
    }

    private func recordActiveDNSProbes(
        phaseId: String,
        networkState: WiFiServiceNetworkState,
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        let resolvers = Array(networkState.dnsServers.prefix(2))
        guard !resolvers.isEmpty else {
            return
        }
        let targets = uniqueProbeHosts(config.probeHTTPTargets)
        let timeout = min(config.probeHTTPTimeout, 2.0)
        for resolver in resolvers {
            for target in targets {
                let result = runDNSAProbe(
                    target: target,
                    resolver: resolver,
                    timeout: timeout,
                    interfaceName: snapshot.interfaceName
                )
                metricState.recordDNSProbe(result)
                recorder.recordSpan(
                    name: "probe.dns.resolve",
                    id: recorder.newSpanId(),
                    startWallNanos: result.startWallNanos,
                    durationNanos: result.durationNanos,
                    parentId: phaseId,
                    tags: activeDNSTags(result: result, snapshot: snapshot),
                    statusOK: result.ok
                )
                logEvent(
                    result.ok ? .debug : .warn, "active_dns_probe_completed",
                    fields: [
                        "trace_id": recorder.traceId,
                        "target": result.target,
                        "resolver": result.resolver,
                        "transport": result.transport,
                        "status": result.ok ? "ok" : "error",
                        "rcode": result.rcode.map(String.init) ?? "",
                        "answers": result.answerCount.map(String.init) ?? "",
                        "error": result.error ?? "",
                    ]
                )
            }
        }
    }

    private func recordActiveGatewayProbe(
        phaseId: String,
        networkState: WiFiServiceNetworkState,
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        guard let gateway = networkState.routerIPv4 else {
            return
        }
        let result = runGatewayTCPConnectProbe(
            gateway: gateway,
            timeout: min(config.probeHTTPTimeout, 2.0),
            interfaceName: snapshot.interfaceName
        )
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
                "error": result.error ?? "",
            ]
        )
    }

    private func activeDNSTags(result: ActiveDNSProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags: [String: String] = [
            "span.source": "network_framework_dns_probe",
            "active_probe.interface": snapshot.interfaceName ?? "",
            "active_probe.required_interface": snapshot.interfaceName ?? "",
            "probe.target": result.target,
            "dns.resolver": result.resolver,
            "dns.transport": result.transport,
            "dns.answer_count": result.answerCount.map(String.init) ?? "",
            "wifi.essid": snapshot.ssid ?? "unknown",
            "wifi.bssid": snapshot.bssid ?? "unknown",
        ]
        if let rcode = result.rcode {
            tags["dns.rcode"] = "\(rcode)"
        }
        if let error = result.error {
            tags["error"] = clipped(error, limit: 240)
        }
        return tags
    }

    private func activeGatewayTags(result: ActiveGatewayProbeResult, snapshot: WiFiSnapshot) -> [String: String] {
        var tags: [String: String] = [
            "span.source": "network_framework_gateway_probe",
            "active_probe.interface": snapshot.interfaceName ?? "",
            "active_probe.required_interface": snapshot.interfaceName ?? "",
            "network.wifi_gateway": result.gateway,
            "network.gateway_probe.port": "\(result.port)",
            "network.gateway_probe.outcome": result.outcome,
            "network.gateway_probe.reachable": result.reachable ? "true" : "false",
            "network.gateway_probe.connect_success": result.connectSuccess ? "true" : "false",
            "wifi.essid": snapshot.ssid ?? "unknown",
            "wifi.bssid": snapshot.bssid ?? "unknown",
        ]
        if let error = result.error {
            tags["error"] = clipped(error, limit: 240)
        }
        return tags
    }
}

func uniqueProbeHosts(_ targets: [String]) -> [String] {
    var seen = Set<String>()
    return targets.compactMap { target in
        let host = normalizedTargetURL(target).host ?? target
        guard !host.isEmpty, !seen.contains(host) else {
            return nil
        }
        seen.insert(host)
        return host
    }
}
