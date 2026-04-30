import Foundation
import WatchmeBPF
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
        logEvent(
            .info,
            "bpf_monitor_started",
            fields: ["interface": interfaceName, "profiles": "dhcp,icmpv6_control,active_dns,active_icmp,active_http"]
        )
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
        _ = exportMetrics(snapshot: snapshot)
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
        rootTags["otlp.url"] = config.otlpURL.absoluteString
        rootTags["bpf.enabled"] = config.bpfEnabled ? "true" : "false"

        let networkState = currentWiFiServiceNetworkState(interfaceName: snapshot.interfaceName)
        if let bpfStats = bpfMonitor?.stats() {
            rootTags["bpf.filter"] = watchmeWiFiBPFFilterName
            rootTags["bpf.packets_received"] = "\(bpfStats.packetsReceived)"
            rootTags["bpf.packets_dropped"] = "\(bpfStats.packetsDropped)"
        }

        let packetSpans = packetStore.recentPacketSpans(
            interfaceName: snapshot.interfaceName,
            ipv4Gateway: networkState.routerIPv4,
            maxAge: config.bpfSpanMaxAge,
            consume: consumePacketSpans
        )
        if !packetSpans.isEmpty, let window = spanWindow(packetSpans) {
            recordPacketWindow(packetSpans, window: window, recorder: recorder, snapshot: snapshot)
        }

        if includeActive {
            recordActiveValidation(recorder: recorder, snapshot: snapshot, networkState: networkState)
            _ = exportMetrics(snapshot: snapshot)
        }

        let rootName = traceRootName(reason)
        rootTags["trace.root_name"] = rootName
        rootTags["trace.start_epoch_ns"] = "\(traceStarted)"
        let batch = recorder.finish(rootName: rootName, rootTags: rootTags)
        let result = telemetry.exportTrace(records: batch)
        var logFields = [
            "trace_id": result.traceId,
            "local_trace_id": recorder.traceId,
            "reason": reason,
            "spans": "\(batch.spans.count + 1)",
            "otlp_url": config.otlpURL.absoluteString,
            "traces_endpoint_url": result.endpoint.absoluteString,
        ]
        if let error = result.error {
            logFields["error"] = error
        }
        logEvent(
            result.ok ? .info : .warn,
            result.ok ? "trace_sent" : "trace_export_failed",
            fields: logFields
        )
    }

    func exportMetrics(snapshot: WiFiSnapshot) -> Bool {
        telemetry.exportMetrics(
            name: "watchme_wifi",
            fields: snapshot.traceTags,
            metrics: WiFiMetricBuilder.metrics(snapshot: snapshot, state: metricState, bpfStats: bpfMonitor?.stats())
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

    private func recordActiveValidation(recorder: TraceRecorder, snapshot: WiFiSnapshot, networkState: WiFiServiceNetworkState) {
        let phaseId = recorder.newSpanId()
        let phaseStart = wallClockNanos()
        let internetResults = runActiveInternetProbes(
            config: config,
            networkState: networkState,
            interfaceName: snapshot.interfaceName,
            packetStore: packetStore
        )
        let gatewayResult = runGatewayProbe(networkState: networkState, snapshot: snapshot)

        recordInternetProbeResults(internetResults, phaseId: phaseId, recorder: recorder, snapshot: snapshot)
        if let gatewayResult {
            recordGatewayProbeResult(gatewayResult, phaseId: phaseId, recorder: recorder, snapshot: snapshot)
        }

        recorder.recordSpan(
            name: "phase.active_validation",
            id: phaseId,
            startWallNanos: phaseStart,
            durationNanos: max(wallClockNanos() - phaseStart, 1000),
            tags: [
                "phase.name": "active_validation",
                "phase.source": "network_framework_active_probe",
                "phase.validation_scope": "internet_dns,internet_icmp,internet_http,gateway_icmp",
                "probe.internet.targets": config.probeInternetTargets.joined(separator: ","),
                "probe.internet.family": config.probeInternetFamily.metricValue,
                "probe.internet.dns.enabled": config.probeInternetDNS ? "true" : "false",
                "probe.internet.icmp.enabled": config.probeInternetICMP ? "true" : "false",
                "probe.internet.http.enabled": config.probeInternetHTTP ? "true" : "false",
                "probe.internet.dns.span_count": "\(internetResults.dns.count)",
                "probe.internet.icmp.span_count": "\(internetResults.icmp.count)",
                "probe.internet.http.span_count": "\(internetResults.http.count)",
                "probe.dns_resolvers": networkState.dnsServers.joined(separator: ","),
                "probe.gateway": networkState.routerIPv4 ?? "",
                "probe.gateway.burst_count": "\(config.probeGatewayBurstCount)",
                "probe.gateway.burst_interval_seconds": formatGatewayProbeDouble(config.probeGatewayBurstInterval),
                "probe.gateway.probe_count": gatewayResult.map { "\($0.probeCount)" } ?? "0",
                "probe.gateway.span_count": gatewayResult == nil ? "0" : "1",
            ]
        )
    }

    private func runGatewayProbe(networkState: WiFiServiceNetworkState, snapshot: WiFiSnapshot) -> ActiveGatewayProbeResult? {
        guard let gateway = networkState.routerIPv4 else {
            return nil
        }
        return runGatewayICMPProbe(
            gateway: gateway,
            timeout: min(config.probeInternetTimeout, 2.0),
            interfaceName: snapshot.interfaceName,
            packetStore: packetStore,
            burstCount: config.probeGatewayBurstCount,
            burstInterval: config.probeGatewayBurstInterval
        )
    }
}
