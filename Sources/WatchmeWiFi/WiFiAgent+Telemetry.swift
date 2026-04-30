import Foundation
import WatchmeBPF
import WatchmeCore
import WatchmeTelemetry

extension WiFiAgent {
    func triggerTrace(
        reason: String,
        eventTags: [String: String],
        force: Bool,
        includeConnectivityCheck: Bool,
        connectivityReadinessTimeout: TimeInterval = 0
    ) {
        triggerQueue.async {
            if self.associationTracePending, WiFiTracePolicy.shouldSuppressEventTraceDuringAssociation(reason: reason) {
                logEvent(
                    .debug, "trace_trigger_suppressed",
                    fields: [
                        "reason": reason,
                        "suppression_reason": "association_trace_pending",
                    ]
                )
                return
            }
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
            self.emitTrace(
                reason: reason,
                eventTags: eventTags,
                consumePacketSpans: true,
                includeConnectivityCheck: includeConnectivityCheck,
                connectivityReadinessTimeout: connectivityReadinessTimeout
            )
        }
    }

    func scheduleAssociationTrace(sourceReason: String? = nil, reason: String, eventTags: [String: String], delay: TimeInterval) {
        associationTraceVersion += 1
        associationTracePending = true
        packetWindowSuppressedUntil = Date().addingTimeInterval(
            delay + config.associationTraceReadinessTimeout + config.packetWindowSuppressionAfterAssociation
        )
        let version = associationTraceVersion
        let sourceReason = sourceReason ?? reason
        logEvent(
            .debug, "association_trace_scheduled",
            fields: [
                "source_reason": sourceReason,
                "reason": reason,
                "delay_seconds": String(format: "%.1f", delay),
                "readiness_timeout_seconds": String(format: "%.1f", config.associationTraceReadinessTimeout),
            ]
        )
        triggerQueue.asyncAfter(deadline: .now() + delay) {
            guard version == self.associationTraceVersion else {
                return
            }
            var tags = eventTags
            tags["association.source_reason"] = sourceReason
            tags["association.delay_seconds"] = String(format: "%.1f", delay)
            self.emitTrace(
                reason: reason,
                eventTags: tags,
                consumePacketSpans: true,
                includeConnectivityCheck: true,
                connectivityReadinessTimeout: self.config.associationTraceReadinessTimeout
            )
            self.associationTracePending = false
            self.packetWindowSuppressedUntil = Date().addingTimeInterval(self.config.packetWindowSuppressionAfterAssociation)
        }
    }

    func schedulePacketWindowTrace(sourceReason: String, eventTags: [String: String], delay: TimeInterval) {
        if associationTracePending || Date() < packetWindowSuppressedUntil {
            logEvent(
                .debug, "network_attachment_trace_suppressed",
                fields: [
                    "source_reason": sourceReason,
                    "suppression_reason": associationTracePending ? "association_trace_pending" : "association_trace_recently_completed",
                ]
            )
            return
        }
        packetWindowVersion += 1
        let version = packetWindowVersion
        logEvent(
            .debug, "network_attachment_trace_scheduled",
            fields: [
                "source_reason": sourceReason,
                "delay_seconds": String(format: "%.1f", delay),
            ]
        )
        triggerQueue.asyncAfter(deadline: .now() + delay) {
            // DHCP and IPv6 control packets usually arrive after the CoreWLAN
            // callback. Delay briefly so the network-attachment trace contains
            // the address acquisition sequence instead of only the trigger event.
            guard version == self.packetWindowVersion else {
                return
            }
            guard !self.associationTracePending, Date() >= self.packetWindowSuppressedUntil else {
                logEvent(
                    .debug, "network_attachment_trace_suppressed",
                    fields: [
                        "source_reason": sourceReason,
                        "suppression_reason": self.associationTracePending ? "association_trace_pending" : "association_trace_recently_completed",
                    ]
                )
                return
            }
            var tags = eventTags
            tags["network_attachment.source_reason"] = sourceReason
            tags["network_attachment.delay_seconds"] = String(format: "%.1f", delay)
            self.emitTrace(reason: "wifi.network.attachment", eventTags: tags, consumePacketSpans: true, includeConnectivityCheck: true)
            self.packetWindowSuppressedUntil = Date().addingTimeInterval(self.config.packetWindowSuppressionAfterAssociation)
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
                guard let self else {
                    return
                }
                self.schedulePacketWindowTrace(sourceReason: reason, eventTags: eventTags, delay: self.config.packetWindowTraceDelay)
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
            fields: ["interface": interfaceName, "profiles": "dhcp,icmpv6_control,active_dns,active_icmp,active_tcp,active_http"]
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

    func emitTrace(
        reason: String,
        eventTags: [String: String],
        consumePacketSpans: Bool,
        includeConnectivityCheck: Bool,
        connectivityReadinessTimeout: TimeInterval = 0
    ) {
        let traceStarted = wallClockNanos()
        let context = traceCaptureContext(
            includeConnectivityCheck: includeConnectivityCheck,
            connectivityReadinessTimeout: connectivityReadinessTimeout
        )
        let snapshot = context.snapshot
        let networkState = context.networkState
        let connectivityReadiness = context.connectivityReadiness
        logIdentityStatus(snapshot)
        _ = exportMetrics(snapshot: snapshot)
        let recorder = TraceRecorder()

        logEvent(
            .info, "trace_started",
            fields: [
                "trace_id": recorder.traceId,
                "reason": reason,
                "include_connectivity_check": includeConnectivityCheck ? "true" : "false",
                "connectivity_readiness": connectivityReadiness.ready ? "ready" : "not_ready",
            ]
        )

        var rootTags = snapshot.traceTags
        rootTags.merge(networkState.traceTags) { _, new in new }
        rootTags.merge(eventTags) { _, new in new }
        rootTags["reason"] = reason
        rootTags["otlp.url"] = config.otlpURL.absoluteString
        rootTags["bpf.enabled"] = config.bpfEnabled ? "true" : "false"
        rootTags["connectivity_check.requested"] = includeConnectivityCheck ? "true" : "false"
        rootTags["connectivity_check.ready"] = connectivityReadiness.ready ? "true" : "false"
        rootTags["connectivity_check.readiness_wait_seconds"] = String(format: "%.3f", context.connectivityReadinessWait)
        if connectivityReadinessTimeout > 0 {
            rootTags["connectivity_check.readiness_timeout_seconds"] = String(format: "%.3f", connectivityReadinessTimeout)
        }
        if let skipReason = connectivityReadiness.skipReason {
            rootTags["connectivity_check.skip_reason"] = skipReason
        }

        if let bpfStats = bpfMonitor?.stats() {
            rootTags["bpf.filter"] = watchmeWiFiBPFFilterName
            rootTags["bpf.packets_received"] = "\(bpfStats.packetsReceived)"
            rootTags["bpf.packets_dropped"] = "\(bpfStats.packetsDropped)"
        }

        let packetSpans = packetStore.recentPacketSpans(
            interfaceName: snapshot.interfaceName,
            ipv4Gateway: networkState.routerIPv4,
            maxAge: config.bpfSpanMaxAge,
            consume: consumePacketSpans,
            includeConsumed: { self.shouldReplayConsumedPacketSpan(reason: reason, span: $0) }
        )
        if !packetSpans.isEmpty, let window = spanWindow(packetSpans) {
            recordNetworkAttachment(packetSpans, window: window, recorder: recorder, snapshot: snapshot)
        }

        if includeConnectivityCheck, connectivityReadiness.ready {
            rootTags["connectivity_check.included"] = "true"
            recordConnectivityCheck(recorder: recorder, snapshot: snapshot, networkState: networkState)
            _ = exportMetrics(snapshot: snapshot)
        } else {
            rootTags["connectivity_check.included"] = "false"
            if includeConnectivityCheck {
                logEvent(
                    .info, "connectivity_check_skipped",
                    fields: [
                        "reason": reason,
                        "skip_reason": connectivityReadiness.skipReason ?? "not_ready",
                        "associated": snapshot.isAssociated ? "true" : "false",
                        "power_on": snapshot.powerOn.map { $0 ? "true" : "false" } ?? "unknown",
                        "dns_resolvers": networkState.dnsServers.joined(separator: ","),
                    ]
                )
            }
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

    private func traceCaptureContext(
        includeConnectivityCheck: Bool,
        connectivityReadinessTimeout: TimeInterval
    ) -> (
        snapshot: WiFiSnapshot,
        networkState: WiFiServiceNetworkState,
        connectivityReadiness: WiFiConnectivityCheckReadiness,
        connectivityReadinessWait: TimeInterval
    ) {
        let waitStarted = Date()
        var snapshot = captureLatestSnapshot()
        var networkState = currentWiFiServiceNetworkState(interfaceName: snapshot.interfaceName)
        var readiness = WiFiTracePolicy.connectivityCheckReadiness(
            snapshot: snapshot,
            networkState: networkState,
            config: config
        )

        guard includeConnectivityCheck, connectivityReadinessTimeout > 0, !readiness.ready else {
            return (snapshot, networkState, readiness, 0)
        }

        let deadline = waitStarted.addingTimeInterval(connectivityReadinessTimeout)
        while Date() < deadline {
            let remaining = deadline.timeIntervalSinceNow
            Thread.sleep(forTimeInterval: min(max(remaining, 0.01), config.connectivityReadinessPollInterval))
            snapshot = captureLatestSnapshot()
            networkState = currentWiFiServiceNetworkState(interfaceName: snapshot.interfaceName)
            readiness = WiFiTracePolicy.connectivityCheckReadiness(
                snapshot: snapshot,
                networkState: networkState,
                config: config
            )
            if readiness.ready {
                break
            }
        }

        return (snapshot, networkState, readiness, Date().timeIntervalSince(waitStarted))
    }

    func exportMetrics(snapshot: WiFiSnapshot) -> Bool {
        telemetry.exportMetrics(
            name: "watchme_wifi",
            fields: snapshot.traceTags,
            metrics: WiFiMetricBuilder.metrics(snapshot: snapshot, state: metricState, bpfStats: bpfMonitor?.stats())
        )
    }

    private func recordNetworkAttachment(
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
            name: "phase.network_attachment",
            id: phaseId,
            startWallNanos: window.start > 1000 ? window.start - 1000 : window.start,
            durationNanos: window.duration + 1000,
            tags: [
                "phase.name": "network_attachment",
                "phase.source": "passive_bpf",
                "phase.packet_span_count": "\(packetSpans.count)",
            ]
        )
    }

    private func recordConnectivityCheck(recorder: TraceRecorder, snapshot: WiFiSnapshot, networkState: WiFiServiceNetworkState) {
        let phaseId = recorder.newSpanId()
        let phaseStart = wallClockNanos()
        let gatewayResult = runGatewayProbe(networkState: networkState, snapshot: snapshot)

        if let gatewayResult {
            recordGatewayProbeResult(gatewayResult, phaseId: phaseId, recorder: recorder, snapshot: snapshot)
        }
        let internetResults: ActiveInternetProbeResults
        let internetSkippedReason: String?
        if gatewayResult?.reachable == false {
            internetResults = ActiveInternetProbeResults(lanes: [])
            internetSkippedReason = "gateway_unreachable"
        } else {
            internetResults = runActiveInternetProbes(
                config: config,
                networkState: networkState,
                interfaceName: snapshot.interfaceName,
                packetStore: packetStore
            )
            internetSkippedReason = nil
            recordInternetProbeResults(internetResults, phaseId: phaseId, recorder: recorder, snapshot: snapshot)
        }

        var phaseTags: [String: String] = [
            "phase.name": "connectivity_check",
            "phase.source": "wifi_connectivity_probe",
            "phase.check_scope": "gateway_icmp,internet_dns,internet_icmp,internet_tcp,internet_http",
            "probe.internet.targets": config.probeInternetTargets.joined(separator: ","),
            "probe.internet.family": config.probeInternetFamily.metricValue,
            "probe.internet.dns.enabled": config.probeInternetDNS ? "true" : "false",
            "probe.internet.icmp.enabled": config.probeInternetICMP ? "true" : "false",
            "probe.internet.tcp.enabled": config.probeInternetTCP ? "true" : "false",
            "probe.internet.http.enabled": config.probeInternetHTTP ? "true" : "false",
            "probe.internet.path.span_count": "\(internetResults.lanes.count)",
            "probe.internet.dns.span_count": "\(internetResults.dns.count)",
            "probe.internet.icmp.span_count": "\(internetResults.icmp.count)",
            "probe.internet.tcp.span_count": "\(internetResults.tcp.count)",
            "probe.internet.http.span_count": "\(internetResults.http.count)",
            "probe.dns_resolvers": networkState.dnsServers.joined(separator: ","),
            "probe.gateway": networkState.routerIPv4 ?? "",
            "probe.gateway.burst_count": "\(config.probeGatewayBurstCount)",
            "probe.gateway.burst_interval_seconds": formatGatewayProbeDouble(config.probeGatewayBurstInterval),
            "probe.gateway.probe_count": gatewayResult.map { "\($0.probeCount)" } ?? "0",
            "probe.gateway.span_count": gatewayResult == nil ? "0" : "1",
        ]
        setTag(&phaseTags, "probe.internet.skipped_reason", internetSkippedReason)
        recorder.recordSpan(
            name: "phase.connectivity_check",
            id: phaseId,
            startWallNanos: phaseStart,
            durationNanos: max(wallClockNanos() - phaseStart, 1000),
            tags: phaseTags
        )
    }

    private func shouldReplayConsumedPacketSpan(reason: String, span: SpanEvent) -> Bool {
        WiFiTracePolicy.isAssociationRecoveryReason(reason) && span.name.hasPrefix("packet.dhcp.")
    }

    private func runGatewayProbe(networkState: WiFiServiceNetworkState, snapshot: WiFiSnapshot) -> ActiveGatewayProbeResult? {
        guard let gateway = networkState.routerIPv4 else {
            return nil
        }
        return runGatewayICMPProbe(
            gateway: gateway,
            gatewayHardwareAddress: networkState.routerHardwareAddress,
            timeout: min(config.probeInternetTimeout, 2.0),
            interfaceName: snapshot.interfaceName,
            packetStore: packetStore,
            burstCount: config.probeGatewayBurstCount,
            burstInterval: config.probeGatewayBurstInterval,
            useDirectBPF: config.bpfEnabled
        )
    }
}
