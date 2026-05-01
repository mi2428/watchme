import Foundation
import WatchmeBPF
import WatchmeCore
import WatchmeTelemetry

extension WiFiAgent {
    func emitTrace(
        reason: String,
        eventTags: [String: String],
        consumePacketSpans: Bool,
        includeConnectivityCheck: Bool,
        connectivityReadinessTimeout: TimeInterval = 0
    ) {
        let traceStarted = wallClockNanos()
        let context = traceCaptureContext(
            reason: reason,
            includeConnectivityCheck: includeConnectivityCheck,
            connectivityReadinessTimeout: connectivityReadinessTimeout
        )
        let snapshot = context.snapshot
        let networkState = context.networkState
        let connectivityReadiness = context.connectivityReadiness

        if shouldSuppressNetworkAttachmentTrace(reason: reason, readiness: connectivityReadiness) {
            logSkippedNetworkAttachmentTrace(reason: reason, snapshot: snapshot, readiness: connectivityReadiness)
            return
        }
        if shouldSuppressStaleAssociationTrace(reason: reason, readiness: connectivityReadiness) {
            logSkippedAssociationTrace(reason: reason, snapshot: snapshot, readiness: connectivityReadiness)
            return
        }

        logIdentityStatus(snapshot)
        _ = exportMetrics(snapshot: snapshot)

        var rootTags = traceRootTags(
            reason: reason,
            eventTags: eventTags,
            context: context,
            includeConnectivityCheck: includeConnectivityCheck,
            connectivityReadinessTimeout: connectivityReadinessTimeout
        )
        let packetCapture = passivePacketSpanCapture(WiFiPassivePacketSpanRequest(
            reason: reason,
            eventTags: eventTags,
            traceStarted: traceStarted,
            snapshot: snapshot,
            networkState: networkState,
            consumePacketSpans: consumePacketSpans,
            connectivityReadinessTimeout: connectivityReadinessTimeout
        ))
        if let packetSpanWindowStart = packetCapture.windowStart {
            rootTags["packet_span.window_start_epoch_ns"] = "\(packetSpanWindowStart)"
        }
        if shouldSuppressNetworkAttachmentPacketTrace(reason: reason, eventTags: eventTags, packetSpans: packetCapture.spans) {
            return
        }

        let recorder = TraceRecorder()
        logTraceStarted(
            traceId: recorder.traceId,
            reason: reason,
            includeConnectivityCheck: includeConnectivityCheck,
            connectivityReadiness: connectivityReadiness
        )
        if !packetCapture.spans.isEmpty, let window = spanWindow(packetCapture.spans) {
            recordNetworkAttachment(packetCapture.spans, window: window, recorder: recorder, snapshot: snapshot)
        }
        if includeConnectivityCheck, connectivityReadiness.ready {
            rootTags["connectivity_check.included"] = "true"
            recordConnectivityCheck(recorder: recorder, snapshot: snapshot, networkState: networkState)
            _ = exportMetrics(snapshot: snapshot)
        } else {
            rootTags["connectivity_check.included"] = "false"
            logSkippedConnectivityCheckIfNeeded(
                reason: reason,
                includeConnectivityCheck: includeConnectivityCheck,
                snapshot: snapshot,
                networkState: networkState,
                connectivityReadiness: connectivityReadiness
            )
        }
        exportTrace(recorder: recorder, rootTags: rootTags, reason: reason, traceStarted: traceStarted)
    }

    func exportMetrics(snapshot: WiFiSnapshot) -> Bool {
        telemetry.exportMetrics(
            name: "watchme_wifi",
            fields: snapshot.traceTags,
            metrics: WiFiMetricBuilder.metrics(snapshot: snapshot, state: metricState, bpfStats: bpfMonitor?.stats())
        )
    }

    private func traceCaptureContext(
        reason: String,
        includeConnectivityCheck: Bool,
        connectivityReadinessTimeout: TimeInterval
    ) -> WiFiTraceCaptureContext {
        let waitStarted = Date()
        var snapshot = captureLatestSnapshot()
        var networkState = currentWiFiServiceNetworkState(interfaceName: snapshot.interfaceName)
        var readiness = WiFiTracePolicy.connectivityCheckReadiness(
            snapshot: snapshot,
            networkState: networkState,
            config: config
        )
        let waitsForAssociationNetworkState = WiFiTracePolicy.isAssociationRecoveryReason(reason)

        guard includeConnectivityCheck, connectivityReadinessTimeout > 0 else {
            return WiFiTraceCaptureContext(
                snapshot: snapshot,
                networkState: networkState,
                connectivityReadiness: readiness,
                connectivityReadinessWait: 0
            )
        }
        if shouldStopWaitingForConnectivityReadiness(
            snapshot: snapshot,
            networkState: networkState,
            readiness: readiness,
            waitsForAssociationNetworkState: waitsForAssociationNetworkState
        ) {
            return WiFiTraceCaptureContext(
                snapshot: snapshot,
                networkState: networkState,
                connectivityReadiness: readiness,
                connectivityReadinessWait: 0
            )
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
            if shouldStopWaitingForConnectivityReadiness(
                snapshot: snapshot,
                networkState: networkState,
                readiness: readiness,
                waitsForAssociationNetworkState: waitsForAssociationNetworkState
            ) {
                break
            }
        }

        return WiFiTraceCaptureContext(
            snapshot: snapshot,
            networkState: networkState,
            connectivityReadiness: readiness,
            connectivityReadinessWait: Date().timeIntervalSince(waitStarted)
        )
    }

    private func shouldStopWaitingForConnectivityReadiness(
        snapshot: WiFiSnapshot,
        networkState: WiFiServiceNetworkState,
        readiness: WiFiConnectivityCheckReadiness,
        waitsForAssociationNetworkState: Bool
    ) -> Bool {
        readiness.ready
            && (!waitsForAssociationNetworkState || !WiFiTracePolicy.shouldContinueWaitingForAssociationNetworkState(
                snapshot: snapshot,
                networkState: networkState,
                config: config
            ))
    }

    private func traceRootTags(
        reason: String,
        eventTags: [String: String],
        context: WiFiTraceCaptureContext,
        includeConnectivityCheck: Bool,
        connectivityReadinessTimeout: TimeInterval
    ) -> [String: String] {
        var tags = context.snapshot.traceTags
        tags.merge(context.networkState.traceTags) { _, new in new }
        tags.merge(eventTags) { _, new in new }
        tags["reason"] = reason
        tags["otlp.url"] = config.otlpURL.absoluteString
        tags["bpf.enabled"] = config.bpfEnabled ? "true" : "false"
        tags["connectivity_check.requested"] = includeConnectivityCheck ? "true" : "false"
        tags["connectivity_check.ready"] = context.connectivityReadiness.ready ? "true" : "false"
        tags["connectivity_check.readiness_wait_seconds"] = String(format: "%.3f", context.connectivityReadinessWait)
        if connectivityReadinessTimeout > 0 {
            tags["connectivity_check.readiness_timeout_seconds"] = String(format: "%.3f", connectivityReadinessTimeout)
        }
        if let skipReason = context.connectivityReadiness.skipReason {
            tags["connectivity_check.skip_reason"] = skipReason
        }
        if let bpfStats = bpfMonitor?.stats() {
            tags["bpf.filter"] = watchmeWiFiBPFFilterName
            tags["bpf.packets_received"] = "\(bpfStats.packetsReceived)"
            tags["bpf.packets_dropped"] = "\(bpfStats.packetsDropped)"
        }
        return tags
    }

    private func passivePacketSpanCapture(_ request: WiFiPassivePacketSpanRequest) -> WiFiPassivePacketSpanCapture {
        let windowStart = passivePacketSpanWindowStart(
            reason: request.reason,
            eventTags: request.eventTags,
            traceStarted: request.traceStarted,
            associationLookback: config.associationTraceDelay + request.connectivityReadinessTimeout + 2.0,
            attachmentLookback: config.associationTraceDelay + config.associationTraceReadinessTimeout + 2.0
        )
        guard shouldAttachPassivePacketSpans(reason: request.reason) else {
            return WiFiPassivePacketSpanCapture(spans: [], windowStart: windowStart)
        }
        let snapshot = request.snapshot
        let networkState = request.networkState
        let interfaceState = request.snapshot.interfaceName.map(nativeInterfaceState(interfaceName:))
        let spans = packetStore.recentPacketSpans(
            interfaceName: snapshot.interfaceName,
            ipv4Gateway: networkState.routerIPv4,
            maxAge: config.bpfSpanMaxAge,
            since: windowStart,
            consume: request.consumePacketSpans,
            includeConsumed: {
                shouldReplayConsumedNetworkAttachmentSpan(reason: request.reason, span: $0, replayStart: windowStart)
            },
            localHardwareAddress: interfaceState?.macAddress,
            localIPv4Addresses: interfaceState?.ipv4Addresses ?? snapshot.ipv4Addresses,
            localIPv6Addresses: (interfaceState?.ipv6Addresses ?? snapshot.ipv6Addresses)
                + (interfaceState?.ipv6LinkLocalAddresses ?? []),
            ipv6Gateway: networkState.routerIPv6
        )
        return WiFiPassivePacketSpanCapture(spans: spans, windowStart: windowStart)
    }

    private func logSkippedNetworkAttachmentTrace(
        reason: String,
        snapshot: WiFiSnapshot,
        readiness: WiFiConnectivityCheckReadiness
    ) {
        logEvent(
            .info, "network_attachment_trace_suppressed",
            fields: [
                "reason": reason,
                "suppression_reason": readiness.skipReason ?? "not_ready",
                "associated": snapshot.isAssociated ? "true" : "false",
                "power_on": snapshot.powerOn.map { $0 ? "true" : "false" } ?? "unknown",
            ]
        )
    }

    private func logSkippedAssociationTrace(
        reason: String,
        snapshot: WiFiSnapshot,
        readiness: WiFiConnectivityCheckReadiness
    ) {
        logEvent(
            .info, "association_trace_suppressed",
            fields: [
                "reason": reason,
                "suppression_reason": readiness.skipReason ?? "not_ready",
                "associated": snapshot.isAssociated ? "true" : "false",
                "power_on": snapshot.powerOn.map { $0 ? "true" : "false" } ?? "unknown",
            ]
        )
    }

    private func shouldSuppressNetworkAttachmentPacketTrace(
        reason: String,
        eventTags: [String: String],
        packetSpans: [SpanEvent]
    ) -> Bool {
        guard reason == "wifi.network.attachment", !networkAttachmentTraceHasAddressAcquisitionEvidence(packetSpans) else {
            return false
        }
        logEvent(
            .debug, "network_attachment_trace_suppressed",
            fields: [
                "source_reason": eventTags["network_attachment.source_reason"] ?? eventTags["agent.observation"] ?? reason,
                "suppression_reason": "no_address_acquisition_packet_span",
                "packet_span_count": "\(packetSpans.count)",
            ]
        )
        return true
    }

    private func logTraceStarted(
        traceId: String,
        reason: String,
        includeConnectivityCheck: Bool,
        connectivityReadiness: WiFiConnectivityCheckReadiness
    ) {
        logEvent(
            .info, "trace_started",
            fields: [
                "trace_id": traceId,
                "reason": reason,
                "include_connectivity_check": includeConnectivityCheck ? "true" : "false",
                "connectivity_readiness": connectivityReadiness.ready ? "ready" : "not_ready",
            ]
        )
    }

    private func logSkippedConnectivityCheckIfNeeded(
        reason: String,
        includeConnectivityCheck: Bool,
        snapshot: WiFiSnapshot,
        networkState: WiFiServiceNetworkState,
        connectivityReadiness: WiFiConnectivityCheckReadiness
    ) {
        guard includeConnectivityCheck else {
            return
        }
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

    private func exportTrace(recorder: TraceRecorder, rootTags: [String: String], reason: String, traceStarted: UInt64) {
        var rootTags = rootTags
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
}
