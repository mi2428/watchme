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
            let suppressesEventAfterAssociation = !force
                && now < self.packetWindowSuppressedUntil
                && WiFiTracePolicy.shouldSuppressEventTraceAfterAssociation(reason: reason)
            if suppressesEventAfterAssociation {
                logEvent(
                    .debug, "trace_trigger_suppressed",
                    fields: [
                        "reason": reason,
                        "suppression_reason": "association_trace_recently_completed",
                    ]
                )
                return
            }
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
            guard self.markDisconnectTraceAcceptedIfNeeded(reason: reason) else {
                logEvent(
                    .debug, "trace_trigger_suppressed",
                    fields: [
                        "reason": reason,
                        "suppression_reason": "disconnect_trace_already_emitted_for_current_outage",
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

    func markDisconnectTraceAcceptedIfNeeded(reason: String) -> Bool {
        guard reason == "wifi.disconnect" else {
            return true
        }
        guard !disconnectTraceEmittedForCurrentOutage else {
            return false
        }
        disconnectTraceEmittedForCurrentOutage = true
        return true
    }

    func resetDisconnectTraceDedupeIfRecovered(snapshot: WiFiSnapshot) {
        if snapshot.isAssociated {
            disconnectTraceEmittedForCurrentOutage = false
        }
    }

    func scheduleAssociationTrace(sourceReason: String? = nil, reason: String, eventTags: [String: String], delay: TimeInterval) {
        if WiFiTracePolicy.shouldSuppressCoveredAssociationTrace(
            eventTags: eventTags,
            lastCompletedEpochNanos: lastAssociationTraceCompletedEpochNanos
        ) || WiFiTracePolicy.shouldSuppressCompletedAssociationWindowTrace(
            eventTags: eventTags,
            lastCompletedWindowFloorEpochNanos: lastAssociationTraceWindowFloorEpochNanos
        ) {
            logEvent(
                .debug, "association_trace_suppressed",
                fields: [
                    "reason": reason,
                    "suppression_reason": "event_already_covered_by_association_trace",
                    "last_association_trace_completed_epoch_ns": lastAssociationTraceCompletedEpochNanos.map(String.init) ?? "",
                    "last_association_trace_window_floor_epoch_ns": lastAssociationTraceWindowFloorEpochNanos.map(String.init) ?? "",
                ]
            )
            return
        }
        if WiFiTracePolicy.shouldSuppressPendingAssociationWindowTrace(
            eventTags: eventTags,
            pendingWindowFloorEpochNanos: pendingAssociationTraceWindowFloorEpochNanos
        ) {
            logEvent(
                .debug, "association_trace_suppressed",
                fields: [
                    "reason": reason,
                    "suppression_reason": "association_trace_already_pending_for_recovery_window",
                    "pending_association_trace_window_floor_epoch_ns": pendingAssociationTraceWindowFloorEpochNanos.map(String.init) ?? "",
                    "incoming_association_trace_window_floor_epoch_ns": eventTags["association.window_floor_epoch_ns"] ?? "",
                ]
            )
            return
        }
        associationTraceVersion += 1
        associationTracePending = true
        pendingAssociationTraceWindowFloorEpochNanos = UInt64(eventTags["association.window_floor_epoch_ns"] ?? "")
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
            self.lastAssociationTraceCompletedEpochNanos = wallClockNanos()
            self.lastAssociationTraceWindowFloorEpochNanos = UInt64(tags["association.window_floor_epoch_ns"] ?? "")
            self.associationTracePending = false
            self.pendingAssociationTraceWindowFloorEpochNanos = nil
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
                        "suppression_reason": self
                            .associationTracePending ? "association_trace_pending" : "association_trace_recently_completed",
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
}
