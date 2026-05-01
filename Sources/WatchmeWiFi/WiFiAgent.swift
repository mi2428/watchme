import Darwin
import Foundation
import SystemConfiguration
import WatchmeCore
import WatchmeTelemetry

final class WiFiAgent: WatchmeCollector {
    let config: WiFiConfig
    let telemetry: TelemetryClient
    let packetStore = PassivePacketStore()
    let triggerQueue = DispatchQueue(label: "watchme.wifi.trigger")
    var lastSnapshot = WiFiSnapshot.capture()
    var lastEventSnapshot = WiFiSnapshot.capture()
    var lastTrigger = Date.distantPast
    var bpfMonitor: PassiveBPFMonitor?
    var bpfInterface: String?
    var coreWLANMonitor: CoreWLANEventMonitor?
    var systemNetworkMonitor: SystemNetworkEventMonitor?
    var metricsTimer: DispatchSourceTimer?
    var activeTimer: DispatchSourceTimer?
    var packetWindowVersion = 0
    var associationTraceVersion = 0
    var associationTracePending = false
    var lastAssociationTraceCompletedEpochNanos: UInt64?
    var lastDisconnectionEpochNanos: UInt64?
    var packetWindowSuppressedUntil = Date.distantPast
    var lastIdentityStatusLogSignature: String?
    var metricState = WiFiMetricState()

    init(config: WiFiConfig, telemetry: TelemetryClient) {
        self.config = config
        self.telemetry = telemetry
    }

    var name: String {
        WiFiCollectorFactory.name
    }

    func runOnce() -> Int32 {
        let snapshot = WiFiSnapshot.capture()
        startBPFIfNeeded(interfaceName: snapshot.interfaceName)
        defer {
            bpfMonitor?.stop()
            bpfMonitor = nil
            bpfInterface = nil
        }
        logIdentityStatus(snapshot)
        _ = exportMetrics(snapshot: snapshot)
        emitTrace(
            reason: "wifi.connectivity",
            eventTags: ["agent.mode": "once"],
            consumePacketSpans: false,
            includeConnectivityCheck: true
        )
        return 0
    }

    func start() {
        logEvent(
            .info, "wifi_agent_started",
            fields: [
                "pid": "\(getpid())",
                "metrics_interval_seconds": "\(Int(config.metricsInterval))",
                "connectivity_interval_seconds": "\(Int(config.traceInterval))",
                "otlp_url": config.otlpURL.absoluteString,
                "bpf_enabled": config.bpfEnabled ? "true" : "false",
            ]
        )

        startBPFIfNeeded(interfaceName: lastSnapshot.interfaceName)
        logIdentityStatus(lastSnapshot)
        _ = exportMetrics(snapshot: lastSnapshot)
        emitTrace(
            reason: "wifi.connectivity",
            eventTags: ["agent.mode": "startup"],
            consumePacketSpans: true,
            includeConnectivityCheck: true
        )

        let metricsTimer = DispatchSource.makeTimerSource(queue: triggerQueue)
        metricsTimer.schedule(deadline: .now() + config.metricsInterval, repeating: config.metricsInterval)
        metricsTimer.setEventHandler { [weak self] in
            guard let self else {
                return
            }
            let previous = lastEventSnapshot
            let snapshot = captureLatestSnapshot()
            if previous.isAssociated, !snapshot.isAssociated {
                lastDisconnectionEpochNanos = wallClockNanos()
            }
            if !previous.isAssociated, snapshot.isAssociated {
                var eventTags = snapshotTransitionTags(previous: previous, current: snapshot, observation: "metrics_snapshot")
                addAssociationWindowFloor(to: &eventTags)
                scheduleAssociationTrace(
                    sourceReason: "metrics.snapshot",
                    reason: "wifi.join",
                    eventTags: eventTags,
                    delay: config.associationTraceDelay
                )
            } else if WiFiTracePolicy.isAddressAcquisition(previous: previous, current: snapshot) {
                var eventTags = snapshotTransitionTags(previous: previous, current: snapshot, observation: "metrics_snapshot")
                addAssociationWindowFloor(to: &eventTags)
                scheduleAssociationTrace(
                    sourceReason: "metrics.snapshot",
                    reason: "wifi.join",
                    eventTags: eventTags,
                    delay: config.associationTraceDelay
                )
            }
            lastEventSnapshot = snapshot
            startBPFIfNeeded(interfaceName: snapshot.interfaceName)
            logIdentityStatus(snapshot)
            _ = exportMetrics(snapshot: snapshot)
        }
        metricsTimer.resume()
        self.metricsTimer = metricsTimer

        let activeTimer = DispatchSource.makeTimerSource(queue: triggerQueue)
        activeTimer.schedule(deadline: .now() + config.traceInterval, repeating: config.traceInterval)
        activeTimer.setEventHandler { [weak self] in
            self?.triggerTrace(
                reason: "wifi.connectivity",
                eventTags: ["agent.observation": "connectivity_interval"],
                force: true,
                includeConnectivityCheck: true
            )
        }
        activeTimer.resume()
        self.activeTimer = activeTimer

        coreWLANMonitor = CoreWLANEventMonitor { [weak self] event in
            self?.handleWiFiEvent(event)
        }
        coreWLANMonitor?.start()

        systemNetworkMonitor = SystemNetworkEventMonitor(watchedInterface: lastSnapshot.interfaceName) { [weak self] reason, tags in
            self?.handleSystemNetworkEvent(reason: reason, tags: tags)
        }
        systemNetworkMonitor?.start(queue: DispatchQueue(label: "watchme.wifi.systemconfiguration"))
    }

    func stop() {
        logEvent(.info, "wifi_agent_stopped")
        coreWLANMonitor?.stop()
        systemNetworkMonitor?.stop()
        metricsTimer?.cancel()
        activeTimer?.cancel()
        bpfMonitor?.stop()
        coreWLANMonitor = nil
        systemNetworkMonitor = nil
        metricsTimer = nil
        activeTimer = nil
        bpfMonitor = nil
        bpfInterface = nil
    }

    private func handleWiFiEvent(_ event: WiFiEvent) {
        triggerQueue.async {
            let previous = self.lastEventSnapshot
            let current = self.captureLatestSnapshot()
            self.lastEventSnapshot = current
            self.metricState.recordCoreWLANEvent(event.name)
            self.startBPFIfNeeded(interfaceName: current.interfaceName)
            self.logIdentityStatus(current)
            _ = self.exportMetrics(snapshot: current)

            var fields = event.tags
            fields["event"] = event.name
            fields["interface"] = event.interfaceName
            fields["previous_bssid"] = previous.bssid ?? ""
            fields["current_bssid"] = current.bssid ?? ""
            fields["previous_essid"] = previous.ssid ?? ""
            fields["current_essid"] = current.ssid ?? ""
            fields["previous_associated"] = previous.isAssociated ? "true" : "false"
            fields["current_associated"] = current.isAssociated ? "true" : "false"
            logEvent(.info, "corewlan_event", fields: fields)

            if event.name == "wifi_link_quality_changed" {
                return
            }

            let reason = self.classifyWiFiTransition(event: event.name, previous: previous, current: current)
            var tags = fields
            tags["agent.observation"] = event.name
            tags["wifi.transition.classification"] = reason

            if reason == "wifi.disconnect" {
                self.lastDisconnectionEpochNanos = event.receivedWallNanos
            }

            if WiFiTracePolicy.isAssociationRecoveryReason(reason) {
                self.addAssociationWindowFloor(to: &tags)
                self.scheduleAssociationTrace(reason: reason, eventTags: tags, delay: self.config.associationTraceDelay)
                return
            }

            let includeConnectivityCheck = WiFiTracePolicy.shouldRequestConnectivityCheck(snapshot: current)
            guard WiFiTracePolicy.shouldEmitEventTrace(reason: reason, snapshot: current) else {
                logEvent(
                    .debug, "trace_trigger_suppressed",
                    fields: [
                        "reason": reason,
                        "suppression_reason": "wifi_not_ready_for_event_trace",
                    ]
                )
                return
            }
            self.triggerTrace(
                reason: reason,
                eventTags: tags,
                force: false,
                includeConnectivityCheck: includeConnectivityCheck
            )
        }
    }

    private func handleSystemNetworkEvent(reason: String, tags: [String: String]) {
        triggerQueue.async {
            let previous = self.lastEventSnapshot
            let current = self.captureLatestSnapshot()
            self.lastEventSnapshot = current
            self.startBPFIfNeeded(interfaceName: current.interfaceName)
            self.logIdentityStatus(current)
            _ = self.exportMetrics(snapshot: current)

            var eventTags = tags
            eventTags["agent.observation"] = reason
            eventTags["previous_associated"] = previous.isAssociated ? "true" : "false"
            eventTags["current_associated"] = current.isAssociated ? "true" : "false"
            eventTags["previous_local_ip"] = previous.primaryIPv4 ?? ""
            eventTags["current_local_ip"] = current.primaryIPv4 ?? ""

            if previous.isAssociated, !current.isAssociated,
               let receivedEpoch = UInt64(tags["network.event_received_epoch_ns"] ?? "")
            {
                self.lastDisconnectionEpochNanos = receivedEpoch
            }

            if !previous.isAssociated, current.isAssociated {
                self.addAssociationWindowFloor(to: &eventTags)
                self.scheduleAssociationTrace(reason: "wifi.join", eventTags: eventTags, delay: self.config.associationTraceDelay)
            } else if WiFiTracePolicy.isAddressAcquisition(previous: previous, current: current) {
                self.addAssociationWindowFloor(to: &eventTags)
                self.scheduleAssociationTrace(reason: "wifi.join", eventTags: eventTags, delay: self.config.associationTraceDelay)
            } else if previous.primaryIPv4 != current.primaryIPv4, current.isAssociated {
                self.triggerTrace(
                    reason: reason,
                    eventTags: eventTags,
                    force: false,
                    includeConnectivityCheck: WiFiTracePolicy.shouldRequestConnectivityCheck(snapshot: current)
                )
            }
        }
    }

    private func snapshotTransitionTags(previous: WiFiSnapshot, current: WiFiSnapshot, observation: String) -> [String: String] {
        [
            "agent.observation": observation,
            "metrics.snapshot_epoch_ns": "\(current.capturedWallNanos)",
            "previous_associated": previous.isAssociated ? "true" : "false",
            "current_associated": current.isAssociated ? "true" : "false",
            "previous_local_ip": previous.primaryIPv4 ?? "",
            "current_local_ip": current.primaryIPv4 ?? "",
        ]
    }

    private func addAssociationWindowFloor(to tags: inout [String: String]) {
        guard let lastDisconnectionEpochNanos else {
            return
        }
        tags["association.window_floor_epoch_ns"] = "\(lastDisconnectionEpochNanos)"
    }

    private func classifyWiFiTransition(event: String, previous: WiFiSnapshot, current: WiFiSnapshot) -> String {
        // CoreWLAN event names are low-level notifications; trace names need a
        // stable semantic reason. Prefer observable association/IP state over
        // the raw callback so SystemConfiguration and CoreWLAN triggers converge
        // on the same join/roam/disconnect vocabulary.
        if previous.isAssociated, !current.isAssociated {
            return "wifi.disconnect"
        }
        if !previous.isAssociated, current.isAssociated {
            return "wifi.join"
        }
        if event == "wifi_power_changed", current.powerOn == false {
            return "wifi.disconnect"
        }
        if event == "wifi_bssid_changed", current.isAssociated {
            if previous.ssid == current.ssid, previous.bssid != nil, current.bssid != nil, previous.bssid != current.bssid {
                return "wifi.roam"
            }
            return "wifi.join"
        }
        if event == "wifi_ssid_changed", current.isAssociated {
            return "wifi.join"
        }
        return event.replacingOccurrences(of: "_", with: ".")
    }

    func captureLatestSnapshot() -> WiFiSnapshot {
        let previous = lastSnapshot
        let current = WiFiSnapshot.capture()
        metricState.recordSnapshotChanges(from: previous, to: current)
        lastSnapshot = current
        return current
    }
}

func dynamicStoreDictionary(_ key: String) -> [String: Any] {
    (SCDynamicStoreCopyValue(nil, key as CFString) as? [String: Any]) ?? [:]
}

func stringValue(_ value: Any?) -> String? {
    switch value {
    case let value as String:
        value
    case let value as NSNumber:
        value.stringValue
    case let value as Date:
        ISO8601DateFormatter().string(from: value)
    default:
        nil
    }
}

func traceRootName(_ reason: String) -> String {
    let normalized = reason.lowercased().map { character -> Character in
        if character.isLetter || character.isNumber || character == "." || character == "_" || character == "-" {
            return character
        }
        return "_"
    }
    return String(normalized).hasPrefix("wifi.") ? String(normalized) : "wifi.\(String(normalized))"
}
