import Darwin
import Foundation
import SystemConfiguration
import WatchmeCore
import WatchmeTelemetry

final class WiFiAgent {
    let config: WiFiConfig
    let telemetry: TelemetryClient
    let packetStore = PassivePacketStore()
    let triggerQueue = DispatchQueue(label: "watchme.wifi.trigger")
    var lastSnapshot = WiFiSnapshot.capture()
    var lastTrigger = Date.distantPast
    var bpfMonitor: PassiveBPFMonitor?
    var bpfInterface: String?
    var coreWLANMonitor: CoreWLANEventMonitor?
    var systemNetworkMonitor: SystemNetworkEventMonitor?
    var metricsTimer: DispatchSourceTimer?
    var activeTimer: DispatchSourceTimer?
    var packetWindowVersion = 0
    var lastIdentityStatusLogSignature: String?

    init(config: WiFiConfig, telemetry: TelemetryClient) {
        self.config = config
        self.telemetry = telemetry
    }

    func runOnce() -> Int32 {
        let snapshot = WiFiSnapshot.capture()
        logIdentityStatus(snapshot)
        _ = pushMetrics(snapshot: snapshot)
        emitTrace(reason: "wifi.active", eventTags: ["agent.mode": "once"], consumePacketSpans: false, includeActive: true)
        return 0
    }

    func run() {
        logEvent(
            .info, "wifi_agent_started",
            fields: [
                "pid": "\(getpid())",
                "metrics_interval_seconds": "\(Int(config.metricsInterval))",
                "active_interval_seconds": "\(Int(config.activeInterval))",
                "traces_url": config.tracesURL.absoluteString,
                "metrics_push_url": config.metricsPushURL.absoluteString,
                "metrics_push_prefix": config.metricsPushPrefix,
                "bpf_enabled": config.bpfEnabled ? "true" : "false",
            ]
        )

        startBPFIfNeeded(interfaceName: lastSnapshot.interfaceName)
        logIdentityStatus(lastSnapshot)
        _ = pushMetrics(snapshot: lastSnapshot)
        emitTrace(reason: "wifi.active", eventTags: ["agent.mode": "startup"], consumePacketSpans: true, includeActive: true)

        let metricsTimer = DispatchSource.makeTimerSource(queue: triggerQueue)
        metricsTimer.schedule(deadline: .now() + config.metricsInterval, repeating: config.metricsInterval)
        metricsTimer.setEventHandler { [weak self] in
            guard let self else {
                return
            }
            let snapshot = WiFiSnapshot.capture()
            lastSnapshot = snapshot
            startBPFIfNeeded(interfaceName: snapshot.interfaceName)
            logIdentityStatus(snapshot)
            _ = pushMetrics(snapshot: snapshot)
        }
        metricsTimer.resume()
        self.metricsTimer = metricsTimer

        let activeTimer = DispatchSource.makeTimerSource(queue: triggerQueue)
        activeTimer.schedule(deadline: .now() + config.activeInterval, repeating: config.activeInterval)
        activeTimer.setEventHandler { [weak self] in
            self?.triggerTrace(reason: "wifi.active", eventTags: ["agent.observation": "active_interval"], force: true, includeActive: true)
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

        let signalQueue = DispatchQueue(label: "watchme.signals")
        let sigint = DispatchSource.makeSignalSource(signal: SIGINT, queue: signalQueue)
        let sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: signalQueue)
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        sigint.setEventHandler { [weak self] in self?.stop(signal: "SIGINT") }
        sigterm.setEventHandler { [weak self] in self?.stop(signal: "SIGTERM") }
        sigint.resume()
        sigterm.resume()

        RunLoop.current.run()
    }

    private func stop(signal: String) {
        logEvent(.info, "wifi_agent_stopped", fields: ["signal": signal])
        coreWLANMonitor?.stop()
        systemNetworkMonitor?.stop()
        metricsTimer?.cancel()
        activeTimer?.cancel()
        bpfMonitor?.stop()
        exit(0)
    }

    private func handleWiFiEvent(_ event: WiFiEvent) {
        triggerQueue.async {
            let previous = self.lastSnapshot
            let current = WiFiSnapshot.capture()
            self.lastSnapshot = current
            self.startBPFIfNeeded(interfaceName: current.interfaceName)
            self.logIdentityStatus(current)
            _ = self.pushMetrics(snapshot: current)

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
            self.triggerTrace(reason: reason, eventTags: tags, force: reason == "wifi.roam" || reason == "wifi.join", includeActive: true)

            if reason == "wifi.join" || reason == "wifi.roam" {
                self.schedulePacketWindowTrace(sourceReason: reason, eventTags: tags, delay: 2.0)
            }
        }
    }

    private func handleSystemNetworkEvent(reason: String, tags: [String: String]) {
        triggerQueue.async {
            let previous = self.lastSnapshot
            let current = WiFiSnapshot.capture()
            self.lastSnapshot = current
            self.startBPFIfNeeded(interfaceName: current.interfaceName)
            self.logIdentityStatus(current)
            _ = self.pushMetrics(snapshot: current)

            var eventTags = tags
            eventTags["agent.observation"] = reason
            eventTags["previous_associated"] = previous.isAssociated ? "true" : "false"
            eventTags["current_associated"] = current.isAssociated ? "true" : "false"
            eventTags["previous_local_ip"] = previous.primaryIPv4 ?? ""
            eventTags["current_local_ip"] = current.primaryIPv4 ?? ""

            if !previous.isAssociated, current.isAssociated {
                self.triggerTrace(reason: "wifi.join", eventTags: eventTags, force: true, includeActive: true)
                self.schedulePacketWindowTrace(sourceReason: "wifi.join", eventTags: eventTags, delay: 2.0)
            } else if previous.primaryIPv4 != current.primaryIPv4, current.isAssociated {
                self.triggerTrace(reason: reason, eventTags: eventTags, force: false, includeActive: true)
            }
        }
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
}

func defaultRouteTags() -> [String: String] {
    let global = dynamicStoreDictionary("State:/Network/Global/IPv4")
    var tags = [
        "network.route_source": "system_configuration_dynamic_store",
    ]
    setTag(&tags, "network.primary_interface", stringValue(global["PrimaryInterface"]))
    setTag(&tags, "network.primary_service", stringValue(global["PrimaryService"]))
    setTag(&tags, "network.gateway", stringValue(global["Router"]))
    return tags
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

func normalizedTargetURL(_ target: String) -> URL {
    if let url = URL(string: target), url.scheme != nil {
        return url
    }
    return URL(string: "https://\(target)/")!
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
