import CoreWLAN
import Foundation
import SystemConfiguration
import WatchmeCore

struct WiFiEvent {
    let name: String
    let interfaceName: String
    let receivedWallNanos: UInt64
    let tags: [String: String]
}

final class CoreWLANEventMonitor: NSObject, CWEventDelegate {
    private let client: CWWiFiClient
    private let onEvent: (WiFiEvent) -> Void

    init(client: CWWiFiClient = CWWiFiClient.shared(), onEvent: @escaping (WiFiEvent) -> Void) {
        self.client = client
        self.onEvent = onEvent
        super.init()
        self.client.delegate = self
    }

    func start() {
        let eventTypes: [CWEventType] = [
            .powerDidChange,
            .ssidDidChange,
            .bssidDidChange,
            .linkDidChange,
            .linkQualityDidChange,
            .countryCodeDidChange,
            .modeDidChange,
        ]
        for eventType in eventTypes {
            do {
                try client.startMonitoringEvent(with: eventType)
                logEvent(.info, "corewlan_monitor_registered", fields: ["event": coreWLANEventTypeName(eventType)])
            } catch {
                logEvent(
                    .warn, "corewlan_monitor_register_failed",
                    fields: [
                        "event": coreWLANEventTypeName(eventType),
                        "error": error.localizedDescription,
                    ]
                )
            }
        }
    }

    func stop() {
        do {
            try client.stopMonitoringAllEvents()
        } catch {
            logEvent(.warn, "corewlan_monitor_stop_failed", fields: ["error": error.localizedDescription])
        }
    }

    private func emit(name: String, interfaceName: String, tags extraTags: [String: String] = [:]) {
        let received = wallClockNanos()
        var tags = extraTags
        tags["wifi.event_received_epoch_ns"] = "\(received)"
        tags["wifi.event_timestamp_source"] = "corewlan_delegate_callback"
        tags["wifi.event_timestamp_semantics"] = "callback_receipt_time"
        onEvent(WiFiEvent(name: name, interfaceName: interfaceName, receivedWallNanos: received, tags: tags))
    }

    func powerStateDidChangeForWiFiInterface(withName interfaceName: String) {
        emit(name: "wifi_power_changed", interfaceName: interfaceName)
    }

    func ssidDidChangeForWiFiInterface(withName interfaceName: String) {
        emit(name: "wifi_ssid_changed", interfaceName: interfaceName)
    }

    func bssidDidChangeForWiFiInterface(withName interfaceName: String) {
        emit(name: "wifi_bssid_changed", interfaceName: interfaceName)
    }

    func countryCodeDidChangeForWiFiInterface(withName interfaceName: String) {
        emit(name: "wifi_country_code_changed", interfaceName: interfaceName)
    }

    func linkDidChangeForWiFiInterface(withName interfaceName: String) {
        emit(name: "wifi_link_changed", interfaceName: interfaceName)
    }

    func linkQualityDidChangeForWiFiInterface(withName interfaceName: String, rssi: Int, transmitRate: Double) {
        emit(
            name: "wifi_link_quality_changed", interfaceName: interfaceName,
            tags: [
                "wifi.rssi_dbm": "\(rssi)",
                "wifi.tx_rate_mbps": String(format: "%.1f", transmitRate),
            ]
        )
    }

    func modeDidChangeForWiFiInterface(withName interfaceName: String) {
        emit(name: "wifi_mode_changed", interfaceName: interfaceName)
    }

    func clientConnectionInterrupted() {
        logEvent(.warn, "corewlan_connection_interrupted")
        start()
    }

    func clientConnectionInvalidated() {
        logEvent(.error, "corewlan_connection_invalidated")
    }
}

final class SystemNetworkEventMonitor {
    private let watchedInterface: String?
    private let onEvent: (String, [String: String]) -> Void
    private var store: SCDynamicStore?

    init(watchedInterface: String?, onEvent: @escaping (String, [String: String]) -> Void) {
        self.watchedInterface = watchedInterface
        self.onEvent = onEvent
    }

    func start(queue: DispatchQueue) {
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let callback: SCDynamicStoreCallBack = { _, changedKeys, info in
            guard let info else {
                return
            }
            let monitor = Unmanaged<SystemNetworkEventMonitor>.fromOpaque(info).takeUnretainedValue()
            monitor.handle(changedKeys: changedKeys as? [String] ?? [])
        }
        guard let dynamicStore = SCDynamicStoreCreate(nil, "watchme.wifi" as CFString, callback, &context) else {
            logEvent(.warn, "scdynamicstore_monitor_create_failed")
            return
        }
        var keys = [
            "State:/Network/Global/IPv4",
            "State:/Network/Global/IPv6",
            "State:/Network/Global/DNS",
        ]
        if let watchedInterface {
            keys.append("State:/Network/Interface/\(watchedInterface)/IPv4")
            keys.append("State:/Network/Interface/\(watchedInterface)/IPv6")
            keys.append("State:/Network/Interface/\(watchedInterface)/Link")
        }
        let patterns = [
            "State:/Network/Service/.*/IPv4",
            "State:/Network/Service/.*/IPv6",
            "State:/Network/Service/.*/DNS",
            "State:/Network/Service/.*/DHCP",
        ]
        guard SCDynamicStoreSetNotificationKeys(dynamicStore, keys as CFArray, patterns as CFArray) else {
            logEvent(.warn, "scdynamicstore_monitor_set_keys_failed")
            return
        }
        guard SCDynamicStoreSetDispatchQueue(dynamicStore, queue) else {
            logEvent(.warn, "scdynamicstore_monitor_set_queue_failed")
            return
        }
        store = dynamicStore
        logEvent(
            .info, "scdynamicstore_monitor_started",
            fields: [
                "keys": keys.joined(separator: ","),
                "patterns": patterns.joined(separator: ","),
            ]
        )
    }

    func stop() {
        if let store {
            SCDynamicStoreSetDispatchQueue(store, nil)
        }
        store = nil
    }

    private func handle(changedKeys: [String]) {
        for key in changedKeys {
            let reason =
                if key.contains("/DHCP") {
                    "wifi.network.dhcp_changed"
                } else if key.contains("/IPv4") {
                    "wifi.network.ipv4_changed"
                } else if key.contains("/IPv6") {
                    "wifi.network.ipv6_changed"
                } else if key.contains("/DNS") {
                    "wifi.network.dns_changed"
                } else if key.contains("/Link") {
                    "wifi.network.link_changed"
                } else {
                    "wifi.network.changed"
                }
            let received = wallClockNanos()
            let tags = [
                "scdynamicstore.key": key,
                "network.event_received_epoch_ns": "\(received)",
                "network.event_timestamp_source": "scdynamicstore_callback",
                "network.event_timestamp_semantics": "callback_receipt_time",
            ]
            logEvent(.debug, "scdynamicstore_event", fields: ["reason": reason, "key": key])
            onEvent(reason, tags)
        }
    }
}

func coreWLANEventTypeName(_ eventType: CWEventType) -> String {
    switch eventType {
    case .powerDidChange: return "powerDidChange"
    case .ssidDidChange: return "ssidDidChange"
    case .bssidDidChange: return "bssidDidChange"
    case .countryCodeDidChange: return "countryCodeDidChange"
    case .linkDidChange: return "linkDidChange"
    case .linkQualityDidChange: return "linkQualityDidChange"
    case .modeDidChange: return "modeDidChange"
    case .scanCacheUpdated: return "scanCacheUpdated"
    case .btCoexStats: return "btCoexStats"
    case .none: return "none"
    case .unknown: return "unknown"
    @unknown default: return "unknown_\(eventType.rawValue)"
    }
}
