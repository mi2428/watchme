import CoreWLAN
import Darwin
import Foundation
import WatchmeCore
import WatchmeTelemetry

struct NativeInterfaceState {
    let isActive: Bool
    let ipv4Addresses: [String]
    let ipv6Addresses: [String]
}

struct WiFiSnapshot {
    let capturedWallNanos: UInt64
    let interfaceName: String?
    let ssid: String?
    let bssid: String?
    let isAssociated: Bool
    let rssiDBM: Int?
    let noiseDBM: Int?
    let txRateMbps: Double?
    let channel: Int?
    let ipv4Addresses: [String]
    let ipv6Addresses: [String]

    var primaryIPv4: String? {
        ipv4Addresses.first
    }

    var metricLabels: [String: String] {
        // Keep label cardinality stable for Prometheus. When macOS redacts
        // identity fields, the label keys remain present with "unknown" values.
        [
            "interface": interfaceName ?? "unknown",
            "essid": ssid ?? "unknown",
            "bssid": bssid ?? "unknown",
        ]
    }

    var traceTags: [String: String] {
        var tags: [String: String] = [
            "wifi.associated": isAssociated ? "true" : "false",
            "wifi.identity_available": identityAvailable ? "true" : "false",
            "wifi.identity_status": identityStatus,
            "wifi.essid": ssid ?? "unknown",
            "wifi.ssid": ssid ?? "unknown",
            "wifi.bssid": bssid ?? "unknown",
            "wifi.snapshot_epoch_ns": "\(capturedWallNanos)",
            "wifi.snapshot_timestamp_source": "corewlan_getifaddrs_snapshot",
            "network.ipv4_addresses": ipv4Addresses.joined(separator: ","),
            "network.ipv6_addresses": ipv6Addresses.joined(separator: ","),
        ]
        setTag(&tags, "wifi.interface", interfaceName)
        setTag(&tags, "network.local_ip", primaryIPv4)
        if let rssiDBM {
            tags["wifi.rssi_dbm"] = "\(rssiDBM)"
        }
        if let noiseDBM {
            tags["wifi.noise_dbm"] = "\(noiseDBM)"
        }
        if let txRateMbps {
            tags["wifi.tx_rate_mbps"] = String(format: "%.1f", txRateMbps)
        }
        if let channel {
            tags["wifi.channel"] = "\(channel)"
        }
        return tags
    }

    var identityAvailable: Bool {
        ssid != nil && bssid != nil
    }

    var identityStatus: String {
        if identityAvailable {
            return "available"
        }
        // A live interface with RSSI/IP data but no SSID/BSSID usually means
        // CoreWLAN identity fields are redacted by Location Services policy.
        if isAssociated {
            return "redacted_or_unavailable"
        }
        return "disconnected"
    }

    var signature: String {
        [
            interfaceName ?? "-",
            isAssociated ? "associated" : "disconnected",
            ssid ?? "-",
            bssid ?? "-",
            primaryIPv4 ?? "-",
        ].joined(separator: "|")
    }

    static func capture() -> WiFiSnapshot {
        let interface = CWWiFiClient.shared().interface()
        let interfaceName = interface?.interfaceName ?? nativeWiFiInterfaceName()
        let state =
            interfaceName.map(nativeInterfaceState(interfaceName:))
                ?? NativeInterfaceState(
                    isActive: false,
                    ipv4Addresses: [],
                    ipv6Addresses: []
                )
        let ssid = interface?.ssid()
        let bssid = interface?.bssid()?.lowercased()
        let isAssociated = ssid != nil || bssid != nil || (state.isActive && !state.ipv4Addresses.isEmpty)

        return WiFiSnapshot(
            capturedWallNanos: wallClockNanos(),
            interfaceName: interfaceName,
            ssid: ssid,
            bssid: bssid,
            isAssociated: isAssociated,
            rssiDBM: interface?.rssiValue(),
            noiseDBM: interface?.noiseMeasurement(),
            txRateMbps: interface?.transmitRate(),
            channel: interface?.wlanChannel()?.channelNumber,
            ipv4Addresses: state.ipv4Addresses,
            ipv6Addresses: state.ipv6Addresses
        )
    }
}

enum WiFiMetricBuilder {
    static func metrics(snapshot: WiFiSnapshot) -> [PrometheusMetric] {
        let labels = snapshot.metricLabels
        var metrics: [PrometheusMetric] = []
        if let value = snapshot.rssiDBM {
            metrics.append(
                PrometheusMetric(
                    name: "watchme_wifi_rssi_dbm",
                    help: "Received signal strength indicator in dBm.",
                    type: .gauge,
                    labels: labels,
                    value: Double(value)
                )
            )
        }
        if let value = snapshot.noiseDBM {
            metrics.append(
                PrometheusMetric(
                    name: "watchme_wifi_noise_dbm",
                    help: "Noise floor in dBm.",
                    type: .gauge,
                    labels: labels,
                    value: Double(value)
                )
            )
        }
        if let value = snapshot.txRateMbps {
            metrics.append(
                PrometheusMetric(
                    name: "watchme_wifi_tx_rate_mbps",
                    help: "Current transmit rate in Mbps.",
                    type: .gauge,
                    labels: labels,
                    value: value
                )
            )
        }
        metrics.append(
            PrometheusMetric(
                name: "watchme_wifi_associated",
                help: "Whether Wi-Fi appears associated.",
                type: .gauge,
                labels: labels,
                value: snapshot.isAssociated ? 1 : 0
            )
        )
        var infoLabels = snapshot.metricLabels
        if let channel = snapshot.channel {
            infoLabels["channel"] = "\(channel)"
        }
        metrics.append(
            PrometheusMetric(
                name: "watchme_wifi_info",
                help: "Constant info metric with current Wi-Fi labels.",
                type: .gauge,
                labels: infoLabels,
                value: 1
            )
        )
        metrics.append(
            PrometheusMetric(
                name: "watchme_wifi_metrics_push_timestamp_seconds",
                help: "Last metric push timestamp.",
                type: .gauge,
                labels: labels,
                value: Date().timeIntervalSince1970
            )
        )
        return metrics
    }
}

func nativeWiFiInterfaceName() -> String? {
    if let name = CWWiFiClient.shared().interface()?.interfaceName {
        return name
    }
    return CWWiFiClient.shared().interfaceNames()?.sorted().first
}

func nativeInterfaceState(interfaceName: String) -> NativeInterfaceState {
    var addresses: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&addresses) == 0, let first = addresses else {
        return NativeInterfaceState(isActive: false, ipv4Addresses: [], ipv6Addresses: [])
    }
    defer { freeifaddrs(addresses) }

    var sawInterface = false
    var flags: UInt32 = 0
    var ipv4: [String] = []
    var ipv6: [String] = []

    var cursor: UnsafeMutablePointer<ifaddrs>? = first
    while let current = cursor {
        defer { cursor = current.pointee.ifa_next }

        guard String(cString: current.pointee.ifa_name) == interfaceName else {
            continue
        }
        sawInterface = true
        flags = current.pointee.ifa_flags

        guard let address = current.pointee.ifa_addr else {
            continue
        }
        let family = Int32(address.pointee.sa_family)
        guard family == AF_INET || family == AF_INET6 else {
            continue
        }

        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let rc = getnameinfo(
            address,
            socklen_t(address.pointee.sa_len),
            &host,
            socklen_t(host.count),
            nil,
            0,
            NI_NUMERICHOST
        )
        guard rc == 0 else {
            continue
        }
        let value = String(cString: host)
        if family == AF_INET {
            ipv4.append(value)
        } else if !value.hasPrefix("fe80:") {
            ipv6.append(value)
        }
    }

    let isUp = (flags & UInt32(IFF_UP)) != 0
    let isRunning = (flags & UInt32(IFF_RUNNING)) != 0
    return NativeInterfaceState(
        isActive: sawInterface && isUp && isRunning,
        ipv4Addresses: ipv4,
        ipv6Addresses: ipv6
    )
}
