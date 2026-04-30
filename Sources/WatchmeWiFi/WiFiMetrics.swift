import Foundation
import WatchmeBPF
import WatchmeTelemetry

enum WiFiMetricBuilder {
    static func metrics(
        snapshot: WiFiSnapshot,
        state: WiFiMetricState = WiFiMetricState(),
        bpfStats: BPFStats? = nil
    ) -> [MetricSample] {
        let labels = snapshot.metricLabels
        var metrics = quantitativeMetrics(snapshot: snapshot, labels: labels)
        metrics.append(contentsOf: interfaceStateMetrics(snapshot: snapshot, labels: labels))
        metrics.append(associatedMetric(snapshot: snapshot, labels: labels))
        metrics.append(infoMetric(snapshot: snapshot))
        metrics.append(exportTimestampMetric(labels: labels))
        metrics.append(contentsOf: bpfMetrics(labels: labels, stats: bpfStats))
        metrics.append(contentsOf: state.metrics(labels: labels))
        return metrics
    }

    private static func quantitativeMetrics(snapshot: WiFiSnapshot, labels: [String: String]) -> [MetricSample] {
        var metrics: [MetricSample] = []
        if let value = snapshot.rssiDBM {
            metrics.append(
                MetricSample(
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
                MetricSample(
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
                MetricSample(
                    name: "watchme_wifi_tx_rate_mbps",
                    help: "Current transmit rate in Mbps.",
                    type: .gauge,
                    labels: labels,
                    value: value
                )
            )
        }
        if let value = snapshot.channel {
            metrics.append(
                MetricSample(
                    name: "watchme_wifi_channel_number",
                    help: "Current Wi-Fi channel number.",
                    type: .gauge,
                    labels: labels,
                    value: Double(value)
                )
            )
        }
        if let value = snapshot.channelWidthMHz {
            metrics.append(
                MetricSample(
                    name: "watchme_wifi_channel_width_mhz",
                    help: "Current Wi-Fi channel width in MHz.",
                    type: .gauge,
                    labels: labels,
                    value: Double(value)
                )
            )
        }
        return metrics
    }

    private static func interfaceStateMetrics(snapshot: WiFiSnapshot, labels: [String: String]) -> [MetricSample] {
        var metrics: [MetricSample] = []
        if let value = snapshot.transmitPowerMW {
            metrics.append(
                MetricSample(
                    name: "watchme_wifi_transmit_power_mw",
                    help: "Current Wi-Fi transmit power in milliwatts.",
                    type: .gauge,
                    labels: labels,
                    value: Double(value)
                )
            )
        }
        if let value = snapshot.powerOn {
            metrics.append(
                MetricSample(
                    name: "watchme_wifi_power_on",
                    help: "Whether the Wi-Fi interface power is on.",
                    type: .gauge,
                    labels: labels,
                    value: value ? 1 : 0
                )
            )
        }
        if let value = snapshot.serviceActive {
            metrics.append(
                MetricSample(
                    name: "watchme_wifi_service_active",
                    help: "Whether the Wi-Fi network service is active.",
                    type: .gauge,
                    labels: labels,
                    value: value ? 1 : 0
                )
            )
        }
        return metrics
    }

    private static func associatedMetric(snapshot: WiFiSnapshot, labels: [String: String]) -> MetricSample {
        MetricSample(
            name: "watchme_wifi_associated",
            help: "Whether Wi-Fi appears associated.",
            type: .gauge,
            labels: labels,
            value: snapshot.isAssociated ? 1 : 0
        )
    }

    private static func infoMetric(snapshot: WiFiSnapshot) -> MetricSample {
        var labels = snapshot.metricLabels
        if let channel = snapshot.channel {
            labels["channel"] = "\(channel)"
        }
        labels["identity_status"] = snapshot.identityStatus
        labels["essid_encoding"] = snapshot.ssidEncoding ?? "unknown"
        labels["channel_band"] = snapshot.channelBand ?? "unknown"
        labels["channel_width"] = snapshot.channelWidth ?? "unknown"
        labels["phy_mode"] = snapshot.phyMode ?? "unknown"
        labels["security"] = snapshot.security ?? "unknown"
        labels["interface_mode"] = snapshot.interfaceMode ?? "unknown"
        labels["country_code"] = snapshot.countryCode ?? "unknown"
        return MetricSample(
            name: "watchme_wifi_info",
            help: "Constant info metric with current Wi-Fi labels.",
            type: .gauge,
            labels: labels,
            value: 1
        )
    }

    private static func exportTimestampMetric(labels: [String: String]) -> MetricSample {
        MetricSample(
            name: "watchme_wifi_metrics_export_timestamp_seconds",
            help: "Last metric export timestamp.",
            type: .gauge,
            labels: labels,
            value: Date().timeIntervalSince1970
        )
    }

    private static func bpfMetrics(labels: [String: String], stats: BPFStats?) -> [MetricSample] {
        guard let stats else {
            return []
        }
        var labels = labels
        labels["filter"] = watchmeWiFiBPFFilterName
        return [
            MetricSample(
                name: "watchme_wifi_bpf_packets_received_total",
                help: "Packets accepted by the WatchMe Wi-Fi BPF descriptor.",
                type: .counter,
                labels: labels,
                value: Double(stats.packetsReceived)
            ),
            MetricSample(
                name: "watchme_wifi_bpf_packets_dropped_total",
                help: "Packets dropped by the WatchMe Wi-Fi BPF descriptor.",
                type: .counter,
                labels: labels,
                value: Double(stats.packetsDropped)
            ),
        ]
    }
}

struct WiFiMetricState {
    static let coreWLANEventNames = [
        "power_did_change",
        "ssid_did_change",
        "bssid_did_change",
        "country_code_did_change",
        "link_did_change",
        "link_quality_did_change",
        "mode_did_change",
    ]

    static let snapshotChangeFieldNames = [
        "ssid",
        "bssid",
        "associated",
        "channel",
        "channel_band",
        "channel_width",
        "country_code",
        "phy_mode",
        "security",
        "interface_mode",
        "power_on",
        "service_active",
    ]

    private(set) var coreWLANEvents: [String: Int] = [:]
    private(set) var snapshotChanges: [String: Int] = [:]
    private(set) var internetHTTPProbes: [String: ActiveInternetHTTPProbeResult] = [:]
    private(set) var internetTCPProbes: [String: ActiveTCPProbeResult] = [:]
    private(set) var dnsProbes: [String: ActiveDNSProbeResult] = [:]
    private(set) var icmpProbes: [String: ActiveICMPProbeResult] = [:]
    private(set) var gatewayProbes: [String: ActiveGatewayProbeResult] = [:]

    mutating func recordCoreWLANEvent(_ event: String) {
        let name = coreWLANMetricEventName(event)
        coreWLANEvents[name, default: 0] += 1
    }

    mutating func recordSnapshotChanges(from previous: WiFiSnapshot, to current: WiFiSnapshot) {
        // This counter records raw OS-observed state transitions only. It does
        // not classify quality or derive roaming semantics; traces handle that.
        for field in current.changedFields(from: previous) {
            snapshotChanges[field, default: 0] += 1
        }
    }

    mutating func recordInternetHTTPProbe(_ result: ActiveInternetHTTPProbeResult) {
        internetHTTPProbes["\(result.target)|\(result.family.metricValue)"] = result
    }

    mutating func recordInternetTCPProbe(_ result: ActiveTCPProbeResult) {
        internetTCPProbes["\(result.target)|\(result.family.metricValue)"] = result
    }

    mutating func recordDNSProbe(_ result: ActiveDNSProbeResult) {
        let familyKey = "\(result.target)|\(result.family.metricValue)"
        if result.resolver == "none" {
            dnsProbes = dnsProbes.filter { _, existing in
                familyKey != "\(existing.target)|\(existing.family.metricValue)"
            }
        } else {
            dnsProbes.removeValue(forKey: "udp|none|\(familyKey)")
        }
        dnsProbes["\(result.transport)|\(result.resolver)|\(familyKey)"] = result
    }

    mutating func recordICMPProbe(_ result: ActiveICMPProbeResult) {
        icmpProbes["\(result.target)|\(result.family.metricValue)"] = result
    }

    mutating func recordGatewayProbe(_ result: ActiveGatewayProbeResult) {
        gatewayProbes["\(result.gateway)|\(result.family.metricValue)"] = result
    }

    func metrics(labels: [String: String]) -> [MetricSample] {
        var metrics: [MetricSample] = []
        metrics.append(contentsOf: counterMetrics(labels: labels))
        metrics.append(contentsOf: dnsProbeMetrics(labels: labels))
        metrics.append(contentsOf: icmpProbeMetrics(labels: labels))
        metrics.append(contentsOf: internetTCPProbeMetrics(labels: labels))
        metrics.append(contentsOf: internetHTTPProbeMetrics(labels: labels))
        metrics.append(contentsOf: gatewayProbeMetrics(labels: labels))
        return metrics
    }

    private func counterMetrics(labels: [String: String]) -> [MetricSample] {
        var metrics: [MetricSample] = []
        for event in Self.coreWLANEventNames {
            var eventLabels = labels
            eventLabels["event"] = event
            metrics.append(
                MetricSample(
                    name: "watchme_wifi_corewlan_event_total",
                    help: "CoreWLAN event callbacks observed by WatchMe.",
                    type: .counter,
                    labels: eventLabels,
                    value: Double(coreWLANEvents[event, default: 0])
                )
            )
        }
        for field in Self.snapshotChangeFieldNames {
            var fieldLabels = labels
            fieldLabels["field"] = field
            metrics.append(
                MetricSample(
                    name: "watchme_wifi_snapshot_change_total",
                    help: "Wi-Fi snapshot field changes observed by WatchMe.",
                    type: .counter,
                    labels: fieldLabels,
                    value: Double(snapshotChanges[field, default: 0])
                )
            )
        }
        return metrics
    }
}

func coreWLANMetricEventName(_ event: String) -> String {
    [
        "wifi_power_changed": "power_did_change",
        "wifi_ssid_changed": "ssid_did_change",
        "wifi_bssid_changed": "bssid_did_change",
        "wifi_country_code_changed": "country_code_did_change",
        "wifi_link_changed": "link_did_change",
        "wifi_link_quality_changed": "link_quality_did_change",
        "wifi_mode_changed": "mode_did_change",
    ][event] ?? event
}

func seconds(fromDurationNanos nanos: UInt64) -> Double {
    Double(nanos) / 1_000_000_000.0
}

func seconds(fromWallNanos nanos: UInt64) -> Double {
    Double(nanos) / 1_000_000_000.0
}
