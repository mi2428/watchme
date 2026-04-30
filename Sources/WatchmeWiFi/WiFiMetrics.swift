import Foundation
import WatchmeTelemetry

enum WiFiMetricBuilder {
    static func metrics(snapshot: WiFiSnapshot, state: WiFiMetricState = WiFiMetricState()) -> [PrometheusMetric] {
        let labels = snapshot.metricLabels
        var metrics = quantitativeMetrics(snapshot: snapshot, labels: labels)
        metrics.append(contentsOf: interfaceStateMetrics(snapshot: snapshot, labels: labels))
        metrics.append(associatedMetric(snapshot: snapshot, labels: labels))
        metrics.append(infoMetric(snapshot: snapshot))
        metrics.append(pushTimestampMetric(labels: labels))
        metrics.append(contentsOf: state.metrics(labels: labels))
        return metrics
    }

    private static func quantitativeMetrics(snapshot: WiFiSnapshot, labels: [String: String]) -> [PrometheusMetric] {
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
        if let value = snapshot.channel {
            metrics.append(
                PrometheusMetric(
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
                PrometheusMetric(
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

    private static func interfaceStateMetrics(snapshot: WiFiSnapshot, labels: [String: String]) -> [PrometheusMetric] {
        var metrics: [PrometheusMetric] = []
        if let value = snapshot.transmitPowerMW {
            metrics.append(
                PrometheusMetric(
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
                PrometheusMetric(
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
                PrometheusMetric(
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

    private static func associatedMetric(snapshot: WiFiSnapshot, labels: [String: String]) -> PrometheusMetric {
        PrometheusMetric(
            name: "watchme_wifi_associated",
            help: "Whether Wi-Fi appears associated.",
            type: .gauge,
            labels: labels,
            value: snapshot.isAssociated ? 1 : 0
        )
    }

    private static func infoMetric(snapshot: WiFiSnapshot) -> PrometheusMetric {
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
        return PrometheusMetric(
            name: "watchme_wifi_info",
            help: "Constant info metric with current Wi-Fi labels.",
            type: .gauge,
            labels: labels,
            value: 1
        )
    }

    private static func pushTimestampMetric(labels: [String: String]) -> PrometheusMetric {
        PrometheusMetric(
            name: "watchme_wifi_metrics_push_timestamp_seconds",
            help: "Last metric push timestamp.",
            type: .gauge,
            labels: labels,
            value: Date().timeIntervalSince1970
        )
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
    private(set) var httpProbes: [String: ActiveProbeResult] = [:]
    private(set) var dnsProbes: [String: ActiveDNSProbeResult] = [:]
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

    mutating func recordHTTPProbe(_ result: ActiveProbeResult) {
        httpProbes["\(result.url.scheme ?? "")|\(result.url.host ?? result.target)"] = result
    }

    mutating func recordDNSProbe(_ result: ActiveDNSProbeResult) {
        dnsProbes["\(result.transport)|\(result.resolver)|\(result.target)"] = result
    }

    mutating func recordGatewayProbe(_ result: ActiveGatewayProbeResult) {
        gatewayProbes["\(result.gateway)|\(result.port)"] = result
    }

    func metrics(labels: [String: String]) -> [PrometheusMetric] {
        var metrics: [PrometheusMetric] = []
        metrics.append(contentsOf: counterMetrics(labels: labels))
        metrics.append(contentsOf: httpProbeMetrics(labels: labels))
        metrics.append(contentsOf: dnsProbeMetrics(labels: labels))
        metrics.append(contentsOf: gatewayProbeMetrics(labels: labels))
        return metrics
    }

    private func counterMetrics(labels: [String: String]) -> [PrometheusMetric] {
        var metrics: [PrometheusMetric] = []
        for event in Self.coreWLANEventNames {
            var eventLabels = labels
            eventLabels["event"] = event
            metrics.append(
                PrometheusMetric(
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
                PrometheusMetric(
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

    private func httpProbeMetrics(labels: [String: String]) -> [PrometheusMetric] {
        httpProbes.values.flatMap { result -> [PrometheusMetric] in
            var probeLabels = labels
            probeLabels["target"] = result.url.host ?? result.target
            probeLabels["scheme"] = result.url.scheme ?? "unknown"
            var metrics = [
                PrometheusMetric(
                    name: "watchme_wifi_probe_http_success",
                    help: "Whether the latest Wi-Fi-bound HTTP probe succeeded.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.ok ? 1 : 0
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_http_last_run_timestamp_seconds",
                    help: "Unix timestamp of the latest Wi-Fi-bound HTTP probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromWallNanos: result.finishedWallNanos)
                ),
            ]
            if let statusCode = result.statusCode {
                metrics.append(
                    PrometheusMetric(
                        name: "watchme_wifi_probe_http_status_code",
                        help: "HTTP status code returned by the latest Wi-Fi-bound HTTP probe.",
                        type: .gauge,
                        labels: probeLabels,
                        value: Double(statusCode)
                    )
                )
            }
            for phase in result.phaseDurations {
                var phaseLabels = probeLabels
                phaseLabels["phase"] = phase.phase
                metrics.append(
                    PrometheusMetric(
                        name: "watchme_wifi_probe_http_duration_seconds",
                        help: "Duration of the latest Wi-Fi-bound HTTP probe phase.",
                        type: .gauge,
                        labels: phaseLabels,
                        value: seconds(fromDurationNanos: phase.durationNanos)
                    )
                )
            }
            return metrics
        }
    }

    private func dnsProbeMetrics(labels: [String: String]) -> [PrometheusMetric] {
        dnsProbes.values.flatMap { result -> [PrometheusMetric] in
            var probeLabels = labels
            probeLabels["target"] = result.target
            probeLabels["resolver"] = result.resolver
            probeLabels["transport"] = result.transport
            var metrics = [
                PrometheusMetric(
                    name: "watchme_wifi_probe_dns_success",
                    help: "Whether the latest Wi-Fi-bound DNS probe succeeded.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.ok ? 1 : 0
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_dns_duration_seconds",
                    help: "Duration of the latest Wi-Fi-bound DNS probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.durationNanos)
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_dns_last_run_timestamp_seconds",
                    help: "Unix timestamp of the latest Wi-Fi-bound DNS probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromWallNanos: result.finishedWallNanos)
                ),
            ]
            if let rcode = result.rcode {
                metrics.append(
                    PrometheusMetric(
                        name: "watchme_wifi_probe_dns_rcode",
                        help: "DNS response code returned by the latest Wi-Fi-bound DNS probe.",
                        type: .gauge,
                        labels: probeLabels,
                        value: Double(rcode)
                    )
                )
            }
            return metrics
        }
    }

    private func gatewayProbeMetrics(labels: [String: String]) -> [PrometheusMetric] {
        gatewayProbes.values.flatMap { result -> [PrometheusMetric] in
            var probeLabels = labels
            probeLabels["gateway"] = result.gateway
            probeLabels["port"] = "\(result.port)"
            probeLabels["outcome"] = result.outcome
            return [
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_tcp_reachable",
                    help: "Whether the latest Wi-Fi-bound gateway TCP probe reached the gateway host.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.reachable ? 1 : 0
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_tcp_connect_success",
                    help: "Whether the latest Wi-Fi-bound gateway TCP probe established a connection.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.connectSuccess ? 1 : 0
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_tcp_duration_seconds",
                    help: "Duration of the latest Wi-Fi-bound gateway TCP probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.durationNanos)
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_tcp_last_run_timestamp_seconds",
                    help: "Unix timestamp of the latest Wi-Fi-bound gateway TCP probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromWallNanos: result.finishedWallNanos)
                ),
            ]
        }
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
