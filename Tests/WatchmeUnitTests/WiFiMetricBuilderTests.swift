import WatchmeTelemetry
@testable import WatchmeWiFi
import XCTest

final class WiFiMetricBuilderTests: XCTestCase {
    func testMetricsAlwaysIncludeEssidAndBssidLabels() {
        let snapshot = makeSnapshot(ssid: nil, bssid: nil)

        let metrics = WiFiMetricBuilder.metrics(snapshot: snapshot)
        let names = Set(metrics.map(\.name))

        XCTAssertTrue(names.isSuperset(of: [
            "watchme_wifi_rssi_dbm",
            "watchme_wifi_noise_dbm",
            "watchme_wifi_tx_rate_mbps",
            "watchme_wifi_channel_number",
            "watchme_wifi_channel_width_mhz",
            "watchme_wifi_transmit_power_mw",
            "watchme_wifi_power_on",
            "watchme_wifi_service_active",
            "watchme_wifi_associated",
            "watchme_wifi_info",
            "watchme_wifi_metrics_push_timestamp_seconds",
            "watchme_wifi_corewlan_event_total",
            "watchme_wifi_snapshot_change_total",
        ]))
        XCTAssertTrue(metrics.allSatisfy { $0.labels["essid"] == "unknown" && $0.labels["bssid"] == "unknown" })
        let info = metric(named: "watchme_wifi_info", in: metrics)
        XCTAssertEqual(info?.labels["channel"], "40")
        XCTAssertEqual(info?.labels["channel_band"], "5ghz")
        XCTAssertEqual(info?.labels["channel_width"], "40mhz")
        XCTAssertEqual(info?.labels["phy_mode"], "11ax")
        XCTAssertEqual(info?.labels["security"], "wpa3_personal")
        XCTAssertEqual(info?.labels["interface_mode"], "station")
        XCTAssertEqual(info?.labels["country_code"], "jp")
        XCTAssertEqual(info?.labels["identity_status"], "redacted_or_unavailable")
        XCTAssertEqual(metric(named: "watchme_wifi_channel_number", in: metrics)?.value, 40)
        XCTAssertEqual(metric(named: "watchme_wifi_channel_width_mhz", in: metrics)?.value, 40)
        XCTAssertEqual(metric(named: "watchme_wifi_transmit_power_mw", in: metrics)?.value, 126)
        XCTAssertEqual(metric(named: "watchme_wifi_power_on", in: metrics)?.value, 1)
        XCTAssertEqual(metric(named: "watchme_wifi_service_active", in: metrics)?.value, 1)
        XCTAssertEqual(metric(named: "watchme_wifi_associated", in: metrics)?.value, 1)
    }

    func testTraceTagsExposeIdentityStatus() {
        let available = makeSnapshot(capturedWallNanos: 2000, ssid: "lab", bssid: "aa:bb:cc:dd:ee:ff")
        let redacted = makeSnapshot(capturedWallNanos: 3000, ssid: nil, bssid: nil)

        XCTAssertEqual(available.traceTags["wifi.identity_available"], "true")
        XCTAssertEqual(available.traceTags["wifi.identity_status"], "available")
        XCTAssertEqual(available.traceTags["wifi.phy_mode"], "11ax")
        XCTAssertEqual(available.traceTags["wifi.security"], "wpa3_personal")
        XCTAssertEqual(available.traceTags["wifi.channel_band"], "5ghz")
        XCTAssertEqual(available.traceTags["wifi.channel_width_mhz"], "40")
        XCTAssertEqual(redacted.traceTags["wifi.identity_available"], "false")
        XCTAssertEqual(redacted.traceTags["wifi.identity_status"], "redacted_or_unavailable")
    }

    func testMetricCountersExposeCoreWLANEventsAndSnapshotChanges() {
        let previous = makeSnapshot(bssid: "aa:bb:cc:dd:ee:ff", channel: 36, channelWidth: "20mhz", channelWidthMHz: 20)
        let current = makeSnapshot(bssid: "11:22:33:44:55:66", channel: 40, channelWidth: "40mhz", channelWidthMHz: 40)
        var counters = WiFiMetricCounters()

        counters.recordCoreWLANEvent("wifi_bssid_changed")
        counters.recordSnapshotChanges(from: previous, to: current)

        let metrics = WiFiMetricBuilder.metrics(snapshot: current, counters: counters)
        XCTAssertEqual(
            metric(named: "watchme_wifi_corewlan_event_total", labels: ["event": "bssid_did_change"], in: metrics)?.value,
            1
        )
        XCTAssertEqual(
            metric(named: "watchme_wifi_snapshot_change_total", labels: ["field": "bssid"], in: metrics)?.value,
            1
        )
        XCTAssertEqual(
            metric(named: "watchme_wifi_snapshot_change_total", labels: ["field": "channel"], in: metrics)?.value,
            1
        )
        XCTAssertEqual(
            metric(named: "watchme_wifi_snapshot_change_total", labels: ["field": "channel_width"], in: metrics)?.value,
            1
        )
        XCTAssertEqual(
            metric(named: "watchme_wifi_snapshot_change_total", labels: ["field": "security"], in: metrics)?.value,
            0
        )
    }

    func testSSIDDataFallbackKeepsEssidLabelWhenStringDecodingFails() {
        let ssid = normalizedSSID(ssid: nil, ssidData: Data([0xDE, 0xAD, 0xBE, 0xEF]))

        XCTAssertEqual(ssid.value, "hex:deadbeef")
        XCTAssertEqual(ssid.encoding, "hex")
    }
}

private func makeSnapshot(
    capturedWallNanos: UInt64 = 1000,
    ssid: String? = "lab",
    ssidEncoding: String? = "utf8",
    bssid: String? = "aa:bb:cc:dd:ee:ff",
    isAssociated: Bool = true,
    rssiDBM: Int? = -51,
    noiseDBM: Int? = -97,
    txRateMbps: Double? = 573,
    channel: Int? = 40,
    channelBand: String? = "5ghz",
    channelWidth: String? = "40mhz",
    channelWidthMHz: Int? = 40,
    phyMode: String? = "11ax",
    security: String? = "wpa3_personal",
    interfaceMode: String? = "station",
    countryCode: String? = "jp",
    transmitPowerMW: Int? = 126,
    powerOn: Bool? = true,
    serviceActive: Bool? = true
) -> WiFiSnapshot {
    WiFiSnapshot(
        capturedWallNanos: capturedWallNanos,
        interfaceName: "en0",
        ssid: ssid,
        ssidEncoding: ssidEncoding,
        bssid: bssid,
        isAssociated: isAssociated,
        rssiDBM: rssiDBM,
        noiseDBM: noiseDBM,
        txRateMbps: txRateMbps,
        channel: channel,
        channelBand: channelBand,
        channelWidth: channelWidth,
        channelWidthMHz: channelWidthMHz,
        phyMode: phyMode,
        security: security,
        interfaceMode: interfaceMode,
        countryCode: countryCode,
        transmitPowerMW: transmitPowerMW,
        powerOn: powerOn,
        serviceActive: serviceActive,
        ipv4Addresses: ["192.168.22.173"],
        ipv6Addresses: []
    )
}

private func metric(
    named name: String,
    labels expectedLabels: [String: String] = [:],
    in metrics: [PrometheusMetric]
) -> PrometheusMetric? {
    metrics.first { metric in
        metric.name == name && expectedLabels.allSatisfy { metric.labels[$0.key] == $0.value }
    }
}
