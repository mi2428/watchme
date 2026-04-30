import WatchmeBPF
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
            "watchme_wifi_metrics_export_timestamp_seconds",
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
        var state = WiFiMetricState()

        state.recordCoreWLANEvent("wifi_bssid_changed")
        state.recordSnapshotChanges(from: previous, to: current)

        let metrics = WiFiMetricBuilder.metrics(snapshot: current, state: state)
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

    func testActiveProbeMetricsExposeInternetAndGatewayResults() throws {
        let snapshot = makeSnapshot()
        var state = WiFiMetricState()
        try recordSampleActiveProbes(in: &state)

        let metrics = WiFiMetricBuilder.metrics(snapshot: snapshot, state: state)

        XCTAssertEqual(
            metric(
                named: "watchme_wifi_probe_internet_http_success",
                labels: ["target": "neverssl.com", "family": "ipv4", "remote_ip": "34.223.124.45"],
                in: metrics
            )?.value,
            1
        )
        XCTAssertEqual(
            metric(named: "watchme_wifi_probe_internet_http_status_code", labels: ["target": "neverssl.com"], in: metrics)?.value,
            200
        )
        XCTAssertEqual(
            metric(
                named: "watchme_wifi_probe_internet_http_duration_seconds",
                labels: ["target": "neverssl.com", "timing_source": "bpf_packet"],
                in: metrics
            )?
                .value ?? -1,
            0.18,
            accuracy: 0.000_001
        )
        XCTAssertEqual(
            metric(
                named: "watchme_wifi_probe_internet_dns_success",
                labels: ["target": "neverssl.com", "family": "ipv4", "record_type": "A", "timing_source": "bpf_packet"],
                in: metrics
            )?
                .value,
            1
        )
        XCTAssertEqual(
            metric(named: "watchme_wifi_probe_internet_dns_rcode", labels: ["resolver": "192.168.23.254"], in: metrics)?.value,
            0
        )
        XCTAssertEqual(
            metric(named: "watchme_wifi_probe_internet_dns_address_count", labels: ["target": "neverssl.com"], in: metrics)?.value,
            1
        )
        XCTAssertEqual(
            metric(
                named: "watchme_wifi_probe_internet_icmp_success",
                labels: ["target": "neverssl.com", "family": "ipv4", "remote_ip": "34.223.124.45"],
                in: metrics
            )?.value,
            1
        )
        XCTAssertEqual(
            metric(
                named: "watchme_wifi_probe_gateway_icmp_success",
                labels: ["gateway": "192.168.23.254", "outcome": "reply", "timing_source": "network_framework_callback"],
                in: metrics
            )?.value,
            1
        )
        XCTAssertEqual(
            metric(named: "watchme_wifi_probe_gateway_icmp_reply_count", labels: ["gateway": "192.168.23.254"], in: metrics)?.value,
            1
        )
    }

    func testBPFStatsMetricsExposeKernelReceivedAndDroppedCounters() {
        let metrics = WiFiMetricBuilder.metrics(
            snapshot: makeSnapshot(),
            bpfStats: BPFStats(packetsReceived: 123, packetsDropped: 4)
        )

        XCTAssertEqual(
            metric(
                named: "watchme_wifi_bpf_packets_received_total",
                labels: ["filter": watchmeWiFiBPFFilterName],
                in: metrics
            )?.value,
            123
        )
        XCTAssertEqual(
            metric(
                named: "watchme_wifi_bpf_packets_dropped_total",
                labels: ["filter": watchmeWiFiBPFFilterName],
                in: metrics
            )?.value,
            4
        )
    }

    func testActiveProbeMetricsReplaceDisconnectedPlaceholderSeries() {
        let snapshot = makeSnapshot()
        var state = WiFiMetricState()

        recordDisconnectedActiveProbePlaceholders(in: &state)
        recordReconnectedActiveProbeSuccesses(in: &state)

        let metrics = WiFiMetricBuilder.metrics(snapshot: snapshot, state: state)

        XCTAssertNil(
            metric(
                named: "watchme_wifi_probe_internet_dns_success",
                labels: ["target": "example.com", "family": "ipv4", "resolver": "none"],
                in: metrics
            )
        )
        XCTAssertNil(
            metric(
                named: "watchme_wifi_probe_internet_icmp_success",
                labels: ["target": "example.com", "family": "ipv4", "remote_ip": "none"],
                in: metrics
            )
        )
        XCTAssertNil(
            metric(
                named: "watchme_wifi_probe_internet_http_success",
                labels: ["target": "example.com", "family": "ipv4", "remote_ip": "none"],
                in: metrics
            )
        )
        XCTAssertEqual(
            metric(
                named: "watchme_wifi_probe_internet_dns_success",
                labels: ["target": "example.com", "family": "ipv4", "resolver": "192.168.23.254"],
                in: metrics
            )?.value,
            1
        )
        XCTAssertEqual(
            metric(
                named: "watchme_wifi_probe_internet_icmp_success",
                labels: ["target": "example.com", "family": "ipv4", "remote_ip": "93.184.216.34"],
                in: metrics
            )?.value,
            1
        )
        XCTAssertEqual(
            metric(
                named: "watchme_wifi_probe_internet_http_success",
                labels: ["target": "example.com", "family": "ipv4", "remote_ip": "93.184.216.34"],
                in: metrics
            )?.value,
            1
        )
    }
}

private func recordDisconnectedActiveProbePlaceholders(in state: inout WiFiMetricState) {
    state.recordDNSProbe(
        ActiveDNSProbeResult(
            target: "example.com",
            family: .ipv4,
            recordType: .a,
            resolver: "none",
            transport: "udp",
            ok: false,
            rcode: nil,
            answerCount: 0,
            addresses: [],
            error: "no resolver",
            timing: ActiveProbeTiming(
                startWallNanos: 1_000_000_000,
                finishedWallNanos: 1_000_001_000,
                timingSource: noAddressTimingSource,
                timestampSource: wallClockTimestampSource
            )
        )
    )
    state.recordICMPProbe(
        ActiveICMPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "none",
            identifier: 0,
            sequence: 0,
            ok: false,
            outcome: "no_address",
            error: "no address",
            timing: ActiveProbeTiming(
                startWallNanos: 1_100_000_000,
                finishedWallNanos: 1_100_001_000,
                timingSource: noAddressTimingSource,
                timestampSource: wallClockTimestampSource
            )
        )
    )
    state.recordInternetHTTPProbe(
        ActiveInternetHTTPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "none",
            ok: false,
            outcome: "no_address",
            statusCode: nil,
            error: "no address",
            timing: ActiveProbeTiming(
                startWallNanos: 1_200_000_000,
                finishedWallNanos: 1_200_001_000,
                timingSource: noAddressTimingSource,
                timestampSource: wallClockTimestampSource
            )
        )
    )
}

private func recordReconnectedActiveProbeSuccesses(in state: inout WiFiMetricState) {
    state.recordDNSProbe(
        ActiveDNSProbeResult(
            target: "example.com",
            family: .ipv4,
            recordType: .a,
            resolver: "192.168.23.254",
            transport: "udp",
            ok: true,
            rcode: 0,
            answerCount: 1,
            addresses: ["93.184.216.34"],
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_000_000_000,
                finishedWallNanos: 2_050_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
    state.recordICMPProbe(
        ActiveICMPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "93.184.216.34",
            identifier: 0x1234,
            sequence: 1,
            ok: true,
            outcome: "reply",
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_100_000_000,
                finishedWallNanos: 2_130_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
    state.recordInternetHTTPProbe(
        ActiveInternetHTTPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "93.184.216.34",
            ok: true,
            outcome: "response",
            statusCode: 200,
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_200_000_000,
                finishedWallNanos: 2_290_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
}

private func recordSampleActiveProbes(in state: inout WiFiMetricState) throws {
    state.recordInternetHTTPProbe(
        ActiveInternetHTTPProbeResult(
            target: "neverssl.com",
            family: .ipv4,
            remoteIP: "34.223.124.45",
            ok: true,
            outcome: "response",
            statusCode: 200,
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 1_000_000_000,
                finishedWallNanos: 1_180_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
    state.recordDNSProbe(
        ActiveDNSProbeResult(
            target: "neverssl.com",
            family: .ipv4,
            recordType: .a,
            resolver: "192.168.23.254",
            transport: "udp",
            ok: true,
            rcode: 0,
            answerCount: 1,
            addresses: ["34.223.124.45"],
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_000_000_000,
                finishedWallNanos: 2_050_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
    state.recordICMPProbe(
        ActiveICMPProbeResult(
            target: "neverssl.com",
            family: .ipv4,
            remoteIP: "34.223.124.45",
            identifier: 0x1234,
            sequence: 7,
            ok: true,
            outcome: "reply",
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_100_000_000,
                finishedWallNanos: 2_120_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
    state.recordGatewayProbe(
        ActiveGatewayProbeResult(
            gateway: "192.168.23.254",
            attempts: [
                ActiveGatewayProbeAttempt(
                    sequence: 1,
                    identifier: nil,
                    icmpSequence: nil,
                    reachable: true,
                    outcome: "reply",
                    error: nil,
                    timing: ActiveProbeTiming(
                        startWallNanos: 3_000_000_000,
                        finishedWallNanos: 3_010_000_000,
                        timingSource: networkFrameworkTimingSource,
                        timestampSource: wallClockTimestampSource
                    )
                ),
            ],
            burstIntervalSeconds: 0
        )
    )
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
    in metrics: [MetricSample]
) -> MetricSample? {
    metrics.first { metric in
        metric.name == name && expectedLabels.allSatisfy { metric.labels[$0.key] == $0.value }
    }
}
