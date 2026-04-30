import WatchmeTelemetry
@testable import WatchmeWiFi
import XCTest

final class GatewayBurstMetricTests: XCTestCase {
    func testGatewayBurstMetricsExposeLossAndJitter() {
        let snapshot = makeGatewayMetricSnapshot()
        var state = WiFiMetricState()
        state.recordGatewayProbe(
            ActiveGatewayProbeResult(
                gateway: "192.168.23.254",
                attempts: [
                    gatewayAttempt(sequence: 1, reachable: true, outcome: "reply", durationNanos: 10_000_000),
                    gatewayAttempt(sequence: 2, reachable: true, outcome: "reply", durationNanos: 15_000_000),
                    gatewayAttempt(sequence: 3, reachable: false, outcome: "timeout", durationNanos: 2_000_000_000),
                    gatewayAttempt(sequence: 4, reachable: true, outcome: "reply", durationNanos: 25_000_000),
                ],
                burstIntervalSeconds: 0.05
            )
        )

        let metrics = WiFiMetricBuilder.metrics(snapshot: snapshot, state: state)

        XCTAssertEqual(metric(named: "watchme_wifi_probe_gateway_icmp_probe_count", in: metrics)?.value, 4)
        XCTAssertEqual(metric(named: "watchme_wifi_probe_gateway_icmp_reply_count", in: metrics)?.value, 3)
        XCTAssertEqual(metric(named: "watchme_wifi_probe_gateway_icmp_loss_ratio", in: metrics)?.value ?? -1, 0.25, accuracy: 0.000_001)
        XCTAssertEqual(
            metric(named: "watchme_wifi_probe_gateway_icmp_jitter_seconds", in: metrics)?.value ?? -1,
            0.0075,
            accuracy: 0.000_001
        )
        XCTAssertEqual(
            metric(named: "watchme_wifi_probe_gateway_icmp_duration_seconds", in: metrics)?.value ?? -1,
            0.016666,
            accuracy: 0.000_001
        )
        XCTAssertEqual(
            metric(
                named: "watchme_wifi_probe_gateway_icmp_success",
                labels: ["gateway": "192.168.23.254", "outcome": "partial_loss", "timing_source": "bpf_packet"],
                in: metrics
            )?.value,
            1
        )
    }
}

private func gatewayAttempt(
    sequence: Int,
    reachable: Bool,
    outcome: String,
    durationNanos: UInt64
) -> ActiveGatewayProbeAttempt {
    let start = UInt64(sequence) * 1_000_000_000
    return ActiveGatewayProbeAttempt(
        sequence: sequence,
        identifier: UInt16(sequence),
        icmpSequence: UInt16(sequence + 100),
        reachable: reachable,
        outcome: outcome,
        error: reachable ? nil : "ICMP echo reply was not observed before timeout",
        startWallNanos: start,
        finishedWallNanos: start + durationNanos,
        durationNanos: durationNanos,
        timingSource: bpfPacketTimingSource,
        timestampSource: bpfHeaderTimestampSource
    )
}

private func makeGatewayMetricSnapshot() -> WiFiSnapshot {
    WiFiSnapshot(
        capturedWallNanos: 1000,
        interfaceName: "en0",
        ssid: "lab",
        ssidEncoding: "utf8",
        bssid: "aa:bb:cc:dd:ee:ff",
        isAssociated: true,
        rssiDBM: -51,
        noiseDBM: -97,
        txRateMbps: 573,
        channel: 40,
        channelBand: "5ghz",
        channelWidth: "40mhz",
        channelWidthMHz: 40,
        phyMode: "11ax",
        security: "wpa3_personal",
        interfaceMode: "station",
        countryCode: "jp",
        transmitPowerMW: 126,
        powerOn: true,
        serviceActive: true,
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
