@testable import WatchmeWiFi
import XCTest

final class WiFiMetricBuilderTests: XCTestCase {
    func testMetricsAlwaysIncludeEssidAndBssidLabels() {
        let snapshot = WiFiSnapshot(
            capturedWallNanos: 1000,
            interfaceName: "en0",
            ssid: nil,
            bssid: nil,
            isAssociated: true,
            rssiDBM: -51,
            noiseDBM: -97,
            txRateMbps: 573,
            channel: 40,
            ipv4Addresses: ["192.168.22.173"],
            ipv6Addresses: []
        )

        let metrics = WiFiMetricBuilder.metrics(snapshot: snapshot)
        let names = Set(metrics.map(\.name))

        XCTAssertEqual(
            names,
            [
                "watchme_wifi_rssi_dbm",
                "watchme_wifi_noise_dbm",
                "watchme_wifi_tx_rate_mbps",
                "watchme_wifi_associated",
                "watchme_wifi_info",
                "watchme_wifi_metrics_push_timestamp_seconds",
            ]
        )
        XCTAssertTrue(metrics.allSatisfy { $0.labels["essid"] == "unknown" && $0.labels["bssid"] == "unknown" })
        XCTAssertEqual(metrics.first { $0.name == "watchme_wifi_info" }?.labels["channel"], "40")
        XCTAssertEqual(metrics.first { $0.name == "watchme_wifi_associated" }?.value, 1)
    }

    func testTraceTagsExposeIdentityStatus() {
        let available = WiFiSnapshot(
            capturedWallNanos: 2000,
            interfaceName: "en0",
            ssid: "lab",
            bssid: "aa:bb:cc:dd:ee:ff",
            isAssociated: true,
            rssiDBM: nil,
            noiseDBM: nil,
            txRateMbps: nil,
            channel: nil,
            ipv4Addresses: [],
            ipv6Addresses: []
        )
        let redacted = WiFiSnapshot(
            capturedWallNanos: 3000,
            interfaceName: "en0",
            ssid: nil,
            bssid: nil,
            isAssociated: true,
            rssiDBM: nil,
            noiseDBM: nil,
            txRateMbps: nil,
            channel: nil,
            ipv4Addresses: [],
            ipv6Addresses: []
        )

        XCTAssertEqual(available.traceTags["wifi.identity_available"], "true")
        XCTAssertEqual(available.traceTags["wifi.identity_status"], "available")
        XCTAssertEqual(redacted.traceTags["wifi.identity_available"], "false")
        XCTAssertEqual(redacted.traceTags["wifi.identity_status"], "redacted_or_unavailable")
    }
}
