@testable import WatchmeTelemetry
import XCTest

final class PrometheusTextEncoderTests: XCTestCase {
    func testEncodeSortsAndEscapesLabelsAndDescribesMetricOnce() {
        let metrics = [
            PrometheusMetric(
                name: "watchme_wifi_rssi_dbm",
                help: "RSSI \"quoted\" \\ path\nline",
                type: .gauge,
                labels: ["essid": "office\nwifi", "bssid": #"aa"bb\cc"#, "interface": "en0"],
                value: -51
            ),
            PrometheusMetric(
                name: "watchme_wifi_rssi_dbm",
                help: "ignored duplicate help",
                type: .gauge,
                labels: ["interface": "en1"],
                value: -48.1234567
            ),
        ]

        let encoded = PrometheusTextEncoder.encode(metrics)

        XCTAssertEqual(encoded.components(separatedBy: "# HELP watchme_wifi_rssi_dbm").count - 1, 1)
        XCTAssertTrue(encoded.contains(#"# TYPE watchme_wifi_rssi_dbm gauge"#))
        XCTAssertTrue(encoded.contains(#"watchme_wifi_rssi_dbm{bssid="aa\"bb\\cc",essid="office\nwifi",interface="en0"} -51"#))
        XCTAssertTrue(encoded.contains(#"watchme_wifi_rssi_dbm{interface="en1"} -48.123457"#))
        XCTAssertTrue(encoded.hasSuffix("\n"))
    }
}
