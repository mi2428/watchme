@testable import WatchmeWiFi
import XCTest

final class WiFiServiceNetworkStateTests: XCTestCase {
    func testFindsWiFiServiceRouterAndDNSServersByInterfaceName() {
        let dictionaries: [String: [String: Any]] = [
            "State:/Network/Service/wifi/IPv4": [
                "InterfaceName": "en0",
                "Router": "192.168.23.254",
            ],
            "State:/Network/Service/wifi/DNS": [
                "ServerAddresses": ["192.168.23.254", "1.1.1.1"],
            ],
            "State:/Network/Service/ethernet/IPv4": [
                "InterfaceName": "en7",
                "Router": "10.0.0.1",
            ],
            "State:/Network/Service/ethernet/DNS": [
                "ServerAddresses": ["10.0.0.1"],
            ],
        ]

        let state = wifiServiceNetworkState(interfaceName: "en0", serviceIDs: ["ethernet", "wifi"]) {
            dictionaries[$0] ?? [:]
        }

        XCTAssertEqual(state.serviceID, "wifi")
        XCTAssertEqual(state.routerIPv4, "192.168.23.254")
        XCTAssertEqual(state.dnsServers, ["192.168.23.254", "1.1.1.1"])
        XCTAssertEqual(state.traceTags["network.wifi_gateway"], "192.168.23.254")
    }

    func testServiceIDParsingRejectsUnrelatedKeys() {
        XCTAssertEqual(
            serviceID(fromDynamicStoreKey: "State:/Network/Service/ABCDEF/IPv4", suffix: "IPv4"),
            "ABCDEF"
        )
        XCTAssertNil(serviceID(fromDynamicStoreKey: "State:/Network/Global/IPv4", suffix: "IPv4"))
    }
}
