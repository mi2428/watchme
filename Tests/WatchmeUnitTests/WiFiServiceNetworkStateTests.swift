@testable import WatchmeWiFi
import XCTest

final class WiFiServiceNetworkStateTests: XCTestCase {
    func testFindsWiFiServiceRouterAndDNSServersByInterfaceName() {
        let dictionaries: [String: [String: Any]] = [
            "State:/Network/Service/wifi/IPv4": [
                "InterfaceName": "en0",
                "Router": "192.168.23.254",
                "ARPResolvedHardwareAddress": "b6:99:e5:2b:f8:cc",
            ],
            "State:/Network/Service/wifi/IPv6": [
                "InterfaceName": "en0",
                "Router": "fe80::b499:e5ff:fe2b:f8cc%en0",
                "NetworkSignature": "IPv6.Prefix=2405:6581:3e00:a600::/64;IPv6.RouterHardwareAddress=b6:99:e5:2b:f8:cc",
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
        XCTAssertEqual(state.routerHardwareAddress, "b6:99:e5:2b:f8:cc")
        XCTAssertEqual(state.routerIPv6, "fe80::b499:e5ff:fe2b:f8cc")
        XCTAssertEqual(state.routerIPv6HardwareAddress, "b6:99:e5:2b:f8:cc")
        XCTAssertEqual(state.dnsServers, ["192.168.23.254", "1.1.1.1"])
        XCTAssertEqual(state.traceTags["network.wifi_gateway"], "192.168.23.254")
        XCTAssertEqual(state.traceTags["network.wifi_gateway_hwaddr"], "b6:99:e5:2b:f8:cc")
        XCTAssertEqual(state.traceTags["network.wifi_ipv6_gateway"], "fe80::b499:e5ff:fe2b:f8cc")
        XCTAssertEqual(state.traceTags["network.wifi_ipv6_gateway_hwaddr"], "b6:99:e5:2b:f8:cc")
    }

    func testServiceIDParsingRejectsUnrelatedKeys() {
        XCTAssertEqual(
            serviceID(fromDynamicStoreKey: "State:/Network/Service/ABCDEF/IPv4", suffix: "IPv4"),
            "ABCDEF"
        )
        XCTAssertNil(serviceID(fromDynamicStoreKey: "State:/Network/Global/IPv4", suffix: "IPv4"))
    }
}
