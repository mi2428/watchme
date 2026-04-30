@testable import WatchmeWiFi
import XCTest

final class WiFiTracePolicyTests: XCTestCase {
    func testAssociationRecoveryReasonsAreDelayed() {
        XCTAssertTrue(WiFiTracePolicy.isAssociationRecoveryReason("wifi.join"))
        XCTAssertTrue(WiFiTracePolicy.isAssociationRecoveryReason("wifi.roam"))
        XCTAssertFalse(WiFiTracePolicy.isAssociationRecoveryReason("wifi.disconnect"))
        XCTAssertFalse(WiFiTracePolicy.isAssociationRecoveryReason("wifi.power.changed"))
    }

    func testConnectivityCheckIsOnlyRequestedForAssociatedPoweredWiFi() {
        XCTAssertTrue(WiFiTracePolicy.shouldRequestConnectivityCheck(snapshot: makeSnapshot()))
        XCTAssertFalse(WiFiTracePolicy.shouldRequestConnectivityCheck(snapshot: makeSnapshot(isAssociated: false)))
        XCTAssertFalse(WiFiTracePolicy.shouldRequestConnectivityCheck(snapshot: makeSnapshot(powerOn: false)))
    }

    func testConnectivityCheckReadinessWaitsForWiFiDNSWhenInternetProbesNeedResolution() {
        let config = WiFiConfig()
        let readyState = WiFiServiceNetworkState(
            interfaceName: "en0",
            serviceID: "wifi-service",
            routerIPv4: "192.168.23.254",
            dnsServers: ["192.168.23.254"]
        )
        let noDNSState = WiFiServiceNetworkState(
            interfaceName: "en0",
            serviceID: "wifi-service",
            routerIPv4: "192.168.23.254",
            dnsServers: []
        )

        XCTAssertEqual(
            WiFiTracePolicy.connectivityCheckReadiness(
                snapshot: makeSnapshot(isAssociated: false),
                networkState: readyState,
                config: config
            ),
            .skip("wifi_not_associated")
        )
        XCTAssertEqual(
            WiFiTracePolicy.connectivityCheckReadiness(
                snapshot: makeSnapshot(powerOn: false),
                networkState: readyState,
                config: config
            ),
            .skip("wifi_power_off")
        )
        XCTAssertEqual(
            WiFiTracePolicy.connectivityCheckReadiness(
                snapshot: makeSnapshot(),
                networkState: noDNSState,
                config: config
            ),
            .skip("wifi_dns_unavailable")
        )
        XCTAssertEqual(
            WiFiTracePolicy.connectivityCheckReadiness(
                snapshot: makeSnapshot(),
                networkState: readyState,
                config: config
            ),
            .ready
        )
    }

    func testConnectivityCheckDoesNotRequireDNSWhenInternetProbesAreDisabled() {
        var config = WiFiConfig()
        config.probeInternetDNS = false
        config.probeInternetICMP = false
        config.probeInternetTCP = false
        config.probeInternetHTTP = false
        let noDNSState = WiFiServiceNetworkState(
            interfaceName: "en0",
            serviceID: "wifi-service",
            routerIPv4: "192.168.23.254",
            dnsServers: []
        )

        XCTAssertEqual(
            WiFiTracePolicy.connectivityCheckReadiness(
                snapshot: makeSnapshot(),
                networkState: noDNSState,
                config: config
            ),
            .ready
        )
    }

    func testIPv4AddressAcquisitionSchedulesJoinRecoveryTrace() {
        XCTAssertTrue(
            WiFiTracePolicy.isAddressAcquisition(
                previous: makeSnapshot(ipv4Addresses: []),
                current: makeSnapshot(ipv4Addresses: ["192.168.22.173"])
            )
        )
        XCTAssertFalse(
            WiFiTracePolicy.isAddressAcquisition(
                previous: makeSnapshot(ipv4Addresses: ["192.168.22.172"]),
                current: makeSnapshot(ipv4Addresses: ["192.168.22.173"])
            )
        )
        XCTAssertFalse(
            WiFiTracePolicy.isAddressAcquisition(
                previous: makeSnapshot(isAssociated: false, ipv4Addresses: []),
                current: makeSnapshot(isAssociated: false, ipv4Addresses: ["192.168.22.173"])
            )
        )
    }

    func testAssociationPendingSuppressesOnlyNonDisconnectEventTraces() {
        XCTAssertTrue(WiFiTracePolicy.shouldSuppressEventTraceDuringAssociation(reason: "wifi.link.changed"))
        XCTAssertTrue(WiFiTracePolicy.shouldSuppressEventTraceDuringAssociation(reason: "wifi.network.ipv4_changed"))
        XCTAssertFalse(WiFiTracePolicy.shouldSuppressEventTraceDuringAssociation(reason: "wifi.join"))
        XCTAssertFalse(WiFiTracePolicy.shouldSuppressEventTraceDuringAssociation(reason: "wifi.roam"))
        XCTAssertFalse(WiFiTracePolicy.shouldSuppressEventTraceDuringAssociation(reason: "wifi.disconnect"))
    }

    private func makeSnapshot(
        isAssociated: Bool = true,
        powerOn: Bool? = true,
        ipv4Addresses: [String] = ["192.168.22.173"]
    ) -> WiFiSnapshot {
        WiFiSnapshot(
            capturedWallNanos: 1_000_000_000,
            interfaceName: "en0",
            ssid: isAssociated ? "lab" : nil,
            ssidEncoding: isAssociated ? "utf8" : nil,
            bssid: isAssociated ? "aa:bb:cc:dd:ee:ff" : nil,
            isAssociated: isAssociated,
            rssiDBM: isAssociated ? -51 : nil,
            noiseDBM: isAssociated ? -97 : nil,
            txRateMbps: isAssociated ? 573 : nil,
            channel: isAssociated ? 40 : nil,
            channelBand: isAssociated ? "5ghz" : nil,
            channelWidth: isAssociated ? "40mhz" : nil,
            channelWidthMHz: isAssociated ? 40 : nil,
            phyMode: isAssociated ? "11ax" : nil,
            security: isAssociated ? "wpa3_personal" : nil,
            interfaceMode: "station",
            countryCode: "jp",
            transmitPowerMW: isAssociated ? 126 : nil,
            powerOn: powerOn,
            serviceActive: isAssociated,
            ipv4Addresses: ipv4Addresses,
            ipv6Addresses: isAssociated ? ["2405:6581:3e00:a600::1"] : []
        )
    }
}
