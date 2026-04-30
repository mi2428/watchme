@testable import WatchmeWiFi
import XCTest

final class ActiveInternetProbeRunnerTests: XCTestCase {
    func testDNSProbeReportsNoResolverForEachTargetAndFamily() {
        var config = WiFiConfig()
        config.probeInternetTargets = ["Example.com", "https://www.apple.com/path"]
        config.probeInternetFamily = .dual
        config.probeInternetDNS = true
        config.probeInternetICMP = false
        config.probeInternetHTTP = false

        let results = runActiveInternetProbes(
            config: config,
            networkState: WiFiServiceNetworkState(
                interfaceName: "en0",
                serviceID: "wifi-service",
                routerIPv4: "192.0.2.1",
                dnsServers: []
            ),
            interfaceName: "en0",
            packetStore: PassivePacketStore()
        )

        XCTAssertEqual(
            results.dns.map { "\($0.target)|\($0.family.metricValue)|\($0.recordType.name)|\($0.resolver)" },
            [
                "example.com|ipv4|A|none",
                "example.com|ipv6|AAAA|none",
                "www.apple.com|ipv4|A|none",
                "www.apple.com|ipv6|AAAA|none",
            ]
        )
        XCTAssertTrue(results.dns.allSatisfy { !$0.ok })
        XCTAssertTrue(results.dns.allSatisfy(\.addresses.isEmpty))
        XCTAssertTrue(results.dns.allSatisfy { $0.error == "no Wi-Fi DNS resolver was available" })
        XCTAssertTrue(results.dns.allSatisfy { $0.timingSource == noAddressTimingSource })
        XCTAssertTrue(results.dns.allSatisfy { $0.timestampSource == wallClockTimestampSource })
        XCTAssertTrue(results.icmp.isEmpty)
        XCTAssertTrue(results.http.isEmpty)
    }

    func testDisabledDNSProducesNoAddressResultsWithoutNetworkAccess() {
        var config = WiFiConfig()
        config.probeInternetTargets = ["Example.com", "https://example.com/duplicate", "www.apple.com"]
        config.probeInternetFamily = .dual
        config.probeInternetDNS = false
        config.probeInternetICMP = true
        config.probeInternetHTTP = true

        let results = runActiveInternetProbes(
            config: config,
            networkState: WiFiServiceNetworkState(
                interfaceName: "en0",
                serviceID: "wifi-service",
                routerIPv4: "192.0.2.1",
                dnsServers: ["192.0.2.53"]
            ),
            interfaceName: "en0",
            packetStore: PassivePacketStore()
        )

        let expected = [
            "example.com|ipv4|none|no_address",
            "example.com|ipv6|none|no_address",
            "www.apple.com|ipv4|none|no_address",
            "www.apple.com|ipv6|none|no_address",
        ]
        XCTAssertTrue(results.dns.isEmpty)
        XCTAssertEqual(results.icmp.map { "\($0.target)|\($0.family.metricValue)|\($0.remoteIP)|\($0.outcome)" }, expected)
        XCTAssertEqual(results.http.map { "\($0.target)|\($0.family.metricValue)|\($0.remoteIP)|\($0.outcome)" }, expected)
        XCTAssertTrue(results.icmp.allSatisfy { !$0.ok && $0.timingSource == noAddressTimingSource })
        XCTAssertTrue(results.http.allSatisfy { !$0.ok && $0.timingSource == noAddressTimingSource })
    }
}
