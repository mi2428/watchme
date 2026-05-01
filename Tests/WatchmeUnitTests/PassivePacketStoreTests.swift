@testable import WatchmeWiFi
import XCTest

final class PassivePacketStoreTests: XCTestCase {
    func testBuildDHCPSpansPairsLifecycleAndRetries() {
        let base: UInt64 = 1_000_000_000
        let observations = [
            dhcp(base, xid: 0x1234_5678, type: 1),
            dhcp(base + 1_000_000_000, xid: 0x1234_5678, type: 1),
            dhcp(base + 2_000_000_000, xid: 0x1234_5678, type: 2, server: "192.168.1.1"),
            dhcp(base + 3_000_000_000, xid: 0x1234_5678, type: 3),
            dhcp(base + 4_000_000_000, xid: 0x1234_5678, type: 5, yiaddr: "192.168.1.44", server: "192.168.1.1", lease: 3600),
        ]

        let spans = buildDHCPSpans(observations)
        let names = spans.map(\.name)

        XCTAssertTrue(names.contains("packet.dhcp.discover_retry_gap"))
        XCTAssertTrue(names.contains("packet.dhcp.discover_to_offer"))
        XCTAssertTrue(names.contains("packet.dhcp.request_to_ack"))
        let ack = spans.first { $0.name == "packet.dhcp.request_to_ack" }
        XCTAssertEqual(ack?.tags["dhcp.xid"], "0x12345678")
        XCTAssertEqual(ack?.tags["dhcp.yiaddr"], "192.168.1.44")
        XCTAssertEqual(ack?.tags["dhcp.lease_time_seconds"], "3600")
    }

    func testBuildICMPv6SpansPairsRouterAndNeighborResolution() {
        let base: UInt64 = 5_000_000_000
        let observations = [
            icmp(base, type: 133, source: "fe80::1", destination: "ff02::2"),
            icmp(
                base + 500_000_000,
                type: 134,
                source: "fe80::router",
                destination: "ff02::1",
                routerLifetime: 1800,
                sourceLLA: "aa:bb:cc:dd:ee:ff"
            ),
            icmp(base + 1_000_000_000, type: 135, source: "fe80::host", destination: "ff02::1:ff00:1", target: "fe80::router"),
            icmp(base + 2_000_000_000, type: 135, source: "fe80::host", destination: "ff02::1:ff00:1", target: "fe80::router"),
            icmp(
                base + 2_500_000_000,
                type: 136,
                source: "fe80::router",
                destination: "fe80::host",
                target: "fe80::router",
                targetLLA: "aa:bb:cc:dd:ee:ff"
            ),
        ]

        let spans = buildICMPv6Spans(observations)
        let names = spans.map(\.name)

        XCTAssertTrue(names.contains("packet.icmpv6.router_solicitation_to_advertisement"))
        XCTAssertTrue(names.contains("packet.icmpv6.neighbor_solicitation_retry_gap"))
        XCTAssertTrue(names.contains("packet.icmpv6.neighbor_solicitation_to_advertisement"))
        let resolution = spans.first { $0.name == "packet.icmpv6.neighbor_solicitation_to_advertisement" }
        XCTAssertEqual(resolution?.tags["icmpv6.nd.target_address"], "fe80::router")
        XCTAssertEqual(resolution?.tags["icmpv6.nd.target_link_layer_address"], "aa:bb:cc:dd:ee:ff")
    }

    func testBuildICMPv6SpansSuppressesNonGatewayNeighborRetryGaps() {
        let base: UInt64 = 5_000_000_000
        let observations = [
            icmp(
                base,
                type: 134,
                source: "fe80::router",
                destination: "ff02::1",
                routerLifetime: 1800,
                sourceLLA: "aa:bb:cc:dd:ee:ff"
            ),
            icmp(base + 1_000_000_000, type: 135, source: "fe80::host", destination: "ff02::1:ff00:2", target: "fe80::peer"),
            icmp(base + 2_000_000_000, type: 135, source: "fe80::host", destination: "ff02::1:ff00:2", target: "fe80::peer"),
            icmp(
                base + 2_500_000_000,
                type: 136,
                source: "fe80::peer",
                destination: "fe80::host",
                target: "fe80::peer",
                targetLLA: "11:22:33:44:55:66"
            ),
        ]

        let spans = buildICMPv6Spans(observations)

        XCTAssertFalse(spans.contains { $0.name == "packet.icmpv6.neighbor_solicitation_retry_gap" })
        XCTAssertTrue(spans.contains { $0.name == "packet.icmpv6.neighbor_solicitation_to_advertisement" })
    }

    func testPassivePacketStoreConsumeSuppressesPreviouslyReturnedSpans() {
        let store = PassivePacketStore()
        let now = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        store.appendDHCP(dhcp(now, xid: 0xAABB_CCDD, type: 3))
        store.appendDHCP(dhcp(now + 1_000_000, xid: 0xAABB_CCDD, type: 5, yiaddr: "10.0.0.20"))

        let first = store.recentPacketSpans(interfaceName: "en0", ipv4Gateway: nil, maxAge: 60, consume: true)
        let second = store.recentPacketSpans(interfaceName: "en0", ipv4Gateway: nil, maxAge: 60, consume: true)
        let nonConsumed = store.recentPacketSpans(interfaceName: "en0", ipv4Gateway: nil, maxAge: 60, consume: false)

        XCTAssertEqual(first.map(\.name), ["packet.dhcp.request_to_ack"])
        XCTAssertTrue(second.isEmpty)
        XCTAssertEqual(nonConsumed.map(\.name), ["packet.dhcp.request_to_ack"])
    }

    func testConsumedDHCPExchangeCanBeReplayedForAssociationTrace() {
        let store = PassivePacketStore()
        let now = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        store.appendDHCP(dhcp(now, xid: 0xAABB_CCDD, type: 1))
        store.appendDHCP(dhcp(now + 1_000_000, xid: 0xAABB_CCDD, type: 2, server: "10.0.0.1"))
        store.appendDHCP(dhcp(now + 2_000_000, xid: 0xAABB_CCDD, type: 3))
        store.appendDHCP(dhcp(now + 3_000_000, xid: 0xAABB_CCDD, type: 5, yiaddr: "10.0.0.20"))

        _ = store.recentPacketSpans(interfaceName: "en0", ipv4Gateway: nil, maxAge: 60, consume: true)
        let replayed = store.recentPacketSpans(
            interfaceName: "en0",
            ipv4Gateway: nil,
            maxAge: 60,
            consume: true,
            includeConsumed: { $0.name.hasPrefix("packet.dhcp.") }
        )

        XCTAssertEqual(replayed.map(\.name), ["packet.dhcp.discover_to_offer", "packet.dhcp.request_to_ack"])
    }

    func testBuildARPSpansPairsGatewayResolutionAndRetries() {
        let base: UInt64 = 7_000_000_000
        let observations = [
            arpRequest(base, targetIP: "192.168.1.1"),
            arpRequest(base + 1_000_000_000, targetIP: "192.168.1.1"),
            arpReply(base + 1_300_000_000, senderIP: "192.168.1.1", senderMAC: "aa:bb:cc:dd:ee:ff"),
            arpRequest(base + 1_400_000_000, targetIP: "192.168.1.200"),
            arpReply(base + 1_500_000_000, senderIP: "192.168.1.200", senderMAC: "11:22:33:44:55:66"),
        ]

        let spans = buildARPSpans(observations, ipv4Gateway: "192.168.1.1")
        let names = spans.map(\.name)

        XCTAssertEqual(names, ["packet.arp.request_retry_gap", "packet.arp.request_to_reply"])
        let resolution = spans.first { $0.name == "packet.arp.request_to_reply" }
        XCTAssertEqual(resolution?.tags["arp.target_ip"], "192.168.1.1")
        XCTAssertEqual(resolution?.tags["arp.target_role"], "gateway")
        XCTAssertEqual(resolution?.tags["network.gateway"], "192.168.1.1")
        XCTAssertEqual(resolution?.tags["arp.sender_mac"], "aa:bb:cc:dd:ee:ff")
    }

    func testRecentPacketSpansFiltersARPToLocalWiFiAttachment() {
        let store = PassivePacketStore()
        let now = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        store.appendARP(
            arp(
                now,
                packet: ARPTestPacket(
                    operation: 1,
                    senderMAC: "00:e0:4c:96:80:5b",
                    senderIP: "192.168.22.206",
                    targetMAC: "00:00:00:00:00:00",
                    targetIP: "192.168.23.254"
                )
            )
        )
        store.appendARP(
            arp(
                now + 1_000_000,
                packet: ARPTestPacket(
                    operation: 1,
                    senderMAC: "00:e0:4c:96:80:5b",
                    senderIP: "192.168.22.206",
                    targetMAC: "00:00:00:00:00:00",
                    targetIP: "192.168.22.173"
                )
            )
        )
        store.appendARP(
            arp(
                now + 2_000_000,
                packet: ARPTestPacket(
                    operation: 1,
                    senderMAC: "00:e0:4c:96:80:5b",
                    senderIP: "192.168.22.206",
                    targetMAC: "00:00:00:00:00:00",
                    targetIP: "192.168.22.173"
                )
            )
        )
        store.appendARP(
            arp(
                now + 3_000_000,
                packet: ARPTestPacket(
                    operation: 1,
                    senderMAC: "50:f2:65:f2:4a:63",
                    senderIP: "192.168.22.173",
                    targetMAC: "00:00:00:00:00:00",
                    targetIP: "192.168.23.254"
                )
            )
        )
        store.appendARP(
            arp(
                now + 4_000_000,
                packet: ARPTestPacket(
                    operation: 2,
                    senderMAC: "b6:99:e5:2b:f8:cc",
                    senderIP: "192.168.23.254",
                    targetMAC: "50:f2:65:f2:4a:63",
                    targetIP: "192.168.22.173"
                )
            )
        )

        let spans = store.recentPacketSpans(
            interfaceName: "en0",
            ipv4Gateway: "192.168.23.254",
            maxAge: 60,
            consume: false,
            localHardwareAddress: "50:f2:65:f2:4a:63",
            localIPv4Addresses: ["192.168.22.173"]
        )

        XCTAssertEqual(spans.map(\.name), ["packet.arp.request_to_reply"])
        XCTAssertEqual(spans.first?.tags["arp.sender_ip"], "192.168.23.254")
    }

    func testRecentPacketSpansFiltersNeighborDiscoveryToLocalOrRouterTargets() {
        let store = PassivePacketStore()
        let now = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        store.appendICMPv6(icmp(now, type: 135, source: "fe80::peer", destination: "ff02::1:ff00:1", target: "fe80::other"))
        store.appendICMPv6(
            icmp(
                now + 1_000_000,
                type: 136,
                source: "fe80::other",
                destination: "fe80::peer",
                target: "fe80::other",
                targetLLA: "aa:aa:aa:aa:aa:aa"
            )
        )
        store.appendICMPv6(icmp(
            now + 1_500_000,
            type: 135,
            source: "fe80::local",
            destination: "ff02::1:ff00:2",
            target: "fe80::peer-target",
            sourceLLA: "50:f2:65:f2:4a:63"
        ))
        store.appendICMPv6(
            icmp(
                now + 1_600_000,
                type: 136,
                source: "fe80::peer-target",
                destination: "fe80::local",
                target: "fe80::peer-target",
                targetLLA: "aa:bb:cc:dd:ee:ff"
            )
        )
        store.appendICMPv6(icmp(now + 2_000_000, type: 135, source: "fe80::local", destination: "ff02::1:ffcc", target: "fe80::router"))
        store.appendICMPv6(
            icmp(
                now + 3_000_000,
                type: 136,
                source: "fe80::router",
                destination: "fe80::local",
                target: "fe80::router",
                targetLLA: "b6:99:e5:2b:f8:cc"
            )
        )
        store.appendICMPv6(icmp(
            now + 4_000_000,
            type: 135,
            source: "::",
            destination: "ff02::1:ff00:173",
            target: "2405:6581:3e00:a600::173"
        ))
        store.appendICMPv6(
            icmp(
                now + 5_000_000,
                type: 136,
                source: "2405:6581:3e00:a600::173",
                destination: "fe80::local",
                target: "2405:6581:3e00:a600::173",
                targetLLA: "50:f2:65:f2:4a:63"
            )
        )

        let spans = store.recentPacketSpans(
            interfaceName: "en0",
            ipv4Gateway: nil,
            maxAge: 60,
            consume: false,
            localIPv6Addresses: ["fe80::local", "2405:6581:3e00:a600::173"],
            ipv6Gateway: "fe80::router"
        )

        XCTAssertEqual(spans.map(\.name), [
            "packet.icmpv6.neighbor_solicitation_to_advertisement",
            "packet.icmpv6.neighbor_solicitation_to_advertisement",
        ])
        XCTAssertEqual(Set(spans.compactMap { $0.tags["icmpv6.nd.target_address"] }), [
            "fe80::router",
            "2405:6581:3e00:a600::173",
        ])
    }
}
