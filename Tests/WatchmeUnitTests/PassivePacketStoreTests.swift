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
        XCTAssertTrue(names.contains("packet.icmpv6.default_router_neighbor_solicitation_retry_gap"))
        XCTAssertTrue(names.contains("packet.icmpv6.default_router_neighbor_resolution"))
        let resolution = spans.first { $0.name == "packet.icmpv6.default_router_neighbor_resolution" }
        XCTAssertEqual(resolution?.tags["icmpv6.nd.target_address"], "fe80::router")
        XCTAssertEqual(resolution?.tags["icmpv6.nd.target_link_layer_address"], "aa:bb:cc:dd:ee:ff")
    }

    func testPassivePacketStoreConsumeSuppressesPreviouslyReturnedSpans() {
        let store = PassivePacketStore()
        let now = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        store.appendDHCP(dhcp(now, xid: 0xAABB_CCDD, type: 3))
        store.appendDHCP(dhcp(now + 1_000_000, xid: 0xAABB_CCDD, type: 5, yiaddr: "10.0.0.20"))

        let first = store.recentPacketSpans(interfaceName: "en0", maxAge: 60, consume: true)
        let second = store.recentPacketSpans(interfaceName: "en0", maxAge: 60, consume: true)
        let nonConsumed = store.recentPacketSpans(interfaceName: "en0", maxAge: 60, consume: false)

        XCTAssertEqual(first.map(\.name), ["packet.dhcp.request_to_ack"])
        XCTAssertTrue(second.isEmpty)
        XCTAssertEqual(nonConsumed.map(\.name), ["packet.dhcp.request_to_ack"])
    }

    func testActiveDNSExchangeUsesOnlyRegisteredProbePackets() {
        let store = PassivePacketStore()
        let start = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        let request = ActiveDNSProbeRequest(
            transactionID: 0xCAFE,
            target: "www.example.test",
            resolver: "192.168.23.254",
            interfaceName: "en0",
            startWallNanos: start,
            timeout: 1
        )
        store.registerActiveDNSProbe(request)

        XCTAssertFalse(
            store.appendDNS(
                dns(start + 500_000, transactionID: 0xBEEF, target: "www.example.test", response: false, sourcePort: 53000)
            )
        )
        XCTAssertTrue(
            store.appendDNS(
                dns(start + 1_000_000, transactionID: 0xCAFE, target: "www.example.test", response: false, sourcePort: 53001)
            )
        )
        XCTAssertTrue(
            store.appendDNS(
                dns(start + 4_000_000, transactionID: 0xCAFE, target: "www.example.test", response: true, destinationPort: 53001)
            )
        )

        let exchange = store.dnsExchange(
            for: request,
            finishedWallNanos: start + 5_000_000,
            wait: 0
        )

        XCTAssertEqual(exchange?.timing.timingSource, "bpf_packet")
        XCTAssertEqual(exchange?.timing.durationNanos, 3_000_000)
        XCTAssertEqual(exchange?.response.rcode, 0)
        XCTAssertEqual(exchange?.response.answerCount, 1)
    }

    func testActiveTCPExchangePairsOutboundSYNWithGatewayResponse() {
        let store = PassivePacketStore()
        let start = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        let request = ActiveTCPProbeRequest(
            remoteIP: "192.168.23.254",
            port: 53,
            interfaceName: "en0",
            startWallNanos: start,
            timeout: 1
        )
        store.registerActiveTCPProbe(request)

        XCTAssertTrue(
            store.appendTCP(
                tcp(start + 1_000_000, sourcePort: 54000, destinationPort: 53, flags: 0x02)
            )
        )
        XCTAssertTrue(
            store.appendTCP(
                tcp(
                    start + 3_500_000,
                    sourceIP: "192.168.23.254",
                    destinationIP: "192.168.22.173",
                    sourcePort: 53,
                    destinationPort: 54000,
                    flags: 0x14
                )
            )
        )

        let exchange = store.tcpConnectExchange(
            for: request,
            finishedWallNanos: start + 4_000_000,
            wait: 0
        )

        XCTAssertEqual(exchange?.responseKind, "rst")
        XCTAssertEqual(exchange?.timing.timingSource, "bpf_packet")
        XCTAssertEqual(exchange?.timing.durationNanos, 2_500_000)
    }

    private func dhcp(
        _ nanos: UInt64,
        xid: UInt32,
        type: UInt8,
        yiaddr: String? = nil,
        server: String? = nil,
        lease: UInt32? = nil
    ) -> DHCPObservation {
        DHCPObservation(
            interfaceName: "en0",
            wallNanos: nanos,
            xid: xid,
            messageType: type,
            yiaddr: yiaddr,
            serverIdentifier: server,
            leaseTimeSeconds: lease
        )
    }

    private func icmp(
        _ nanos: UInt64,
        type: UInt8,
        source: String,
        destination: String,
        target: String? = nil,
        routerLifetime: UInt16? = nil,
        sourceLLA: String? = nil,
        targetLLA: String? = nil
    ) -> ICMPv6Observation {
        ICMPv6Observation(
            interfaceName: "en0",
            wallNanos: nanos,
            type: type,
            code: 0,
            sourceIP: source,
            destinationIP: destination,
            targetAddress: target,
            routerLifetimeSeconds: routerLifetime,
            sourceLinkLayerAddress: sourceLLA,
            targetLinkLayerAddress: targetLLA
        )
    }

    private func dns(
        _ nanos: UInt64,
        transactionID: UInt16,
        target: String,
        response: Bool,
        sourcePort: UInt16 = 53,
        destinationPort: UInt16 = 53
    ) -> DNSPacketObservation {
        DNSPacketObservation(
            interfaceName: "en0",
            wallNanos: nanos,
            sourceIP: response ? "192.168.23.254" : "192.168.22.173",
            destinationIP: response ? "192.168.22.173" : "192.168.23.254",
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            transactionID: transactionID,
            isResponse: response,
            rcode: response ? 0 : nil,
            answerCount: response ? 1 : nil,
            queryName: target,
            queryType: 1
        )
    }

    private func tcp(
        _ nanos: UInt64,
        sourceIP: String = "192.168.22.173",
        destinationIP: String = "192.168.23.254",
        sourcePort: UInt16,
        destinationPort: UInt16,
        flags: UInt8
    ) -> TCPPacketObservation {
        TCPPacketObservation(
            interfaceName: "en0",
            wallNanos: nanos,
            sourceIP: sourceIP,
            destinationIP: destinationIP,
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            flags: flags
        )
    }
}
