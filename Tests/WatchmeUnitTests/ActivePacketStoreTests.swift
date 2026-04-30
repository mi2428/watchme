@testable import WatchmeWiFi
import XCTest

final class ActivePacketStoreTests: XCTestCase {
    func testActiveDNSExchangeUsesOnlyRegisteredProbePackets() {
        let store = PassivePacketStore()
        let start = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        let request = ActiveDNSProbeRequest(
            transactionID: 0xCAFE,
            target: "www.example.test",
            queryType: DNSRecordType.a.rawValue,
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

    func testActiveICMPExchangePairsEchoRequestAndReply() {
        let store = PassivePacketStore()
        let start = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        let request = ActiveICMPProbeRequest(
            family: .ipv4,
            remoteIP: "34.223.124.45",
            identifier: 0x1234,
            sequence: 7,
            interfaceName: "en0",
            startWallNanos: start,
            timeout: 1
        )
        store.registerActiveICMPProbe(request)

        XCTAssertTrue(
            store.appendICMP(
                activeICMP(
                    start + 1_000_000,
                    type: 8,
                    flow: ICMPTestFlow(
                        sourceIP: "192.168.22.173",
                        destinationIP: "34.223.124.45",
                        identifier: 0x1234,
                        sequence: 7
                    )
                )
            )
        )
        XCTAssertTrue(
            store.appendICMP(
                activeICMP(
                    start + 9_000_000,
                    type: 0,
                    flow: ICMPTestFlow(
                        sourceIP: "34.223.124.45",
                        destinationIP: "192.168.22.173",
                        identifier: 0x1234,
                        sequence: 7
                    )
                )
            )
        )

        let exchange = store.icmpExchange(for: request, wait: 0)

        XCTAssertEqual(exchange?.timing.timingSource, "bpf_packet")
        XCTAssertEqual(exchange?.timing.durationNanos, 8_000_000)
    }

    func testActiveTCPExchangePairsOutboundSYNWithResponse() {
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

    func testActiveTCPExchangeUsesProbeStartWhenBurstOverlaps() {
        let store = PassivePacketStore()
        let start = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        let first = ActiveTCPProbeRequest(
            remoteIP: "192.168.23.254",
            port: 53,
            interfaceName: "en0",
            startWallNanos: start,
            timeout: 1
        )
        let second = ActiveTCPProbeRequest(
            remoteIP: "192.168.23.254",
            port: 53,
            interfaceName: "en0",
            startWallNanos: start + 50_000_000,
            timeout: 1
        )
        store.registerActiveTCPProbe(first)
        store.registerActiveTCPProbe(second)

        XCTAssertTrue(store.appendTCP(tcp(start + 1_000_000, sourcePort: 54000, destinationPort: 53, flags: 0x02)))
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
        XCTAssertTrue(store.appendTCP(tcp(start + 51_000_000, sourcePort: 54001, destinationPort: 53, flags: 0x02)))
        XCTAssertTrue(
            store.appendTCP(
                tcp(
                    start + 57_000_000,
                    sourceIP: "192.168.23.254",
                    destinationIP: "192.168.22.173",
                    sourcePort: 53,
                    destinationPort: 54001,
                    flags: 0x14
                )
            )
        )

        let exchange = store.tcpConnectExchange(
            for: second,
            finishedWallNanos: start + 60_000_000,
            wait: 0
        )

        XCTAssertEqual(exchange?.syn.sourcePort, 54001)
        XCTAssertEqual(exchange?.response.destinationPort, 54001)
        XCTAssertEqual(exchange?.timing.durationNanos, 6_000_000)
    }

    func testActiveHTTPExchangePairsHeadRequestWithFirstResponsePacket() {
        let store = PassivePacketStore()
        let start = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        let request = ActiveHTTPProbeRequest(
            target: "neverssl.com",
            remoteIP: "34.223.124.45",
            port: 80,
            interfaceName: "en0",
            startWallNanos: start,
            timeout: 1
        )
        store.registerActiveHTTPProbe(request)

        XCTAssertTrue(
            store.appendTCP(
                tcp(
                    start + 1_000_000,
                    destinationIP: "34.223.124.45",
                    sourcePort: 54000,
                    destinationPort: 80,
                    flags: 0x18,
                    payload: "HEAD / HTTP/1.1\r\nHost: neverssl.com\r\n\r\n"
                )
            )
        )
        XCTAssertTrue(
            store.appendTCP(
                tcp(
                    start + 11_000_000,
                    sourceIP: "34.223.124.45",
                    destinationIP: "192.168.22.173",
                    sourcePort: 80,
                    destinationPort: 54000,
                    flags: 0x18,
                    payload: "HTTP/1.1 200 OK\r\n"
                )
            )
        )

        let exchange = store.httpExchange(for: request, finishedWallNanos: start + 12_000_000, wait: 0)

        XCTAssertEqual(exchange?.statusCode, 200)
        XCTAssertEqual(exchange?.timing.timingSource, "bpf_packet")
        XCTAssertEqual(exchange?.timing.durationNanos, 10_000_000)
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
        flags: UInt8,
        payload: String = ""
    ) -> TCPPacketObservation {
        let payloadBytes = Array(payload.utf8)
        return TCPPacketObservation(
            interfaceName: "en0",
            wallNanos: nanos,
            sourceIP: sourceIP,
            destinationIP: destinationIP,
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            flags: flags,
            payloadLength: payloadBytes.count,
            payloadPrefix: payloadBytes
        )
    }

    private struct ICMPTestFlow {
        let sourceIP: String
        let destinationIP: String
        let identifier: UInt16
        let sequence: UInt16
    }

    private func activeICMP(_ nanos: UInt64, type: UInt8, flow: ICMPTestFlow) -> ICMPPacketObservation {
        ICMPPacketObservation(
            interfaceName: "en0",
            wallNanos: nanos,
            family: .ipv4,
            type: type,
            code: 0,
            sourceIP: flow.sourceIP,
            destinationIP: flow.destinationIP,
            identifier: flow.identifier,
            sequence: flow.sequence
        )
    }
}
