@testable import WatchmeWiFi
import XCTest

final class PacketParserTests: XCTestCase {
    func testParseDHCPv4PacketExtractsOptionsUsedByTraceSpans() {
        var packet = dhcpPacketBase()
        packet[240...] = [
            53, 1, 5,
            54, 4, 192, 168, 1, 1,
            51, 4, 0, 0, 14, 16,
            255,
        ]

        let parsed = parseDHCPv4Packet(buffer: packet, offset: 0, packetEnd: packet.count)

        XCTAssertEqual(parsed?.xid, 0x1234_5678)
        XCTAssertEqual(parsed?.messageType, 5)
        XCTAssertEqual(parsed?.yiaddr, "192.168.1.44")
        XCTAssertEqual(parsed?.serverIdentifier, "192.168.1.1")
        XCTAssertEqual(parsed?.leaseTimeSeconds, 3600)
    }

    func testParseDHCPv4PacketPreservesBootpFieldsWhenOptionsAreMissing() {
        var packet = dhcpPacketBase()
        packet[236] = 0
        packet[237] = 0
        packet[238] = 0
        packet[239] = 0

        let parsed = parseDHCPv4Packet(buffer: packet, offset: 0, packetEnd: packet.count)

        XCTAssertEqual(parsed?.xid, 0x1234_5678)
        XCTAssertEqual(parsed?.yiaddr, "192.168.1.44")
        XCTAssertNil(parsed?.messageType)
        XCTAssertNil(parsed?.serverIdentifier)
        XCTAssertNil(parsed?.leaseTimeSeconds)
    }

    func testICMPv6NDLinkLayerAddressOptionScansVariableLengthOptions() {
        let options: [UInt8] = [
            5, 1, 0, 0, 0, 0, 0, 0,
            2, 1, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ]

        XCTAssertEqual(
            icmpv6NDLinkLayerAddressOption(buffer: options, optionsOffset: 0, packetEnd: options.count, optionType: 2),
            "aa:bb:cc:dd:ee:ff"
        )
        XCTAssertNil(icmpv6NDLinkLayerAddressOption(buffer: [2, 0], optionsOffset: 0, packetEnd: 2, optionType: 2))
    }

    func testParseDNSPacketObservationExtractsActiveProbeCorrelationFields() throws {
        let query = try XCTUnwrap(dnsAQueryPacket(host: "www.example.test", id: 0xCAFE))
        let queryBytes = [UInt8](query.data)
        let queryContext = TransportPacketContext(
            interfaceName: "en0",
            packetEnd: queryBytes.count,
            timestampNanos: 1000,
            sourceIP: "192.168.22.173",
            destinationIP: "192.168.23.254"
        )
        let parsedQuery = parseDNSPacketObservation(
            buffer: queryBytes,
            offset: 0,
            context: queryContext,
            sourcePort: 53000,
            destinationPort: 53
        )

        XCTAssertEqual(parsedQuery?.transactionID, 0xCAFE)
        XCTAssertEqual(parsedQuery?.isResponse, false)
        XCTAssertEqual(parsedQuery?.queryName, "www.example.test")
        XCTAssertEqual(parsedQuery?.queryType, 1)

        var responseBytes = queryBytes
        responseBytes[2] = 0x81
        responseBytes[3] = 0x80
        responseBytes[7] = 0x01
        let responseContext = TransportPacketContext(
            interfaceName: "en0",
            packetEnd: responseBytes.count,
            timestampNanos: 2000,
            sourceIP: "192.168.23.254",
            destinationIP: "192.168.22.173"
        )
        let parsedResponse = parseDNSPacketObservation(
            buffer: responseBytes,
            offset: 0,
            context: responseContext,
            sourcePort: 53,
            destinationPort: 53000
        )

        XCTAssertEqual(parsedResponse?.isResponse, true)
        XCTAssertEqual(parsedResponse?.rcode, 0)
        XCTAssertEqual(parsedResponse?.answerCount, 1)
        XCTAssertEqual(parsedResponse?.queryName, "www.example.test")
    }

    func testParseTCPPacketObservationExtractsPortsAndFlags() {
        var packet = [UInt8](repeating: 0, count: 20)
        packet[0] = 0xD2
        packet[1] = 0xF0
        packet[2] = 0x00
        packet[3] = 0x35
        packet[12] = 0x50
        packet[13] = 0x02
        let context = TransportPacketContext(
            interfaceName: "en0",
            packetEnd: packet.count,
            timestampNanos: 1000,
            sourceIP: "192.168.22.173",
            destinationIP: "192.168.23.254"
        )

        let parsed = parseTCPPacketObservation(
            buffer: packet,
            offset: 0,
            context: context
        )

        XCTAssertEqual(parsed?.sourcePort, 54000)
        XCTAssertEqual(parsed?.destinationPort, 53)
        XCTAssertEqual(parsed?.isSYN, true)
        XCTAssertEqual(parsed?.isACK, false)
        XCTAssertEqual(parsed?.isRST, false)
        XCTAssertEqual(parsed?.payloadLength, 0)
    }

    func testParseTCPPacketObservationExtractsPayloadPrefix() {
        var packet = [UInt8](repeating: 0, count: 20)
        packet[0] = 0xD2
        packet[1] = 0xF0
        packet[2] = 0x00
        packet[3] = 0x50
        packet[12] = 0x50
        packet[13] = 0x18
        packet.append(contentsOf: Array("HEAD / HTTP/1.1\r\n".utf8))
        let context = TransportPacketContext(
            interfaceName: "en0",
            packetEnd: packet.count,
            timestampNanos: 1000,
            sourceIP: "192.168.22.173",
            destinationIP: "34.223.124.45"
        )

        let parsed = parseTCPPacketObservation(buffer: packet, offset: 0, context: context)

        XCTAssertEqual(parsed?.payloadLength, 17)
        XCTAssertEqual(String(bytes: parsed?.payloadPrefix ?? [], encoding: .utf8), "HEAD / HTTP/1.1\r\n")
    }

    func testParseICMPEchoObservationExtractsCorrelationFields() {
        let packet: [UInt8] = [8, 0, 0, 0, 0x12, 0x34, 0x00, 0x07]
        let context = TransportPacketContext(
            interfaceName: "en0",
            packetEnd: packet.count,
            timestampNanos: 1000,
            sourceIP: "192.168.22.173",
            destinationIP: "34.223.124.45"
        )

        let parsed = parseICMPv4PacketObservation(buffer: packet, offset: 0, context: context)

        XCTAssertEqual(parsed?.family, .ipv4)
        XCTAssertEqual(parsed?.isEchoRequest, true)
        XCTAssertEqual(parsed?.identifier, 0x1234)
        XCTAssertEqual(parsed?.sequence, 7)
    }

    func testParseICMPv6EchoObservationExtractsCorrelationFields() {
        let packet: [UInt8] = [128, 0, 0, 0, 0xBE, 0xEF, 0x00, 0x09]
        let context = TransportPacketContext(
            interfaceName: "en0",
            packetEnd: packet.count,
            timestampNanos: 1000,
            sourceIP: "2405:6581:3e00:a600::1",
            destinationIP: "2606:4700:4700::1111"
        )

        let parsed = parseICMPv6EchoPacketObservation(buffer: packet, offset: 0, context: context)

        XCTAssertEqual(parsed?.family, .ipv6)
        XCTAssertEqual(parsed?.isEchoRequest, true)
        XCTAssertEqual(parsed?.identifier, 0xBEEF)
        XCTAssertEqual(parsed?.sequence, 9)
    }

    private func dhcpPacketBase() -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: 260)
        packet[1] = 1
        packet[2] = 6
        packet[4] = 0x12
        packet[5] = 0x34
        packet[6] = 0x56
        packet[7] = 0x78
        packet[16] = 192
        packet[17] = 168
        packet[18] = 1
        packet[19] = 44
        packet[236] = 0x63
        packet[237] = 0x82
        packet[238] = 0x53
        packet[239] = 0x63
        packet[240] = 255
        return packet
    }
}
