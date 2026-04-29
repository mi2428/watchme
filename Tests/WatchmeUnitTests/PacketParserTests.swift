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
