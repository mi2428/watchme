@testable import WatchmeWiFi
import XCTest

final class ActiveProbeUtilitiesTests: XCTestCase {
    func testHTTPHeadRequestIncludesRequiredHeaders() throws {
        let request = try XCTUnwrap(String(data: httpHeadRequestBytes(path: "/", host: "example.test"), encoding: .utf8))

        XCTAssertTrue(request.hasPrefix("HEAD / HTTP/1.1\r\n"))
        XCTAssertTrue(request.contains("Host: example.test\r\n"))
        XCTAssertTrue(request.contains("User-Agent: watchme/0.1\r\n"))
        XCTAssertTrue(request.hasSuffix("\r\n\r\n"))
    }

    func testParseHTTPStatusCodeReadsOnlyStatusLine() {
        XCTAssertEqual(parseHTTPStatusCode(Data("HTTP/1.1 204 No Content\r\nHeader: value\r\n".utf8)), 204)
        XCTAssertNil(parseHTTPStatusCode(Data("not-http\r\n".utf8)))
    }

    func testDNSQueryPacketAndResponseMetadata() throws {
        let query = try XCTUnwrap(dnsQueryPacket(host: "www.example.test", recordType: .a, id: 0xCAFE))

        XCTAssertEqual(query.data.prefix(2), Data([0xCA, 0xFE]))
        XCTAssertTrue(query.data.contains(Data([3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 4, 116, 101, 115, 116, 0])))

        let response = Data([0xCA, 0xFE, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
        let metadata = try XCTUnwrap(parseDNSResponseMetadata(data: response, expectedID: 0xCAFE))
        XCTAssertEqual(metadata.rcode, 0)
        XCTAssertEqual(metadata.answerCount, 2)
        XCTAssertTrue(metadata.addresses.isEmpty)
        XCTAssertNil(parseDNSResponseMetadata(data: response, expectedID: 0xBEEF))
    }

    func testUniqueInternetProbeTargetsNormalizesAndDeduplicates() throws {
        XCTAssertEqual(
            try uniqueInternetProbeTargets(["www.apple.com", "https://www.apple.com/path", "http://www.cloudflare.com"]).map(\.host),
            ["www.apple.com", "www.cloudflare.com"]
        )
    }

    func testRunProbeBurstReturnsSequenceOrderedResults() {
        let results = runProbeBurst(count: 4, interval: 0) { sequence in
            sequence * 10
        }

        XCTAssertEqual(results, [10, 20, 30, 40])
    }

    func testInternetChecksumUsesOnesComplementSum() {
        XCTAssertEqual(internetChecksum([8, 0, 0, 0, 0x12, 0x34, 0, 1]), 0xE5CA)
    }

    func testGatewayICMPEchoFrameBuildsParseableEthernetPacket() throws {
        let frame = ethernetICMPEchoFrame(
            sourceMAC: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            destinationMAC: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            sourceIP: [192, 168, 22, 173],
            destinationIP: [192, 168, 23, 254],
            identifier: 0x1234,
            sequence: 0x5678,
            payloadSize: 4
        )

        XCTAssertEqual(Array(frame[0 ..< 6]), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        XCTAssertEqual(Array(frame[6 ..< 12]), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        XCTAssertEqual(Array(frame[12 ..< 14]), [0x08, 0x00])
        XCTAssertEqual(internetChecksum(Array(frame[14 ..< 34])), 0)
        XCTAssertEqual(internetChecksum(Array(frame[34 ..< frame.count])), 0)

        let packet = try XCTUnwrap(parseBPFGatewayICMPPacket(buffer: frame, offset: 0, length: frame.count))
        XCTAssertEqual(packet.type, 8)
        XCTAssertEqual(packet.code, 0)
        XCTAssertEqual(packet.sourceIP, "192.168.22.173")
        XCTAssertEqual(packet.destinationIP, "192.168.23.254")
        XCTAssertEqual(packet.identifier, 0x1234)
        XCTAssertEqual(packet.sequence, 0x5678)
    }

    func testGatewayARPRequestFrameBuildsParseableEthernetPacket() throws {
        let frame = ethernetARPRequestFrame(
            sourceMAC: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            sourceIP: [192, 168, 22, 173],
            targetIP: [192, 168, 23, 254]
        )

        XCTAssertEqual(Array(frame[0 ..< 6]), [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        XCTAssertEqual(Array(frame[6 ..< 12]), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        XCTAssertEqual(Array(frame[12 ..< 14]), [0x08, 0x06])

        let packet = try XCTUnwrap(parseARPPacket(buffer: frame, offset: 14, packetEnd: frame.count))
        XCTAssertEqual(packet.operation, 1)
        XCTAssertEqual(packet.senderHardwareAddress, "00:11:22:33:44:55")
        XCTAssertEqual(packet.senderProtocolAddress, "192.168.22.173")
        XCTAssertEqual(packet.targetHardwareAddress, "00:00:00:00:00:00")
        XCTAssertEqual(packet.targetProtocolAddress, "192.168.23.254")
    }

    func testGatewayARPTimingUsesObservedRequestPacketTimestamp() {
        let timing = gatewayARPRequestToReplyTiming(
            requestPacketWallNanos: 2_000,
            requestWriteWallNanos: 1_000,
            replyWallNanos: 5_000
        )

        XCTAssertEqual(timing.startWallNanos, 2_000)
        XCTAssertEqual(timing.finishedWallNanos, 5_000)
        XCTAssertEqual(timing.durationNanos, 3_000)
        XCTAssertEqual(timing.timingSource, bpfPacketTimingSource)
        XCTAssertEqual(timing.timestampSource, bpfHeaderTimestampSource)
    }

    func testGatewayARPTimingFallsBackToRequestWriteBoundary() {
        let timing = gatewayARPRequestToReplyTiming(
            requestPacketWallNanos: nil,
            requestWriteWallNanos: 1_000,
            replyWallNanos: 5_000
        )

        XCTAssertEqual(timing.startWallNanos, 1_000)
        XCTAssertEqual(timing.finishedWallNanos, 5_000)
        XCTAssertEqual(timing.durationNanos, 4_000)
        XCTAssertEqual(timing.timingSource, wallClockPacketBoundaryTimingSource)
        XCTAssertEqual(timing.timestampSource, wallClockTimestampSource)
    }

    func testProbeResultTimingAccessorsExposeUnderlyingTiming() {
        let result = ActiveInternetHTTPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "93.184.216.34",
            ok: true,
            outcome: "response",
            statusCode: 204,
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 1_000_000,
                finishedWallNanos: 1_075_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )

        XCTAssertEqual(result.startWallNanos, 1_000_000)
        XCTAssertEqual(result.finishedWallNanos, 1_075_000)
        XCTAssertEqual(result.durationNanos, 75000)
        XCTAssertEqual(result.timingSource, bpfPacketTimingSource)
        XCTAssertEqual(result.timestampSource, bpfHeaderTimestampSource)
    }
}
