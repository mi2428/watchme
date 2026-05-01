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
            EthernetICMPEchoFrame(
                sourceMAC: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                destinationMAC: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                sourceIP: [192, 168, 22, 173],
                destinationIP: [192, 168, 23, 254],
                identifier: 0x1234,
                sequence: 0x5678,
                payloadSize: 4
            )
        )

        XCTAssertEqual(Array(frame[0 ..< 6]), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
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

    func testGatewayICMPv6EchoFrameBuildsParseableEthernetPacket() throws {
        let sourceIP: [UInt8] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x04, 0x91, 0x53, 0x41, 0x80, 0x6B, 0x7B, 0x1B]
        let gatewayIP: [UInt8] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0xB4, 0x99, 0xE5, 0xFF, 0xFE, 0x2B, 0xF8, 0xCC]
        let frame = ethernetICMPv6EchoFrame(
            EthernetICMPv6EchoFrame(
                sourceMAC: [0x50, 0xF2, 0x65, 0xF2, 0x4A, 0x63],
                destinationMAC: [0xB6, 0x99, 0xE5, 0x2B, 0xF8, 0xCC],
                sourceIP: sourceIP,
                destinationIP: gatewayIP,
                identifier: 0x1234,
                sequence: 0x5678,
                payloadSize: 4
            )
        )

        XCTAssertEqual(Array(frame[0 ..< 6]), [0xB6, 0x99, 0xE5, 0x2B, 0xF8, 0xCC])
        XCTAssertEqual(Array(frame[6 ..< 12]), [0x50, 0xF2, 0x65, 0xF2, 0x4A, 0x63])
        XCTAssertEqual(Array(frame[12 ..< 14]), [0x86, 0xDD])

        let packet = try XCTUnwrap(parseBPFGatewayICMPv6Packet(buffer: frame, offset: 0, length: frame.count))
        XCTAssertEqual(packet.family, .ipv6)
        XCTAssertEqual(packet.type, 128)
        XCTAssertEqual(packet.code, 0)
        XCTAssertEqual(packet.sourceIP, "fe80::491:5341:806b:7b1b")
        XCTAssertEqual(packet.destinationIP, "fe80::b499:e5ff:fe2b:f8cc")
        XCTAssertEqual(packet.identifier, 0x1234)
        XCTAssertEqual(packet.sequence, 0x5678)
    }

    func testGatewayNeighborSolicitationFrameBuildsParseableEthernetPacket() throws {
        let sourceIP: [UInt8] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x04, 0x91, 0x53, 0x41, 0x80, 0x6B, 0x7B, 0x1B]
        let gatewayIP: [UInt8] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0xB4, 0x99, 0xE5, 0xFF, 0xFE, 0x2B, 0xF8, 0xCC]
        let frame = ethernetIPv6NeighborSolicitationFrame(
            sourceMAC: [0x50, 0xF2, 0x65, 0xF2, 0x4A, 0x63],
            sourceIP: sourceIP,
            targetIP: gatewayIP
        )

        XCTAssertEqual(Array(frame[0 ..< 6]), [0x33, 0x33, 0xFF, 0x2B, 0xF8, 0xCC])
        XCTAssertEqual(Array(frame[6 ..< 12]), [0x50, 0xF2, 0x65, 0xF2, 0x4A, 0x63])
        XCTAssertEqual(Array(frame[12 ..< 14]), [0x86, 0xDD])

        let packet = try XCTUnwrap(parseBPFGatewayNeighborPacket(buffer: frame, offset: 0, length: frame.count))
        XCTAssertEqual(packet.type, 135)
        XCTAssertEqual(packet.sourceIP, "fe80::491:5341:806b:7b1b")
        XCTAssertEqual(packet.destinationIP, "ff02::1:ff2b:f8cc")
        XCTAssertEqual(packet.targetAddress, "fe80::b499:e5ff:fe2b:f8cc")
        XCTAssertEqual(packet.sourceLinkLayerAddress, "50:f2:65:f2:4a:63")
    }

    func testGatewayARPRequestFrameBuildsParseableEthernetPacket() throws {
        let frame = ethernetARPRequestFrame(
            sourceMAC: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            sourceIP: [192, 168, 22, 173],
            targetIP: [192, 168, 23, 254]
        )

        XCTAssertEqual(Array(frame[0 ..< 6]), [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
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
            requestPacketWallNanos: 2000,
            requestWriteWallNanos: 1000,
            replyWallNanos: 5000
        )

        XCTAssertEqual(timing.startWallNanos, 2000)
        XCTAssertEqual(timing.finishedWallNanos, 5000)
        XCTAssertEqual(timing.durationNanos, 3000)
        XCTAssertEqual(timing.timingSource, bpfPacketTimingSource)
        XCTAssertEqual(timing.timestampSource, bpfHeaderTimestampSource)
    }

    func testGatewayARPTimingFallsBackToRequestWriteBoundary() {
        let timing = gatewayARPRequestToReplyTiming(
            requestPacketWallNanos: nil,
            requestWriteWallNanos: 1000,
            replyWallNanos: 5000
        )

        XCTAssertEqual(timing.startWallNanos, 1000)
        XCTAssertEqual(timing.finishedWallNanos, 5000)
        XCTAssertEqual(timing.durationNanos, 4000)
        XCTAssertEqual(timing.timingSource, wallClockPacketBoundaryTimingSource)
        XCTAssertEqual(timing.timestampSource, wallClockTimestampSource)
    }

    func testGatewayARPResolutionUsesInjectedBPFIOBoundary() throws {
        let recorder = GatewayBPFIORecorder()
        let io = gatewayBPFIO(
            recorder: recorder,
            readARPReply: { fd, bufferLength, timeout, localIP, gateway in
                XCTAssertEqual(fd, 42)
                XCTAssertEqual(bufferLength, 8192)
                XCTAssertEqual(timeout, 1)
                XCTAssertEqual(localIP, "192.168.22.173")
                XCTAssertEqual(gateway, "192.168.23.254")
                return BPFGatewayARPReadResult(
                    ok: true,
                    error: nil,
                    requestWallNanos: 1000,
                    replyWallNanos: 5000,
                    gatewayHardwareAddress: "aa:bb:cc:dd:ee:ff"
                )
            }
        )

        let result = runBPFGatewayARPResolution(gateway: "192.168.23.254", timeout: 1, interfaceName: "en0", bpfIO: io)

        XCTAssertTrue(result.ok)
        XCTAssertEqual(result.gatewayHardwareAddress, "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(result.timing.durationNanos, 4000)
        XCTAssertEqual(recorder.closedFDs, [42])
        let frame = try XCTUnwrap(recorder.writes.first)
        let packet = try XCTUnwrap(parseARPPacket(buffer: frame, offset: 14, packetEnd: frame.count))
        XCTAssertEqual(packet.senderProtocolAddress, "192.168.22.173")
        XCTAssertEqual(packet.targetProtocolAddress, "192.168.23.254")
    }

    func testGatewayICMPAttemptUsesInjectedBPFIOBoundary() throws {
        let recorder = GatewayBPFIORecorder()
        let io = gatewayBPFIO(
            recorder: recorder,
            readICMPReply: { request in
                XCTAssertEqual(request.fd, 42)
                XCTAssertEqual(request.bufferLength, 8192)
                XCTAssertEqual(request.localIP, "192.168.22.173")
                XCTAssertEqual(request.gateway, "192.168.23.254")
                return BPFGatewayICMPReadResult(
                    ok: true,
                    error: nil,
                    requestWallNanos: 2000,
                    replyWallNanos: 7000
                )
            }
        )

        let attempt = runBPFGatewayICMPAttempt(
            sequence: 3,
            gateway: "192.168.23.254",
            gatewayHardwareAddress: "aa:bb:cc:dd:ee:ff",
            timeout: 1,
            interfaceName: "en0",
            bpfIO: io
        )

        XCTAssertTrue(attempt.reachable)
        XCTAssertEqual(attempt.outcome, "reply")
        XCTAssertEqual(attempt.timing.durationNanos, 5000)
        XCTAssertEqual(recorder.closedFDs, [42])
        let frame = try XCTUnwrap(recorder.writes.first)
        let packet = try XCTUnwrap(parseBPFGatewayICMPPacket(buffer: frame, offset: 0, length: frame.count))
        XCTAssertEqual(packet.sourceIP, "192.168.22.173")
        XCTAssertEqual(packet.destinationIP, "192.168.23.254")
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

    private func gatewayBPFIO(
        recorder: GatewayBPFIORecorder,
        readARPReply: @escaping (Int32, Int, TimeInterval, String, String) -> BPFGatewayARPReadResult = { _, _, _, _, _ in
            XCTFail("unexpected ARP read")
            return BPFGatewayARPReadResult(ok: false, error: "unexpected", requestWallNanos: nil, replyWallNanos: nil, gatewayHardwareAddress: nil)
        },
        readICMPReply: @escaping (GatewayICMPReadRequest) -> BPFGatewayICMPReadResult = { _ in
            XCTFail("unexpected ICMP read")
            return BPFGatewayICMPReadResult(ok: false, error: "unexpected", requestWallNanos: nil, replyWallNanos: nil)
        }
    ) -> GatewayBPFIO {
        GatewayBPFIO(
            interfaceState: { _ in
                NativeInterfaceState(
                    isActive: true,
                    ipv4Addresses: ["192.168.22.173"],
                    ipv6Addresses: ["2001:db8::1"],
                    macAddress: "00:11:22:33:44:55",
                    ipv6LinkLocalAddresses: ["fe80::1"]
                )
            },
            openConfigured: { interfaceName in
                XCTAssertEqual(interfaceName, "en0")
                return .success(GatewayBPFDescriptor(fd: 42, bufferLength: 8192))
            },
            closeDescriptor: { descriptor in
                recorder.closedFDs.append(descriptor.fd)
            },
            writeFrame: { descriptor, frame in
                XCTAssertEqual(descriptor.fd, 42)
                recorder.writes.append(frame)
                return frame.count
            },
            readARPReply: readARPReply,
            readNeighborAdvertisement: { _, _, _, _, _ in
                XCTFail("unexpected NDP read")
                return BPFGatewayNDPReadResult(ok: false, error: "unexpected", requestWallNanos: nil, replyWallNanos: nil, gatewayHardwareAddress: nil)
            },
            readICMPReply: readICMPReply,
            readICMPv6Reply: { _ in
                XCTFail("unexpected ICMPv6 read")
                return BPFGatewayICMPReadResult(ok: false, error: "unexpected", requestWallNanos: nil, replyWallNanos: nil)
            }
        )
    }
}

private final class GatewayBPFIORecorder {
    var writes: [[UInt8]] = []
    var closedFDs: [Int32] = []
}
