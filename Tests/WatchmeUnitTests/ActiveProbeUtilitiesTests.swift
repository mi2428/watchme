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
        let query = try XCTUnwrap(dnsAQueryPacket(host: "www.example.test", id: 0xCAFE))

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

    func testInternetChecksumUsesOnesComplementSum() {
        XCTAssertEqual(internetChecksum([8, 0, 0, 0, 0x12, 0x34, 0, 1]), 0xE5CA)
    }
}
