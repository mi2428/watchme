@testable import WatchmeWiFi
import XCTest

final class ActiveProbeUtilitiesTests: XCTestCase {
    func testNormalizedTargetURLDefaultsToHTTPSRootPath() {
        XCTAssertEqual(normalizedTargetURL("www.apple.com").absoluteString, "https://www.apple.com/")
        XCTAssertEqual(normalizedTargetURL("http://example.test/health").absoluteString, "http://example.test/health")
    }

    func testHTTPHeadRequestIncludesPathQueryAndRequiredHeaders() throws {
        let url = try XCTUnwrap(URL(string: "https://example.test/search?q=wifi"))
        let request = try XCTUnwrap(String(data: httpHeadRequestBytes(url: url, host: "example.test"), encoding: .utf8))

        XCTAssertTrue(request.hasPrefix("HEAD /search?q=wifi HTTP/1.1\r\n"))
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
        XCTAssertNil(parseDNSResponseMetadata(data: response, expectedID: 0xBEEF))
    }

    func testUniqueProbeHostsNormalizesURLsAndDeduplicates() {
        XCTAssertEqual(
            uniqueProbeHosts(["www.apple.com", "https://www.apple.com/path", "http://www.cloudflare.com"]),
            ["www.apple.com", "www.cloudflare.com"]
        )
    }
}
