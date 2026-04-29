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
}
