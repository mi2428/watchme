@testable import WatchmeTelemetry
import XCTest

final class TelemetryTraceExporterTests: XCTestCase {
    private var spoolDirectory: URL!

    override func setUp() {
        super.setUp()
        spoolDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("watchme-trace-exporter-tests-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: spoolDirectory)
        spoolDirectory = nil
        super.tearDown()
    }

    func testTraceExporterUsesInjectedHTTPClient() throws {
        let httpClient = RecordingOTLPTraceHTTPClient()
        let endpoint = try XCTUnwrap(URL(string: "http://collector.example/v1/traces"))
        let exporter = OTelTraceExporter(serviceName: "watchme-test", endpoint: endpoint, httpClient: httpClient)

        let result = exporter.export(TraceBatch(
            rootName: "wifi.test",
            rootTags: ["reason": "unit"],
            rootStartWallNanos: 1_000_000_000,
            rootDurationNanos: 2_000_000,
            spans: [
                TraceSpanRecord(
                    id: "child",
                    parentId: nil,
                    name: "probe.test",
                    startWallNanos: 1_000_500_000,
                    durationNanos: 1_000_000,
                    tags: ["span.source": "unit"],
                    statusOK: true
                ),
            ]
        ))

        XCTAssertTrue(result.ok)
        let request = try XCTUnwrap(httpClient.requests.first)
        XCTAssertEqual(request.url, endpoint)
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertFalse(request.httpBody?.isEmpty ?? true)
    }

    func testBlockingHTTPClientFlushesPendingBeforeCurrentRequestWithInjectedSender() {
        let spool = OTLPSpool(directory: spoolDirectory)
        spool.enqueue(makeRequest(path: "/v1/metrics"), reason: "unit")
        var paths: [String] = []
        let client = BlockingHTTPClient(timeout: 1, spool: spool) { request in
            paths.append(request.url?.path ?? "")
            return .success(self.httpResponse(for: request))
        }

        var completion: Result<HTTPURLResponse, Error>?
        client.send(request: makeRequest(path: "/v1/traces")) { result in
            completion = result
        }

        XCTAssertTrue(completion?.isSuccess ?? false)
        XCTAssertEqual(paths, ["/v1/metrics", "/v1/traces"])
        XCTAssertEqual(spool.pendingCount(), 0)
    }

    func testBlockingHTTPClientEnqueuesCurrentRequestWhenInjectedSenderFailsRetryably() {
        let spool = OTLPSpool(directory: spoolDirectory)
        let client = BlockingHTTPClient(timeout: 1, spool: spool) { _ in
            .failure(URLError(.notConnectedToInternet))
        }

        var completion: Result<HTTPURLResponse, Error>?
        client.send(request: makeRequest(path: "/v1/traces")) { result in
            completion = result
        }

        XCTAssertFalse(completion?.isSuccess ?? true)
        XCTAssertEqual(spool.pendingCount(), 1)
        let flushed = spool.flushPending { request in
            XCTAssertEqual(request.url?.path, "/v1/traces")
            return .success(self.httpResponse(for: request))
        }
        XCTAssertTrue(flushed.ok)
        XCTAssertEqual(flushed.flushed, 1)
    }

    private func makeRequest(path: String) -> URLRequest {
        var request = URLRequest(url: URL(string: "http://collector.example\(path)")!)
        request.httpMethod = "POST"
        request.httpBody = Data([0x2A])
        return request
    }

    private func httpResponse(for request: URLRequest) -> HTTPURLResponse {
        HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
    }
}

private final class RecordingOTLPTraceHTTPClient: OTLPTraceHTTPClient {
    var requests: [URLRequest] = []
    var result: Result<HTTPURLResponse, Error>?

    func send(request: URLRequest, completion: @escaping (Result<HTTPURLResponse, Error>) -> Void) {
        requests.append(request)
        completion(result ?? .success(HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!))
    }
}
