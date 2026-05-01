@testable import WatchmeCore
@testable import WatchmeTelemetry
import XCTest

final class OTLPSpoolTests: XCTestCase {
    private var directory: URL!

    override func setUp() {
        super.setUp()
        logger.minimumLevel = .error
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("watchme-otlp-spool-tests-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: directory)
        directory = nil
        super.tearDown()
    }

    func testFlushReplaysSerializedRequestAndDeletesItAfterSuccess() {
        let spool = OTLPSpool(directory: directory)
        let body = Data([0x01, 0x02, 0x03])
        let request = makeRequest(path: "/v1/metrics", body: body)

        spool.enqueue(request, reason: "unit")

        XCTAssertEqual(spool.pendingCount(), 1)
        let result = spool.flushPending { replayed in
            XCTAssertEqual(replayed.url?.path, "/v1/metrics")
            XCTAssertEqual(replayed.httpMethod, "POST")
            XCTAssertEqual(replayed.value(forHTTPHeaderField: "Content-Type"), "application/x-protobuf")
            XCTAssertEqual(replayed.httpBody, body)
            return .success(httpResponse(for: replayed))
        }

        XCTAssertTrue(result.ok)
        XCTAssertEqual(result.flushed, 1)
        XCTAssertEqual(result.dropped, 0)
        XCTAssertEqual(spool.pendingCount(), 0)
    }

    func testRetryableFailureKeepsPendingRequestsForLaterFlush() {
        let spool = OTLPSpool(directory: directory)
        spool.enqueue(makeRequest(path: "/v1/metrics"), reason: "unit")
        Thread.sleep(forTimeInterval: 0.001)
        spool.enqueue(makeRequest(path: "/v1/traces"), reason: "unit")

        var attempts = 0
        let blocked = spool.flushPending { _ in
            attempts += 1
            return .failure(URLError(.notConnectedToInternet))
        }

        XCTAssertFalse(blocked.ok)
        XCTAssertEqual(attempts, 1)
        XCTAssertEqual(spool.pendingCount(), 2)

        var replayedPaths: [String] = []
        let recovered = spool.flushPending { replayed in
            replayedPaths.append(replayed.url?.path ?? "")
            return .success(httpResponse(for: replayed))
        }

        XCTAssertTrue(recovered.ok)
        XCTAssertEqual(recovered.flushed, 2)
        XCTAssertEqual(replayedPaths, ["/v1/metrics", "/v1/traces"])
        XCTAssertEqual(spool.pendingCount(), 0)
    }

    func testNonRetryableStatusDropsBadPayloadAndContinuesFlush() {
        let spool = OTLPSpool(directory: directory)
        spool.enqueue(makeRequest(path: "/v1/metrics"), reason: "unit")
        Thread.sleep(forTimeInterval: 0.001)
        spool.enqueue(makeRequest(path: "/v1/traces"), reason: "unit")

        var attempts = 0
        let result = spool.flushPending { replayed in
            attempts += 1
            if replayed.url?.path == "/v1/metrics" {
                return .failure(OTLPHTTPError.statusCode(404))
            }
            return .success(httpResponse(for: replayed))
        }

        XCTAssertTrue(result.ok)
        XCTAssertEqual(attempts, 2)
        XCTAssertEqual(result.flushed, 1)
        XCTAssertEqual(result.dropped, 1)
        XCTAssertEqual(spool.pendingCount(), 0)
    }

    func testRetentionDropsOldestFilesAndFlushesInBoundedBatches() {
        let spool = OTLPSpool(
            directory: directory,
            policy: OTLPSpoolPolicy(
                maxPendingFiles: 2,
                maxPendingBytes: 1_000_000,
                maxRecordAge: 60,
                maxFlushBatchSize: 1
            )
        )
        spool.enqueue(makeRequest(path: "/v1/old"), reason: "unit")
        Thread.sleep(forTimeInterval: 0.001)
        spool.enqueue(makeRequest(path: "/v1/middle"), reason: "unit")
        Thread.sleep(forTimeInterval: 0.001)
        spool.enqueue(makeRequest(path: "/v1/new"), reason: "unit")

        XCTAssertEqual(spool.pendingCount(), 2)

        var replayedPaths: [String] = []
        let first = spool.flushPending { replayed in
            replayedPaths.append(replayed.url?.path ?? "")
            return .success(httpResponse(for: replayed))
        }

        XCTAssertTrue(first.ok)
        XCTAssertEqual(first.flushed, 1)
        XCTAssertEqual(first.remaining, 1)
        XCTAssertEqual(replayedPaths, ["/v1/middle"])

        let second = spool.flushPending { replayed in
            replayedPaths.append(replayed.url?.path ?? "")
            return .success(httpResponse(for: replayed))
        }

        XCTAssertTrue(second.ok)
        XCTAssertEqual(second.flushed, 1)
        XCTAssertEqual(second.remaining, 0)
        XCTAssertEqual(replayedPaths, ["/v1/middle", "/v1/new"])
    }

    private func makeRequest(path: String, body: Data = Data([0x2A])) -> URLRequest {
        var request = URLRequest(url: URL(string: "http://collector.example\(path)")!)
        request.httpMethod = "POST"
        request.setValue("application/x-protobuf", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        return request
    }

    private func httpResponse(for request: URLRequest) -> HTTPURLResponse {
        HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
    }
}
