import Darwin
import Foundation
import WatchmeCore

private let otlpSpoolEnvironmentKey = "WATCHME_OTLP_SPOOL_DIR"

private struct PendingOTLPSpoolRequest {
    let file: URL
    let record: OTLPSpoolRecord
    let request: URLRequest
}

struct OTLPSpoolPolicy {
    let maxPendingFiles: Int
    let maxPendingBytes: UInt64
    let maxRecordAge: TimeInterval
    let maxFlushBatchSize: Int

    static let `default` = OTLPSpoolPolicy(
        maxPendingFiles: 1000,
        maxPendingBytes: 100 * 1024 * 1024,
        maxRecordAge: 7 * 24 * 60 * 60,
        maxFlushBatchSize: 100
    )

    init(
        maxPendingFiles: Int,
        maxPendingBytes: UInt64,
        maxRecordAge: TimeInterval,
        maxFlushBatchSize: Int
    ) {
        self.maxPendingFiles = max(maxPendingFiles, 1)
        self.maxPendingBytes = max(maxPendingBytes, 1)
        self.maxRecordAge = max(maxRecordAge, 1)
        self.maxFlushBatchSize = max(maxFlushBatchSize, 1)
    }
}

struct OTLPSpoolFlushResult {
    let flushed: Int
    let dropped: Int
    let remaining: Int
    let error: Error?

    var ok: Bool {
        error == nil
    }
}

enum OTLPHTTPError: Error, CustomStringConvertible {
    case statusCode(Int)
    case timedOut
    case missingHTTPResponse

    var description: String {
        switch self {
        case let .statusCode(statusCode):
            "OTLP HTTP export failed with status \(statusCode)"
        case .timedOut:
            "OTLP HTTP export timed out"
        case .missingHTTPResponse:
            "OTLP HTTP export did not receive an HTTP response"
        }
    }
}

final class OTLPSpool {
    static let shared = OTLPSpool(directory: defaultOTLPSpoolDirectory())

    private let directory: URL
    private let fileManager: FileManager
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let policy: OTLPSpoolPolicy

    init(directory: URL, fileManager: FileManager = .default, policy: OTLPSpoolPolicy = .default) {
        self.directory = directory
        self.fileManager = fileManager
        self.policy = policy
    }

    var path: String {
        directory.path
    }

    func enqueue(_ request: URLRequest, reason: String) {
        guard let record = OTLPSpoolRecord(request: request) else {
            logEvent(
                .warn, "otlp_spool_enqueue_failed",
                fields: [
                    "reason": reason,
                    "error": "request_not_serializable",
                ]
            )
            return
        }

        withFileLock {
            do {
                try ensureDirectory()
                let url = directory.appendingPathComponent("\(record.id).json")
                try encoder.encode(record).write(to: url, options: .atomic)
                let retained = enforceRetentionLocked()
                logEvent(
                    .warn, "otlp_spool_enqueued",
                    fields: [
                        "reason": reason,
                        "endpoint_url": record.url,
                        "spool_path": directory.path,
                        "spool_pending": "\(retained.pending)",
                        "spool_retention_dropped": "\(retained.dropped)",
                    ]
                )
            } catch {
                logEvent(
                    .error, "otlp_spool_enqueue_failed",
                    fields: [
                        "reason": reason,
                        "endpoint_url": record.url,
                        "spool_path": directory.path,
                        "error": "\(error)",
                    ]
                )
            }
        }
    }

    func flushPending(send: (URLRequest) -> Result<HTTPURLResponse, Error>) -> OTLPSpoolFlushResult {
        withFileLock {
            // The spool is intentionally bounded. Collector outages should keep
            // the most recent evidence without letting a long-running agent grow
            // disk usage or spend an unbounded interval replaying old payloads.
            var retained = enforceRetentionLocked()
            var flushed = 0
            var dropped = retained.dropped

            for file in pendingFiles().prefix(policy.maxFlushBatchSize) {
                guard let pending = pendingRequest(from: file, dropped: &dropped) else {
                    continue
                }

                switch send(pending.request) {
                case .success:
                    remove(file)
                    flushed += 1
                case let .failure(error):
                    if let blocked = retryableFlushBlockedResult(
                        record: pending.record,
                        flushed: flushed,
                        dropped: dropped,
                        error: error
                    ) {
                        return blocked
                    }
                    dropNonRetryableFailure(pending.file, record: pending.record, error: error)
                    dropped += 1
                }
            }

            retained = enforceRetentionLocked()
            dropped += retained.dropped
            let remaining = pendingFiles().count
            if flushed > 0 || dropped > 0 {
                logEvent(
                    .info, "otlp_spool_flushed",
                    fields: [
                        "spool_path": directory.path,
                        "spool_flushed": "\(flushed)",
                        "spool_dropped": "\(dropped)",
                        "spool_pending": "\(remaining)",
                    ]
                )
            }
            return OTLPSpoolFlushResult(flushed: flushed, dropped: dropped, remaining: remaining, error: nil)
        }
    }

    private func pendingRequest(from file: URL, dropped: inout Int) -> PendingOTLPSpoolRequest? {
        let record: OTLPSpoolRecord
        do {
            let data = try Data(contentsOf: file)
            record = try decoder.decode(OTLPSpoolRecord.self, from: data)
        } catch {
            remove(file)
            dropped += 1
            logEvent(
                .warn, "otlp_spool_dropped",
                fields: [
                    "spool_file": file.lastPathComponent,
                    "reason": "decode_failed",
                    "error": "\(error)",
                ]
            )
            return nil
        }

        guard let request = record.urlRequest else {
            remove(file)
            dropped += 1
            logEvent(
                .warn, "otlp_spool_dropped",
                fields: [
                    "spool_file": file.lastPathComponent,
                    "reason": "request_not_deserializable",
                    "endpoint_url": record.url,
                ]
            )
            return nil
        }
        return PendingOTLPSpoolRequest(file: file, record: record, request: request)
    }

    private func retryableFlushBlockedResult(
        record: OTLPSpoolRecord,
        flushed: Int,
        dropped: Int,
        error: Error
    ) -> OTLPSpoolFlushResult? {
        guard isRetryableOTLPError(error) else {
            return nil
        }
        let remaining = pendingFiles().count
        logEvent(
            .warn, "otlp_spool_flush_blocked",
            fields: [
                "endpoint_url": record.url,
                "spool_path": directory.path,
                "spool_pending": "\(remaining)",
                "spool_flushed": "\(flushed)",
                "spool_dropped": "\(dropped)",
                "error": "\(error)",
            ]
        )
        return OTLPSpoolFlushResult(flushed: flushed, dropped: dropped, remaining: remaining, error: error)
    }

    private func dropNonRetryableFailure(_ file: URL, record: OTLPSpoolRecord, error: Error) {
        remove(file)
        logEvent(
            .warn, "otlp_spool_dropped",
            fields: [
                "endpoint_url": record.url,
                "reason": "non_retryable_export_failure",
                "error": "\(error)",
            ]
        )
    }

    func pendingCount() -> Int {
        withFileLock {
            pendingFiles().count
        }
    }

    private func ensureDirectory() throws {
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    private func pendingFiles() -> [URL] {
        guard
            let files = try? fileManager.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )
        else {
            return []
        }
        return files
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private func enforceRetentionLocked() -> (dropped: Int, pending: Int) {
        var dropped = 0
        let now = wallClockNanos()
        let maxAgeNanos = UInt64(policy.maxRecordAge * 1_000_000_000)

        for file in pendingFiles() {
            guard let record = try? decoder.decode(OTLPSpoolRecord.self, from: Data(contentsOf: file)) else {
                continue
            }
            if record.createdWallNanos + maxAgeNanos < now {
                if remove(file, reason: "retention_max_age") {
                    dropped += 1
                }
            }
        }

        var files = pendingFiles()
        while files.count > policy.maxPendingFiles, let file = files.first {
            if remove(file, reason: "retention_max_files") {
                dropped += 1
            }
            files = pendingFiles()
        }

        while totalBytes(files) > policy.maxPendingBytes, let file = files.first {
            if remove(file, reason: "retention_max_bytes") {
                dropped += 1
            }
            files = pendingFiles()
        }

        return (dropped: dropped, pending: pendingFiles().count)
    }

    private func totalBytes(_ files: [URL]) -> UInt64 {
        files.reduce(UInt64(0)) { total, file in
            total + fileSize(file)
        }
    }

    private func fileSize(_ file: URL) -> UInt64 {
        guard
            let attributes = try? fileManager.attributesOfItem(atPath: file.path),
            let size = attributes[.size] as? NSNumber
        else {
            return 0
        }
        return size.uint64Value
    }

    @discardableResult
    private func remove(_ file: URL) -> Bool {
        do {
            try fileManager.removeItem(at: file)
            return true
        } catch {
            logEvent(.warn, "otlp_spool_remove_failed", fields: ["spool_file": file.lastPathComponent, "error": "\(error)"])
            return false
        }
    }

    private func remove(_ file: URL, reason: String) -> Bool {
        if remove(file) {
            logEvent(.warn, "otlp_spool_dropped", fields: ["spool_file": file.lastPathComponent, "reason": reason])
            return true
        }
        return false
    }

    private func withFileLock<T>(_ body: () -> T) -> T {
        try? ensureDirectory()
        let lockURL = directory.appendingPathComponent(".lock")
        let fd = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard fd >= 0 else {
            return body()
        }
        flock(fd, LOCK_EX)
        defer {
            flock(fd, LOCK_UN)
            close(fd)
        }
        return body()
    }
}

struct OTLPSpoolRecord: Codable {
    let id: String
    let createdWallNanos: UInt64
    let method: String
    let url: String
    let headers: [String: String]
    let bodyBase64: String

    init?(request: URLRequest) {
        guard let url = request.url?.absoluteString else {
            return nil
        }
        let body = request.httpBody ?? Data()
        id = "\(wallClockNanos())-\(randomHex(bytes: 8))"
        createdWallNanos = wallClockNanos()
        method = request.httpMethod ?? "POST"
        self.url = url
        headers = request.allHTTPHeaderFields ?? [:]
        bodyBase64 = body.base64EncodedString()
    }

    var urlRequest: URLRequest? {
        guard let endpoint = URL(string: url), let body = Data(base64Encoded: bodyBase64) else {
            return nil
        }
        var request = URLRequest(url: endpoint)
        request.httpMethod = method
        request.allHTTPHeaderFields = headers
        request.httpBody = body
        return request
    }
}

func defaultOTLPSpoolDirectory() -> URL {
    if let path = ProcessInfo.processInfo.environment[otlpSpoolEnvironmentKey], !path.isEmpty {
        return URL(fileURLWithPath: (path as NSString).expandingTildeInPath, isDirectory: true)
    }
    let home = FileManager.default.homeDirectoryForCurrentUser
    return home
        .appendingPathComponent(".watchme", isDirectory: true)
        .appendingPathComponent("otlp-spool", isDirectory: true)
}

func isRetryableOTLPError(_ error: Error) -> Bool {
    if let error = error as? OTLPHTTPError {
        switch error {
        case let .statusCode(statusCode):
            return statusCode == 408 || statusCode == 429 || statusCode >= 500
        case .timedOut, .missingHTTPResponse:
            return true
        }
    }
    if error is URLError {
        return true
    }
    return true
}
