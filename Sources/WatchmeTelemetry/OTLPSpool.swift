import Darwin
import Foundation
import WatchmeCore

private let otlpSpoolEnvironmentKey = "WATCHME_OTLP_SPOOL_DIR"

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

    init(directory: URL, fileManager: FileManager = .default) {
        self.directory = directory
        self.fileManager = fileManager
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
                logEvent(
                    .warn, "otlp_spool_enqueued",
                    fields: [
                        "reason": reason,
                        "endpoint_url": record.url,
                        "spool_path": directory.path,
                        "spool_pending": "\(pendingFiles().count)",
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
            var flushed = 0
            var dropped = 0

            for file in pendingFiles() {
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
                    continue
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
                    continue
                }

                switch send(request) {
                case .success:
                    remove(file)
                    flushed += 1
                case let .failure(error):
                    if isRetryableOTLPError(error) {
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

                    remove(file)
                    dropped += 1
                    logEvent(
                        .warn, "otlp_spool_dropped",
                        fields: [
                            "endpoint_url": record.url,
                            "reason": "non_retryable_export_failure",
                            "error": "\(error)",
                        ]
                    )
                }
            }

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

    private func remove(_ file: URL) {
        do {
            try fileManager.removeItem(at: file)
        } catch {
            logEvent(.warn, "otlp_spool_remove_failed", fields: ["spool_file": file.lastPathComponent, "error": "\(error)"])
        }
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
