import Foundation
import OpenTelemetryApi
import OpenTelemetryProtocolExporterHttp
import WatchmeCore

protocol OTLPTraceHTTPClient {
    func send(request: URLRequest, completion: @escaping (Result<HTTPURLResponse, Error>) -> Void)
}

final class OTelHTTPClientAdapter: HTTPClient {
    private let client: OTLPTraceHTTPClient

    init(client: OTLPTraceHTTPClient) {
        self.client = client
    }

    func send(request: URLRequest, completion: @escaping (Result<HTTPURLResponse, Error>) -> Void) {
        client.send(request: request, completion: completion)
    }
}

final class BlockingHTTPClient: HTTPClient, OTLPHTTPTransport, OTLPTraceHTTPClient {
    private let session: URLSession
    private let timeout: TimeInterval
    private let spool: OTLPSpool
    private let directSendOverride: ((URLRequest) -> Result<HTTPURLResponse, Error>)?

    init(
        timeout: TimeInterval,
        spool: OTLPSpool = .shared,
        directSend: ((URLRequest) -> Result<HTTPURLResponse, Error>)? = nil
    ) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.urlCache = nil
        session = URLSession(configuration: configuration)
        self.timeout = timeout
        self.spool = spool
        directSendOverride = directSend
    }

    func send(request: URLRequest, completion: @escaping (Result<HTTPURLResponse, Error>) -> Void) {
        // The exporter API is callback-based, but WatchMe Agent emits traces
        // from a serial collector path and needs completion before logging export state.
        // Blocking here keeps lifecycle semantics simple without shelling out.
        let flushResult = spool.flushPending { [weak self] pendingRequest in
            guard let self else {
                return .failure(WatchmeError.invalidArgument("OTLP HTTP client was released"))
            }
            return sendDirect(request: pendingRequest)
        }
        if let error = flushResult.error {
            spool.enqueue(request, reason: "pending_spool_flush_failed")
            completion(.failure(error))
            return
        }

        let result = sendDirect(request: request)
        if case let .failure(error) = result, isRetryableOTLPError(error) {
            spool.enqueue(request, reason: "export_failed")
        }
        completion(result)
    }

    func sendSynchronously(request: URLRequest) -> Result<HTTPURLResponse, Error> {
        var output: Result<HTTPURLResponse, Error>?
        send(request: request) { result in
            output = result
        }
        return output ?? .failure(OTLPHTTPError.missingHTTPResponse)
    }

    private func sendDirect(request: URLRequest) -> Result<HTTPURLResponse, Error> {
        if let directSendOverride {
            return directSendOverride(request)
        }
        let completion = SynchronousCompletion<Result<HTTPURLResponse, Error>>()
        let task = session.dataTask(with: request) { _, response, error in
            if let error {
                completion.complete(.failure(error))
            } else if let http = response as? HTTPURLResponse {
                if (200 ..< 300).contains(http.statusCode) {
                    completion.complete(.success(http))
                } else {
                    completion.complete(.failure(OTLPHTTPError.statusCode(http.statusCode)))
                }
            } else {
                completion.complete(.failure(OTLPHTTPError.missingHTTPResponse))
            }
        }
        task.resume()
        let result = completion.wait(timeout: timeout, timeoutValue: .failure(OTLPHTTPError.timedOut))
        if case let .failure(error) = result, let otlpError = error as? OTLPHTTPError {
            if case .timedOut = otlpError {
                task.cancel()
            }
        }
        return result
    }
}

extension Result where Success == HTTPURLResponse, Failure == Error {
    var isSuccess: Bool {
        if case .success = self {
            return true
        }
        return false
    }

    var errorDescription: String? {
        if case let .failure(error) = self {
            return "\(error)"
        }
        return nil
    }
}

func attributeValues(_ tags: [String: String]) -> [String: AttributeValue] {
    tags.reduce(into: [:]) { result, entry in
        result[entry.key] = .string(entry.value)
    }
}
