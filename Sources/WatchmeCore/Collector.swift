import Foundation

public protocol WatchmeCollector: AnyObject {
    var name: String { get }
    func runOnce() -> Int32
    func start()
    func stop()
}

public struct CollectorBuildContext {
    public let otlpURL: URL

    public init(otlpURL: URL) {
        self.otlpURL = otlpURL
    }
}

public protocol WatchmeCollectorFactory {
    static var name: String { get }
    static var summary: String { get }
    static func makeCollector(arguments: [String], context: CollectorBuildContext) throws -> any WatchmeCollector
    static func usageRows() -> [(String, String)]
}
