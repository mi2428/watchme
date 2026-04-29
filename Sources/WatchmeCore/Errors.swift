import Foundation

public enum WatchmeError: Error, CustomStringConvertible {
    case invalidArgument(String)

    public var description: String {
        switch self {
        case let .invalidArgument(message):
            message
        }
    }
}
