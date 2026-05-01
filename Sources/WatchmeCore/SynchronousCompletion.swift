import Foundation

/// Bridges a callback-style operation into the agent's synchronous probe path.
///
/// The first completion wins. If the caller times out, the timeout value is
/// stored as the result so any later callback is ignored consistently.
public final class SynchronousCompletion<Value> {
    private let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var completed = false
    private var storedValue: Value?

    public init() {}

    public func complete(_ value: @autoclosure () -> Value) {
        lock.lock()
        defer {
            lock.unlock()
        }
        guard !completed else {
            return
        }
        storedValue = value()
        completed = true
        semaphore.signal()
    }

    public func wait(timeout: TimeInterval, timeoutValue: @autoclosure () -> Value) -> Value {
        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            complete(timeoutValue())
        }
        return value(or: timeoutValue())
    }

    public func value(or fallback: @autoclosure () -> Value) -> Value {
        lock.lock()
        defer {
            lock.unlock()
        }
        return storedValue ?? fallback()
    }
}
