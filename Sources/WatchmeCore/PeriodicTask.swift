import Foundation

/// Runs a repeated operation on a private dispatch queue.
public final class PeriodicTask {
    private let queue: DispatchQueue
    private var timer: DispatchSourceTimer?

    public init(queueLabel: String, qos: DispatchQoS = .utility) {
        queue = DispatchQueue(label: queueLabel, qos: qos)
    }

    public func start(interval: TimeInterval, fireImmediately: Bool = false, operation: @escaping () -> Void) {
        stop()
        if fireImmediately {
            operation()
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler(handler: operation)
        timer.resume()
        self.timer = timer
    }

    public func stop() {
        timer?.cancel()
        timer = nil
    }
}
