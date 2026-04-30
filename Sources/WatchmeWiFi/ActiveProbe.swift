import Foundation
import Network

func requiredProbeInterface(named interfaceName: String?, timeout: TimeInterval) -> NWInterface? {
    guard let interfaceName, !interfaceName.isEmpty else {
        return nil
    }
    // Active probes must validate the Wi-Fi path itself, not the system default
    // route. On Macs with Ethernet or VPN as default, this prevents a
    // successful non-Wi-Fi route from hiding Wi-Fi join failures.
    return networkInterface(named: interfaceName, timeout: min(1.0, timeout))
}

func networkInterface(named name: String?, timeout: TimeInterval) -> NWInterface? {
    guard let name, !name.isEmpty else {
        return nil
    }
    // NWPathMonitor is asynchronous even for a simple interface lookup, so keep
    // this bounded. A missing interface is a useful probe failure, not a reason
    // to block the whole trace.
    let monitor = NWPathMonitor()
    let queue = DispatchQueue(label: "watchme.network_interface_lookup")
    let semaphore = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var selected: NWInterface?
    monitor.pathUpdateHandler = { path in
        lock.lock()
        selected = path.availableInterfaces.first { $0.name == name }
        lock.unlock()
        semaphore.signal()
    }
    monitor.start(queue: queue)
    _ = semaphore.wait(timeout: .now() + timeout)
    monitor.cancel()
    lock.lock()
    defer { lock.unlock() }
    return selected
}

func runProbeBurst<Value>(
    count: Int,
    interval: TimeInterval,
    qos: DispatchQoS.QoSClass = .utility,
    operation: @escaping (_ sequence: Int) -> Value
) -> [Value] {
    let normalizedCount = max(count, 1)
    let normalizedInterval = max(interval, 0)
    let queue = DispatchQueue.global(qos: qos)
    let group = DispatchGroup()
    let lock = NSLock()
    var values: [(sequence: Int, value: Value)] = []

    for sequence in 1 ... normalizedCount {
        group.enter()
        queue.asyncAfter(deadline: .now() + dispatchDelay(seconds: normalizedInterval * Double(sequence - 1))) {
            let value = operation(sequence)
            lock.lock()
            values.append((sequence: sequence, value: value))
            lock.unlock()
            group.leave()
        }
    }

    group.wait()
    return values.sorted { $0.sequence < $1.sequence }.map(\.value)
}

func isConnectionRefused(_ error: NWError) -> Bool {
    if case let .posix(code) = error {
        return code == .ECONNREFUSED
    }
    return false
}

func parseHTTPStatusCode(_ data: Data) -> Int? {
    // The active probe only needs the status line. Cap the decoded prefix so a
    // misbehaving endpoint cannot turn response parsing into unbounded work.
    guard let text = String(data: data.prefix(256), encoding: .utf8),
          let firstLine = text.components(separatedBy: "\r\n").first
    else {
        return nil
    }
    let parts = firstLine.split(separator: " ")
    guard parts.count >= 2 else {
        return nil
    }
    return Int(parts[1])
}

private func dispatchDelay(seconds: TimeInterval) -> DispatchTimeInterval {
    .nanoseconds(Int(max(seconds, 0) * 1_000_000_000))
}
