import Darwin
import Foundation
import WatchmeCore

/// A single Ethernet frame read from BPF with its kernel timestamp.
public struct BPFPacket {
    /// Interface name the BPF descriptor is bound to.
    public let interfaceName: String
    /// BPF header timestamp converted to wall-clock nanoseconds.
    public let timestampNanos: UInt64
    /// Captured Ethernet frame bytes.
    public let frame: [UInt8]

    public init(interfaceName: String, timestampNanos: UInt64, frame: [UInt8]) {
        self.interfaceName = interfaceName
        self.timestampNanos = timestampNanos
        self.frame = frame
    }
}

/// Reads packets from a configured BPF descriptor on a utility queue.
public final class BPFPacketMonitor {
    private let interfaceName: String
    private let onPacket: (BPFPacket) -> Void
    private let onReadError: (String) -> Void
    private let queue: DispatchQueue
    private let stateLock = NSLock()
    private var fd: Int32 = -1
    private var running = false
    private var bufferLength = 4096

    public init(
        interfaceName: String,
        queueLabel: String = "watchme.bpf",
        onPacket: @escaping (BPFPacket) -> Void,
        onReadError: @escaping (String) -> Void = { _ in }
    ) {
        self.interfaceName = interfaceName
        self.onPacket = onPacket
        self.onReadError = onReadError
        queue = DispatchQueue(label: queueLabel, qos: .utility)
    }

    /// Starts the read loop and returns an error string on setup failure.
    public func start() -> String? {
        let opened = openBPFDevice()
        guard let fd = opened.fd else {
            return opened.error ?? "could not open /dev/bpf"
        }

        var tags: [String: String] = [:]
        guard configureBPF(fd: fd, interfaceName: interfaceName, tags: &tags) else {
            Darwin.close(fd)
            return tags["bpf.error"] ?? "BPF configure failed"
        }
        setNonBlocking(fd)
        if let length = Int(tags["bpf.buffer_length"] ?? "") {
            bufferLength = max(length, 4096)
        }

        stateLock.lock()
        self.fd = fd
        running = true
        stateLock.unlock()

        queue.async { [weak self] in
            self?.readLoop(fd: fd)
        }
        return nil
    }

    /// Stops the read loop and closes the BPF descriptor.
    public func stop() {
        stateLock.lock()
        running = false
        let oldFD = fd
        fd = -1
        stateLock.unlock()
        if oldFD >= 0 {
            Darwin.close(oldFD)
        }
    }

    /// Returns kernel packet counters for the active descriptor.
    public func stats() -> BPFStats? {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard fd >= 0 else {
            return nil
        }
        return readBPFStats(fd: fd)
    }

    private func isRunning() -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return running
    }

    private func readLoop(fd: Int32) {
        var buffer = [UInt8](repeating: 0, count: bufferLength)
        while isRunning() {
            var pollFD = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let pollResult = poll(&pollFD, 1, 250)
            if pollResult <= 0 {
                continue
            }
            let bytesRead = Darwin.read(fd, &buffer, buffer.count)
            if bytesRead > 0 {
                parseBPFReadBuffer(buffer, bytesRead: bytesRead)
            } else if bytesRead < 0, errno != EWOULDBLOCK, errno != EAGAIN, isRunning() {
                onReadError(posixErrorString())
            }
        }
    }

    private func parseBPFReadBuffer(_ buffer: [UInt8], bytesRead: Int) {
        forEachBPFReadBufferRecord(buffer, bytesRead: bytesRead) { record in
            let frame = Array(record.buffer[record.packetOffset ..< (record.packetOffset + record.caplen)])
            onPacket(BPFPacket(interfaceName: interfaceName, timestampNanos: record.packetWallNanos, frame: frame))
        }
    }
}
