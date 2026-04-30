import Darwin
import Foundation
import WatchmeCore

public struct BPFPacket {
    public let interfaceName: String
    public let timestampNanos: UInt64
    public let frame: [UInt8]

    public init(interfaceName: String, timestampNanos: UInt64, frame: [UInt8]) {
        self.interfaceName = interfaceName
        self.timestampNanos = timestampNanos
        self.frame = frame
    }
}

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
        var offset = 0
        while offset + 20 <= bytesRead {
            // A single BPF read can contain multiple bpf_hdr + frame records.
            // Each record is word-aligned, so offset advancement must follow
            // BPF_WORDALIGN semantics or the next packet will be misread.
            let caplen = Int(readLittleUInt32(buffer, offset: offset + bpfHeaderCaplenOffset))
            let headerLength = Int(readLittleUInt16(buffer, offset: offset + bpfHeaderHeaderLengthOffset))
            guard caplen > 0, headerLength > 0 else {
                break
            }
            let packetOffset = offset + headerLength
            if packetOffset + caplen <= bytesRead {
                let timestamp = bpfTimestampNanos(buffer: buffer, offset: offset) ?? wallClockNanos()
                let frame = Array(buffer[packetOffset ..< (packetOffset + caplen)])
                onPacket(BPFPacket(interfaceName: interfaceName, timestampNanos: timestamp, frame: frame))
            }
            let advance = bpfWordAlign(headerLength + caplen)
            guard advance > 0 else {
                break
            }
            offset += advance
        }
    }
}
