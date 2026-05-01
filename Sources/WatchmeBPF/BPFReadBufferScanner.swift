import Foundation
import WatchmeCore

/// One packet record inside a multi-record BPF read buffer.
public struct BPFReadBufferRecord {
    /// The original read buffer containing the BPF header and packet bytes.
    public let buffer: [UInt8]
    /// Offset where the captured frame begins.
    public let packetOffset: Int
    /// Captured frame length from the BPF header.
    public let caplen: Int
    /// Packet timestamp in wall-clock nanoseconds.
    public let packetWallNanos: UInt64
}

/// Iterates over every complete BPF packet record in a read buffer.
public func forEachBPFReadBufferRecord(
    _ readBuffer: [UInt8],
    bytesRead: Int,
    timestampFallback: () -> UInt64 = wallClockNanos,
    body: (BPFReadBufferRecord) -> Void
) {
    let _: Bool? = scanBPFReadBuffer(
        readBuffer,
        bytesRead: bytesRead,
        timestampFallback: timestampFallback
    ) { record in
        body(record)
        return nil
    }
}

/// Scans BPF packet records until `match` returns a value.
public func scanBPFReadBuffer<Result>(
    _ readBuffer: [UInt8],
    bytesRead: Int,
    timestampFallback: () -> UInt64 = wallClockNanos,
    match: (BPFReadBufferRecord) -> Result?
) -> Result? {
    var offset = 0
    while offset + 20 <= bytesRead {
        let caplen = Int(readLittleUInt32(readBuffer, offset: offset + bpfHeaderCaplenOffset))
        let headerLength = Int(readLittleUInt16(readBuffer, offset: offset + bpfHeaderHeaderLengthOffset))
        guard headerLength > 0, caplen > 0 else {
            break
        }

        let packetOffset = offset + headerLength
        if packetOffset + caplen <= bytesRead {
            let record = BPFReadBufferRecord(
                buffer: readBuffer,
                packetOffset: packetOffset,
                caplen: caplen,
                packetWallNanos: bpfTimestampNanos(buffer: readBuffer, offset: offset) ?? timestampFallback()
            )
            if let result = match(record) {
                return result
            }
        }
        let advance = bpfWordAlign(headerLength + caplen)
        guard advance > 0 else {
            break
        }
        offset += advance
    }
    return nil
}
