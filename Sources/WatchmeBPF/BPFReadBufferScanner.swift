import Foundation
import WatchmeCore

public struct BPFReadBufferRecord {
    public let buffer: [UInt8]
    public let packetOffset: Int
    public let caplen: Int
    public let packetWallNanos: UInt64
}

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
