@testable import WatchmeBPF
import XCTest

final class BPFUtilitiesTests: XCTestCase {
    func testBPFWordAlignUsesFourByteBoundaries() {
        XCTAssertEqual(bpfWordAlign(0), 0)
        XCTAssertEqual(bpfWordAlign(1), 4)
        XCTAssertEqual(bpfWordAlign(4), 4)
        XCTAssertEqual(bpfWordAlign(5), 8)
        XCTAssertEqual(bpfWordAlign(17), 20)
    }

    func testBPFTimestampConvertsLittleEndianTimevalToWallNanos() {
        let buffer: [UInt8] = [
            0x01, 0x00, 0x00, 0x00,
            0x47, 0x94, 0x03, 0x00,
        ]

        XCTAssertEqual(bpfTimestampNanos(buffer: buffer, offset: 0), 1_234_567_000)
    }

    func testBPFTimestampRejectsInvalidTimeval() {
        XCTAssertNil(bpfTimestampNanos(buffer: [0x01, 0x00, 0x00], offset: 0))
        XCTAssertNil(
            bpfTimestampNanos(
                buffer: [
                    0x00, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x00, 0x00,
                ],
                offset: 0
            )
        )
        XCTAssertNil(
            bpfTimestampNanos(
                buffer: [
                    0x01, 0x00, 0x00, 0x00,
                    0x40, 0x42, 0x0F, 0x00,
                ],
                offset: 0
            )
        )
    }

    func testWiFiBPFFilterMatchesExpectedControlTrafficProgramShape() {
        let instructions = watchmeWiFiBPFFilterInstructions()

        XCTAssertEqual(watchmeWiFiBPFFilterName, "wifi_control_active_probe_v1")
        XCTAssertEqual(instructions.count, 46)
        XCTAssertEqual(instructions.first, BPFInstruction(code: 40, jt: 0, jf: 0, k: 12))
        XCTAssertTrue(instructions.contains(BPFInstruction(code: 21, jt: 42, jf: 0, k: 2054)))
        XCTAssertTrue(instructions.contains(BPFInstruction(code: 21, jt: 39, jf: 0, k: 1)))
        XCTAssertTrue(instructions.contains(BPFInstruction(code: 21, jt: 15, jf: 0, k: 58)))
        XCTAssertEqual(Array(instructions.suffix(2)), [
            BPFInstruction(code: 6, jt: 0, jf: 0, k: 524_288),
            BPFInstruction(code: 6, jt: 0, jf: 0, k: 0),
        ])
    }

    func testScanBPFReadBufferWalksAlignedMultiRecordBuffer() {
        let firstFrame: [UInt8] = [0xAA, 0xBB, 0xCC]
        let secondFrame: [UInt8] = [0x11, 0x22, 0x33, 0x44, 0x55]
        let buffer = bpfRecord(seconds: 1, microseconds: 2, frame: firstFrame)
            + bpfRecord(seconds: 3, microseconds: 4, frame: secondFrame)

        var frames: [[UInt8]] = []
        var timestamps: [UInt64] = []
        forEachBPFReadBufferRecord(buffer, bytesRead: buffer.count) { record in
            frames.append(Array(record.buffer[record.packetOffset ..< (record.packetOffset + record.caplen)]))
            timestamps.append(record.packetWallNanos)
        }

        XCTAssertEqual(frames, [firstFrame, secondFrame])
        XCTAssertEqual(timestamps, [1_000_002_000, 3_000_004_000])
    }

    func testScanBPFReadBufferUsesFallbackTimestampForInvalidHeaderTimeval() {
        let frame: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let buffer = bpfRecord(seconds: 0, microseconds: 1, frame: frame)

        let timestamp = scanBPFReadBuffer(
            buffer,
            bytesRead: buffer.count,
            timestampFallback: { 42 },
            match: { record in
                record.packetWallNanos
            }
        )

        XCTAssertEqual(timestamp, 42)
    }

    func testScanBPFReadBufferStopsAtInvalidHeaderWithoutReadingTrailingBytes() {
        var buffer = bpfRecord(seconds: 1, microseconds: 2, frame: [0xAA])
        buffer += [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        var count = 0
        forEachBPFReadBufferRecord(buffer, bytesRead: buffer.count) { _ in
            count += 1
        }

        XCTAssertEqual(count, 1)
    }

    private func bpfRecord(seconds: UInt32, microseconds: UInt32, frame: [UInt8]) -> [UInt8] {
        var header = [UInt8](repeating: 0, count: 20)
        writeLittleUInt32(seconds, to: &header, offset: 0)
        writeLittleUInt32(microseconds, to: &header, offset: 4)
        writeLittleUInt32(UInt32(frame.count), to: &header, offset: bpfHeaderCaplenOffset)
        writeLittleUInt32(UInt32(frame.count), to: &header, offset: 12)
        writeLittleUInt16(UInt16(header.count), to: &header, offset: bpfHeaderHeaderLengthOffset)

        let padding = [UInt8](repeating: 0, count: bpfWordAlign(header.count + frame.count) - header.count - frame.count)
        return header + frame + padding
    }

    private func writeLittleUInt16(_ value: UInt16, to buffer: inout [UInt8], offset: Int) {
        buffer[offset] = UInt8(value & 0x00FF)
        buffer[offset + 1] = UInt8((value >> 8) & 0x00FF)
    }

    private func writeLittleUInt32(_ value: UInt32, to buffer: inout [UInt8], offset: Int) {
        buffer[offset] = UInt8(value & 0x0000_00FF)
        buffer[offset + 1] = UInt8((value >> 8) & 0x0000_00FF)
        buffer[offset + 2] = UInt8((value >> 16) & 0x0000_00FF)
        buffer[offset + 3] = UInt8((value >> 24) & 0x0000_00FF)
    }
}
