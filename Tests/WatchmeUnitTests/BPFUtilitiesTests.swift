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
}
