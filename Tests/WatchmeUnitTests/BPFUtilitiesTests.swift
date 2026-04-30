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
}
