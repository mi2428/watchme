import Darwin
import Foundation

// The Darwin Swift overlay does not expose BIOC* constants, so these ioctl
// numbers are the macOS values from <net/bpf.h>. Keeping them together makes it
// obvious which boundary this module owns when new BPF features are added.
let bpfIOCSetInterface: UInt = 2_149_597_804
let bpfIOCSetFilter: UInt = 2_148_549_223
let bpfIOCImmediate: UInt = 2_147_762_800
let bpfIOCGetBufferLength: UInt = 1_074_020_966
let bpfIOCGetStats: UInt = 1_074_283_119
let bpfIOCSeeSent: UInt = 2_147_762_807
let bpfIOCHeaderComplete: UInt = 2_147_762_805
let bpfIOCGetDLT: UInt = 1_074_020_970
let bpfIOCFlush: UInt = 536_887_912
let bpfDLTEthernet: UInt32 = 1
let bpfIfreqSize = 32
let bpfHeaderCaplenOffset = 8
let bpfHeaderHeaderLengthOffset = 16

struct BPFOpenResult {
    let fd: Int32?
    let path: String?
    let error: String?
}

public struct BPFStats: Equatable {
    public let packetsReceived: UInt64
    public let packetsDropped: UInt64

    public init(packetsReceived: UInt64, packetsDropped: UInt64) {
        self.packetsReceived = packetsReceived
        self.packetsDropped = packetsDropped
    }
}

public let watchmeWiFiBPFFilterName = "wifi_control_active_probe_v1"

struct BPFInstruction: Equatable {
    var code: UInt16
    var jt: UInt8
    var jf: UInt8
    var k: UInt32
}

struct BPFProgram {
    var bfLen: UInt32
    var bfInsns: UnsafeMutablePointer<BPFInstruction>?
}

struct RawBPFStats {
    var packetsReceived: UInt32 = 0
    var packetsDropped: UInt32 = 0
}

func openBPFDevice() -> BPFOpenResult {
    // macOS exposes BPF devices as a small numbered pool. Opening the first
    // available descriptor is the stable API; there is no interface-specific
    // device path.
    var lastError: String?
    for index in 0 ..< 256 {
        let path = "/dev/bpf\(index)"
        let fd = Darwin.open(path, O_RDWR)
        if fd >= 0 {
            return BPFOpenResult(fd: fd, path: path, error: nil)
        }
        lastError = "\(path): \(posixErrorString())"
    }
    return BPFOpenResult(fd: nil, path: nil, error: lastError)
}

func configureBPF(fd: Int32, interfaceName: String, tags: inout [String: String]) -> Bool {
    var ifreq = [UInt8](repeating: 0, count: bpfIfreqSize)
    let nameBytes = Array(interfaceName.utf8.prefix(Int(IF_NAMESIZE) - 1))
    for index in nameBytes.indices {
        ifreq[index] = nameBytes[index]
    }

    let setInterface = ifreq.withUnsafeMutableBytes { rawBuffer in
        ioctl(fd, bpfIOCSetInterface, rawBuffer.baseAddress!)
    }
    guard setInterface == 0 else {
        tags["bpf.error"] = "BIOCSETIF \(interfaceName) failed: \(posixErrorString())"
        return false
    }

    var one: UInt32 = 1
    var zero: UInt32 = 0
    // Immediate mode returns packets without waiting for the kernel buffer to
    // fill, which is critical for timing DHCP/RS/RA control-plane exchanges.
    _ = ioctl(fd, bpfIOCImmediate, &one)
    _ = ioctl(fd, bpfIOCSeeSent, &one)
    _ = ioctl(fd, bpfIOCHeaderComplete, &one)

    var bufferLength: UInt32 = 0
    if ioctl(fd, bpfIOCGetBufferLength, &bufferLength) == 0, bufferLength > 0 {
        tags["bpf.buffer_length"] = "\(bufferLength)"
    }

    var dataLinkType: UInt32 = 0
    if ioctl(fd, bpfIOCGetDLT, &dataLinkType) == 0 {
        tags["bpf.dlt"] = "\(dataLinkType)"
        // Packet parsing below assumes Ethernet headers. Bail early if a future
        // interface exposes a different datalink framing.
        guard dataLinkType == bpfDLTEthernet else {
            tags["bpf.error"] = "unsupported BPF DLT \(dataLinkType)"
            return false
        }
    }
    guard installBPFFilter(fd: fd, tags: &tags) else {
        return false
    }
    _ = ioctl(fd, bpfIOCFlush, &zero)
    return true
}

func installBPFFilter(fd: Int32, tags: inout [String: String]) -> Bool {
    var instructions = watchmeWiFiBPFFilterInstructions()
    return instructions.withUnsafeMutableBufferPointer { buffer in
        var program = BPFProgram(
            bfLen: UInt32(buffer.count),
            bfInsns: buffer.baseAddress
        )
        guard ioctl(fd, bpfIOCSetFilter, &program) == 0 else {
            tags["bpf.error"] = "BIOCSETF \(watchmeWiFiBPFFilterName) failed: \(posixErrorString())"
            return false
        }
        tags["bpf.filter"] = watchmeWiFiBPFFilterName
        tags["bpf.filter_instruction_count"] = "\(buffer.count)"
        return true
    }
}

func readBPFStats(fd: Int32) -> BPFStats? {
    var stats = RawBPFStats()
    guard ioctl(fd, bpfIOCGetStats, &stats) == 0 else {
        return nil
    }
    return BPFStats(
        packetsReceived: UInt64(stats.packetsReceived),
        packetsDropped: UInt64(stats.packetsDropped)
    )
}

func watchmeWiFiBPFFilterInstructions() -> [BPFInstruction] {
    // Generated for DLT_EN10MB from:
    // arp or (ip and (icmp or (udp and (port 53 or port 67 or port 68))
    // or (tcp and port 80))) or
    // (ip6 and (icmp6 or (udp and port 53) or (tcp and port 80)))
    [
        BPFInstruction(code: 40, jt: 0, jf: 0, k: 12),
        BPFInstruction(code: 21, jt: 42, jf: 0, k: 2054),
        BPFInstruction(code: 21, jt: 0, jf: 23, k: 2048),
        BPFInstruction(code: 48, jt: 0, jf: 0, k: 23),
        BPFInstruction(code: 21, jt: 39, jf: 0, k: 1),
        BPFInstruction(code: 21, jt: 0, jf: 11, k: 17),
        BPFInstruction(code: 40, jt: 0, jf: 0, k: 20),
        BPFInstruction(code: 69, jt: 37, jf: 0, k: 8191),
        BPFInstruction(code: 177, jt: 0, jf: 0, k: 14),
        BPFInstruction(code: 72, jt: 0, jf: 0, k: 14),
        BPFInstruction(code: 21, jt: 33, jf: 0, k: 53),
        BPFInstruction(code: 21, jt: 32, jf: 0, k: 67),
        BPFInstruction(code: 21, jt: 31, jf: 0, k: 68),
        BPFInstruction(code: 72, jt: 0, jf: 0, k: 16),
        BPFInstruction(code: 21, jt: 29, jf: 0, k: 53),
        BPFInstruction(code: 21, jt: 28, jf: 0, k: 67),
        BPFInstruction(code: 21, jt: 27, jf: 28, k: 68),
        BPFInstruction(code: 21, jt: 0, jf: 27, k: 6),
        BPFInstruction(code: 40, jt: 0, jf: 0, k: 20),
        BPFInstruction(code: 69, jt: 25, jf: 0, k: 8191),
        BPFInstruction(code: 177, jt: 0, jf: 0, k: 14),
        BPFInstruction(code: 72, jt: 0, jf: 0, k: 14),
        BPFInstruction(code: 21, jt: 21, jf: 0, k: 80),
        BPFInstruction(code: 21, jt: 20, jf: 0, k: 80),
        BPFInstruction(code: 72, jt: 0, jf: 0, k: 16),
        BPFInstruction(code: 21, jt: 18, jf: 17, k: 80),
        BPFInstruction(code: 21, jt: 0, jf: 18, k: 34525),
        BPFInstruction(code: 48, jt: 0, jf: 0, k: 20),
        BPFInstruction(code: 21, jt: 15, jf: 0, k: 58),
        BPFInstruction(code: 21, jt: 0, jf: 2, k: 44),
        BPFInstruction(code: 48, jt: 0, jf: 0, k: 54),
        BPFInstruction(code: 21, jt: 12, jf: 13, k: 58),
        BPFInstruction(code: 21, jt: 0, jf: 4, k: 17),
        BPFInstruction(code: 40, jt: 0, jf: 0, k: 54),
        BPFInstruction(code: 21, jt: 9, jf: 0, k: 53),
        BPFInstruction(code: 40, jt: 0, jf: 0, k: 56),
        BPFInstruction(code: 21, jt: 7, jf: 8, k: 53),
        BPFInstruction(code: 21, jt: 0, jf: 7, k: 6),
        BPFInstruction(code: 40, jt: 0, jf: 0, k: 54),
        BPFInstruction(code: 21, jt: 4, jf: 0, k: 80),
        BPFInstruction(code: 21, jt: 3, jf: 0, k: 80),
        BPFInstruction(code: 40, jt: 0, jf: 0, k: 56),
        BPFInstruction(code: 21, jt: 1, jf: 0, k: 80),
        BPFInstruction(code: 21, jt: 0, jf: 1, k: 80),
        BPFInstruction(code: 6, jt: 0, jf: 0, k: 524_288),
        BPFInstruction(code: 6, jt: 0, jf: 0, k: 0),
    ]
}

func setNonBlocking(_ fd: Int32) {
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 {
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
    }
}

func bpfTimestampNanos(buffer: [UInt8], offset: Int) -> UInt64? {
    guard offset + 8 <= buffer.count else {
        return nil
    }
    // macOS BPF headers store timeval as little-endian seconds/useconds. Convert
    // to wall-clock nanoseconds so packet spans share the same time base as
    // CoreWLAN and active probe spans.
    let seconds = UInt64(readLittleUInt32(buffer, offset: offset))
    let microseconds = UInt64(readLittleUInt32(buffer, offset: offset + 4))
    guard seconds > 0, microseconds < 1_000_000 else {
        return nil
    }
    return seconds * 1_000_000_000 + microseconds * 1000
}

func bpfWordAlign(_ value: Int) -> Int {
    // BPF records in a read buffer are padded to 32-bit boundaries. Misalignment
    // corrupts every packet after the first multi-record read.
    (value + 3) & ~3
}

func readLittleUInt16(_ buffer: [UInt8], offset: Int) -> UInt16 {
    UInt16(buffer[offset]) | (UInt16(buffer[offset + 1]) << 8)
}

func readLittleUInt32(_ buffer: [UInt8], offset: Int) -> UInt32 {
    UInt32(buffer[offset])
        | (UInt32(buffer[offset + 1]) << 8)
        | (UInt32(buffer[offset + 2]) << 16)
        | (UInt32(buffer[offset + 3]) << 24)
}

func posixErrorString(_ code: Int32 = errno) -> String {
    String(cString: strerror(code))
}
