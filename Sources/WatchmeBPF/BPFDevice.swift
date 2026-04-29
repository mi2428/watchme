import Darwin
import Foundation

// The Darwin Swift overlay does not expose BIOC* constants, so these ioctl
// numbers are the macOS values from <net/bpf.h>. Keeping them together makes it
// obvious which boundary this module owns when new BPF features are added.
let bpfIOCSetInterface: UInt = 2_149_597_804
let bpfIOCImmediate: UInt = 2_147_762_800
let bpfIOCGetBufferLength: UInt = 1_074_020_966
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
    // fill, which is critical for timing DHCP/RS/RA during short rejoin windows.
    _ = ioctl(fd, bpfIOCImmediate, &one)
    _ = ioctl(fd, bpfIOCSeeSent, &one)
    _ = ioctl(fd, bpfIOCHeaderComplete, &one)
    _ = ioctl(fd, bpfIOCFlush, &zero)

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
    return true
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
