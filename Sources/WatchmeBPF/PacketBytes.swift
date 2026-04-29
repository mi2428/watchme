import Darwin
import Foundation

public func readBigUInt16(_ buffer: [UInt8], offset: Int) -> UInt16 {
    (UInt16(buffer[offset]) << 8) | UInt16(buffer[offset + 1])
}

public func readBigUInt32(_ buffer: [UInt8], offset: Int) -> UInt32 {
    (UInt32(buffer[offset]) << 24)
        | (UInt32(buffer[offset + 1]) << 16)
        | (UInt32(buffer[offset + 2]) << 8)
        | UInt32(buffer[offset + 3])
}

public func ipv4String(bytes: [UInt8]) -> String {
    bytes.prefix(4).map(String.init).joined(separator: ".")
}

public func ipv6String(bytes: [UInt8]) -> String {
    guard bytes.count >= 16 else {
        return ""
    }
    var address = in6_addr()
    withUnsafeMutableBytes(of: &address) { destination in
        destination.copyBytes(from: bytes.prefix(16))
    }
    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    return inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)).map { String(cString: $0) } ?? ""
}

public func macAddressString(bytes: [UInt8]) -> String {
    bytes.prefix(6).map { String(format: "%02x", $0) }.joined(separator: ":")
}
