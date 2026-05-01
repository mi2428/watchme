import Darwin
import Foundation

/// Reads a big-endian 16-bit integer from a packet buffer.
public func readBigUInt16(_ buffer: [UInt8], offset: Int) -> UInt16 {
    (UInt16(buffer[offset]) << 8) | UInt16(buffer[offset + 1])
}

/// Reads a big-endian 32-bit integer from a packet buffer.
public func readBigUInt32(_ buffer: [UInt8], offset: Int) -> UInt32 {
    (UInt32(buffer[offset]) << 24)
        | (UInt32(buffer[offset + 1]) << 16)
        | (UInt32(buffer[offset + 2]) << 8)
        | UInt32(buffer[offset + 3])
}

/// Formats four IPv4 address bytes as dotted decimal text.
public func ipv4String(bytes: [UInt8]) -> String {
    bytes.prefix(4).map(String.init).joined(separator: ".")
}

/// Formats sixteen IPv6 address bytes using `inet_ntop`.
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

/// Formats six Ethernet MAC address bytes as lower-case hex octets.
public func macAddressString(bytes: [UInt8]) -> String {
    bytes.prefix(6).map { String(format: "%02x", $0) }.joined(separator: ":")
}
