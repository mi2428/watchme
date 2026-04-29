import Foundation
import WatchmeBPF

func icmpv6NDLinkLayerAddressOption(buffer: [UInt8], optionsOffset: Int, packetEnd: Int, optionType: UInt8) -> String? {
    var offset = optionsOffset
    while offset + 2 <= packetEnd {
        let type = buffer[offset]
        let units = Int(buffer[offset + 1])
        guard units > 0 else {
            return nil
        }
        let length = units * 8
        guard offset + length <= packetEnd else {
            return nil
        }
        if type == optionType, length >= 8 {
            return macAddressString(bytes: Array(buffer[(offset + 2) ..< (offset + 8)]))
        }
        offset += length
    }
    return nil
}

func dhcpMessageTypeName(_ value: UInt8) -> String {
    switch value {
    case 1: "discover"
    case 2: "offer"
    case 3: "request"
    case 4: "decline"
    case 5: "ack"
    case 6: "nak"
    case 7: "release"
    case 8: "inform"
    default: "type_\(value)"
    }
}

func icmpv6TypeName(_ value: UInt8) -> String {
    switch value {
    case 133: "router_solicitation"
    case 134: "router_advertisement"
    case 135: "neighbor_solicitation"
    case 136: "neighbor_advertisement"
    default: "type_\(value)"
    }
}
