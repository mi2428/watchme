import Foundation
import WatchmeCore

func logActiveDNSPacket(_ observation: DNSPacketObservation) {
    var fields: [String: String] = [
        "interface": observation.interfaceName,
        "dns.transaction_id": String(format: "0x%04x", observation.transactionID),
        "dns.direction": observation.isResponse ? "response" : "query",
        "dns.source_ip": observation.sourceIP,
        "dns.destination_ip": observation.destinationIP,
        "dns.source_port": "\(observation.sourcePort)",
        "dns.destination_port": "\(observation.destinationPort)",
        "packet.timestamp_epoch_ns": "\(observation.wallNanos)",
    ]
    setTag(&fields, "dns.query_name", observation.queryName)
    if let rcode = observation.rcode {
        fields["dns.rcode"] = "\(rcode)"
    }
    if let answerCount = observation.answerCount {
        fields["dns.answer_count"] = "\(answerCount)"
    }
    logEvent(.debug, "active_dns_packet_observed", fields: fields)
}

func logActiveHTTPPacket(_ observation: TCPPacketObservation) {
    var fields: [String: String] = [
        "interface": observation.interfaceName,
        "tcp.source_ip": observation.sourceIP,
        "tcp.destination_ip": observation.destinationIP,
        "tcp.source_port": "\(observation.sourcePort)",
        "tcp.destination_port": "\(observation.destinationPort)",
        "tcp.flags": String(format: "0x%02x", observation.flags),
        "tcp.payload_length": "\(observation.payloadLength)",
        "packet.timestamp_epoch_ns": "\(observation.wallNanos)",
    ]
    if observation.payloadLength > 0 {
        fields["tcp.payload_prefix_ascii"] = clipped(
            String(bytes: observation.payloadPrefix.prefix(64), encoding: .utf8) ?? "",
            limit: 64
        )
    }
    logEvent(.debug, "active_http_packet_observed", fields: fields)
}

func logActiveICMPPacket(_ observation: ICMPPacketObservation) {
    logEvent(
        .debug, "active_icmp_packet_observed",
        fields: [
            "interface": observation.interfaceName,
            "network.family": observation.family.metricValue,
            "icmp.type": "\(observation.type)",
            "icmp.code": "\(observation.code)",
            "icmp.identifier": String(format: "0x%04x", observation.identifier),
            "icmp.sequence": "\(observation.sequence)",
            "icmp.source_ip": observation.sourceIP,
            "icmp.destination_ip": observation.destinationIP,
            "packet.timestamp_epoch_ns": "\(observation.wallNanos)",
        ]
    )
}
