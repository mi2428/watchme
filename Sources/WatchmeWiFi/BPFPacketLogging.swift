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

func logActiveTCPPacket(_ observation: TCPPacketObservation) {
    logEvent(
        .debug, "active_tcp_packet_observed",
        fields: [
            "interface": observation.interfaceName,
            "tcp.source_ip": observation.sourceIP,
            "tcp.destination_ip": observation.destinationIP,
            "tcp.source_port": "\(observation.sourcePort)",
            "tcp.destination_port": "\(observation.destinationPort)",
            "tcp.flags": String(format: "0x%02x", observation.flags),
            "packet.timestamp_epoch_ns": "\(observation.wallNanos)",
        ]
    )
}
