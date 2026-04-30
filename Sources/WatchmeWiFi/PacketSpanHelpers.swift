import Foundation
import WatchmeCore
import WatchmeTelemetry

func dhcpTags(xid: UInt32, event: String, interfaceName: String?) -> [String: String] {
    var tags: [String: String] = [
        "span.source": "bpf_packet",
        "packet.protocol": "dhcpv4",
        "packet.event": event,
        "packet.timestamp_source": "bpf_header_timeval",
        "packet.timestamp_resolution": "microsecond",
        "dhcp.xid": String(format: "0x%08x", xid),
    ]
    setTag(&tags, "network.interface", interfaceName)
    return tags
}

func packetSpan(_ name: String, start: UInt64, end: UInt64, tags: [String: String]) -> SpanEvent {
    var tags = tags
    if tags["span.source"] == nil {
        tags["span.source"] = "bpf_packet"
    }
    if tags["packet.timestamp_source"] == nil {
        tags["packet.timestamp_source"] = "bpf_header_timeval"
        tags["packet.timestamp_resolution"] = "microsecond"
    }
    return SpanEvent(
        name: name,
        startWallNanos: start,
        durationNanos: max(end >= start ? end - start : 0, 1000),
        tags: tags,
        statusOK: true
    )
}

func latest<T: AnyObject>(beforeOrAt end: UInt64, in values: [T], timestamp: (T) -> UInt64) -> T? {
    values.last { timestamp($0) <= end }
}

func latest(beforeOrAt end: UInt64, in values: [DHCPObservation]) -> DHCPObservation? {
    values.last { $0.wallNanos <= end }
}

func latest(beforeOrAt end: UInt64, in values: [ICMPv6Observation]) -> ICMPv6Observation? {
    values.last { $0.wallNanos <= end }
}

func retryGaps(_ timestamps: [UInt64]) -> [(start: UInt64, end: UInt64)] {
    let sorted = timestamps.sorted()
    guard sorted.count > 1 else {
        return []
    }
    return sorted.indices.dropFirst().map { (sorted[$0 - 1], sorted[$0]) }
}

func spanWindow(_ spans: [SpanEvent]) -> (start: UInt64, duration: UInt64)? {
    guard let start = spans.map(\.startWallNanos).min() else {
        return nil
    }
    let end = spans.map { $0.startWallNanos + $0.durationNanos }.max() ?? start
    return (start, max(end - start, 1000))
}

func spanKey(_ span: SpanEvent) -> String {
    [
        span.name,
        "\(span.startWallNanos)",
        "\(span.durationNanos)",
        span.tags["packet.event"] ?? "",
        span.tags["dhcp.xid"] ?? "",
        span.tags["icmpv6.nd.target_address"] ?? "",
        span.tags["arp.target_ip"] ?? "",
    ].joined(separator: "|")
}
