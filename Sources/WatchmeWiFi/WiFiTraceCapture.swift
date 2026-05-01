import Foundation
import WatchmeCore
import WatchmeTelemetry

struct WiFiTraceCaptureContext {
    let snapshot: WiFiSnapshot
    let networkState: WiFiServiceNetworkState
    let connectivityReadiness: WiFiConnectivityCheckReadiness
    let connectivityReadinessWait: TimeInterval
}

struct WiFiPassivePacketSpanCapture {
    let spans: [SpanEvent]
    let windowStart: UInt64?
}

struct WiFiPassivePacketSpanRequest {
    let reason: String
    let eventTags: [String: String]
    let traceStarted: UInt64
    let snapshot: WiFiSnapshot
    let networkState: WiFiServiceNetworkState
    let consumePacketSpans: Bool
    let connectivityReadinessTimeout: TimeInterval
}

struct ConnectivityProbeCapture {
    let gatewayResults: [ActiveGatewayProbeResult]
    let internetResults: ActiveInternetProbeResults
}

func collectConnectivityProbeResults(
    gatewayProbe: () -> [ActiveGatewayProbeResult],
    internetProbes: () -> ActiveInternetProbeResults
) -> ConnectivityProbeCapture {
    let gatewayResults = gatewayProbe()
    let internetResults = internetProbes()
    return ConnectivityProbeCapture(gatewayResults: gatewayResults, internetResults: internetResults)
}

func shouldSuppressStaleAssociationTrace(reason: String, readiness: WiFiConnectivityCheckReadiness) -> Bool {
    guard WiFiTracePolicy.isAssociationRecoveryReason(reason), !readiness.ready else {
        return false
    }
    switch readiness.skipReason {
    case "wifi_not_associated", "wifi_power_off", "wifi_interface_unknown":
        return true
    default:
        return false
    }
}

func shouldSuppressNetworkAttachmentTrace(reason: String, readiness: WiFiConnectivityCheckReadiness) -> Bool {
    reason == "wifi.network.attachment" && !readiness.ready
}

func associationPacketSpanWindowStart(
    reason: String,
    eventTags: [String: String],
    traceStarted: UInt64,
    lookback: TimeInterval
) -> UInt64? {
    guard WiFiTracePolicy.isAssociationRecoveryReason(reason) else {
        return nil
    }
    let anchors = [
        eventTags["wifi.event_received_epoch_ns"],
        eventTags["network.event_received_epoch_ns"],
    ].compactMap { value -> UInt64? in
        guard let value else {
            return nil
        }
        return UInt64(value)
    }
    let anchor = anchors.max() ?? traceStarted
    let lookbackNanos = UInt64(max(lookback, 0) * 1_000_000_000)
    let windowStart = anchor > lookbackNanos ? anchor - lookbackNanos : 0
    guard let windowFloor = UInt64(eventTags["association.window_floor_epoch_ns"] ?? ""), windowFloor <= anchor else {
        return windowStart
    }
    return max(windowStart, windowFloor)
}

func shouldAttachPassivePacketSpans(reason: String) -> Bool {
    WiFiTracePolicy.isAssociationRecoveryReason(reason) || reason == "wifi.network.attachment"
}

func passivePacketSpanWindowStart(
    reason: String,
    eventTags: [String: String],
    traceStarted: UInt64,
    associationLookback: TimeInterval,
    attachmentLookback: TimeInterval
) -> UInt64? {
    if WiFiTracePolicy.isAssociationRecoveryReason(reason) {
        return associationPacketSpanWindowStart(
            reason: reason,
            eventTags: eventTags,
            traceStarted: traceStarted,
            lookback: associationLookback
        )
    }
    guard reason == "wifi.network.attachment" else {
        return nil
    }
    let anchor = UInt64(eventTags["packet.timestamp_epoch_ns"] ?? "") ?? traceStarted
    let lookbackNanos = UInt64(max(attachmentLookback, 0) * 1_000_000_000)
    return anchor > lookbackNanos ? anchor - lookbackNanos : 0
}

func shouldReplayConsumedNetworkAttachmentSpan(reason: String, span: SpanEvent, replayStart: UInt64?) -> Bool {
    guard WiFiTracePolicy.isAssociationRecoveryReason(reason), span.name.hasPrefix("packet."), let replayStart else {
        return false
    }
    return span.startWallNanos >= replayStart
}

func networkAttachmentTraceHasAddressAcquisitionEvidence(_ spans: [SpanEvent]) -> Bool {
    spans.contains { span in
        span.name.hasPrefix("packet.dhcp.") || span.name == "packet.icmpv6.router_solicitation_to_advertisement"
    }
}
