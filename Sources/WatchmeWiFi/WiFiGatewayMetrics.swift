import WatchmeTelemetry

extension WiFiMetricState {
    func gatewayProbeMetrics(labels: [String: String]) -> [MetricSample] {
        gatewayProbes.values.flatMap { result -> [MetricSample] in
            let probeLabels = labels.merging(activeProbeGatewayStableLabels(result)) { _, new in new }
            var infoLabels = probeLabels
            infoLabels["outcome"] = result.outcome
            infoLabels["timing_source"] = result.icmpTimingSource
            var metrics = [
                MetricSample(
                    name: "watchme_wifi_probe_gateway_icmp_success",
                    help: "Whether any gateway ICMP burst attempt received an echo reply.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.reachable ? 1 : 0
                ),
                MetricSample(
                    name: "watchme_wifi_probe_gateway_icmp_duration_seconds",
                    help: "Mean echo request-to-reply duration for reachable gateway burst attempts.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.durationNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_gateway_icmp_probe_count",
                    help: "Number of ICMP echo requests sent in the latest gateway burst probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: Double(result.probeCount)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_gateway_icmp_reply_count",
                    help: "Number of ICMP echo replies received from the gateway in the latest burst.",
                    type: .gauge,
                    labels: probeLabels,
                    value: Double(result.reachableCount)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_gateway_icmp_loss_ratio",
                    help: "Fraction of latest gateway burst attempts that did not reach the gateway.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.lossRatio
                ),
                MetricSample(
                    name: "watchme_wifi_probe_gateway_icmp_jitter_seconds",
                    help: "Mean absolute delta between consecutive reachable gateway ICMP durations.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.jitterNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_gateway_icmp_last_run_timestamp_seconds",
                    help: "Unix timestamp of the latest Wi-Fi-bound gateway ICMP burst probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromWallNanos: result.finishedWallNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_gateway_icmp_info",
                    help: "Constant info metric with latest Wi-Fi-bound gateway ICMP burst probe metadata.",
                    type: .gauge,
                    labels: infoLabels,
                    value: 1
                ),
            ]
            if let resolution = result.arpResolution {
                metrics.append(contentsOf: gatewayResolutionProbeMetrics(labels: labels, result: resolution))
            }
            return metrics
        }
    }

    private func gatewayResolutionProbeMetrics(labels: [String: String], result: ActiveGatewayARPResult) -> [MetricSample] {
        let probeLabels = labels.merging(activeProbeGatewayResolutionStableLabels(result)) { _, new in new }
        var infoLabels = probeLabels
        infoLabels["outcome"] = result.outcome
        infoLabels["timing_source"] = result.timingSource
        if let gatewayHardwareAddress = result.gatewayHardwareAddress {
            infoLabels["gateway_hwaddr"] = gatewayHardwareAddress
        }
        return [
            MetricSample(
                name: "watchme_wifi_probe_gateway_resolution_success",
                help: "Whether the latest Wi-Fi-bound gateway ARP or NDP resolution probe succeeded.",
                type: .gauge,
                labels: probeLabels,
                value: result.ok ? 1 : 0
            ),
            MetricSample(
                name: "watchme_wifi_probe_gateway_resolution_duration_seconds",
                help: "Duration of the latest Wi-Fi-bound gateway ARP or NDP resolution probe.",
                type: .gauge,
                labels: probeLabels,
                value: seconds(fromDurationNanos: result.durationNanos)
            ),
            MetricSample(
                name: "watchme_wifi_probe_gateway_resolution_last_run_timestamp_seconds",
                help: "Unix timestamp of the latest Wi-Fi-bound gateway ARP or NDP resolution probe.",
                type: .gauge,
                labels: probeLabels,
                value: seconds(fromWallNanos: result.finishedWallNanos)
            ),
            MetricSample(
                name: "watchme_wifi_probe_gateway_resolution_info",
                help: "Constant info metric with latest Wi-Fi-bound gateway ARP or NDP resolution probe metadata.",
                type: .gauge,
                labels: infoLabels,
                value: 1
            ),
        ]
    }
}
