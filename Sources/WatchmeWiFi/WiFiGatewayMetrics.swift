import WatchmeTelemetry

extension WiFiMetricState {
    func gatewayProbeMetrics(labels: [String: String]) -> [PrometheusMetric] {
        gatewayProbes.values.flatMap { result -> [PrometheusMetric] in
            var probeLabels = labels
            probeLabels["gateway"] = result.gateway
            probeLabels["family"] = result.family.metricValue
            probeLabels["outcome"] = result.outcome
            probeLabels["timing_source"] = result.timingSource
            return [
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_icmp_success",
                    help: "Whether any gateway ICMP burst attempt received an echo reply.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.reachable ? 1 : 0
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_icmp_duration_seconds",
                    help: "Mean echo request-to-reply duration for reachable gateway burst attempts.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.durationNanos)
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_icmp_probe_count",
                    help: "Number of ICMP echo requests sent in the latest gateway burst probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: Double(result.probeCount)
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_icmp_reply_count",
                    help: "Number of ICMP echo replies received from the gateway in the latest burst.",
                    type: .gauge,
                    labels: probeLabels,
                    value: Double(result.reachableCount)
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_icmp_loss_ratio",
                    help: "Fraction of latest gateway burst attempts that did not reach the gateway.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.lossRatio
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_icmp_jitter_seconds",
                    help: "Mean absolute delta between consecutive reachable gateway ICMP durations.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.jitterNanos)
                ),
                PrometheusMetric(
                    name: "watchme_wifi_probe_gateway_icmp_last_run_timestamp_seconds",
                    help: "Unix timestamp of the latest Wi-Fi-bound gateway ICMP burst probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromWallNanos: result.finishedWallNanos)
                ),
            ]
        }
    }
}
