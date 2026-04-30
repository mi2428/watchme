import WatchmeTelemetry

extension WiFiMetricState {
    func internetHTTPProbeMetrics(labels: [String: String]) -> [MetricSample] {
        internetHTTPProbes.values.flatMap { result -> [MetricSample] in
            var probeLabels = labels
            probeLabels["target"] = result.target
            probeLabels["family"] = result.family.metricValue
            probeLabels["remote_ip"] = result.remoteIP
            probeLabels["scheme"] = "http"
            probeLabels["outcome"] = result.outcome
            probeLabels["timing_source"] = result.timingSource
            var metrics = [
                MetricSample(
                    name: "watchme_wifi_probe_internet_http_success",
                    help: "Whether the latest Wi-Fi-bound internet plain HTTP probe succeeded.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.ok ? 1 : 0
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_http_duration_seconds",
                    help: "Duration of the latest Wi-Fi-bound internet plain HTTP request-to-first-byte probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.durationNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_http_last_run_timestamp_seconds",
                    help: "Unix timestamp of the latest Wi-Fi-bound internet plain HTTP probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromWallNanos: result.finishedWallNanos)
                ),
            ]
            if let statusCode = result.statusCode {
                metrics.append(
                    MetricSample(
                        name: "watchme_wifi_probe_internet_http_status_code",
                        help: "HTTP status code returned by the latest Wi-Fi-bound internet plain HTTP probe.",
                        type: .gauge,
                        labels: probeLabels,
                        value: Double(statusCode)
                    )
                )
            }
            return metrics
        }
    }

    func dnsProbeMetrics(labels: [String: String]) -> [MetricSample] {
        dnsProbes.values.flatMap { result -> [MetricSample] in
            var probeLabels = labels
            probeLabels["target"] = result.target
            probeLabels["family"] = result.family.metricValue
            probeLabels["resolver"] = result.resolver
            probeLabels["transport"] = result.transport
            probeLabels["record_type"] = result.recordType.name
            probeLabels["timing_source"] = result.timingSource
            var metrics = [
                MetricSample(
                    name: "watchme_wifi_probe_internet_dns_success",
                    help: "Whether the latest Wi-Fi-bound internet DNS probe succeeded.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.ok ? 1 : 0
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_dns_duration_seconds",
                    help: "Duration of the latest Wi-Fi-bound internet DNS probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.durationNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_dns_last_run_timestamp_seconds",
                    help: "Unix timestamp of the latest Wi-Fi-bound internet DNS probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromWallNanos: result.finishedWallNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_dns_address_count",
                    help: "Number of addresses returned by the latest Wi-Fi-bound internet DNS probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: Double(result.addresses.count)
                ),
            ]
            if let rcode = result.rcode {
                metrics.append(
                    MetricSample(
                        name: "watchme_wifi_probe_internet_dns_rcode",
                        help: "DNS response code returned by the latest Wi-Fi-bound internet DNS probe.",
                        type: .gauge,
                        labels: probeLabels,
                        value: Double(rcode)
                    )
                )
            }
            return metrics
        }
    }

    func icmpProbeMetrics(labels: [String: String]) -> [MetricSample] {
        icmpProbes.values.flatMap { result -> [MetricSample] in
            var probeLabels = labels
            probeLabels["target"] = result.target
            probeLabels["family"] = result.family.metricValue
            probeLabels["remote_ip"] = result.remoteIP
            probeLabels["outcome"] = result.outcome
            probeLabels["timing_source"] = result.timingSource
            return [
                MetricSample(
                    name: "watchme_wifi_probe_internet_icmp_success",
                    help: "Whether the latest Wi-Fi-bound internet ICMP echo probe succeeded.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.ok ? 1 : 0
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_icmp_duration_seconds",
                    help: "Duration of the latest Wi-Fi-bound internet ICMP echo probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.durationNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_icmp_last_run_timestamp_seconds",
                    help: "Unix timestamp of the latest Wi-Fi-bound internet ICMP echo probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromWallNanos: result.finishedWallNanos)
                ),
            ]
        }
    }
}
