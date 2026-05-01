import WatchmeTelemetry

extension WiFiMetricState {
    func internetPathProbeMetrics(labels: [String: String]) -> [MetricSample] {
        internetPathProbes.values.flatMap { result -> [MetricSample] in
            let probeLabels = labels.merging(activeProbeInternetPathStableLabels(result)) { _, new in new }
            var infoLabels = probeLabels
            infoLabels["remote_ip"] = result.remoteIP
            infoLabels["outcome"] = internetPathOutcome(result)
            return [
                MetricSample(
                    name: "watchme_wifi_probe_internet_path_success",
                    help: "Whether the latest Wi-Fi-bound internet path probe succeeded.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.ok ? 1 : 0
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_path_duration_seconds",
                    help: "Duration of the latest Wi-Fi-bound internet path probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.durationNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_path_last_run_timestamp_seconds",
                    help: "Unix timestamp of the latest Wi-Fi-bound internet path probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromWallNanos: result.finishedWallNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_path_info",
                    help: "Constant info metric with latest Wi-Fi-bound internet path probe metadata.",
                    type: .gauge,
                    labels: infoLabels,
                    value: 1
                ),
            ]
        }
    }

    func internetTCPProbeMetrics(labels: [String: String]) -> [MetricSample] {
        internetTCPProbes.values.flatMap { result -> [MetricSample] in
            let probeLabels = labels.merging(activeProbeTCPStableLabels(result)) { _, new in new }
            var infoLabels = probeLabels
            infoLabels["remote_ip"] = result.remoteIP
            infoLabels["outcome"] = result.outcome
            infoLabels["timing_source"] = result.timingSource
            return [
                MetricSample(
                    name: "watchme_wifi_probe_internet_tcp_success",
                    help: "Whether the latest Wi-Fi-bound internet TCP connect probe succeeded.",
                    type: .gauge,
                    labels: probeLabels,
                    value: result.ok ? 1 : 0
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_tcp_duration_seconds",
                    help: "Duration of the latest Wi-Fi-bound internet TCP connect probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromDurationNanos: result.durationNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_tcp_last_run_timestamp_seconds",
                    help: "Unix timestamp of the latest Wi-Fi-bound internet TCP probe.",
                    type: .gauge,
                    labels: probeLabels,
                    value: seconds(fromWallNanos: result.finishedWallNanos)
                ),
                MetricSample(
                    name: "watchme_wifi_probe_internet_tcp_info",
                    help: "Constant info metric with latest Wi-Fi-bound internet TCP connect probe metadata.",
                    type: .gauge,
                    labels: infoLabels,
                    value: 1
                ),
            ]
        }
    }

    func internetHTTPProbeMetrics(labels: [String: String]) -> [MetricSample] {
        internetHTTPProbes.values.flatMap { result -> [MetricSample] in
            let probeLabels = labels.merging(activeProbeHTTPStableLabels(result)) { _, new in new }
            var infoLabels = probeLabels
            infoLabels["remote_ip"] = result.remoteIP
            infoLabels["outcome"] = result.outcome
            infoLabels["timing_source"] = result.timingSource
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
                MetricSample(
                    name: "watchme_wifi_probe_internet_http_info",
                    help: "Constant info metric with latest Wi-Fi-bound internet plain HTTP probe metadata.",
                    type: .gauge,
                    labels: infoLabels,
                    value: 1
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
            let probeLabels = labels.merging(activeProbeDNSStableLabels(result)) { _, new in new }
            var infoLabels = probeLabels
            infoLabels["outcome"] = dnsProbeOutcome(result)
            infoLabels["timing_source"] = result.timingSource
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
                MetricSample(
                    name: "watchme_wifi_probe_internet_dns_info",
                    help: "Constant info metric with latest Wi-Fi-bound internet DNS probe metadata.",
                    type: .gauge,
                    labels: infoLabels,
                    value: 1
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
            let probeLabels = labels.merging(activeProbeICMPStableLabels(result)) { _, new in new }
            var infoLabels = probeLabels
            infoLabels["remote_ip"] = result.remoteIP
            infoLabels["outcome"] = result.outcome
            infoLabels["timing_source"] = result.timingSource
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
                MetricSample(
                    name: "watchme_wifi_probe_internet_icmp_info",
                    help: "Constant info metric with latest Wi-Fi-bound internet ICMP echo probe metadata.",
                    type: .gauge,
                    labels: infoLabels,
                    value: 1
                ),
            ]
        }
    }
}
