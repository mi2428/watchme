import Foundation
import WatchmeCore
import WatchmeTelemetry

extension WiFiAgent {
    func recordNetworkAttachment(
        _ packetSpans: [SpanEvent],
        window: (start: UInt64, duration: UInt64),
        recorder: TraceRecorder,
        snapshot: WiFiSnapshot
    ) {
        let phaseId = recorder.newSpanId()
        for span in packetSpans {
            recorder.recordEvent(
                span, parentId: phaseId,
                tags: [
                    "wifi.essid": snapshot.ssid ?? "unknown",
                    "wifi.bssid": snapshot.bssid ?? "unknown",
                ]
            )
        }
        recorder.recordSpan(
            name: "phase.network_attachment",
            id: phaseId,
            startWallNanos: window.start > 1000 ? window.start - 1000 : window.start,
            durationNanos: window.duration + 1000,
            tags: [
                "phase.name": "network_attachment",
                "phase.source": "passive_bpf",
                "phase.packet_span_count": "\(packetSpans.count)",
            ]
        )
    }

    func recordConnectivityCheck(recorder: TraceRecorder, snapshot: WiFiSnapshot, networkState: WiFiServiceNetworkState) {
        let phaseId = recorder.newSpanId()
        let phaseStart = wallClockNanos()
        let probeCapture = collectConnectivityProbeResults(
            gatewayProbe: {
                self.runGatewayProbes(networkState: networkState, snapshot: snapshot)
            },
            internetProbes: {
                runActiveInternetProbes(
                    config: self.config,
                    networkState: networkState,
                    interfaceName: snapshot.interfaceName,
                    packetStore: self.packetStore
                )
            }
        )

        for gatewayResult in probeCapture.gatewayResults {
            recordGatewayProbeResult(gatewayResult, phaseId: phaseId, recorder: recorder, snapshot: snapshot)
        }
        recordInternetProbeResults(probeCapture.internetResults, phaseId: phaseId, recorder: recorder, snapshot: snapshot)

        recorder.recordSpan(
            name: "phase.connectivity_check",
            id: phaseId,
            startWallNanos: phaseStart,
            durationNanos: max(wallClockNanos() - phaseStart, 1000),
            tags: connectivityCheckPhaseTags(probeCapture: probeCapture, networkState: networkState)
        )
    }

    func runGatewayProbes(networkState: WiFiServiceNetworkState, snapshot: WiFiSnapshot) -> [ActiveGatewayProbeResult] {
        var results: [ActiveGatewayProbeResult] = []
        if let gateway = networkState.routerIPv4 {
            results.append(
                runGatewayICMPProbe(
                    gateway: gateway,
                    timeout: min(config.probeInternetTimeout, 2.0),
                    interfaceName: snapshot.interfaceName,
                    packetStore: packetStore,
                    burstCount: config.probeGatewayBurstCount,
                    burstInterval: config.probeGatewayBurstInterval,
                    useDirectBPF: config.bpfEnabled
                )
            )
        }
        if let gateway = networkState.routerIPv6 {
            results.append(
                runGatewayICMPv6Probe(
                    gateway: gateway,
                    timeout: min(config.probeInternetTimeout, 2.0),
                    interfaceName: snapshot.interfaceName,
                    packetStore: packetStore,
                    burstCount: config.probeGatewayBurstCount,
                    burstInterval: config.probeGatewayBurstInterval,
                    useDirectBPF: config.bpfEnabled
                )
            )
        }
        return results
    }

    private func connectivityCheckPhaseTags(
        probeCapture: ConnectivityProbeCapture,
        networkState: WiFiServiceNetworkState
    ) -> [String: String] {
        let gatewayResults = probeCapture.gatewayResults
        let internetResults = probeCapture.internetResults
        return [
            "phase.name": "connectivity_check",
            "phase.source": "wifi_connectivity_probe",
            "phase.check_scope": "gateway_arp,gateway_ndp,gateway_icmp,internet_dns,internet_icmp,internet_tcp,internet_http",
            "probe.internet.targets": config.probeInternetTargets.joined(separator: ","),
            "probe.internet.family": config.probeInternetFamily.metricValue,
            "probe.internet.dns.enabled": config.probeInternetDNS ? "true" : "false",
            "probe.internet.icmp.enabled": config.probeInternetICMP ? "true" : "false",
            "probe.internet.tcp.enabled": config.probeInternetTCP ? "true" : "false",
            "probe.internet.http.enabled": config.probeInternetHTTP ? "true" : "false",
            "probe.internet.path.span_count": "\(internetResults.lanes.count)",
            "probe.internet.dns.span_count": "\(internetResults.dns.count)",
            "probe.internet.icmp.span_count": "\(internetResults.icmp.count)",
            "probe.internet.tcp.span_count": "\(internetResults.tcp.count)",
            "probe.internet.http.span_count": "\(internetResults.http.count)",
            "probe.dns_resolvers": networkState.dnsServers.joined(separator: ","),
            "probe.gateway": [networkState.routerIPv4, networkState.routerIPv6].compactMap(\.self).joined(separator: ","),
            "probe.gateway.ipv4": networkState.routerIPv4 ?? "",
            "probe.gateway.ipv6": networkState.routerIPv6 ?? "",
            "probe.gateway.burst_count": "\(config.probeGatewayBurstCount)",
            "probe.gateway.burst_interval_seconds": formatGatewayProbeDouble(config.probeGatewayBurstInterval),
            "probe.gateway.arp.span_count": "\(gatewayResolutionSpanCount(gatewayResults, family: .ipv4))",
            "probe.gateway.ndp.span_count": "\(gatewayResolutionSpanCount(gatewayResults, family: .ipv6))",
            "probe.gateway.probe_count": "\(gatewayResults.map(\.probeCount).reduce(0, +))",
            "probe.gateway.span_count": "\(gatewayResults.count)",
        ]
    }
}

private func gatewayResolutionSpanCount(_ results: [ActiveGatewayProbeResult], family: InternetAddressFamily) -> Int {
    results.count(where: { $0.family == family && $0.arpResolution != nil })
}
