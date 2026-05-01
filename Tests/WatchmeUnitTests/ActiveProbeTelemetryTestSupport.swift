import Foundation
@testable import WatchmeCore
import WatchmeTelemetry
@testable import WatchmeWiFi

extension ActiveProbeTelemetryTests {
    func makeAgent() -> WiFiAgent {
        WiFiAgent(
            config: WiFiConfig(),
            telemetry: TelemetryClient(
                serviceName: "watchme-test",
                tracesEndpoint: otlpEndpointURL(baseURL: WatchmeDefaults.otlpURL, path: "v1/traces"),
                metricsEndpoint: otlpEndpointURL(baseURL: WatchmeDefaults.otlpURL, path: "v1/metrics")
            )
        )
    }

    func dnsResult(timingSource: String, timestampSource: String) -> ActiveDNSProbeResult {
        ActiveDNSProbeResult(
            target: "neverssl.com",
            family: .ipv4,
            recordType: .a,
            resolver: "192.168.23.254",
            transport: "udp",
            ok: true,
            rcode: 0,
            answerCount: 1,
            addresses: ["34.223.124.45"],
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 1_000_000_000,
                finishedWallNanos: 1_050_000_000,
                timingSource: timingSource,
                timestampSource: timestampSource
            )
        )
    }

    func icmpResult(
        family: InternetAddressFamily = .ipv6,
        remoteIP: String = "2606:4700:4700::1111"
    ) -> ActiveICMPProbeResult {
        ActiveICMPProbeResult(
            target: "neverssl.com",
            family: family,
            remoteIP: remoteIP,
            identifier: 0xBEEF,
            sequence: 9,
            ok: true,
            outcome: "reply",
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_000_000_000,
                finishedWallNanos: 2_012_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    }

    func httpResult() -> ActiveInternetHTTPProbeResult {
        ActiveInternetHTTPProbeResult(
            target: "neverssl.com",
            family: .ipv4,
            remoteIP: "34.223.124.45",
            ok: true,
            outcome: "response",
            statusCode: 204,
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 3_000_000_000,
                finishedWallNanos: 3_080_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    }

    func tcpResult() -> ActiveTCPProbeResult {
        ActiveTCPProbeResult(
            target: "neverssl.com",
            family: .ipv4,
            remoteIP: "34.223.124.45",
            port: 80,
            ok: true,
            outcome: "connected",
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_500_000_000,
                finishedWallNanos: 2_530_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    }

    func gatewayResult() -> ActiveGatewayProbeResult {
        ActiveGatewayProbeResult(
            gateway: "192.168.23.254",
            attempts: [
                ActiveGatewayProbeAttempt(
                    sequence: 1,
                    identifier: 0xCAFE,
                    icmpSequence: 7,
                    reachable: true,
                    outcome: "reply",
                    error: nil,
                    timing: ActiveProbeTiming(
                        startWallNanos: 4_000_000_000,
                        finishedWallNanos: 4_004_000_000,
                        timingSource: bpfPacketTimingSource,
                        timestampSource: bpfHeaderTimestampSource
                    )
                ),
            ],
            burstIntervalSeconds: 0,
            arpResolution: gatewayARPResult()
        )
    }

    func gatewayARPResult() -> ActiveGatewayARPResult {
        ActiveGatewayARPResult(
            gateway: "192.168.23.254",
            sourceIP: "192.168.22.173",
            sourceHardwareAddress: "00:11:22:33:44:55",
            gatewayHardwareAddress: "aa:bb:cc:dd:ee:ff",
            ok: true,
            outcome: "reply",
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 3_990_000_000,
                finishedWallNanos: 3_995_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    }

    func gatewayIPv6Result() -> ActiveGatewayProbeResult {
        ActiveGatewayProbeResult(
            gateway: "fe80::b499:e5ff:fe2b:f8cc",
            family: .ipv6,
            attempts: [
                ActiveGatewayProbeAttempt(
                    sequence: 1,
                    identifier: 0xBEEF,
                    icmpSequence: 9,
                    reachable: true,
                    outcome: "reply",
                    error: nil,
                    timing: ActiveProbeTiming(
                        startWallNanos: 4_100_000_000,
                        finishedWallNanos: 4_106_000_000,
                        timingSource: bpfPacketTimingSource,
                        timestampSource: bpfHeaderTimestampSource
                    )
                ),
            ],
            burstIntervalSeconds: 0,
            arpResolution: ActiveGatewayARPResult(
                gateway: "fe80::b499:e5ff:fe2b:f8cc",
                family: .ipv6,
                protocolName: "ndp",
                sourceIP: "fe80::1",
                sourceHardwareAddress: "00:11:22:33:44:55",
                gatewayHardwareAddress: "aa:bb:cc:dd:ee:ff",
                ok: true,
                outcome: "reply",
                error: nil,
                timing: ActiveProbeTiming(
                    startWallNanos: 4_090_000_000,
                    finishedWallNanos: 4_095_000_000,
                    timingSource: bpfPacketTimingSource,
                    timestampSource: bpfHeaderTimestampSource
                )
            )
        )
    }

    func gatewayARPFailureResult() -> ActiveGatewayProbeResult {
        ActiveGatewayProbeResult(
            gateway: "192.168.23.254",
            attempts: [],
            burstIntervalSeconds: 0,
            arpResolution: ActiveGatewayARPResult(
                gateway: "192.168.23.254",
                sourceIP: "192.168.22.173",
                sourceHardwareAddress: "00:11:22:33:44:55",
                gatewayHardwareAddress: nil,
                ok: false,
                outcome: "timeout",
                error: "BPF gateway ARP reply timed out",
                timing: ActiveProbeTiming(
                    startWallNanos: 3_990_000_000,
                    finishedWallNanos: 4_000_000_000,
                    timingSource: wallClockDeadlineTimingSource,
                    timestampSource: wallClockTimestampSource
                )
            )
        )
    }

    func gatewayLossResult() -> ActiveGatewayProbeResult {
        ActiveGatewayProbeResult(
            gateway: "192.168.23.254",
            attempts: [
                ActiveGatewayProbeAttempt(
                    sequence: 1,
                    identifier: nil,
                    icmpSequence: nil,
                    reachable: false,
                    outcome: "loss",
                    error: "ICMP echo reply was not observed before timeout",
                    timing: ActiveProbeTiming(
                        startWallNanos: 4_000_000_000,
                        finishedWallNanos: 4_200_000_000,
                        timingSource: networkFrameworkTimingSource,
                        timestampSource: wallClockTimestampSource
                    )
                ),
            ],
            burstIntervalSeconds: 0
        )
    }

    func internetLaneResult(icmp: ActiveICMPProbeResult? = nil) -> ActiveInternetProbeLaneResult {
        ActiveInternetProbeLaneResult(
            target: "neverssl.com",
            family: .ipv4,
            dns: [dnsResult(timingSource: networkFrameworkTimingSource, timestampSource: wallClockTimestampSource)],
            icmp: icmp,
            tcp: tcpResult(),
            http: httpResult(),
            startWallNanos: 1_000_000_000,
            finishedWallNanos: 3_080_000_000
        )
    }

    func packetSpanEvent(name: String, startWallNanos: UInt64 = 1_000_000_000) -> SpanEvent {
        SpanEvent(
            name: name,
            startWallNanos: startWallNanos,
            durationNanos: 1000,
            tags: [:],
            statusOK: true
        )
    }

    func makeSnapshot(ssid: String? = "lab", bssid: String? = "aa:bb:cc:dd:ee:ff") -> WiFiSnapshot {
        WiFiSnapshot(
            capturedWallNanos: 1_000_000_000,
            interfaceName: "en0",
            ssid: ssid,
            ssidEncoding: "utf8",
            bssid: bssid,
            isAssociated: true,
            rssiDBM: -51,
            noiseDBM: -97,
            txRateMbps: 573,
            channel: 40,
            channelBand: "5ghz",
            channelWidth: "40mhz",
            channelWidthMHz: 40,
            phyMode: "11ax",
            security: "wpa3_personal",
            interfaceMode: "station",
            countryCode: "jp",
            transmitPowerMW: 126,
            powerOn: true,
            serviceActive: true,
            ipv4Addresses: ["192.168.22.173"],
            ipv6Addresses: ["2405:6581:3e00:a600::1"]
        )
    }
}
