import WatchmeBPF
import WatchmeTelemetry
@testable import WatchmeWiFi

func recordDisconnectedActiveProbePlaceholders(in state: inout WiFiMetricState) {
    state.recordDNSProbe(
        ActiveDNSProbeResult(
            target: "example.com",
            family: .ipv4,
            recordType: .a,
            resolver: "none",
            transport: "udp",
            ok: false,
            rcode: nil,
            answerCount: 0,
            addresses: [],
            error: "no resolver",
            timing: ActiveProbeTiming(
                startWallNanos: 1_000_000_000,
                finishedWallNanos: 1_000_001_000,
                timingSource: noAddressTimingSource,
                timestampSource: wallClockTimestampSource
            )
        )
    )
    state.recordICMPProbe(
        ActiveICMPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "none",
            identifier: 0,
            sequence: 0,
            ok: false,
            outcome: "no_address",
            error: "no address",
            timing: ActiveProbeTiming(
                startWallNanos: 1_100_000_000,
                finishedWallNanos: 1_100_001_000,
                timingSource: noAddressTimingSource,
                timestampSource: wallClockTimestampSource
            )
        )
    )
    state.recordInternetHTTPProbe(
        ActiveInternetHTTPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "none",
            ok: false,
            outcome: "no_address",
            statusCode: nil,
            error: "no address",
            timing: ActiveProbeTiming(
                startWallNanos: 1_200_000_000,
                finishedWallNanos: 1_200_001_000,
                timingSource: noAddressTimingSource,
                timestampSource: wallClockTimestampSource
            )
        )
    )
    state.recordInternetTCPProbe(
        ActiveTCPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "none",
            port: 80,
            ok: false,
            outcome: "no_address",
            error: "no address",
            timing: ActiveProbeTiming(
                startWallNanos: 1_150_000_000,
                finishedWallNanos: 1_150_001_000,
                timingSource: noAddressTimingSource,
                timestampSource: wallClockTimestampSource
            )
        )
    )
}

func recordReconnectedActiveProbeSuccesses(in state: inout WiFiMetricState) {
    state.recordDNSProbe(
        ActiveDNSProbeResult(
            target: "example.com",
            family: .ipv4,
            recordType: .a,
            resolver: "192.168.23.254",
            transport: "udp",
            ok: true,
            rcode: 0,
            answerCount: 1,
            addresses: ["93.184.216.34"],
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_000_000_000,
                finishedWallNanos: 2_050_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
    state.recordICMPProbe(
        ActiveICMPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "93.184.216.34",
            identifier: 0x1234,
            sequence: 1,
            ok: true,
            outcome: "reply",
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_100_000_000,
                finishedWallNanos: 2_130_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
    state.recordInternetHTTPProbe(
        ActiveInternetHTTPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "93.184.216.34",
            ok: true,
            outcome: "response",
            statusCode: 200,
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_200_000_000,
                finishedWallNanos: 2_290_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
    state.recordInternetTCPProbe(
        ActiveTCPProbeResult(
            target: "example.com",
            family: .ipv4,
            remoteIP: "93.184.216.34",
            port: 80,
            ok: true,
            outcome: "connected",
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_150_000_000,
                finishedWallNanos: 2_180_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
}

func recordSampleActiveProbes(in state: inout WiFiMetricState) throws {
    recordSampleInternetPathProbe(in: &state)
    recordSampleInternetHTTPProbe(in: &state)
    recordSampleInternetTCPProbe(in: &state)
    recordSampleDNSProbe(in: &state)
    recordSampleICMPProbe(in: &state)
    recordSampleGatewayProbe(in: &state)
}

func makeSnapshot(
    capturedWallNanos: UInt64 = 1000,
    ssid: String? = "lab",
    ssidEncoding: String? = "utf8",
    bssid: String? = "aa:bb:cc:dd:ee:ff",
    isAssociated: Bool = true,
    rssiDBM: Int? = -51,
    noiseDBM: Int? = -97,
    txRateMbps: Double? = 573,
    channel: Int? = 40,
    channelBand: String? = "5ghz",
    channelWidth: String? = "40mhz",
    channelWidthMHz: Int? = 40,
    phyMode: String? = "11ax",
    security: String? = "wpa3_personal",
    interfaceMode: String? = "station",
    countryCode: String? = "jp",
    transmitPowerMW: Int? = 126,
    powerOn: Bool? = true,
    serviceActive: Bool? = true
) -> WiFiSnapshot {
    WiFiSnapshot(
        capturedWallNanos: capturedWallNanos,
        interfaceName: "en0",
        ssid: ssid,
        ssidEncoding: ssidEncoding,
        bssid: bssid,
        isAssociated: isAssociated,
        rssiDBM: rssiDBM,
        noiseDBM: noiseDBM,
        txRateMbps: txRateMbps,
        channel: channel,
        channelBand: channelBand,
        channelWidth: channelWidth,
        channelWidthMHz: channelWidthMHz,
        phyMode: phyMode,
        security: security,
        interfaceMode: interfaceMode,
        countryCode: countryCode,
        transmitPowerMW: transmitPowerMW,
        powerOn: powerOn,
        serviceActive: serviceActive,
        ipv4Addresses: ["192.168.22.173"],
        ipv6Addresses: []
    )
}

private func recordSampleInternetHTTPProbe(in state: inout WiFiMetricState) {
    state.recordInternetHTTPProbe(
        ActiveInternetHTTPProbeResult(
            target: "neverssl.com",
            family: .ipv4,
            remoteIP: "34.223.124.45",
            ok: true,
            outcome: "response",
            statusCode: 200,
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 1_000_000_000,
                finishedWallNanos: 1_180_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
}

private func recordSampleInternetPathProbe(in state: inout WiFiMetricState) {
    state.recordInternetPathProbe(
        ActiveInternetProbeLaneResult(
            target: "neverssl.com",
            family: .ipv4,
            dns: [sampleDNSProbeResult()],
            icmp: nil,
            tcp: nil,
            http: nil,
            startWallNanos: 1_000_000_000,
            finishedWallNanos: 1_300_000_000
        )
    )
}

private func recordSampleInternetTCPProbe(in state: inout WiFiMetricState) {
    state.recordInternetTCPProbe(
        ActiveTCPProbeResult(
            target: "neverssl.com",
            family: .ipv4,
            remoteIP: "34.223.124.45",
            port: 80,
            ok: true,
            outcome: "connected",
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 1_500_000_000,
                finishedWallNanos: 1_540_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
}

private func recordSampleDNSProbe(in state: inout WiFiMetricState) {
    state.recordDNSProbe(sampleDNSProbeResult())
}

private func sampleDNSProbeResult() -> ActiveDNSProbeResult {
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
            startWallNanos: 2_000_000_000,
            finishedWallNanos: 2_050_000_000,
            timingSource: bpfPacketTimingSource,
            timestampSource: bpfHeaderTimestampSource
        )
    )
}

private func recordSampleICMPProbe(in state: inout WiFiMetricState) {
    state.recordICMPProbe(
        ActiveICMPProbeResult(
            target: "neverssl.com",
            family: .ipv4,
            remoteIP: "34.223.124.45",
            identifier: 0x1234,
            sequence: 7,
            ok: true,
            outcome: "reply",
            error: nil,
            timing: ActiveProbeTiming(
                startWallNanos: 2_100_000_000,
                finishedWallNanos: 2_120_000_000,
                timingSource: bpfPacketTimingSource,
                timestampSource: bpfHeaderTimestampSource
            )
        )
    )
}

private func recordSampleGatewayProbe(in state: inout WiFiMetricState) {
    state.recordGatewayProbe(
        ActiveGatewayProbeResult(
            gateway: "192.168.23.254",
            attempts: [
                ActiveGatewayProbeAttempt(
                    sequence: 1,
                    identifier: nil,
                    icmpSequence: nil,
                    reachable: true,
                    outcome: "reply",
                    error: nil,
                    timing: ActiveProbeTiming(
                        startWallNanos: 3_000_000_000,
                        finishedWallNanos: 3_010_000_000,
                        timingSource: networkFrameworkTimingSource,
                        timestampSource: wallClockTimestampSource
                    )
                ),
            ],
            burstIntervalSeconds: 0,
            arpResolution: ActiveGatewayARPResult(
                gateway: "192.168.23.254",
                sourceIP: "192.168.22.173",
                sourceHardwareAddress: "00:11:22:33:44:55",
                gatewayHardwareAddress: "aa:bb:cc:dd:ee:ff",
                ok: true,
                outcome: "reply",
                error: nil,
                timing: ActiveProbeTiming(
                    startWallNanos: 2_900_000_000,
                    finishedWallNanos: 2_910_000_000,
                    timingSource: bpfPacketTimingSource,
                    timestampSource: bpfHeaderTimestampSource
                )
            )
        )
    )
}
