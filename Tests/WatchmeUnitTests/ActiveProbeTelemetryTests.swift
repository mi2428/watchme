import Foundation
@testable import WatchmeCore
import WatchmeTelemetry
@testable import WatchmeWiFi
import XCTest

final class ActiveProbeTelemetryTests: XCTestCase {
    func testDNSTagsExposePacketTimingOnlyForBPFMatchedResults() {
        let agent = makeAgent()
        let snapshot = makeSnapshot()

        let bpfTags = agent.activeDNSTags(
            result: dnsResult(timingSource: bpfPacketTimingSource, timestampSource: bpfHeaderTimestampSource),
            snapshot: snapshot
        )
        let fallbackTags = agent.activeDNSTags(
            result: dnsResult(timingSource: networkFrameworkTimingSource, timestampSource: wallClockTimestampSource),
            snapshot: snapshot
        )

        XCTAssertEqual(bpfTags["probe.target"], "neverssl.com")
        XCTAssertEqual(bpfTags["probe.internet.target"], "neverssl.com")
        XCTAssertEqual(bpfTags["dns.question.type"], "A")
        XCTAssertEqual(bpfTags["dns.rcode"], "0")
        XCTAssertEqual(bpfTags["packet.event"], "dns_query_to_response")
        XCTAssertEqual(bpfTags["packet.timestamp_source"], bpfHeaderTimestampSource)
        XCTAssertEqual(bpfTags["packet.timestamp_resolution"], "microsecond")
        XCTAssertNil(fallbackTags["packet.event"])
        XCTAssertNil(fallbackTags["packet.timestamp_source"])
    }

    func testICMPTagsExposeEchoCorrelationFields() {
        let tags = makeAgent().activeICMPTags(result: icmpResult(), snapshot: makeSnapshot())

        XCTAssertEqual(tags["span.source"], "darwin_icmp_socket")
        XCTAssertEqual(tags["network.family"], "ipv6")
        XCTAssertEqual(tags["network.peer.address"], "2606:4700:4700::1111")
        XCTAssertEqual(tags["icmp.identifier"], "0xbeef")
        XCTAssertEqual(tags["icmp.sequence"], "9")
        XCTAssertEqual(tags["packet.event"], "icmp_echo_request_to_reply")
        XCTAssertEqual(tags["packet.timestamp_source"], bpfHeaderTimestampSource)
    }

    func testHTTPTagsExposePlainHTTPAndPacketTimingFields() {
        let tags = makeAgent().activeInternetHTTPTags(result: httpResult(), snapshot: makeSnapshot())

        XCTAssertEqual(tags["span.source"], "network_framework_plain_http_probe")
        XCTAssertEqual(tags["net.peer.port"], "80")
        XCTAssertEqual(tags["url.scheme"], "http")
        XCTAssertEqual(tags["http.request.method"], "HEAD")
        XCTAssertEqual(tags["http.response.status_code"], "204")
        XCTAssertEqual(tags["packet.event"], "http_request_to_first_response_byte")
        XCTAssertEqual(tags["packet.timestamp_source"], bpfHeaderTimestampSource)
    }

    func testTCPTagsExposeConnectTimingFields() {
        let tags = makeAgent().activeTCPTags(result: tcpResult(), snapshot: makeSnapshot())

        XCTAssertEqual(tags["span.source"], "network_framework_tcp_probe")
        XCTAssertEqual(tags["network.family"], "ipv4")
        XCTAssertEqual(tags["network.peer.address"], "34.223.124.45")
        XCTAssertEqual(tags["net.peer.port"], "80")
        XCTAssertEqual(tags["tcp.outcome"], "connected")
        XCTAssertEqual(tags["packet.event"], "tcp_syn_to_response")
        XCTAssertEqual(tags["packet.timestamp_source"], bpfHeaderTimestampSource)
    }

    func testGatewayTagsExposeFirstHopOutcomeAndPacketTimingFields() {
        let tags = makeAgent().activeGatewayTags(result: gatewayResult(), snapshot: makeSnapshot())

        XCTAssertEqual(tags["span.source"], "darwin_icmp_gateway_probe")
        XCTAssertEqual(tags["network.wifi_gateway"], "192.168.23.254")
        XCTAssertEqual(tags["network.family"], "ipv4")
        XCTAssertEqual(tags["network.gateway_probe.protocol"], "icmp")
        XCTAssertEqual(tags["network.gateway_probe.outcome"], "reply")
        XCTAssertEqual(tags["network.gateway_probe.reachable"], "true")
        XCTAssertEqual(tags["network.gateway_probe.probe_count"], "1")
        XCTAssertEqual(tags["network.gateway_probe.reply_count"], "1")
        XCTAssertEqual(tags["network.gateway_probe.lost_count"], "0")
        XCTAssertEqual(tags["network.gateway_probe.loss_ratio"], "0.000000")
        XCTAssertEqual(tags["network.gateway_probe.jitter_seconds"], "0.000000")
        XCTAssertEqual(tags["packet.event"], "icmp_echo_request_to_reply")
        XCTAssertEqual(tags["packet.timestamp_source"], bpfHeaderTimestampSource)
    }

    func testGatewayProbeRecordsPathParentForICMPEcho() {
        let agent = makeAgent()
        let recorder = TraceRecorder()
        let phaseId = recorder.newSpanId()

        agent.recordGatewayProbeResult(gatewayResult(), phaseId: phaseId, recorder: recorder, snapshot: makeSnapshot())
        let spans = recorder.finish(rootName: "wifi.test", rootTags: [:]).spans
        let path = spans.first { $0.name == "probe.gateway.path" }
        let echo = spans.first { $0.name == "probe.gateway.icmp.echo" }

        XCTAssertEqual(path?.parentId, phaseId)
        XCTAssertEqual(echo?.parentId, path?.id)
        XCTAssertEqual(path?.tags["probe.gateway.path.status"], "ok")
        XCTAssertEqual(path?.tags["probe.gateway.icmp.span_count"], "1")
    }

    func testConnectivityProbeCaptureRunsInternetWhenGatewayICMPLosses() {
        var internetProbeRan = false

        let capture = collectConnectivityProbeResults(
            gatewayProbe: {
                self.gatewayLossResult()
            },
            internetProbes: {
                internetProbeRan = true
                return ActiveInternetProbeResults(lanes: [self.internetLaneResult()])
            }
        )

        XCTAssertTrue(internetProbeRan)
        XCTAssertEqual(capture.gatewayResult?.reachable, false)
        XCTAssertEqual(capture.internetResults.lanes.count, 1)
        XCTAssertEqual(capture.internetResults.tcp.count, 1)
    }

    func testAssociationTraceReplaysConsumedNetworkAttachmentPacketSpans() {
        let packetNames = [
            "packet.dhcp.request_to_ack",
            "packet.icmpv6.router_solicitation_to_advertisement",
            "packet.arp.request_to_reply",
        ]

        for name in packetNames {
            XCTAssertTrue(
                shouldReplayConsumedNetworkAttachmentSpan(
                    reason: "wifi.join",
                    span: packetSpanEvent(name: name, startWallNanos: 1_000_000_000),
                    replayStart: 900_000_000
                )
            )
        }
        XCTAssertFalse(
            shouldReplayConsumedNetworkAttachmentSpan(
                reason: "wifi.power.changed",
                span: packetSpanEvent(name: "packet.arp.request_to_reply", startWallNanos: 1_000_000_000),
                replayStart: 900_000_000
            )
        )
        XCTAssertFalse(
            shouldReplayConsumedNetworkAttachmentSpan(
                reason: "wifi.join",
                span: packetSpanEvent(name: "probe.internet.path", startWallNanos: 1_000_000_000),
                replayStart: 900_000_000
            )
        )
        XCTAssertFalse(
            shouldReplayConsumedNetworkAttachmentSpan(
                reason: "wifi.join",
                span: packetSpanEvent(name: "packet.arp.request_to_reply", startWallNanos: 800_000_000),
                replayStart: 900_000_000
            )
        )
    }

    func testAssociationPacketWindowUsesEventTimestampLookback() {
        let start = associationPacketSpanWindowStart(
            reason: "wifi.join",
            eventTags: ["wifi.event_received_epoch_ns": "10_000".replacingOccurrences(of: "_", with: "")],
            traceStarted: 20_000,
            lookback: 0.000002
        )

        XCTAssertEqual(start, 8_000)
        XCTAssertNil(
            associationPacketSpanWindowStart(
                reason: "wifi.power.changed",
                eventTags: ["wifi.event_received_epoch_ns": "10000"],
                traceStarted: 20_000,
                lookback: 0.000002
            )
        )
    }

    func testPassivePacketSpansAttachOnlyToRecoveryTraces() {
        XCTAssertTrue(shouldAttachPassivePacketSpans(reason: "wifi.join"))
        XCTAssertTrue(shouldAttachPassivePacketSpans(reason: "wifi.roam"))
        XCTAssertTrue(shouldAttachPassivePacketSpans(reason: "wifi.network.attachment"))
        XCTAssertFalse(shouldAttachPassivePacketSpans(reason: "wifi.disconnect"))
        XCTAssertFalse(shouldAttachPassivePacketSpans(reason: "wifi.connectivity"))
        XCTAssertFalse(shouldAttachPassivePacketSpans(reason: "wifi.power.changed"))
    }

    func testPassivePacketWindowUsesBoundedAttachmentTimestampLookback() {
        XCTAssertEqual(
            passivePacketSpanWindowStart(
                reason: "wifi.network.attachment",
                eventTags: ["packet.timestamp_epoch_ns": "20000"],
                traceStarted: 30_000,
                associationLookback: 0.000002,
                attachmentLookback: 0.000003
            ),
            17_000
        )
        XCTAssertNil(
            passivePacketSpanWindowStart(
                reason: "wifi.disconnect",
                eventTags: ["wifi.event_received_epoch_ns": "20_000"],
                traceStarted: 30_000,
                associationLookback: 0.000002,
                attachmentLookback: 0.000003
            )
        )
    }

    func testNetworkAttachmentTraceRequiresAddressAcquisitionEvidence() {
        XCTAssertTrue(
            networkAttachmentTraceHasAddressAcquisitionEvidence([
                packetSpanEvent(name: "packet.dhcp.request_to_ack"),
            ])
        )
        XCTAssertTrue(
            networkAttachmentTraceHasAddressAcquisitionEvidence([
                packetSpanEvent(name: "packet.icmpv6.router_solicitation_to_advertisement"),
            ])
        )
        XCTAssertFalse(
            networkAttachmentTraceHasAddressAcquisitionEvidence([
                packetSpanEvent(name: "packet.arp.request_to_reply"),
                packetSpanEvent(name: "packet.icmpv6.neighbor_solicitation_to_advertisement"),
            ])
        )
    }

    func testStaleAssociationTraceIsSuppressedWhenWiFiIsGone() {
        XCTAssertTrue(
            shouldSuppressStaleAssociationTrace(
                reason: "wifi.join",
                readiness: .skip("wifi_not_associated")
            )
        )
        XCTAssertTrue(
            shouldSuppressStaleAssociationTrace(
                reason: "wifi.join",
                readiness: .skip("wifi_power_off")
            )
        )
        XCTAssertFalse(
            shouldSuppressStaleAssociationTrace(
                reason: "wifi.join",
                readiness: .skip("wifi_dns_unavailable")
            )
        )
        XCTAssertFalse(
            shouldSuppressStaleAssociationTrace(
                reason: "wifi.power.changed",
                readiness: .skip("wifi_not_associated")
            )
        )
    }

    func testNetworkAttachmentTraceIsSuppressedUntilWiFiIsReady() {
        XCTAssertTrue(
            shouldSuppressNetworkAttachmentTrace(
                reason: "wifi.network.attachment",
                readiness: .skip("wifi_not_associated")
            )
        )
        XCTAssertTrue(
            shouldSuppressNetworkAttachmentTrace(
                reason: "wifi.network.attachment",
                readiness: .skip("wifi_dns_unavailable")
            )
        )
        XCTAssertFalse(
            shouldSuppressNetworkAttachmentTrace(
                reason: "wifi.network.attachment",
                readiness: .ready
            )
        )
        XCTAssertFalse(
            shouldSuppressNetworkAttachmentTrace(
                reason: "wifi.join",
                readiness: .skip("wifi_not_associated")
            )
        )
    }

    func testActiveProbeTagsCarryWiFiIdentityContext() {
        let snapshot = makeSnapshot(ssid: "lab-wifi", bssid: "aa:bb:cc:dd:ee:ff")
        let tags = makeAgent().activeInternetHTTPTags(result: httpResult(), snapshot: snapshot)

        XCTAssertEqual(tags["active_probe.interface"], "en0")
        XCTAssertEqual(tags["active_probe.required_interface"], "en0")
        XCTAssertEqual(tags["wifi.essid"], "lab-wifi")
        XCTAssertEqual(tags["wifi.bssid"], "aa:bb:cc:dd:ee:ff")
    }

    private func makeAgent() -> WiFiAgent {
        WiFiAgent(
            config: WiFiConfig(),
            telemetry: TelemetryClient(
                serviceName: "watchme-test",
                tracesEndpoint: otlpEndpointURL(baseURL: WatchmeDefaults.otlpURL, path: "v1/traces"),
                metricsEndpoint: otlpEndpointURL(baseURL: WatchmeDefaults.otlpURL, path: "v1/metrics")
            )
        )
    }

    private func dnsResult(timingSource: String, timestampSource: String) -> ActiveDNSProbeResult {
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

    private func icmpResult() -> ActiveICMPProbeResult {
        ActiveICMPProbeResult(
            target: "neverssl.com",
            family: .ipv6,
            remoteIP: "2606:4700:4700::1111",
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

    private func httpResult() -> ActiveInternetHTTPProbeResult {
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

    private func tcpResult() -> ActiveTCPProbeResult {
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

    private func gatewayResult() -> ActiveGatewayProbeResult {
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
                        startWallNanos: 4_000_000_000,
                        finishedWallNanos: 4_004_000_000,
                        timingSource: bpfPacketTimingSource,
                        timestampSource: bpfHeaderTimestampSource
                    )
                ),
            ],
            burstIntervalSeconds: 0
        )
    }

    private func gatewayLossResult() -> ActiveGatewayProbeResult {
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

    private func internetLaneResult() -> ActiveInternetProbeLaneResult {
        ActiveInternetProbeLaneResult(
            target: "neverssl.com",
            family: .ipv4,
            dns: [dnsResult(timingSource: networkFrameworkTimingSource, timestampSource: wallClockTimestampSource)],
            icmp: nil,
            tcp: tcpResult(),
            http: httpResult(),
            startWallNanos: 1_000_000_000,
            finishedWallNanos: 3_080_000_000
        )
    }

    private func packetSpanEvent(name: String, startWallNanos: UInt64 = 1_000_000_000) -> SpanEvent {
        SpanEvent(
            name: name,
            startWallNanos: startWallNanos,
            durationNanos: 1_000,
            tags: [:],
            statusOK: true
        )
    }

    private func makeSnapshot(ssid: String? = "lab", bssid: String? = "aa:bb:cc:dd:ee:ff") -> WiFiSnapshot {
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
