import Foundation
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
                tracesEndpoint: URL(string: "http://127.0.0.1:4318/v1/traces")!,
                metricsEndpoint: URL(string: "http://127.0.0.1:4318/v1/metrics")!
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
            startWallNanos: 1_000_000_000,
            finishedWallNanos: 1_050_000_000,
            durationNanos: 50_000_000,
            timingSource: timingSource,
            timestampSource: timestampSource
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
            startWallNanos: 2_000_000_000,
            finishedWallNanos: 2_012_000_000,
            durationNanos: 12_000_000,
            timingSource: bpfPacketTimingSource,
            timestampSource: bpfHeaderTimestampSource
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
            startWallNanos: 3_000_000_000,
            finishedWallNanos: 3_080_000_000,
            durationNanos: 80_000_000,
            timingSource: bpfPacketTimingSource,
            timestampSource: bpfHeaderTimestampSource
        )
    }

    private func gatewayResult() -> ActiveGatewayProbeResult {
        ActiveGatewayProbeResult(
            gateway: "192.168.23.254",
            reachable: true,
            outcome: "reply",
            error: nil,
            startWallNanos: 4_000_000_000,
            finishedWallNanos: 4_004_000_000,
            durationNanos: 4_000_000,
            timingSource: bpfPacketTimingSource,
            timestampSource: bpfHeaderTimestampSource
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
