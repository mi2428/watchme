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
        XCTAssertEqual(tags["probe.internet.http.scheme"], "http")
        XCTAssertEqual(tags["probe.internet.http.method"], "HEAD")
        XCTAssertEqual(tags["probe.internet.http.status_code"], "204")
        XCTAssertNil(tags["url.scheme"])
        XCTAssertNil(tags["http.request.method"])
        XCTAssertNil(tags["http.response.status_code"])
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

    func testGatewayTagsExposeBurstOutcomeFields() {
        let tags = makeAgent().activeGatewayTags(result: gatewayResult(), snapshot: makeSnapshot())

        XCTAssertEqual(tags["span.source"], "darwin_icmp_gateway_probe")
        XCTAssertEqual(tags["probe.target"], "192.168.23.254")
        XCTAssertEqual(tags["probe.gateway.target"], "192.168.23.254")
        XCTAssertEqual(tags["network.peer.address"], "192.168.23.254")
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
        XCTAssertEqual(tags["network.wifi_gateway_hwaddr"], "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(tags["probe.gateway.icmp.span_kind"], "burst")
        XCTAssertNil(tags["packet.event"])
    }

    func testGatewayAttemptTagsExposeEchoCorrelationFields() throws {
        let result = gatewayResult()
        let attempt = try XCTUnwrap(result.attempts.first)
        let tags = makeAgent().activeGatewayAttemptTags(result: result, attempt: attempt, snapshot: makeSnapshot())

        XCTAssertEqual(tags["span.source"], "darwin_icmp_gateway_probe")
        XCTAssertEqual(tags["probe.target"], "192.168.23.254")
        XCTAssertEqual(tags["probe.gateway.target"], "192.168.23.254")
        XCTAssertEqual(tags["network.family"], "ipv4")
        XCTAssertEqual(tags["network.peer.address"], "192.168.23.254")
        XCTAssertEqual(tags["network.gateway_probe.protocol"], "icmp")
        XCTAssertEqual(tags["network.gateway_probe.outcome"], "reply")
        XCTAssertEqual(tags["network.gateway_probe.reachable"], "true")
        XCTAssertEqual(tags["network.gateway_probe.attempt_sequence"], "1")
        XCTAssertEqual(tags["icmp.outcome"], "reply")
        XCTAssertEqual(tags["icmp.identifier"], "0xcafe")
        XCTAssertEqual(tags["icmp.sequence"], "7")
        XCTAssertEqual(tags["packet.event"], "icmp_echo_request_to_reply")
        XCTAssertEqual(tags["packet.timestamp_source"], bpfHeaderTimestampSource)
    }

    func testGatewayARPTagsExposeResolutionFields() {
        let tags = makeAgent().activeGatewayARPTags(result: gatewayARPResult(), snapshot: makeSnapshot())

        XCTAssertEqual(tags["span.source"], "darwin_bpf_gateway_arp_probe")
        XCTAssertEqual(tags["network.gateway_probe.protocol"], "arp")
        XCTAssertEqual(tags["network.gateway_arp.outcome"], "reply")
        XCTAssertEqual(tags["network.gateway_arp.resolved"], "true")
        XCTAssertEqual(tags["network.wifi_gateway"], "192.168.23.254")
        XCTAssertEqual(tags["network.wifi_gateway_hwaddr"], "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(tags["arp.target_ip"], "192.168.23.254")
        XCTAssertEqual(tags["arp.sender_ip"], "192.168.23.254")
        XCTAssertEqual(tags["arp.sender_mac"], "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(tags["arp.target_mac"], "00:11:22:33:44:55")
        XCTAssertEqual(tags["packet.event"], "arp_request_to_reply")
        XCTAssertEqual(tags["packet.timestamp_source"], bpfHeaderTimestampSource)
    }

    func testGatewayIPv6ProbeRecordsNDPAndICMPv6Spans() {
        let agent = makeAgent()
        let recorder = TraceRecorder()
        let phaseId = recorder.newSpanId()

        agent.recordGatewayProbeResult(gatewayIPv6Result(), phaseId: phaseId, recorder: recorder, snapshot: makeSnapshot())
        let spans = recorder.finish(rootName: "wifi.test", rootTags: [:]).spans
        let path = spans.first { $0.name == "probe.gateway.path.ipv6" }
        let ndp = spans.first { $0.name == "probe.gateway.ndp.neighbor_solicitation_to_advertisement" }
        let burst = spans.first { $0.name == "probe.gateway.icmp.burst" }
        let echo = spans.first { $0.name == "probe.gateway.icmp.echo" }

        XCTAssertEqual(path?.tags["network.family"], "ipv6")
        XCTAssertEqual(path?.tags["probe.gateway.arp.span_count"], "0")
        XCTAssertEqual(path?.tags["probe.gateway.ndp.span_count"], "1")
        XCTAssertEqual(path?.tags["probe.gateway.icmp.echo_span_count"], "1")
        XCTAssertEqual(path?.tags["probe.gateway.icmp.burst_span_count"], "1")
        XCTAssertEqual(ndp?.parentId, path?.id)
        XCTAssertEqual(ndp?.tags["span.source"], "darwin_bpf_gateway_ndp_probe")
        XCTAssertEqual(ndp?.tags["network.gateway_probe.protocol"], "ndp")
        XCTAssertEqual(ndp?.tags["network.gateway_ndp.outcome"], "reply")
        XCTAssertEqual(ndp?.tags["icmpv6.nd.target_address"], "fe80::b499:e5ff:fe2b:f8cc")
        XCTAssertEqual(burst?.parentId, path?.id)
        XCTAssertEqual(burst?.tags["probe.gateway.icmp.span_kind"], "burst")
        XCTAssertEqual(echo?.parentId, burst?.id)
        XCTAssertEqual(echo?.tags["network.family"], "ipv6")
        XCTAssertEqual(echo?.tags["packet.event"], "icmpv6_echo_request_to_reply")
    }

    func testGatewayProbeRecordsPathParentForICMPEcho() {
        let agent = makeAgent()
        let recorder = TraceRecorder()
        let phaseId = recorder.newSpanId()

        agent.recordGatewayProbeResult(gatewayResult(), phaseId: phaseId, recorder: recorder, snapshot: makeSnapshot())
        let spans = recorder.finish(rootName: "wifi.test", rootTags: [:]).spans
        let path = spans.first { $0.name == "probe.gateway.path.ipv4" }
        let arp = spans.first { $0.name == "probe.gateway.arp.request_to_reply" }
        let burst = spans.first { $0.name == "probe.gateway.icmp.burst" }
        let echo = spans.first { $0.name == "probe.gateway.icmp.echo" }

        XCTAssertEqual(path?.parentId, phaseId)
        XCTAssertEqual(arp?.parentId, path?.id)
        XCTAssertEqual(burst?.parentId, path?.id)
        XCTAssertEqual(echo?.parentId, burst?.id)
        XCTAssertLessThan(arp?.startWallNanos ?? 0, echo?.startWallNanos ?? 0)
        XCTAssertEqual(path?.tags["probe.gateway.path.status"], "ok")
        XCTAssertEqual(path?.tags["probe.gateway.arp.span_count"], "1")
        XCTAssertEqual(path?.tags["probe.gateway.icmp.span_count"], "1")
        XCTAssertEqual(path?.tags["probe.gateway.icmp.echo_span_count"], "1")
        XCTAssertEqual(path?.tags["probe.gateway.icmp.burst_span_count"], "1")
        XCTAssertEqual(path?.tags["network.wifi_gateway_hwaddr"], "aa:bb:cc:dd:ee:ff")
    }

    func testGatewayProbeRecordsOnlyARPWhenResolutionFails() {
        let agent = makeAgent()
        let recorder = TraceRecorder()
        let phaseId = recorder.newSpanId()

        agent.recordGatewayProbeResult(gatewayARPFailureResult(), phaseId: phaseId, recorder: recorder, snapshot: makeSnapshot())
        let spans = recorder.finish(rootName: "wifi.test", rootTags: [:]).spans
        let path = spans.first { $0.name == "probe.gateway.path.ipv4" }
        let arp = spans.first { $0.name == "probe.gateway.arp.request_to_reply" }

        XCTAssertNotNil(arp)
        XCTAssertNil(spans.first { $0.name == "probe.gateway.icmp.burst" })
        XCTAssertNil(spans.first { $0.name == "probe.gateway.icmp.echo" })
        XCTAssertEqual(path?.tags["probe.gateway.path.status"], "error")
        XCTAssertEqual(path?.tags["probe.gateway.arp.span_count"], "1")
        XCTAssertEqual(path?.tags["probe.gateway.icmp.span_count"], "0")
        XCTAssertEqual(path?.tags["probe.gateway.icmp.echo_span_count"], "0")
        XCTAssertEqual(path?.tags["probe.gateway.icmp.burst_span_count"], "0")
        XCTAssertEqual(path?.tags["network.gateway_probe.outcome"], "arp_timeout")
    }

    func testInternetProbeRecordsFamilySpecificPathParent() {
        let agent = makeAgent()
        let recorder = TraceRecorder()
        let phaseId = recorder.newSpanId()

        agent.recordInternetProbeResults(
            ActiveInternetProbeResults(lanes: [internetLaneResult(
                icmp: icmpResult(family: .ipv4, remoteIP: "34.223.124.45")
            )]),
            phaseId: phaseId,
            recorder: recorder,
            snapshot: makeSnapshot()
        )
        let spans = recorder.finish(rootName: "wifi.test", rootTags: [:]).spans
        let path = spans.first { $0.name == "probe.internet.path.ipv4" }
        let dns = spans.first { $0.name == "probe.internet.dns.resolve" }
        let icmp = spans.first { $0.name == "probe.internet.icmp.echo" }
        let tcp = spans.first { $0.name == "probe.internet.tcp.connect" }
        let http = spans.first { $0.name == "probe.internet.http.head" }

        XCTAssertEqual(path?.parentId, phaseId)
        XCTAssertEqual(path?.tags["network.family"], "ipv4")
        XCTAssertEqual(path?.tags["probe.internet.path.status"], "ok")
        XCTAssertEqual(path?.tags["probe.internet.checks.summary"], "DNS=ok,ICMP=ok,TCP=ok,HTTP=ok")
        XCTAssertEqual(path?.tags["probe.internet.checks.ok"], "DNS,ICMP,TCP,HTTP")
        XCTAssertEqual(path?.tags["probe.internet.checks.failed"], "")
        XCTAssertEqual(path?.tags["probe.internet.check.dns.status"], "ok")
        XCTAssertEqual(path?.tags["probe.internet.check.icmp.status"], "ok")
        XCTAssertEqual(path?.tags["probe.internet.check.tcp.status"], "ok")
        XCTAssertEqual(path?.tags["probe.internet.check.http.status"], "ok")
        XCTAssertEqual(dns?.parentId, path?.id)
        XCTAssertEqual(icmp?.parentId, path?.id)
        XCTAssertEqual(tcp?.parentId, path?.id)
        XCTAssertEqual(http?.parentId, path?.id)
    }

    func testConnectivityProbeCaptureRunsGatewayBeforeInternetWhenGatewayICMPLosses() {
        var internetProbeRan = false
        var order: [String] = []

        let capture = collectConnectivityProbeResults(
            gatewayProbe: {
                order.append("gateway")
                return [self.gatewayLossResult()]
            },
            internetProbes: {
                order.append("internet")
                internetProbeRan = true
                return ActiveInternetProbeResults(lanes: [self.internetLaneResult()])
            }
        )

        XCTAssertEqual(order, ["gateway", "internet"])
        XCTAssertTrue(internetProbeRan)
        XCTAssertEqual(capture.gatewayResults.first?.reachable, false)
        XCTAssertEqual(capture.internetResults.lanes.count, 1)
        XCTAssertEqual(capture.internetResults.tcp.count, 1)
    }

    func testGatewayProbeTasksRunIPv4AndIPv6Concurrently() {
        let bothStarted = DispatchSemaphore(value: 0)
        let releaseTasks = DispatchSemaphore(value: 0)
        let finishGroup = DispatchGroup()
        let startedLock = NSLock()
        var startedFamilies: [InternetAddressFamily] = []
        var results: [ActiveGatewayProbeResult] = []

        func markStarted(_ family: InternetAddressFamily) {
            startedLock.lock()
            startedFamilies.append(family)
            if startedFamilies.count == 2 {
                bothStarted.signal()
            }
            startedLock.unlock()
        }

        let tasks = [
            GatewayProbeTask {
                markStarted(.ipv4)
                _ = releaseTasks.wait(timeout: .now() + 2)
                return self.gatewayResult()
            },
            GatewayProbeTask {
                markStarted(.ipv6)
                _ = releaseTasks.wait(timeout: .now() + 2)
                return self.gatewayIPv6Result()
            },
        ]

        finishGroup.enter()
        DispatchQueue.global(qos: .utility).async {
            results = runGatewayProbeTasks(tasks)
            finishGroup.leave()
        }

        XCTAssertEqual(bothStarted.wait(timeout: .now() + 1), .success)
        releaseTasks.signal()
        releaseTasks.signal()
        XCTAssertEqual(finishGroup.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(results.map(\.family), [.ipv4, .ipv6])
    }

    func testDisconnectTraceDedupeAllowsOneTraceUntilAssociationRecovers() {
        let agent = makeAgent()

        XCTAssertTrue(agent.markDisconnectTraceAcceptedIfNeeded(reason: "wifi.disconnect"))
        XCTAssertFalse(agent.markDisconnectTraceAcceptedIfNeeded(reason: "wifi.disconnect"))
        XCTAssertTrue(agent.markDisconnectTraceAcceptedIfNeeded(reason: "wifi.link.changed"))

        agent.resetDisconnectTraceDedupeIfRecovered(snapshot: makeSnapshot())

        XCTAssertTrue(agent.markDisconnectTraceAcceptedIfNeeded(reason: "wifi.disconnect"))
    }
}
