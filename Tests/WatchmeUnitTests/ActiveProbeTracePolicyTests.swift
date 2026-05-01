@testable import WatchmeWiFi
import XCTest

extension ActiveProbeTelemetryTests {
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
            traceStarted: 20000,
            lookback: 0.000002
        )

        XCTAssertEqual(start, 8000)
        XCTAssertNil(
            associationPacketSpanWindowStart(
                reason: "wifi.power.changed",
                eventTags: ["wifi.event_received_epoch_ns": "10000"],
                traceStarted: 20000,
                lookback: 0.000002
            )
        )
    }

    func testAssociationPacketWindowDoesNotStartBeforeLastDisconnect() {
        XCTAssertEqual(
            associationPacketSpanWindowStart(
                reason: "wifi.join",
                eventTags: [
                    "network.event_received_epoch_ns": "20000",
                    "association.window_floor_epoch_ns": "15000",
                ],
                traceStarted: 21000,
                lookback: 0.000010
            ),
            15000
        )

        XCTAssertEqual(
            associationPacketSpanWindowStart(
                reason: "wifi.join",
                eventTags: [
                    "network.event_received_epoch_ns": "20000",
                    "association.window_floor_epoch_ns": "25000",
                ],
                traceStarted: 21000,
                lookback: 0.000010
            ),
            10000
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
                traceStarted: 30000,
                associationLookback: 0.000002,
                attachmentLookback: 0.000003
            ),
            17000
        )
        XCTAssertNil(
            passivePacketSpanWindowStart(
                reason: "wifi.disconnect",
                eventTags: ["wifi.event_received_epoch_ns": "20_000"],
                traceStarted: 30000,
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
}
