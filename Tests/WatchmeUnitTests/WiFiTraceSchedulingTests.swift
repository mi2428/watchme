import Foundation
@testable import WatchmeCore
import WatchmeTelemetry
@testable import WatchmeWiFi
import XCTest

final class WiFiTraceSchedulingTests: XCTestCase {
    func testTriggerTraceUsesInjectedClockForCooldown() {
        let clock = MutableWiFiAgentClock(now: Date(timeIntervalSince1970: 105), wallNanos: 105_000_000_000)
        let scheduler = ManualWiFiTraceScheduler()
        var config = WiFiConfig()
        config.triggerCooldown = 10
        let agent = makeAgent(config: config, clock: clock, scheduler: scheduler)
        agent.lastTrigger = Date(timeIntervalSince1970: 100)

        var emissions: [WiFiTraceEmission] = []
        agent.traceEmissionHandler = { emissions.append($0) }

        agent.triggerTrace(reason: "wifi.roam", eventTags: [:], force: false, includeConnectivityCheck: false)
        scheduler.runAsync()
        XCTAssertTrue(emissions.isEmpty)

        clock.now = Date(timeIntervalSince1970: 111)
        agent.triggerTrace(reason: "wifi.roam", eventTags: ["event": "roam"], force: false, includeConnectivityCheck: true)
        scheduler.runAsync()

        XCTAssertEqual(emissions.count, 1)
        XCTAssertEqual(emissions.first?.reason, "wifi.roam")
        XCTAssertEqual(emissions.first?.eventTags["event"], "roam")
        XCTAssertEqual(agent.lastTrigger, clock.now)
    }

    func testAssociationTraceSchedulesDelayedEmissionAndUpdatesState() {
        let clock = MutableWiFiAgentClock(now: Date(timeIntervalSince1970: 10), wallNanos: 10_000_000_000)
        let scheduler = ManualWiFiTraceScheduler()
        var config = WiFiConfig()
        config.associationTraceReadinessTimeout = 2
        config.packetWindowSuppressionAfterAssociation = 3
        let agent = makeAgent(config: config, clock: clock, scheduler: scheduler)

        var emissions: [WiFiTraceEmission] = []
        agent.traceEmissionHandler = { emissions.append($0) }

        agent.scheduleAssociationTrace(
            sourceReason: "corewlan",
            reason: "wifi.join",
            eventTags: ["association.window_floor_epoch_ns": "9000"],
            delay: 4
        )

        XCTAssertTrue(agent.associationTracePending)
        XCTAssertEqual(agent.pendingAssociationTraceWindowFloorEpochNanos, 9000)
        XCTAssertEqual(agent.packetWindowSuppressedUntil, Date(timeIntervalSince1970: 19))
        XCTAssertEqual(scheduler.delayedDelays, [4])

        clock.now = Date(timeIntervalSince1970: 20)
        clock.wallNanos = 20_000_000_000
        scheduler.runDelayed()

        XCTAssertEqual(emissions.count, 1)
        XCTAssertEqual(emissions.first?.reason, "wifi.join")
        XCTAssertEqual(emissions.first?.eventTags["association.source_reason"], "corewlan")
        XCTAssertEqual(emissions.first?.eventTags["association.delay_seconds"], "4.0")
        XCTAssertEqual(emissions.first?.connectivityReadinessTimeout, 2)
        XCTAssertEqual(agent.lastAssociationTraceCompletedEpochNanos, 20_000_000_000)
        XCTAssertEqual(agent.lastAssociationTraceWindowFloorEpochNanos, 9000)
        XCTAssertFalse(agent.associationTracePending)
        XCTAssertNil(agent.pendingAssociationTraceWindowFloorEpochNanos)
        XCTAssertEqual(agent.packetWindowSuppressedUntil, Date(timeIntervalSince1970: 23))
    }

    func testPacketWindowTraceUsesInjectedSchedulerAndSuppressionClock() {
        let clock = MutableWiFiAgentClock(now: Date(timeIntervalSince1970: 10), wallNanos: 10_000_000_000)
        let scheduler = ManualWiFiTraceScheduler()
        var config = WiFiConfig()
        config.packetWindowSuppressionAfterAssociation = 5
        let agent = makeAgent(config: config, clock: clock, scheduler: scheduler)
        agent.packetWindowSuppressedUntil = Date(timeIntervalSince1970: 20)

        var emissions: [WiFiTraceEmission] = []
        agent.traceEmissionHandler = { emissions.append($0) }

        agent.schedulePacketWindowTrace(sourceReason: "wifi.packet.dhcp_ack", eventTags: [:], delay: 1)
        XCTAssertTrue(scheduler.delayedDelays.isEmpty)

        clock.now = Date(timeIntervalSince1970: 21)
        agent.schedulePacketWindowTrace(sourceReason: "wifi.packet.dhcp_ack", eventTags: ["packet.event": "dhcp_ack"], delay: 1.5)
        XCTAssertEqual(scheduler.delayedDelays, [1.5])

        clock.now = Date(timeIntervalSince1970: 23)
        scheduler.runDelayed()

        XCTAssertEqual(emissions.count, 1)
        XCTAssertEqual(emissions.first?.reason, "wifi.network.attachment")
        XCTAssertEqual(emissions.first?.eventTags["network_attachment.source_reason"], "wifi.packet.dhcp_ack")
        XCTAssertEqual(emissions.first?.eventTags["packet.event"], "dhcp_ack")
        XCTAssertEqual(agent.packetWindowSuppressedUntil, Date(timeIntervalSince1970: 28))
    }

    private func makeAgent(
        config: WiFiConfig = WiFiConfig(),
        clock: MutableWiFiAgentClock,
        scheduler: ManualWiFiTraceScheduler
    ) -> WiFiAgent {
        WiFiAgent(
            config: config,
            telemetry: TelemetryClient(
                serviceName: "watchme-test",
                tracesEndpoint: otlpEndpointURL(baseURL: WatchmeDefaults.otlpURL, path: "v1/traces"),
                metricsEndpoint: otlpEndpointURL(baseURL: WatchmeDefaults.otlpURL, path: "v1/metrics")
            ),
            clock: clock,
            traceScheduler: scheduler
        )
    }
}

private final class MutableWiFiAgentClock: WiFiAgentClock {
    var now: Date
    var wallNanos: UInt64

    init(now: Date, wallNanos: UInt64) {
        self.now = now
        self.wallNanos = wallNanos
    }

    func wallClockNanos() -> UInt64 {
        wallNanos
    }
}

private final class ManualWiFiTraceScheduler: WiFiTraceScheduler {
    private var asyncJobs: [() -> Void] = []
    private var delayedJobs: [() -> Void] = []
    private(set) var delayedDelays: [TimeInterval] = []

    func async(_ work: @escaping () -> Void) {
        asyncJobs.append(work)
    }

    func asyncAfter(delay: TimeInterval, _ work: @escaping () -> Void) {
        delayedDelays.append(delay)
        delayedJobs.append(work)
    }

    func runAsync() {
        let jobs = asyncJobs
        asyncJobs.removeAll()
        for job in jobs {
            job()
        }
    }

    func runDelayed() {
        let jobs = delayedJobs
        delayedJobs.removeAll()
        for job in jobs {
            job()
        }
    }
}
