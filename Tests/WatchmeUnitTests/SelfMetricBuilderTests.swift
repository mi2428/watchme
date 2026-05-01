@testable import WatchmeSelf
import WatchmeTelemetry
import XCTest

final class SelfMetricBuilderTests: XCTestCase {
    func testMetricsExposeProcessResourceUsage() {
        let snapshot = SelfSnapshot(
            cpu: SelfCPUTimeSnapshot(user: 1.5, system: 0.25),
            task: SelfTaskSnapshot(
                residentMemoryBytes: 10_000,
                virtualMemoryBytes: 20_000,
                threadCount: 7
            ),
            openFileDescriptorCount: 12
        )

        let metrics = SelfMetricBuilder.metrics(snapshot: snapshot)
        let names = Set(metrics.map(\.name))

        XCTAssertEqual(names, [
            "watchme_self_process_cpu_time_seconds_total",
            "watchme_self_process_resident_memory_bytes",
            "watchme_self_process_virtual_memory_bytes",
            "watchme_self_process_threads",
            "watchme_self_process_open_fds",
        ])
        XCTAssertEqual(
            metric(named: "watchme_self_process_cpu_time_seconds_total", labels: ["mode": "user"], in: metrics)?.value,
            1.5
        )
        XCTAssertEqual(
            metric(named: "watchme_self_process_cpu_time_seconds_total", labels: ["mode": "system"], in: metrics)?.value,
            0.25
        )
        XCTAssertEqual(metric(named: "watchme_self_process_resident_memory_bytes", in: metrics)?.value, 10_000)
        XCTAssertEqual(metric(named: "watchme_self_process_virtual_memory_bytes", in: metrics)?.value, 20_000)
        XCTAssertEqual(metric(named: "watchme_self_process_threads", in: metrics)?.value, 7)
        XCTAssertEqual(metric(named: "watchme_self_process_open_fds", in: metrics)?.value, 12)
    }

    func testMetricsOmitUnavailableSections() {
        let metrics = SelfMetricBuilder.metrics(
            snapshot: SelfSnapshot(cpu: nil, task: nil, openFileDescriptorCount: 3)
        )

        XCTAssertNil(metric(named: "watchme_self_process_cpu_time_seconds_total", in: metrics))
        XCTAssertNil(metric(named: "watchme_self_process_resident_memory_bytes", in: metrics))
        XCTAssertEqual(metric(named: "watchme_self_process_open_fds", in: metrics)?.value, 3)
    }
}

private func metric(
    named name: String,
    labels expectedLabels: [String: String] = [:],
    in metrics: [MetricSample]
) -> MetricSample? {
    metrics.first { metric in
        metric.name == name && expectedLabels.allSatisfy { metric.labels[$0.key] == $0.value }
    }
}
