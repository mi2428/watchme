@testable import WatchmeSystem
import WatchmeTelemetry
import XCTest

final class SystemMetricBuilderTests: XCTestCase {
    func testMetricsExposeCPUTimeMemoryAndDiskCounters() {
        let snapshot = SystemSnapshot(
            cpu: CPUTimeSnapshot(user: 12.5, system: 3.25, idle: 100, nice: 1),
            memory: MemorySnapshot(
                freeBytes: 1000,
                activeBytes: 2000,
                inactiveBytes: 3000,
                wiredBytes: 4000,
                compressedBytes: 5000
            ),
            disks: [
                DiskIOSnapshot(
                    disk: "disk0",
                    readBytes: 10000,
                    writeBytes: 20000,
                    readOperations: 30,
                    writeOperations: 40
                ),
            ]
        )

        let metrics = SystemMetricBuilder.metrics(snapshot: snapshot)
        let names = Set(metrics.map(\.name))

        XCTAssertEqual(names, [
            "watchme_system_cpu_time_seconds_total",
            "watchme_system_memory_bytes",
            "watchme_system_disk_read_bytes_total",
            "watchme_system_disk_write_bytes_total",
            "watchme_system_disk_read_ops_total",
            "watchme_system_disk_write_ops_total",
        ])
        XCTAssertEqual(
            metric(named: "watchme_system_cpu_time_seconds_total", labels: ["mode": "user"], in: metrics)?.value,
            12.5
        )
        XCTAssertEqual(
            metric(named: "watchme_system_cpu_time_seconds_total", labels: ["mode": "system"], in: metrics)?.value,
            3.25
        )
        XCTAssertEqual(
            metric(named: "watchme_system_memory_bytes", labels: ["state": "compressed"], in: metrics)?.value,
            5000
        )
        XCTAssertEqual(
            metric(named: "watchme_system_disk_read_bytes_total", labels: ["disk": "disk0"], in: metrics)?.value,
            10000
        )
        XCTAssertEqual(
            metric(named: "watchme_system_disk_write_ops_total", labels: ["disk": "disk0"], in: metrics)?.value,
            40
        )
    }

    func testMetricsOmitUnavailableCPUAndMemoryButKeepDiskMetrics() {
        let snapshot = SystemSnapshot(
            cpu: nil,
            memory: nil,
            disks: [
                DiskIOSnapshot(
                    disk: "disk1",
                    readBytes: 1,
                    writeBytes: 2,
                    readOperations: 3,
                    writeOperations: 4
                ),
            ]
        )

        let metrics = SystemMetricBuilder.metrics(snapshot: snapshot)

        XCTAssertNil(metric(named: "watchme_system_cpu_time_seconds_total", in: metrics))
        XCTAssertNil(metric(named: "watchme_system_memory_bytes", in: metrics))
        XCTAssertEqual(
            metric(named: "watchme_system_disk_write_bytes_total", labels: ["disk": "disk1"], in: metrics)?.value,
            2
        )
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
