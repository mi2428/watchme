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
            ],
            vmActivityCounters: [
                VMActivityCounterSnapshot(event: "pagein", count: 11),
                VMActivityCounterSnapshot(event: "swapout", count: 12),
            ],
            networkInterfaces: [
                NetworkInterfaceSnapshot(
                    interface: "en0",
                    receiveBytes: 111,
                    transmitBytes: 222,
                    receivePackets: 3,
                    transmitPackets: 4,
                    receiveErrors: 5,
                    transmitErrors: 6,
                    receiveDrops: 7
                ),
            ],
            filesystems: [
                FileSystemSnapshot(
                    mount: "/",
                    fstype: "apfs",
                    sizeBytes: 1_000_000,
                    freeBytes: 200_000,
                    availableBytes: 150_000
                ),
            ],
            host: HostBasicsSnapshot(
                uptimeSeconds: 1234.5,
                loadAverage: LoadAverageSnapshot(oneMinute: 1.1, fiveMinutes: 0.8, fifteenMinutes: 0.5),
                cpuCount: CPUCountSnapshot(logical: 10, physical: 8)
            )
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
            "watchme_system_vm_activity_total",
            "watchme_system_network_bytes_total",
            "watchme_system_network_packets_total",
            "watchme_system_network_errors_total",
            "watchme_system_network_drops_total",
            "watchme_system_filesystem_bytes",
            "watchme_system_uptime_seconds",
            "watchme_system_load_average",
            "watchme_system_cpu_count",
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
        XCTAssertEqual(
            metric(named: "watchme_system_vm_activity_total", labels: ["event": "swapout"], in: metrics)?.value,
            12
        )
        XCTAssertEqual(
            metric(
                named: "watchme_system_network_bytes_total",
                labels: ["interface": "en0", "direction": "receive"],
                in: metrics
            )?.value,
            111
        )
        XCTAssertEqual(
            metric(
                named: "watchme_system_network_errors_total",
                labels: ["interface": "en0", "direction": "transmit"],
                in: metrics
            )?.value,
            6
        )
        XCTAssertEqual(
            metric(
                named: "watchme_system_filesystem_bytes",
                labels: ["mount": "/", "fstype": "apfs", "state": "available"],
                in: metrics
            )?.value,
            150_000
        )
        XCTAssertEqual(
            metric(named: "watchme_system_uptime_seconds", in: metrics)?.value,
            1234.5
        )
        XCTAssertEqual(
            metric(named: "watchme_system_load_average", labels: ["window": "5m"], in: metrics)?.value,
            0.8
        )
        XCTAssertEqual(
            metric(named: "watchme_system_cpu_count", labels: ["kind": "physical"], in: metrics)?.value,
            8
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
