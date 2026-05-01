import Foundation
import WatchmeTelemetry

enum SystemMetricBuilder {
    static func metrics(snapshot: SystemSnapshot) -> [MetricSample] {
        var metrics: [MetricSample] = []
        if let cpu = snapshot.cpu {
            metrics.append(contentsOf: cpuMetrics(cpu))
        }
        if let memory = snapshot.memory {
            metrics.append(contentsOf: memoryMetrics(memory))
        }
        metrics.append(contentsOf: diskMetrics(snapshot.disks))
        metrics.append(contentsOf: vmActivityMetrics(snapshot.vmActivityCounters))
        metrics.append(contentsOf: networkInterfaceMetrics(snapshot.networkInterfaces))
        metrics.append(contentsOf: filesystemMetrics(snapshot.filesystems))
        if let host = snapshot.host {
            metrics.append(contentsOf: hostMetrics(host))
        }
        return metrics
    }

    private static func cpuMetrics(_ cpu: CPUTimeSnapshot) -> [MetricSample] {
        [
            cpuTimeMetric(mode: "user", value: cpu.user),
            cpuTimeMetric(mode: "system", value: cpu.system),
            cpuTimeMetric(mode: "idle", value: cpu.idle),
            cpuTimeMetric(mode: "nice", value: cpu.nice),
        ]
    }

    private static func cpuTimeMetric(mode: String, value: Double) -> MetricSample {
        MetricSample(
            name: "watchme_system_cpu_time_seconds_total",
            help: "Total CPU time in seconds.",
            type: .counter,
            labels: ["mode": mode],
            value: value
        )
    }

    private static func memoryMetrics(_ memory: MemorySnapshot) -> [MetricSample] {
        [
            memoryMetric(state: "free", value: memory.freeBytes),
            memoryMetric(state: "active", value: memory.activeBytes),
            memoryMetric(state: "inactive", value: memory.inactiveBytes),
            memoryMetric(state: "wired", value: memory.wiredBytes),
            memoryMetric(state: "compressed", value: memory.compressedBytes),
        ]
    }

    private static func memoryMetric(state: String, value: UInt64) -> MetricSample {
        MetricSample(
            name: "watchme_system_memory_bytes",
            help: "Memory by VM page state in bytes.",
            type: .gauge,
            labels: ["state": state],
            value: Double(value)
        )
    }

    private static func diskMetrics(_ disks: [DiskIOSnapshot]) -> [MetricSample] {
        disks.flatMap { disk in
            [
                diskCounterMetric(
                    name: "watchme_system_disk_read_bytes_total",
                    help: "Total bytes read from disk.",
                    disk: disk.disk,
                    value: disk.readBytes
                ),
                diskCounterMetric(
                    name: "watchme_system_disk_write_bytes_total",
                    help: "Total bytes written to disk.",
                    disk: disk.disk,
                    value: disk.writeBytes
                ),
                diskCounterMetric(
                    name: "watchme_system_disk_read_ops_total",
                    help: "Total disk read operations.",
                    disk: disk.disk,
                    value: disk.readOperations
                ),
                diskCounterMetric(
                    name: "watchme_system_disk_write_ops_total",
                    help: "Total disk write operations.",
                    disk: disk.disk,
                    value: disk.writeOperations
                ),
            ]
        }
    }

    private static func diskCounterMetric(name: String, help: String, disk: String, value: UInt64) -> MetricSample {
        MetricSample(
            name: name,
            help: help,
            type: .counter,
            labels: ["disk": disk],
            value: Double(value)
        )
    }

    private static func vmActivityMetrics(_ counters: [VMActivityCounterSnapshot]) -> [MetricSample] {
        counters.map { counter in
            MetricSample(
                name: "watchme_system_vm_activity_total",
                help: "Total VM activity events observed by the kernel.",
                type: .counter,
                labels: ["event": counter.event],
                value: Double(counter.count)
            )
        }
    }

    private static func networkInterfaceMetrics(_ interfaces: [NetworkInterfaceSnapshot]) -> [MetricSample] {
        interfaces.flatMap { interface in
            [
                networkCounterMetric(
                    name: "watchme_system_network_bytes_total",
                    help: "Total network bytes by interface and direction.",
                    interface: interface.interface,
                    direction: "receive",
                    value: interface.receiveBytes
                ),
                networkCounterMetric(
                    name: "watchme_system_network_bytes_total",
                    help: "Total network bytes by interface and direction.",
                    interface: interface.interface,
                    direction: "transmit",
                    value: interface.transmitBytes
                ),
                networkCounterMetric(
                    name: "watchme_system_network_packets_total",
                    help: "Total network packets by interface and direction.",
                    interface: interface.interface,
                    direction: "receive",
                    value: interface.receivePackets
                ),
                networkCounterMetric(
                    name: "watchme_system_network_packets_total",
                    help: "Total network packets by interface and direction.",
                    interface: interface.interface,
                    direction: "transmit",
                    value: interface.transmitPackets
                ),
                networkCounterMetric(
                    name: "watchme_system_network_errors_total",
                    help: "Total network errors by interface and direction.",
                    interface: interface.interface,
                    direction: "receive",
                    value: interface.receiveErrors
                ),
                networkCounterMetric(
                    name: "watchme_system_network_errors_total",
                    help: "Total network errors by interface and direction.",
                    interface: interface.interface,
                    direction: "transmit",
                    value: interface.transmitErrors
                ),
                networkCounterMetric(
                    name: "watchme_system_network_drops_total",
                    help: "Total network packet drops by interface and direction.",
                    interface: interface.interface,
                    direction: "receive",
                    value: interface.receiveDrops
                ),
            ]
        }
    }

    private static func networkCounterMetric(
        name: String,
        help: String,
        interface: String,
        direction: String,
        value: UInt64
    ) -> MetricSample {
        MetricSample(
            name: name,
            help: help,
            type: .counter,
            labels: ["interface": interface, "direction": direction],
            value: Double(value)
        )
    }

    private static func filesystemMetrics(_ filesystems: [FileSystemSnapshot]) -> [MetricSample] {
        filesystems.flatMap { filesystem in
            [
                filesystemMetric(filesystem, state: "size", value: filesystem.sizeBytes),
                filesystemMetric(filesystem, state: "free", value: filesystem.freeBytes),
                filesystemMetric(filesystem, state: "available", value: filesystem.availableBytes),
            ]
        }
    }

    private static func filesystemMetric(_ filesystem: FileSystemSnapshot, state: String, value: UInt64) -> MetricSample {
        MetricSample(
            name: "watchme_system_filesystem_bytes",
            help: "Filesystem capacity bytes by mount, filesystem type, and state.",
            type: .gauge,
            labels: ["mount": filesystem.mount, "fstype": filesystem.fstype, "state": state],
            value: Double(value)
        )
    }

    private static func hostMetrics(_ host: HostBasicsSnapshot) -> [MetricSample] {
        var metrics = [
            MetricSample(
                name: "watchme_system_uptime_seconds",
                help: "System uptime in seconds.",
                type: .gauge,
                labels: [:],
                value: host.uptimeSeconds
            ),
            cpuCountMetric(kind: "logical", value: host.cpuCount.logical),
            cpuCountMetric(kind: "physical", value: host.cpuCount.physical),
        ]
        if let loadAverage = host.loadAverage {
            metrics.append(loadAverageMetric(window: "1m", value: loadAverage.oneMinute))
            metrics.append(loadAverageMetric(window: "5m", value: loadAverage.fiveMinutes))
            metrics.append(loadAverageMetric(window: "15m", value: loadAverage.fifteenMinutes))
        }
        return metrics
    }

    private static func cpuCountMetric(kind: String, value: Int) -> MetricSample {
        MetricSample(
            name: "watchme_system_cpu_count",
            help: "CPU count by kind.",
            type: .gauge,
            labels: ["kind": kind],
            value: Double(value)
        )
    }

    private static func loadAverageMetric(window: String, value: Double) -> MetricSample {
        MetricSample(
            name: "watchme_system_load_average",
            help: "System load average by window.",
            type: .gauge,
            labels: ["window": window],
            value: value
        )
    }
}
