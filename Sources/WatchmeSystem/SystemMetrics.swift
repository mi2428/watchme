import Darwin
import Foundation
import IOKit
import WatchmeTelemetry

struct CPUTimeSnapshot {
    let user: Double
    let system: Double
    let idle: Double
    let nice: Double
}

struct MemorySnapshot {
    let freeBytes: UInt64
    let activeBytes: UInt64
    let inactiveBytes: UInt64
    let wiredBytes: UInt64
    let compressedBytes: UInt64
}

struct DiskIOSnapshot {
    let disk: String
    let readBytes: UInt64
    let writeBytes: UInt64
    let readOperations: UInt64
    let writeOperations: UInt64
}

struct SystemSnapshot {
    let cpu: CPUTimeSnapshot?
    let memory: MemorySnapshot?
    let disks: [DiskIOSnapshot]

    static func capture() -> SystemSnapshot {
        SystemSnapshot(
            cpu: captureCPUTime(),
            memory: captureMemory(),
            disks: captureDiskIO()
        )
    }
}

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
}

func captureCPUTime() -> CPUTimeSnapshot? {
    var processorCount: natural_t = 0
    var processorInfo: processor_info_array_t?
    var processorInfoCount: mach_msg_type_number_t = 0
    let result = host_processor_info(
        mach_host_self(),
        PROCESSOR_CPU_LOAD_INFO,
        &processorCount,
        &processorInfo,
        &processorInfoCount
    )
    guard result == KERN_SUCCESS, let processorInfo else {
        return nil
    }
    defer {
        vm_deallocate(
            mach_task_self_,
            vm_address_t(bitPattern: processorInfo),
            vm_size_t(processorInfoCount) * vm_size_t(MemoryLayout<integer_t>.stride)
        )
    }

    let ticksPerSecond = Double(max(sysconf(_SC_CLK_TCK), 1))
    let values = UnsafeBufferPointer(start: processorInfo, count: Int(processorInfoCount))
    let statesPerCPU = Int(CPU_STATE_MAX)
    var user: UInt64 = 0
    var system: UInt64 = 0
    var idle: UInt64 = 0
    var nice: UInt64 = 0

    for cpuIndex in 0 ..< Int(processorCount) {
        let offset = cpuIndex * statesPerCPU
        user += UInt64(values[offset + Int(CPU_STATE_USER)])
        system += UInt64(values[offset + Int(CPU_STATE_SYSTEM)])
        idle += UInt64(values[offset + Int(CPU_STATE_IDLE)])
        nice += UInt64(values[offset + Int(CPU_STATE_NICE)])
    }

    return CPUTimeSnapshot(
        user: Double(user) / ticksPerSecond,
        system: Double(system) / ticksPerSecond,
        idle: Double(idle) / ticksPerSecond,
        nice: Double(nice) / ticksPerSecond
    )
}

func captureMemory() -> MemorySnapshot? {
    var pageSize: vm_size_t = 0
    guard host_page_size(mach_host_self(), &pageSize) == KERN_SUCCESS else {
        return nil
    }

    var statistics = vm_statistics64()
    var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.stride / MemoryLayout<integer_t>.stride)
    let result = withUnsafeMutablePointer(to: &statistics) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
            host_statistics64(mach_host_self(), HOST_VM_INFO64, rebound, &count)
        }
    }
    guard result == KERN_SUCCESS else {
        return nil
    }

    let bytesPerPage = UInt64(pageSize)
    return MemorySnapshot(
        freeBytes: UInt64(statistics.free_count) * bytesPerPage,
        activeBytes: UInt64(statistics.active_count) * bytesPerPage,
        inactiveBytes: UInt64(statistics.inactive_count) * bytesPerPage,
        wiredBytes: UInt64(statistics.wire_count) * bytesPerPage,
        compressedBytes: UInt64(statistics.compressor_page_count) * bytesPerPage
    )
}

func captureDiskIO() -> [DiskIOSnapshot] {
    guard let matching = IOServiceMatching("IOMedia") else {
        return []
    }
    let matchingDictionary = matching as NSMutableDictionary
    matchingDictionary["Whole"] = kCFBooleanTrue

    var iterator: io_iterator_t = 0
    guard IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) == KERN_SUCCESS else {
        return []
    }
    defer { IOObjectRelease(iterator) }

    var disks: [DiskIOSnapshot] = []
    while true {
        let media = IOIteratorNext(iterator)
        if media == 0 {
            break
        }
        defer { IOObjectRelease(media) }

        guard
            let disk = registryStringProperty(media, key: kIOBSDNameKey),
            let statistics = blockStorageStatistics(media)
        else {
            continue
        }
        disks.append(
            DiskIOSnapshot(
                disk: disk,
                readBytes: statistics.unsignedValue("Bytes (Read)"),
                writeBytes: statistics.unsignedValue("Bytes (Write)"),
                readOperations: statistics.unsignedValue("Operations (Read)"),
                writeOperations: statistics.unsignedValue("Operations (Write)")
            )
        )
    }
    return disks.sorted { $0.disk < $1.disk }
}

private func registryStringProperty(_ entry: io_registry_entry_t, key: String) -> String? {
    guard let property = IORegistryEntryCreateCFProperty(entry, key as CFString, kCFAllocatorDefault, 0) else {
        return nil
    }
    return property.takeRetainedValue() as? String
}

private func blockStorageStatistics(_ entry: io_registry_entry_t) -> [String: Any]? {
    let options = IOOptionBits(kIORegistryIterateParents | kIORegistryIterateRecursively)
    guard
        let property = IORegistryEntrySearchCFProperty(
            entry,
            kIOServicePlane,
            "Statistics" as CFString,
            kCFAllocatorDefault,
            options
        )
    else {
        return nil
    }
    return property as? [String: Any]
}

private extension [String: Any] {
    func unsignedValue(_ key: String) -> UInt64 {
        switch self[key] {
        case let value as UInt64:
            value
        case let value as UInt:
            UInt64(value)
        case let value as Int64:
            UInt64(Swift.max(value, 0))
        case let value as Int:
            UInt64(Swift.max(value, 0))
        case let value as NSNumber:
            value.uint64Value
        default:
            0
        }
    }
}
