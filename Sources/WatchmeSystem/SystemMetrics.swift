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

struct VMActivityCounterSnapshot {
    let event: String
    let count: UInt64
}

struct DiskIOSnapshot {
    let disk: String
    let readBytes: UInt64
    let writeBytes: UInt64
    let readOperations: UInt64
    let writeOperations: UInt64
}

struct NetworkInterfaceSnapshot {
    let interface: String
    let receiveBytes: UInt64
    let transmitBytes: UInt64
    let receivePackets: UInt64
    let transmitPackets: UInt64
    let receiveErrors: UInt64
    let transmitErrors: UInt64
    let receiveDrops: UInt64
}

struct FileSystemSnapshot {
    let mount: String
    let fstype: String
    let sizeBytes: UInt64
    let freeBytes: UInt64
    let availableBytes: UInt64
}

struct LoadAverageSnapshot {
    let oneMinute: Double
    let fiveMinutes: Double
    let fifteenMinutes: Double
}

struct CPUCountSnapshot {
    let logical: Int
    let physical: Int
}

struct HostBasicsSnapshot {
    let uptimeSeconds: Double
    let loadAverage: LoadAverageSnapshot?
    let cpuCount: CPUCountSnapshot
}

struct VMStatisticsSnapshot {
    let memory: MemorySnapshot
    let activityCounters: [VMActivityCounterSnapshot]
}

struct SystemSnapshot {
    let cpu: CPUTimeSnapshot?
    let memory: MemorySnapshot?
    let disks: [DiskIOSnapshot]
    let vmActivityCounters: [VMActivityCounterSnapshot]
    let networkInterfaces: [NetworkInterfaceSnapshot]
    let filesystems: [FileSystemSnapshot]
    let host: HostBasicsSnapshot?

    init(
        cpu: CPUTimeSnapshot?,
        memory: MemorySnapshot?,
        disks: [DiskIOSnapshot],
        vmActivityCounters: [VMActivityCounterSnapshot] = [],
        networkInterfaces: [NetworkInterfaceSnapshot] = [],
        filesystems: [FileSystemSnapshot] = [],
        host: HostBasicsSnapshot? = nil
    ) {
        self.cpu = cpu
        self.memory = memory
        self.disks = disks
        self.vmActivityCounters = vmActivityCounters
        self.networkInterfaces = networkInterfaces
        self.filesystems = filesystems
        self.host = host
    }

    static func capture() -> SystemSnapshot {
        let vmStatistics = captureVMStatistics()
        return SystemSnapshot(
            cpu: captureCPUTime(),
            memory: vmStatistics?.memory,
            disks: captureDiskIO(),
            vmActivityCounters: vmStatistics?.activityCounters ?? [],
            networkInterfaces: captureNetworkInterfaces(),
            filesystems: captureFileSystems(),
            host: captureHostBasics()
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
    captureVMStatistics()?.memory
}

func captureVMStatistics() -> VMStatisticsSnapshot? {
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
    return VMStatisticsSnapshot(
        memory: MemorySnapshot(
            freeBytes: UInt64(statistics.free_count) * bytesPerPage,
            activeBytes: UInt64(statistics.active_count) * bytesPerPage,
            inactiveBytes: UInt64(statistics.inactive_count) * bytesPerPage,
            wiredBytes: UInt64(statistics.wire_count) * bytesPerPage,
            compressedBytes: UInt64(statistics.compressor_page_count) * bytesPerPage
        ),
        activityCounters: [
            VMActivityCounterSnapshot(event: "zero_fill", count: UInt64(statistics.zero_fill_count)),
            VMActivityCounterSnapshot(event: "reactivation", count: UInt64(statistics.reactivations)),
            VMActivityCounterSnapshot(event: "pagein", count: UInt64(statistics.pageins)),
            VMActivityCounterSnapshot(event: "pageout", count: UInt64(statistics.pageouts)),
            VMActivityCounterSnapshot(event: "fault", count: UInt64(statistics.faults)),
            VMActivityCounterSnapshot(event: "copy_on_write_fault", count: UInt64(statistics.cow_faults)),
            VMActivityCounterSnapshot(event: "lookup", count: UInt64(statistics.lookups)),
            VMActivityCounterSnapshot(event: "hit", count: UInt64(statistics.hits)),
            VMActivityCounterSnapshot(event: "purge", count: UInt64(statistics.purges)),
            VMActivityCounterSnapshot(event: "decompression", count: UInt64(statistics.decompressions)),
            VMActivityCounterSnapshot(event: "compression", count: UInt64(statistics.compressions)),
            VMActivityCounterSnapshot(event: "swapin", count: UInt64(statistics.swapins)),
            VMActivityCounterSnapshot(event: "swapout", count: UInt64(statistics.swapouts)),
        ]
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

func captureNetworkInterfaces() -> [NetworkInterfaceSnapshot] {
    var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0]
    var length = 0
    guard sysctl(&mib, u_int(mib.count), nil, &length, nil, 0) == 0, length > 0 else {
        return []
    }

    var buffer = [UInt8](repeating: 0, count: length)
    guard sysctl(&mib, u_int(mib.count), &buffer, &length, nil, 0) == 0 else {
        return []
    }

    var interfaces: [String: NetworkInterfaceSnapshot] = [:]
    var offset = 0
    while offset + MemoryLayout<if_msghdr2>.stride <= length {
        let message = ifMessage(from: buffer, offset: offset)
        let messageLength = Int(message.ifm_msglen)
        guard messageLength > 0, offset + messageLength <= length else {
            break
        }
        defer { offset += messageLength }

        guard message.ifm_type == UInt8(RTM_IFINFO2),
              let interface = networkInterfaceName(from: buffer, messageOffset: offset, messageLength: messageLength)
        else {
            continue
        }

        let data = message.ifm_data
        interfaces[interface] = NetworkInterfaceSnapshot(
            interface: interface,
            receiveBytes: data.ifi_ibytes,
            transmitBytes: data.ifi_obytes,
            receivePackets: data.ifi_ipackets,
            transmitPackets: data.ifi_opackets,
            receiveErrors: data.ifi_ierrors,
            transmitErrors: data.ifi_oerrors,
            receiveDrops: data.ifi_iqdrops
        )
    }
    return interfaces.values.sorted { $0.interface < $1.interface }
}

func captureFileSystems() -> [FileSystemSnapshot] {
    let count = getfsstat(nil, 0, MNT_NOWAIT)
    guard count > 0 else {
        return []
    }

    let stats = UnsafeMutableBufferPointer<statfs>.allocate(capacity: Int(count))
    defer { stats.deallocate() }
    let byteCount = Int32(Int(count) * MemoryLayout<statfs>.stride)
    let actualCount = getfsstat(stats.baseAddress, byteCount, MNT_NOWAIT)
    guard actualCount > 0 else {
        return []
    }

    return (0 ..< Int(actualCount))
        .compactMap { fileSystemSnapshot(stats[$0]) }
        .sorted { $0.mount < $1.mount }
}

func captureHostBasics() -> HostBasicsSnapshot {
    HostBasicsSnapshot(
        uptimeSeconds: ProcessInfo.processInfo.systemUptime,
        loadAverage: captureLoadAverage(),
        cpuCount: CPUCountSnapshot(
            logical: ProcessInfo.processInfo.processorCount,
            physical: sysctlInt("hw.physicalcpu") ?? ProcessInfo.processInfo.processorCount
        )
    )
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

private func ifMessage(from buffer: [UInt8], offset: Int) -> if_msghdr2 {
    var message = if_msghdr2()
    withUnsafeMutableBytes(of: &message) { destination in
        buffer.withUnsafeBytes { source in
            destination.copyBytes(from: source[offset ..< offset + MemoryLayout<if_msghdr2>.stride])
        }
    }
    return message
}

private func linkLayerSocketAddress(from buffer: [UInt8], offset: Int, messageEnd: Int) -> sockaddr_dl? {
    guard offset + 8 <= messageEnd else {
        return nil
    }
    var address = sockaddr_dl()
    let byteCount = min(MemoryLayout<sockaddr_dl>.stride, messageEnd - offset)
    withUnsafeMutableBytes(of: &address) { destination in
        buffer.withUnsafeBytes { source in
            destination.prefix(byteCount).copyBytes(from: source[offset ..< offset + byteCount])
        }
    }
    return address
}

private func networkInterfaceName(from buffer: [UInt8], messageOffset: Int, messageLength: Int) -> String? {
    let addressOffset = messageOffset + MemoryLayout<if_msghdr2>.stride
    let messageEnd = messageOffset + messageLength
    guard let address = linkLayerSocketAddress(from: buffer, offset: addressOffset, messageEnd: messageEnd) else {
        return nil
    }
    let nameLength = Int(address.sdl_nlen)
    let nameOffset = addressOffset + 8
    guard nameLength > 0, nameOffset + nameLength <= messageEnd else {
        return nil
    }
    return String(bytes: buffer[nameOffset ..< nameOffset + nameLength], encoding: .utf8)
}

private func fileSystemSnapshot(_ stat: statfs) -> FileSystemSnapshot? {
    let fstype = fixedCString(from: stat.f_fstypename)
    let mount = fixedCString(from: stat.f_mntonname)
    guard !mount.isEmpty,
          !ignoredFileSystemTypes.contains(fstype),
          ignoredMountPrefixes.allSatisfy({ !mount.hasPrefix($0) })
    else {
        return nil
    }

    let flags = UInt64(stat.f_flags)
    guard flags & UInt64(MNT_LOCAL) != 0 else {
        return nil
    }

    let blockSize = nonNegativeUInt64(stat.f_bsize)
    let blocks = nonNegativeUInt64(stat.f_blocks)
    guard blockSize > 0, blocks > 0 else {
        return nil
    }

    return FileSystemSnapshot(
        mount: mount,
        fstype: fstype,
        sizeBytes: blocks * blockSize,
        freeBytes: nonNegativeUInt64(stat.f_bfree) * blockSize,
        availableBytes: nonNegativeUInt64(stat.f_bavail) * blockSize
    )
}

private let ignoredFileSystemTypes: Set<String> = [
    "autofs",
    "devfs",
    "fdesc",
    "nfs",
    "smbfs",
    "webdav",
]

private let ignoredMountPrefixes = [
    "/System/Volumes/Hardware",
    "/System/Volumes/Preboot",
    "/System/Volumes/Update",
    "/System/Volumes/VM",
    "/System/Volumes/iSCPreboot",
    "/System/Volumes/xarts",
]

private func fixedCString<T>(from tuple: T) -> String {
    withUnsafeBytes(of: tuple) { rawBuffer in
        let end = rawBuffer.firstIndex(of: 0) ?? rawBuffer.count
        return String(decoding: rawBuffer[..<end], as: UTF8.self)
    }
}

private func nonNegativeUInt64<T: BinaryInteger>(_ value: T) -> UInt64 {
    value > 0 ? UInt64(value) : 0
}

private func captureLoadAverage() -> LoadAverageSnapshot? {
    var averages = [Double](repeating: 0, count: 3)
    guard getloadavg(&averages, Int32(averages.count)) == Int32(averages.count) else {
        return nil
    }
    return LoadAverageSnapshot(
        oneMinute: averages[0],
        fiveMinutes: averages[1],
        fifteenMinutes: averages[2]
    )
}

private func sysctlInt(_ name: String) -> Int? {
    var value: Int32 = 0
    var size = MemoryLayout<Int32>.stride
    let result = name.withCString { pointer in
        sysctlbyname(pointer, &value, &size, nil, 0)
    }
    guard result == 0, value > 0 else {
        return nil
    }
    return Int(value)
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
