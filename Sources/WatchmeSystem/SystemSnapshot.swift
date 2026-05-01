import Foundation

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
