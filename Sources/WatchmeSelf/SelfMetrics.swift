import Darwin
import Foundation
import WatchmeTelemetry

struct SelfCPUTimeSnapshot {
    let user: Double
    let system: Double
}

struct SelfTaskSnapshot {
    let residentMemoryBytes: UInt64
    let virtualMemoryBytes: UInt64
    let threadCount: Int
}

struct SelfSnapshot {
    let cpu: SelfCPUTimeSnapshot?
    let task: SelfTaskSnapshot?
    let openFileDescriptorCount: Int?

    static func capture() -> SelfSnapshot {
        SelfSnapshot(
            cpu: captureSelfCPUTime(),
            task: captureSelfTask(),
            openFileDescriptorCount: captureSelfOpenFileDescriptorCount()
        )
    }
}

enum SelfMetricBuilder {
    static func metrics(snapshot: SelfSnapshot) -> [MetricSample] {
        var metrics: [MetricSample] = []
        if let cpu = snapshot.cpu {
            metrics.append(Self.cpuMetric(mode: "user", value: cpu.user))
            metrics.append(Self.cpuMetric(mode: "system", value: cpu.system))
        }
        if let task = snapshot.task {
            metrics.append(
                MetricSample(
                    name: "watchme_self_process_resident_memory_bytes",
                    help: "Resident memory used by the WatchMe process.",
                    type: .gauge,
                    labels: [:],
                    value: Double(task.residentMemoryBytes)
                )
            )
            metrics.append(
                MetricSample(
                    name: "watchme_self_process_virtual_memory_bytes",
                    help: "Virtual memory used by the WatchMe process.",
                    type: .gauge,
                    labels: [:],
                    value: Double(task.virtualMemoryBytes)
                )
            )
            metrics.append(
                MetricSample(
                    name: "watchme_self_process_threads",
                    help: "Thread count in the WatchMe process.",
                    type: .gauge,
                    labels: [:],
                    value: Double(task.threadCount)
                )
            )
        }
        if let openFileDescriptorCount = snapshot.openFileDescriptorCount {
            metrics.append(
                MetricSample(
                    name: "watchme_self_process_open_fds",
                    help: "Open file descriptor count in the WatchMe process.",
                    type: .gauge,
                    labels: [:],
                    value: Double(openFileDescriptorCount)
                )
            )
        }
        return metrics
    }

    private static func cpuMetric(mode: String, value: Double) -> MetricSample {
        MetricSample(
            name: "watchme_self_process_cpu_time_seconds_total",
            help: "CPU time consumed by the WatchMe process.",
            type: .counter,
            labels: ["mode": mode],
            value: value
        )
    }
}

func captureSelfCPUTime() -> SelfCPUTimeSnapshot? {
    var usage = rusage()
    guard getrusage(RUSAGE_SELF, &usage) == 0 else {
        return nil
    }
    return SelfCPUTimeSnapshot(
        user: seconds(from: usage.ru_utime),
        system: seconds(from: usage.ru_stime)
    )
}

func captureSelfTask() -> SelfTaskSnapshot? {
    var info = proc_taskinfo()
    let byteCount = withUnsafeMutablePointer(to: &info) { pointer in
        proc_pidinfo(
            getpid(),
            PROC_PIDTASKINFO,
            0,
            UnsafeMutableRawPointer(pointer),
            Int32(MemoryLayout<proc_taskinfo>.stride)
        )
    }
    guard byteCount == Int32(MemoryLayout<proc_taskinfo>.stride) else {
        return nil
    }
    return SelfTaskSnapshot(
        residentMemoryBytes: info.pti_resident_size,
        virtualMemoryBytes: info.pti_virtual_size,
        threadCount: Int(max(info.pti_threadnum, 0))
    )
}

func captureSelfOpenFileDescriptorCount() -> Int? {
    let byteCount = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, nil, 0)
    guard byteCount >= 0 else {
        return nil
    }
    return Int(byteCount) / MemoryLayout<proc_fdinfo>.stride
}

private func seconds(from timeval: timeval) -> Double {
    Double(timeval.tv_sec) + Double(timeval.tv_usec) / 1_000_000.0
}
