import Foundation

let networkFrameworkTimingSource = "network_framework_callback"
let bpfPacketTimingSource = "bpf_packet"
let wallClockDeadlineTimingSource = "wall_clock_deadline"
let wallClockPacketBoundaryTimingSource = "wall_clock_packet_boundary"
let noAddressTimingSource = "no_address"
let wallClockTimestampSource = "wall_clock"
let bpfHeaderTimestampSource = "bpf_header_timeval"

struct ActiveProbeTiming {
    let startWallNanos: UInt64
    let finishedWallNanos: UInt64
    let timingSource: String
    let timestampSource: String

    var durationNanos: UInt64 {
        max(finishedWallNanos >= startWallNanos ? finishedWallNanos - startWallNanos : 0, 1000)
    }

    static func networkFramework(start: UInt64, finished: UInt64) -> ActiveProbeTiming {
        ActiveProbeTiming(
            startWallNanos: start,
            finishedWallNanos: finished,
            timingSource: networkFrameworkTimingSource,
            timestampSource: wallClockTimestampSource
        )
    }

    static func bpfPacket(start: UInt64, finished: UInt64) -> ActiveProbeTiming {
        ActiveProbeTiming(
            startWallNanos: start,
            finishedWallNanos: finished,
            timingSource: bpfPacketTimingSource,
            timestampSource: bpfHeaderTimestampSource
        )
    }
}
