import Foundation
import WatchmeCore

extension WiFiAgent {
    func activeProbeBaseTags(
        snapshot: WiFiSnapshot,
        timingSource: String,
        timestampSource: String,
        spanSource: String
    ) -> [String: String] {
        [
            "span.source": spanSource,
            "active_probe.interface": snapshot.interfaceName ?? "",
            "active_probe.required_interface": snapshot.interfaceName ?? "",
            "probe.timing_source": timingSource,
            "probe.timestamp_source": timestampSource,
            "wifi.essid": snapshot.ssid ?? "unknown",
            "wifi.bssid": snapshot.bssid ?? "unknown",
        ]
    }

    func addPacketTimingTags(_ tags: inout [String: String], timingSource: String, event: String) {
        guard timingSource == bpfPacketTimingSource else {
            return
        }
        tags["packet.event"] = event
        tags["packet.timestamp_source"] = bpfHeaderTimestampSource
        tags["packet.timestamp_resolution"] = "microsecond"
    }

    func addErrorTag(_ tags: inout [String: String], error: String?) {
        guard let error else {
            return
        }
        tags["error"] = clipped(error, limit: 240)
    }
}
