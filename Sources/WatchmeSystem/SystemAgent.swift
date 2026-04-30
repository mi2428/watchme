import Darwin
import Foundation
import WatchmeCore
import WatchmeTelemetry

final class SystemAgent: WatchmeCollector {
    let config: SystemConfig
    let telemetry: TelemetryClient
    let queue = DispatchQueue(label: "watchme.system.metrics")
    var metricsTimer: DispatchSourceTimer?

    init(config: SystemConfig, telemetry: TelemetryClient) {
        self.config = config
        self.telemetry = telemetry
    }

    var name: String {
        SystemCollectorFactory.name
    }

    func runOnce() -> Int32 {
        _ = exportMetrics()
        return 0
    }

    func start() {
        logEvent(
            .info, "system_agent_started",
            fields: [
                "pid": "\(getpid())",
                "metrics_interval_seconds": "\(Int(config.metricsInterval))",
                "otlp_url": config.otlpURL.absoluteString,
            ]
        )

        _ = exportMetrics()

        let metricsTimer = DispatchSource.makeTimerSource(queue: queue)
        metricsTimer.schedule(deadline: .now() + config.metricsInterval, repeating: config.metricsInterval)
        metricsTimer.setEventHandler { [weak self] in
            _ = self?.exportMetrics()
        }
        metricsTimer.resume()
        self.metricsTimer = metricsTimer
    }

    func stop() {
        logEvent(.info, "system_agent_stopped")
        metricsTimer?.cancel()
        metricsTimer = nil
    }

    func exportMetrics() -> Bool {
        let snapshot = SystemSnapshot.capture()
        return telemetry.exportMetrics(
            name: "watchme_system",
            fields: [
                "otlp_url": config.otlpURL.absoluteString,
                "metrics_scope": "system",
            ],
            metrics: SystemMetricBuilder.metrics(snapshot: snapshot)
        )
    }
}
