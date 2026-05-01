import Darwin
import Foundation
import WatchmeCore
import WatchmeTelemetry

final class SelfAgent: WatchmeCollector {
    let config: SelfConfig
    let telemetry: TelemetryClient
    let metricsTask = PeriodicTask(queueLabel: "watchme.self.metrics")

    init(config: SelfConfig, telemetry: TelemetryClient) {
        self.config = config
        self.telemetry = telemetry
    }

    var name: String {
        SelfCollectorFactory.name
    }

    func runOnce() -> Int32 {
        _ = exportMetrics()
        return 0
    }

    func start() {
        logEvent(
            .info, "self_agent_started",
            fields: [
                "pid": "\(getpid())",
                "metrics_interval_seconds": "\(Int(config.metricsInterval))",
                "otlp_url": config.otlpURL.absoluteString,
            ]
        )

        metricsTask.start(interval: config.metricsInterval, fireImmediately: true) { [weak self] in
            _ = self?.exportMetrics()
        }
    }

    func stop() {
        logEvent(.info, "self_agent_stopped")
        metricsTask.stop()
    }

    func exportMetrics() -> Bool {
        let snapshot = SelfSnapshot.capture()
        return telemetry.exportMetrics(
            name: "watchme_self",
            fields: [
                "otlp_url": config.otlpURL.absoluteString,
                "metrics_scope": "self",
            ],
            metrics: SelfMetricBuilder.metrics(snapshot: snapshot)
        )
    }
}
