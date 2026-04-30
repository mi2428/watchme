import Darwin
import Foundation
import WatchmeCore
import WatchmeTelemetry

final class SystemAgent {
    let config: SystemConfig
    let telemetry: TelemetryClient
    let queue = DispatchQueue(label: "watchme.system.metrics")
    var metricsTimer: DispatchSourceTimer?

    init(config: SystemConfig, telemetry: TelemetryClient) {
        self.config = config
        self.telemetry = telemetry
    }

    func runOnce() -> Int32 {
        _ = exportMetrics()
        return 0
    }

    func run() {
        logEvent(
            .info, "system_agent_started",
            fields: [
                "pid": "\(getpid())",
                "metrics_interval_seconds": "\(Int(config.metricsInterval))",
                "collector_url": config.collectorURL.absoluteString,
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

        let signalQueue = DispatchQueue(label: "watchme.system.signals")
        let sigint = DispatchSource.makeSignalSource(signal: SIGINT, queue: signalQueue)
        let sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: signalQueue)
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        sigint.setEventHandler { [weak self] in self?.stop(signal: "SIGINT") }
        sigterm.setEventHandler { [weak self] in self?.stop(signal: "SIGTERM") }
        sigint.resume()
        sigterm.resume()

        RunLoop.current.run()
    }

    private func stop(signal: String) {
        logEvent(.info, "system_agent_stopped", fields: ["signal": signal])
        metricsTimer?.cancel()
        exit(0)
    }

    func exportMetrics() -> Bool {
        let snapshot = SystemSnapshot.capture()
        return telemetry.exportMetrics(
            name: "watchme_system",
            fields: [
                "collector_url": config.collectorURL.absoluteString,
                "metrics_scope": "system",
            ],
            metrics: SystemMetricBuilder.metrics(snapshot: snapshot)
        )
    }
}
