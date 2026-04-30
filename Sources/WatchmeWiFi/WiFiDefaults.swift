import Foundation

enum WiFiDefaults {
    static let metricsInterval: TimeInterval = 5
    static let traceInterval: TimeInterval = 60
    static let triggerCooldown: TimeInterval = 2
    static let probeInternetTimeout: TimeInterval = 5
    static let probeInternetFamily: InternetProbeFamily = .dual
    static let probeInternetDNS = true
    static let probeInternetICMP = true
    static let probeInternetTCP = true
    static let probeInternetHTTP = true
    static let probeInternetTargets = ["www.wide.ad.jp", "www.cloudflare.com"]
    static let gatewayProbeBurstCount = 4
    static let gatewayProbeBurstInterval: TimeInterval = 0.05
    static let bpfEnabled = true
    static let bpfSpanMaxAge: TimeInterval = 180
    static let associationTraceDelay: TimeInterval = 1.5
    static let associationTraceReadinessTimeout: TimeInterval = 8
    static let connectivityReadinessPollInterval: TimeInterval = 0.25
    static let packetWindowTraceDelay: TimeInterval = 1.25
    static let packetWindowSuppressionAfterAssociation: TimeInterval = 20
}
