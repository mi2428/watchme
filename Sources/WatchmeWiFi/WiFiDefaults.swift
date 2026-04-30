import Foundation

enum WiFiDefaults {
    static let metricsInterval: TimeInterval = 5
    static let activeInterval: TimeInterval = 60
    static let triggerCooldown: TimeInterval = 2
    static let probeInternetTimeout: TimeInterval = 5
    static let probeInternetFamily: InternetProbeFamily = .dual
    static let probeInternetDNS = true
    static let probeInternetICMP = true
    static let probeInternetHTTP = true
    static let probeInternetTargets = ["example.com", "www.cloudflare.com"]
    static let gatewayProbeBurstCount = 4
    static let gatewayProbeBurstInterval: TimeInterval = 0.05
    static let bpfEnabled = true
    static let bpfSpanMaxAge: TimeInterval = 180
}
