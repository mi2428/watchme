import Darwin
import Foundation
import WatchmeCore

struct ActiveInternetProbeResults {
    let dns: [ActiveDNSProbeResult]
    let icmp: [ActiveICMPProbeResult]
    let http: [ActiveInternetHTTPProbeResult]
}

func runActiveInternetProbes(
    config: WiFiConfig,
    networkState: WiFiServiceNetworkState,
    interfaceName: String?,
    packetStore: PassivePacketStore
) -> ActiveInternetProbeResults {
    let targets = (try? uniqueInternetProbeTargets(config.probeInternetTargets)) ?? []
    let families = config.probeInternetFamily.concreteFamilies
    let context = InternetProbeExecutionContext(
        timeout: config.probeInternetTimeout,
        interfaceName: interfaceName,
        packetStore: packetStore
    )
    let dnsResults = config.probeInternetDNS
        ? runInternetDNSProbes(
            targets: targets,
            families: families,
            resolvers: Array(networkState.dnsServers.prefix(2)),
            context: context
        )
        : []
    // ICMP and plain HTTP intentionally consume DNS probe output instead of
    // calling a system resolver again. That keeps the trace internally
    // explainable: the remote IP used by later spans came from a Wi-Fi-bound
    // DNS span in the same active validation phase.
    let addressPlan = internetProbeAddressPlan(targets: targets, families: families, dnsResults: dnsResults)
    let postDNSResults = runPostDNSInternetProbes(
        PostDNSInternetProbeInput(
            addressPlan: addressPlan,
            context: context,
            icmpEnabled: config.probeInternetICMP,
            httpEnabled: config.probeInternetHTTP
        )
    )
    return ActiveInternetProbeResults(dns: dnsResults, icmp: postDNSResults.icmp, http: postDNSResults.http)
}

private struct InternetAddressPlan {
    let target: InternetProbeTarget
    let family: InternetAddressFamily
    let remoteIP: String?
}

private struct InternetProbeExecutionContext {
    let timeout: TimeInterval
    let interfaceName: String?
    let packetStore: PassivePacketStore
}

private struct PostDNSInternetProbeInput {
    let addressPlan: [InternetAddressPlan]
    let context: InternetProbeExecutionContext
    let icmpEnabled: Bool
    let httpEnabled: Bool
}

private struct PostDNSInternetProbeResults {
    let icmp: [ActiveICMPProbeResult]
    let http: [ActiveInternetHTTPProbeResult]
}

private func runPostDNSInternetProbes(_ input: PostDNSInternetProbeInput) -> PostDNSInternetProbeResults {
    // After DNS has produced concrete addresses, ICMP and HTTP no longer
    // depend on each other. Run both families of work concurrently so dual
    // stack and multi-target validations describe the same point in time.
    let lock = NSLock()
    let group = DispatchGroup()
    var icmpResults: [ActiveICMPProbeResult] = []
    var httpResults: [ActiveInternetHTTPProbeResult] = []

    if input.icmpEnabled {
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let results = runInternetICMPProbes(
                addressPlan: input.addressPlan,
                context: input.context
            )
            lock.lock()
            icmpResults = results
            lock.unlock()
            group.leave()
        }
    }

    if input.httpEnabled {
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let results = runInternetHTTPProbes(
                addressPlan: input.addressPlan,
                context: input.context
            )
            lock.lock()
            httpResults = results
            lock.unlock()
            group.leave()
        }
    }

    group.wait()
    return PostDNSInternetProbeResults(icmp: icmpResults, http: httpResults)
}

private func runInternetDNSProbes(
    targets: [InternetProbeTarget],
    families: [InternetAddressFamily],
    resolvers: [String],
    context: InternetProbeExecutionContext
) -> [ActiveDNSProbeResult] {
    guard !resolvers.isEmpty else {
        return targets.flatMap { target in
            families.map { family in
                noResolverDNSProbeResult(target: target.host, family: family)
            }
        }
    }
    let results = LockedValues<ActiveDNSProbeResult>()
    let group = DispatchGroup()
    for resolver in resolvers {
        for target in targets {
            for family in families {
                group.enter()
                DispatchQueue.global(qos: .utility).async {
                    let result = runInternetDNSProbe(
                        target: target.host,
                        family: family,
                        resolver: resolver,
                        timeout: context.timeout,
                        interfaceName: context.interfaceName,
                        packetStore: context.packetStore
                    )
                    results.append(result)
                    group.leave()
                }
            }
        }
    }
    group.wait()
    return results.values.sorted {
        [$0.target, $0.family.metricValue, $0.resolver].joined(separator: "|")
            < [$1.target, $1.family.metricValue, $1.resolver].joined(separator: "|")
    }
}

private func runInternetICMPProbes(
    addressPlan: [InternetAddressPlan],
    context: InternetProbeExecutionContext
) -> [ActiveICMPProbeResult] {
    let results = LockedValues<ActiveICMPProbeResult>()
    let group = DispatchGroup()
    for plan in addressPlan {
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let result = runInternetICMPProbe(
                target: plan.target.host,
                family: plan.family,
                remoteIP: plan.remoteIP,
                timeout: context.timeout,
                interfaceName: context.interfaceName,
                packetStore: context.packetStore
            )
            results.append(result)
            group.leave()
        }
    }
    group.wait()
    return results.values.sorted {
        [$0.target, $0.family.metricValue, $0.remoteIP].joined(separator: "|")
            < [$1.target, $1.family.metricValue, $1.remoteIP].joined(separator: "|")
    }
}

private func runInternetHTTPProbes(
    addressPlan: [InternetAddressPlan],
    context: InternetProbeExecutionContext
) -> [ActiveInternetHTTPProbeResult] {
    let results = LockedValues<ActiveInternetHTTPProbeResult>()
    let group = DispatchGroup()
    for plan in addressPlan {
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let result = runInternetHTTPProbe(
                target: plan.target.host,
                family: plan.family,
                remoteIP: plan.remoteIP,
                timeout: context.timeout,
                interfaceName: context.interfaceName,
                packetStore: context.packetStore
            )
            results.append(result)
            group.leave()
        }
    }
    group.wait()
    return results.values.sorted {
        [$0.target, $0.family.metricValue, $0.remoteIP].joined(separator: "|")
            < [$1.target, $1.family.metricValue, $1.remoteIP].joined(separator: "|")
    }
}

private func internetProbeAddressPlan(
    targets: [InternetProbeTarget],
    families: [InternetAddressFamily],
    dnsResults: [ActiveDNSProbeResult]
) -> [InternetAddressPlan] {
    targets.flatMap { target in
        families.map { family in
            InternetAddressPlan(
                target: target,
                family: family,
                remoteIP: literalIPAddress(target.host, family: family)
                    ?? dnsResults.first {
                        $0.target == target.host && $0.family == family && !$0.addresses.isEmpty
                    }?
                    .addresses.first
            )
        }
    }
}

private func noResolverDNSProbeResult(target: String, family: InternetAddressFamily) -> ActiveDNSProbeResult {
    let now = wallClockNanos()
    return ActiveDNSProbeResult(
        target: target,
        family: family,
        recordType: family.dnsRecordType,
        resolver: "none",
        transport: "udp",
        ok: false,
        rcode: nil,
        answerCount: nil,
        addresses: [],
        error: "no Wi-Fi DNS resolver was available",
        timing: ActiveProbeTiming(
            startWallNanos: now,
            finishedWallNanos: now + 1000,
            timingSource: noAddressTimingSource,
            timestampSource: wallClockTimestampSource
        )
    )
}

private func literalIPAddress(_ value: String, family: InternetAddressFamily) -> String? {
    switch family {
    case .ipv4:
        var address = in_addr()
        return inet_pton(AF_INET, value, &address) == 1 ? value : nil
    case .ipv6:
        var address = in6_addr()
        return inet_pton(AF_INET6, value, &address) == 1 ? value : nil
    }
}

private final class LockedValues<Value> {
    private let lock = NSLock()
    private var storage: [Value] = []

    var values: [Value] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func append(_ value: Value) {
        lock.lock()
        storage.append(value)
        lock.unlock()
    }
}
