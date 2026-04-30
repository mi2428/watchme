import Darwin
import Foundation
import WatchmeCore

struct ActiveInternetProbeResults {
    let lanes: [ActiveInternetProbeLaneResult]

    var dns: [ActiveDNSProbeResult] {
        lanes.flatMap(\.dns)
    }

    var icmp: [ActiveICMPProbeResult] {
        lanes.compactMap(\.icmp)
    }

    var tcp: [ActiveTCPProbeResult] {
        lanes.compactMap(\.tcp)
    }

    var http: [ActiveInternetHTTPProbeResult] {
        lanes.compactMap(\.http)
    }
}

struct ActiveInternetProbeLaneResult {
    let target: String
    let family: InternetAddressFamily
    let dns: [ActiveDNSProbeResult]
    let icmp: ActiveICMPProbeResult?
    let tcp: ActiveTCPProbeResult?
    let http: ActiveInternetHTTPProbeResult?
    let startWallNanos: UInt64
    let finishedWallNanos: UInt64

    var durationNanos: UInt64 {
        max(finishedWallNanos >= startWallNanos ? finishedWallNanos - startWallNanos : 0, 1000)
    }

    var remoteIP: String {
        icmp?.remoteIP ?? tcp?.remoteIP ?? http?.remoteIP ?? dns.first { !$0.addresses.isEmpty }?.addresses.first ?? "none"
    }

    var ok: Bool {
        let dnsOK = dns.isEmpty || dns.allSatisfy(\.ok)
        let icmpOK = icmp?.ok ?? true
        let tcpOK = tcp?.ok ?? true
        let httpOK = http?.ok ?? true
        return dnsOK && icmpOK && tcpOK && httpOK
    }
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
    let resolvers = Array(networkState.dnsServers.prefix(2))
    let laneInputs = targets.flatMap { target in
        families.map { family in
            InternetProbeLaneInput(
                target: target,
                family: family,
                resolvers: resolvers,
                context: context,
                dnsEnabled: config.probeInternetDNS,
                icmpEnabled: config.probeInternetICMP,
                tcpEnabled: config.probeInternetTCP,
                httpEnabled: config.probeInternetHTTP
            )
        }
    }
    let lanes = runParallelSorted(laneInputs, sortKey: internetProbeLaneSortKey) { input in
        runInternetProbeLane(input)
    }
    return ActiveInternetProbeResults(lanes: lanes)
}

private struct InternetProbeLaneInput {
    let target: InternetProbeTarget
    let family: InternetAddressFamily
    let resolvers: [String]
    let context: InternetProbeExecutionContext
    let dnsEnabled: Bool
    let icmpEnabled: Bool
    let tcpEnabled: Bool
    let httpEnabled: Bool
}

private struct InternetProbeExecutionContext {
    let timeout: TimeInterval
    let interfaceName: String?
    let packetStore: PassivePacketStore
}

private func runInternetProbeLane(_ input: InternetProbeLaneInput) -> ActiveInternetProbeLaneResult {
    let laneStarted = wallClockNanos()
    let dnsResults = input.dnsEnabled
        ? runInternetDNSProbes(
            target: input.target,
            family: input.family,
            resolvers: input.resolvers,
            context: input.context
        )
        : []
    let remoteIP = literalIPAddress(input.target.host, family: input.family)
        ?? dnsResults.first { $0.ok && !$0.addresses.isEmpty }?.addresses.first
        ?? dnsResults.first { !$0.addresses.isEmpty }?.addresses.first

    let icmpResult = input.icmpEnabled
        ? runInternetICMPProbe(
            target: input.target.host,
            family: input.family,
            remoteIP: remoteIP,
            timeout: input.context.timeout,
            interfaceName: input.context.interfaceName,
            packetStore: input.context.packetStore
        )
        : nil
    let tcpResult = input.tcpEnabled
        ? runInternetTCPProbe(
            target: input.target.host,
            family: input.family,
            remoteIP: remoteIP,
            timeout: input.context.timeout,
            interfaceName: input.context.interfaceName,
            packetStore: input.context.packetStore
        )
        : nil
    let httpResult = input.httpEnabled
        ? runInternetHTTPProbe(
            target: input.target.host,
            family: input.family,
            remoteIP: remoteIP,
            timeout: input.context.timeout,
            interfaceName: input.context.interfaceName,
            packetStore: input.context.packetStore
        )
        : nil

    let starts = dnsResults.map(\.startWallNanos)
        + [icmpResult?.startWallNanos, tcpResult?.startWallNanos, httpResult?.startWallNanos].compactMap { $0 }
    let finishes = dnsResults.map(\.finishedWallNanos)
        + [icmpResult?.finishedWallNanos, tcpResult?.finishedWallNanos, httpResult?.finishedWallNanos].compactMap { $0 }
    return ActiveInternetProbeLaneResult(
        target: input.target.host,
        family: input.family,
        dns: dnsResults,
        icmp: icmpResult,
        tcp: tcpResult,
        http: httpResult,
        startWallNanos: min(starts.min() ?? laneStarted, laneStarted),
        finishedWallNanos: max(finishes.max() ?? laneStarted + 1000, wallClockNanos())
    )
}

private func runInternetDNSProbes(
    target: InternetProbeTarget,
    family: InternetAddressFamily,
    resolvers: [String],
    context: InternetProbeExecutionContext
) -> [ActiveDNSProbeResult] {
    guard !resolvers.isEmpty else {
        return [noResolverDNSProbeResult(target: target.host, family: family)]
    }

    return resolvers.map { resolver in
        runInternetDNSProbe(
            target: target.host,
            family: family,
            resolver: resolver,
            timeout: context.timeout,
            interfaceName: context.interfaceName,
            packetStore: context.packetStore
        )
    }
}

private func runParallelSorted<Input, Output>(
    _ inputs: [Input],
    sortKey: @escaping (Output) -> String,
    operation: @escaping (Input) -> Output
) -> [Output] {
    let results = LockedValues<Output>()
    let group = DispatchGroup()
    for input in inputs {
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            defer {
                group.leave()
            }
            results.append(operation(input))
        }
    }
    group.wait()
    return results.values.sorted {
        sortKey($0) < sortKey($1)
    }
}

private func internetProbeLaneSortKey(_ result: ActiveInternetProbeLaneResult) -> String {
    [result.target, result.family.metricValue].joined(separator: "|")
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
        defer {
            lock.unlock()
        }
        return storage
    }

    func append(_ value: Value) {
        lock.lock()
        storage.append(value)
        lock.unlock()
    }
}
