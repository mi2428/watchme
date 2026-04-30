import Foundation
import WatchmeCore
import WatchmeTelemetry

struct DHCPObservation {
    let interfaceName: String
    let wallNanos: UInt64
    let xid: UInt32
    let messageType: UInt8?
    let yiaddr: String?
    let serverIdentifier: String?
    let leaseTimeSeconds: UInt32?
}

struct ICMPv6Observation {
    let interfaceName: String
    let wallNanos: UInt64
    let type: UInt8
    let code: UInt8
    let sourceIP: String
    let destinationIP: String
    let targetAddress: String?
    let routerLifetimeSeconds: UInt16?
    let sourceLinkLayerAddress: String?
    let targetLinkLayerAddress: String?
}

struct DNSPacketObservation {
    let interfaceName: String
    let wallNanos: UInt64
    let sourceIP: String
    let destinationIP: String
    let sourcePort: UInt16
    let destinationPort: UInt16
    let transactionID: UInt16
    let isResponse: Bool
    let rcode: Int?
    let answerCount: Int?
    let queryName: String?
    let queryType: UInt16?
}

struct TCPPacketObservation {
    let interfaceName: String
    let wallNanos: UInt64
    let sourceIP: String
    let destinationIP: String
    let sourcePort: UInt16
    let destinationPort: UInt16
    let flags: UInt8

    var isSYN: Bool {
        flags & 0x02 != 0
    }

    var isACK: Bool {
        flags & 0x10 != 0
    }

    var isRST: Bool {
        flags & 0x04 != 0
    }
}

struct ActiveDNSPacketExchange {
    let query: DNSPacketObservation
    let response: DNSPacketObservation

    var timing: ActiveProbeTiming {
        .bpfPacket(start: query.wallNanos, finished: response.wallNanos)
    }
}

struct ActiveTCPPacketExchange {
    let syn: TCPPacketObservation
    let response: TCPPacketObservation

    var responseKind: String {
        if response.isRST {
            return "rst"
        }
        if response.isSYN, response.isACK {
            return "syn_ack"
        }
        return "other"
    }

    var timing: ActiveProbeTiming {
        .bpfPacket(start: syn.wallNanos, finished: response.wallNanos)
    }
}

private struct ActiveDNSProbeRegistration {
    let transactionID: UInt16
    let target: String
    let resolver: String
    let interfaceName: String?
    let startWallNanos: UInt64
    let expiresWallNanos: UInt64
}

private struct ActiveTCPProbeRegistration {
    let remoteIP: String
    let port: UInt16
    let interfaceName: String?
    let startWallNanos: UInt64
    let expiresWallNanos: UInt64
}

struct ActiveDNSProbeRequest {
    let transactionID: UInt16
    let target: String
    let resolver: String
    let interfaceName: String?
    let startWallNanos: UInt64
    let timeout: TimeInterval
}

struct ActiveTCPProbeRequest {
    let remoteIP: String
    let port: UInt16
    let interfaceName: String?
    let startWallNanos: UInt64
    let timeout: TimeInterval
}

final class PassivePacketStore {
    private let lock = NSLock()
    private var dhcp: [DHCPObservation] = []
    private var icmpv6: [ICMPv6Observation] = []
    private var dns: [DNSPacketObservation] = []
    private var tcp: [TCPPacketObservation] = []
    private var activeDNSProbes: [ActiveDNSProbeRegistration] = []
    private var activeTCPProbes: [ActiveTCPProbeRegistration] = []
    private var emittedKeys = Set<String>()

    func appendDHCP(_ observation: DHCPObservation) {
        lock.lock()
        dhcp.append(observation)
        pruneLocked()
        lock.unlock()
    }

    func appendICMPv6(_ observation: ICMPv6Observation) {
        lock.lock()
        icmpv6.append(observation)
        pruneLocked()
        lock.unlock()
    }

    func registerActiveDNSProbe(_ request: ActiveDNSProbeRequest) {
        lock.lock()
        activeDNSProbes.append(
            ActiveDNSProbeRegistration(
                transactionID: request.transactionID,
                target: normalizedDNSName(request.target),
                resolver: request.resolver,
                interfaceName: request.interfaceName,
                startWallNanos: request.startWallNanos,
                expiresWallNanos: request.startWallNanos + activeProbeRetentionNanos(timeout: request.timeout)
            )
        )
        pruneLocked()
        lock.unlock()
    }

    func unregisterActiveDNSProbe(_ request: ActiveDNSProbeRequest) {
        let normalizedTarget = normalizedDNSName(request.target)
        lock.lock()
        activeDNSProbes.removeAll {
            $0.transactionID == request.transactionID && $0.target == normalizedTarget && $0.resolver == request.resolver
        }
        lock.unlock()
    }

    @discardableResult
    func appendDNS(_ observation: DNSPacketObservation) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard isActiveDNSObservationLocked(observation) else {
            return false
        }
        dns.append(observation)
        pruneLocked()
        return true
    }

    func dnsExchange(
        for request: ActiveDNSProbeRequest,
        finishedWallNanos: UInt64,
        wait: TimeInterval = 0.05
    ) -> ActiveDNSPacketExchange? {
        let deadline = Date().addingTimeInterval(wait)
        while true {
            lock.lock()
            let match = dnsExchangeLocked(
                request: request,
                finishedWallNanos: finishedWallNanos
            )
            lock.unlock()
            if let match {
                return match
            }
            guard Date() < deadline else {
                return nil
            }
            Thread.sleep(forTimeInterval: 0.005)
        }
    }

    func registerActiveTCPProbe(_ request: ActiveTCPProbeRequest) {
        lock.lock()
        activeTCPProbes.append(
            ActiveTCPProbeRegistration(
                remoteIP: request.remoteIP,
                port: request.port,
                interfaceName: request.interfaceName,
                startWallNanos: request.startWallNanos,
                expiresWallNanos: request.startWallNanos + activeProbeRetentionNanos(timeout: request.timeout)
            )
        )
        pruneLocked()
        lock.unlock()
    }

    func unregisterActiveTCPProbe(_ request: ActiveTCPProbeRequest) {
        lock.lock()
        activeTCPProbes.removeAll {
            $0.remoteIP == request.remoteIP && $0.port == request.port
        }
        lock.unlock()
    }

    @discardableResult
    func appendTCP(_ observation: TCPPacketObservation) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard isActiveTCPObservationLocked(observation) else {
            return false
        }
        tcp.append(observation)
        pruneLocked()
        return true
    }

    func tcpConnectExchange(
        for request: ActiveTCPProbeRequest,
        finishedWallNanos: UInt64,
        wait: TimeInterval = 0.05
    ) -> ActiveTCPPacketExchange? {
        let deadline = Date().addingTimeInterval(wait)
        while true {
            lock.lock()
            let match = tcpConnectExchangeLocked(
                request: request,
                finishedWallNanos: finishedWallNanos
            )
            lock.unlock()
            if let match {
                return match
            }
            guard Date() < deadline else {
                return nil
            }
            Thread.sleep(forTimeInterval: 0.005)
        }
    }

    func recentPacketSpans(interfaceName: String?, maxAge: TimeInterval, consume: Bool) -> [SpanEvent] {
        let cutoff = wallClockNanos() - UInt64(maxAge * 1_000_000_000)
        lock.lock()
        let dhcpSnapshot = dhcp.filter { $0.wallNanos >= cutoff && (interfaceName == nil || $0.interfaceName == interfaceName) }
        let icmpv6Snapshot = icmpv6.filter { $0.wallNanos >= cutoff && (interfaceName == nil || $0.interfaceName == interfaceName) }
        var spans = buildDHCPSpans(dhcpSnapshot) + buildICMPv6Spans(icmpv6Snapshot)
        spans.sort { $0.startWallNanos < $1.startWallNanos }
        if consume {
            // Event-triggered traces should not repeatedly attach the same
            // packet-derived spans. Active interval traces can still inspect the
            // full recent window by calling with consume=false.
            spans = spans.filter { span in
                let key = spanKey(span)
                if emittedKeys.contains(key) {
                    return false
                }
                emittedKeys.insert(key)
                return true
            }
        }
        lock.unlock()
        return spans
    }

    private func isActiveDNSObservationLocked(_ observation: DNSPacketObservation) -> Bool {
        activeDNSProbes.contains { registration in
            guard observation.transactionID == registration.transactionID,
                  observation.wallNanos >= registration.startWallNanos,
                  observation.wallNanos <= registration.expiresWallNanos,
                  registration.interfaceName == nil || observation.interfaceName == registration.interfaceName
            else {
                return false
            }
            let resolverMatches = observation.sourceIP == registration.resolver || observation.destinationIP == registration.resolver
            guard resolverMatches else {
                return false
            }
            if let queryName = observation.queryName, !queryName.isEmpty {
                return normalizedDNSName(queryName) == registration.target
            }
            // Some DNS responses can omit a parseable question section. The
            // active transaction ID plus resolver match is still sufficiently
            // narrow because registrations are short-lived and probe-scoped.
            return observation.isResponse
        }
    }

    private func dnsExchangeLocked(
        request: ActiveDNSProbeRequest,
        finishedWallNanos: UInt64
    ) -> ActiveDNSPacketExchange? {
        let target = normalizedDNSName(request.target)
        let (windowStart, windowEnd) = activeProbeSearchWindow(start: request.startWallNanos, finished: finishedWallNanos)
        let candidates = dns
            .filter {
                $0.transactionID == request.transactionID
                    && $0.wallNanos >= windowStart
                    && $0.wallNanos <= windowEnd
                    && (request.interfaceName == nil || $0.interfaceName == request.interfaceName)
                    && ($0.sourceIP == request.resolver || $0.destinationIP == request.resolver)
            }
            .sorted { $0.wallNanos < $1.wallNanos }
        guard let query = candidates.first(where: {
            !$0.isResponse
                && $0.destinationIP == request.resolver
                && $0.destinationPort == 53
                && normalizedDNSName($0.queryName ?? "") == target
        }) else {
            return nil
        }
        guard let response = candidates.first(where: {
            $0.isResponse
                && $0.wallNanos >= query.wallNanos
                && $0.sourceIP == request.resolver
                && $0.sourcePort == 53
                && $0.destinationPort == query.sourcePort
                && ($0.queryName == nil || normalizedDNSName($0.queryName ?? "") == target)
        }) else {
            return nil
        }
        return ActiveDNSPacketExchange(query: query, response: response)
    }

    private func isActiveTCPObservationLocked(_ observation: TCPPacketObservation) -> Bool {
        activeTCPProbes.contains { registration in
            guard observation.wallNanos >= registration.startWallNanos,
                  observation.wallNanos <= registration.expiresWallNanos,
                  registration.interfaceName == nil || observation.interfaceName == registration.interfaceName
            else {
                return false
            }
            let outboundSYN = observation.destinationIP == registration.remoteIP
                && observation.destinationPort == registration.port
                && observation.isSYN
                && !observation.isACK
            let inboundHandshakeResponse = observation.sourceIP == registration.remoteIP
                && observation.sourcePort == registration.port
                && (observation.isRST || (observation.isSYN && observation.isACK))
            return outboundSYN || inboundHandshakeResponse
        }
    }

    private func tcpConnectExchangeLocked(
        request: ActiveTCPProbeRequest,
        finishedWallNanos: UInt64
    ) -> ActiveTCPPacketExchange? {
        let (windowStart, windowEnd) = activeProbeSearchWindow(start: request.startWallNanos, finished: finishedWallNanos)
        let candidates = tcp
            .filter {
                $0.wallNanos >= windowStart
                    && $0.wallNanos <= windowEnd
                    && (request.interfaceName == nil || $0.interfaceName == request.interfaceName)
                    && ($0.sourceIP == request.remoteIP || $0.destinationIP == request.remoteIP)
                    && ($0.sourcePort == request.port || $0.destinationPort == request.port)
            }
            .sorted { $0.wallNanos < $1.wallNanos }
        guard let syn = candidates.first(where: {
            $0.destinationIP == request.remoteIP && $0.destinationPort == request.port && $0.isSYN && !$0.isACK
        }) else {
            return nil
        }
        guard let response = candidates.first(where: {
            $0.wallNanos >= syn.wallNanos
                && $0.sourceIP == request.remoteIP
                && $0.sourcePort == request.port
                && $0.destinationIP == syn.sourceIP
                && $0.destinationPort == syn.sourcePort
                && ($0.isRST || ($0.isSYN && $0.isACK))
        }) else {
            return nil
        }
        return ActiveTCPPacketExchange(syn: syn, response: response)
    }

    private func pruneLocked() {
        let now = wallClockNanos()
        let cutoff = now - UInt64(600 * 1_000_000_000)
        dhcp.removeAll { $0.wallNanos < cutoff }
        icmpv6.removeAll { $0.wallNanos < cutoff }
        dns.removeAll { $0.wallNanos < cutoff }
        tcp.removeAll { $0.wallNanos < cutoff }
        activeDNSProbes.removeAll { $0.expiresWallNanos < now }
        activeTCPProbes.removeAll { $0.expiresWallNanos < now }
        if emittedKeys.count > 5000 {
            emittedKeys.removeAll()
        }
    }
}

func normalizedDNSName(_ value: String) -> String {
    value.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
}

private func activeProbeRetentionNanos(timeout: TimeInterval) -> UInt64 {
    UInt64((timeout + 1.0) * 1_000_000_000)
}

private func activeProbeSearchWindow(start: UInt64, finished: UInt64) -> (start: UInt64, end: UInt64) {
    let slack: UInt64 = 200_000_000
    let windowStart = start > slack ? start - slack : 0
    return (windowStart, finished + slack)
}
