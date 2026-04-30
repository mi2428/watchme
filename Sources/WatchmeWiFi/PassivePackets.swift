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
    let payloadLength: Int
    let payloadPrefix: [UInt8]

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

struct ICMPPacketObservation {
    let interfaceName: String
    let wallNanos: UInt64
    let family: InternetAddressFamily
    let type: UInt8
    let code: UInt8
    let sourceIP: String
    let destinationIP: String
    let identifier: UInt16
    let sequence: UInt16

    var isEchoRequest: Bool {
        (family == .ipv4 && type == 8) || (family == .ipv6 && type == 128)
    }

    var isEchoReply: Bool {
        (family == .ipv4 && type == 0) || (family == .ipv6 && type == 129)
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

struct ActiveICMPPacketExchange {
    let request: ICMPPacketObservation
    let reply: ICMPPacketObservation

    var timing: ActiveProbeTiming {
        .bpfPacket(start: request.wallNanos, finished: reply.wallNanos)
    }
}

struct ActiveHTTPPacketExchange {
    let request: TCPPacketObservation
    let response: TCPPacketObservation
    let statusCode: Int?

    var timing: ActiveProbeTiming {
        .bpfPacket(start: request.wallNanos, finished: response.wallNanos)
    }
}

struct ActiveDNSProbeRegistration {
    let transactionID: UInt16
    let target: String
    let queryType: UInt16
    let resolver: String
    let interfaceName: String?
    let startWallNanos: UInt64
    let expiresWallNanos: UInt64
}

struct ActiveTCPProbeRegistration {
    let remoteIP: String
    let port: UInt16
    let interfaceName: String?
    let startWallNanos: UInt64
    let expiresWallNanos: UInt64
}

struct ActiveICMPProbeRegistration {
    let family: InternetAddressFamily
    let remoteIP: String
    let identifier: UInt16?
    let sequence: UInt16?
    let interfaceName: String?
    let startWallNanos: UInt64
    let expiresWallNanos: UInt64
}

struct ActiveHTTPProbeRegistration {
    let target: String
    let remoteIP: String
    let port: UInt16
    let interfaceName: String?
    let startWallNanos: UInt64
    let expiresWallNanos: UInt64
}

struct ActiveDNSProbeRequest {
    let transactionID: UInt16
    let target: String
    let queryType: UInt16
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

struct ActiveICMPProbeRequest {
    let family: InternetAddressFamily
    let remoteIP: String
    let identifier: UInt16?
    let sequence: UInt16?
    let interfaceName: String?
    let startWallNanos: UInt64
    let timeout: TimeInterval
}

struct ActiveHTTPProbeRequest {
    let target: String
    let remoteIP: String
    let port: UInt16
    let interfaceName: String?
    let startWallNanos: UInt64
    let timeout: TimeInterval
}

final class PassivePacketStore {
    let lock = NSLock()
    var dhcp: [DHCPObservation] = []
    var icmpv6: [ICMPv6Observation] = []
    var dns: [DNSPacketObservation] = []
    var tcp: [TCPPacketObservation] = []
    var icmp: [ICMPPacketObservation] = []
    var activeDNSProbes: [ActiveDNSProbeRegistration] = []
    var activeTCPProbes: [ActiveTCPProbeRegistration] = []
    var activeICMPProbes: [ActiveICMPProbeRegistration] = []
    var activeHTTPProbes: [ActiveHTTPProbeRegistration] = []
    var emittedKeys = Set<String>()

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
                queryType: request.queryType,
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
            $0.transactionID == request.transactionID
                && $0.target == normalizedTarget
                && $0.queryType == request.queryType
                && $0.resolver == request.resolver
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

    func registerActiveICMPProbe(_ request: ActiveICMPProbeRequest) {
        lock.lock()
        activeICMPProbes.append(
            ActiveICMPProbeRegistration(
                family: request.family,
                remoteIP: request.remoteIP,
                identifier: request.identifier,
                sequence: request.sequence,
                interfaceName: request.interfaceName,
                startWallNanos: request.startWallNanos,
                expiresWallNanos: request.startWallNanos + activeProbeRetentionNanos(timeout: request.timeout)
            )
        )
        pruneLocked()
        lock.unlock()
    }

    func unregisterActiveICMPProbe(_ request: ActiveICMPProbeRequest) {
        lock.lock()
        activeICMPProbes.removeAll {
            $0.family == request.family
                && $0.remoteIP == request.remoteIP
                && $0.identifier == request.identifier
                && $0.sequence == request.sequence
        }
        lock.unlock()
    }

    @discardableResult
    func appendICMP(_ observation: ICMPPacketObservation) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard isActiveICMPObservationLocked(observation) else {
            return false
        }
        icmp.append(observation)
        pruneLocked()
        return true
    }

    func icmpExchange(
        for request: ActiveICMPProbeRequest,
        wait: TimeInterval
    ) -> ActiveICMPPacketExchange? {
        let deadline = Date().addingTimeInterval(wait)
        while true {
            lock.lock()
            let match = icmpExchangeLocked(request: request, finishedWallNanos: wallClockNanos())
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

    func registerActiveHTTPProbe(_ request: ActiveHTTPProbeRequest) {
        lock.lock()
        activeHTTPProbes.append(
            ActiveHTTPProbeRegistration(
                target: normalizedDNSName(request.target),
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

    func unregisterActiveHTTPProbe(_ request: ActiveHTTPProbeRequest) {
        lock.lock()
        activeHTTPProbes.removeAll {
            $0.target == normalizedDNSName(request.target) && $0.remoteIP == request.remoteIP && $0.port == request.port
        }
        lock.unlock()
    }

    @discardableResult
    func appendTCP(_ observation: TCPPacketObservation) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard isActiveTCPObservationLocked(observation) || isActiveHTTPObservationLocked(observation) else {
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

    func httpExchange(
        for request: ActiveHTTPProbeRequest,
        finishedWallNanos: UInt64,
        wait: TimeInterval = 0.05
    ) -> ActiveHTTPPacketExchange? {
        let deadline = Date().addingTimeInterval(wait)
        while true {
            lock.lock()
            let match = httpExchangeLocked(request: request, finishedWallNanos: finishedWallNanos)
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
}

func normalizedDNSName(_ value: String) -> String {
    value.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
}

private func activeProbeRetentionNanos(timeout: TimeInterval) -> UInt64 {
    UInt64((timeout + 1.0) * 1_000_000_000)
}
