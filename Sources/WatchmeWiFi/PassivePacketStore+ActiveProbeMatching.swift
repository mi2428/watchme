import Foundation
import WatchmeCore

extension PassivePacketStore {
    func isActiveDNSObservationLocked(_ observation: DNSPacketObservation) -> Bool {
        activeDNSProbes.contains { registration in
            guard observation.transactionID == registration.transactionID,
                  observation.queryType == registration.queryType,
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

    func dnsExchangeLocked(
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
                    && $0.queryType == request.queryType
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

    func isActiveICMPObservationLocked(_ observation: ICMPPacketObservation) -> Bool {
        activeICMPProbes.contains { registration in
            guard observation.family == registration.family,
                  observation.wallNanos >= registration.startWallNanos,
                  observation.wallNanos <= registration.expiresWallNanos,
                  registration.interfaceName == nil || observation.interfaceName == registration.interfaceName
            else {
                return false
            }
            let remoteMatches = observation.sourceIP == registration.remoteIP || observation.destinationIP == registration.remoteIP
            guard remoteMatches else {
                return false
            }
            // Keep the append filter broad enough to tolerate kernels that
            // rewrite ICMP identifiers for datagram sockets. The exchange
            // lookup below still prefers the generated identifier/sequence
            // when BPF observes them unchanged.
            return true
        }
    }

    func icmpExchangeLocked(
        request: ActiveICMPProbeRequest,
        finishedWallNanos: UInt64
    ) -> ActiveICMPPacketExchange? {
        let (windowStart, windowEnd) = activeProbeSearchWindow(start: request.startWallNanos, finished: finishedWallNanos)
        let candidates = icmp
            .filter {
                $0.family == request.family
                    && $0.wallNanos >= windowStart
                    && $0.wallNanos <= windowEnd
                    && (request.interfaceName == nil || $0.interfaceName == request.interfaceName)
                    && ($0.sourceIP == request.remoteIP || $0.destinationIP == request.remoteIP)
            }
            .sorted { $0.wallNanos < $1.wallNanos }
        let exactRequest = candidates.first {
            $0.isEchoRequest
                && $0.destinationIP == request.remoteIP
                && request.identifier == $0.identifier
                && request.sequence == $0.sequence
        }
        guard let echoRequest = exactRequest ?? candidates.first(where: {
            $0.isEchoRequest && $0.destinationIP == request.remoteIP
        }) else {
            return nil
        }
        guard let echoReply = candidates.first(where: {
            $0.isEchoReply
                && $0.wallNanos >= echoRequest.wallNanos
                && $0.sourceIP == request.remoteIP
                && $0.identifier == echoRequest.identifier
                && $0.sequence == echoRequest.sequence
        }) else {
            return nil
        }
        return ActiveICMPPacketExchange(request: echoRequest, reply: echoReply)
    }

    func isActiveTCPObservationLocked(_ observation: TCPPacketObservation) -> Bool {
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

    func isActiveHTTPObservationLocked(_ observation: TCPPacketObservation) -> Bool {
        activeHTTPProbes.contains { registration in
            guard observation.wallNanos >= registration.startWallNanos,
                  observation.wallNanos <= registration.expiresWallNanos,
                  registration.interfaceName == nil || observation.interfaceName == registration.interfaceName
            else {
                return false
            }
            let outboundPayload = observation.destinationIP == registration.remoteIP
                && observation.destinationPort == registration.port
                && observation.payloadLength > 0
            let inboundPayload = observation.sourceIP == registration.remoteIP
                && observation.sourcePort == registration.port
                && observation.payloadLength > 0
            return outboundPayload || inboundPayload
        }
    }

    func tcpConnectExchangeLocked(
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
            $0.wallNanos >= request.startWallNanos
                && $0.destinationIP == request.remoteIP
                && $0.destinationPort == request.port
                && $0.isSYN
                && !$0.isACK
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

    func httpExchangeLocked(
        request: ActiveHTTPProbeRequest,
        finishedWallNanos: UInt64
    ) -> ActiveHTTPPacketExchange? {
        let (windowStart, windowEnd) = activeProbeSearchWindow(start: request.startWallNanos, finished: finishedWallNanos)
        let candidates = tcp
            .filter {
                $0.wallNanos >= windowStart
                    && $0.wallNanos <= windowEnd
                    && (request.interfaceName == nil || $0.interfaceName == request.interfaceName)
                    && ($0.sourceIP == request.remoteIP || $0.destinationIP == request.remoteIP)
                    && ($0.sourcePort == request.port || $0.destinationPort == request.port)
                    && $0.payloadLength > 0
            }
            .sorted { $0.wallNanos < $1.wallNanos }
        guard let httpRequest = candidates.first(where: {
            $0.destinationIP == request.remoteIP
                && $0.destinationPort == request.port
                && tcpPayloadHasPrefix($0, "HEAD ")
        }) else {
            return nil
        }
        guard let response = candidates.first(where: {
            $0.wallNanos >= httpRequest.wallNanos
                && $0.sourceIP == request.remoteIP
                && $0.sourcePort == request.port
                && $0.destinationIP == httpRequest.sourceIP
                && $0.destinationPort == httpRequest.sourcePort
                && $0.payloadLength > 0
        }) else {
            return nil
        }
        return ActiveHTTPPacketExchange(
            request: httpRequest,
            response: response,
            statusCode: parseHTTPStatusCode(Data(response.payloadPrefix))
        )
    }

    func pruneLocked() {
        let now = wallClockNanos()
        let cutoff = now - UInt64(600 * 1_000_000_000)
        dhcp.removeAll { $0.wallNanos < cutoff }
        icmpv6.removeAll { $0.wallNanos < cutoff }
        arp.removeAll { $0.wallNanos < cutoff }
        dns.removeAll { $0.wallNanos < cutoff }
        tcp.removeAll { $0.wallNanos < cutoff }
        icmp.removeAll { $0.wallNanos < cutoff }
        activeDNSProbes.removeAll { $0.expiresWallNanos < now }
        activeTCPProbes.removeAll { $0.expiresWallNanos < now }
        activeICMPProbes.removeAll { $0.expiresWallNanos < now }
        activeHTTPProbes.removeAll { $0.expiresWallNanos < now }
        if emittedKeys.count > 5000 {
            emittedKeys.removeAll()
        }
    }
}

private func tcpPayloadHasPrefix(_ observation: TCPPacketObservation, _ prefix: String) -> Bool {
    let bytes = Array(prefix.utf8)
    guard observation.payloadPrefix.count >= bytes.count else {
        return false
    }
    return Array(observation.payloadPrefix.prefix(bytes.count)) == bytes
}

private func activeProbeSearchWindow(start: UInt64, finished: UInt64) -> (start: UInt64, end: UInt64) {
    let slack: UInt64 = 200_000_000
    let windowStart = start > slack ? start - slack : 0
    return (windowStart, finished + slack)
}
