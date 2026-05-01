import Foundation
import Network
import WatchmeBPF
import WatchmeCore

struct ActiveDNSProbeResult {
    let target: String
    let family: InternetAddressFamily
    let recordType: DNSRecordType
    let resolver: String
    let transport: String
    let ok: Bool
    let rcode: Int?
    let answerCount: Int?
    let addresses: [String]
    let error: String?
    let timing: ActiveProbeTiming

    var startWallNanos: UInt64 {
        timing.startWallNanos
    }

    var finishedWallNanos: UInt64 {
        timing.finishedWallNanos
    }

    var durationNanos: UInt64 {
        timing.durationNanos
    }

    var timingSource: String {
        timing.timingSource
    }

    var timestampSource: String {
        timing.timestampSource
    }
}

private struct DNSExchangeResult {
    let rcode: Int?
    let answerCount: Int?
    let addresses: [String]
    let error: String?
    let completedWallNanos: UInt64
}

private struct DNSProbeIdentity {
    let target: String
    let family: InternetAddressFamily
    let recordType: DNSRecordType
    let resolver: String
}

struct DNSResponseMetadata {
    let rcode: Int
    let answerCount: Int
    let addresses: [String]
}

func runInternetDNSProbe(
    target: String,
    family: InternetAddressFamily,
    resolver: String,
    timeout: TimeInterval,
    interfaceName: String?,
    packetStore: PassivePacketStore? = nil
) -> ActiveDNSProbeResult {
    let host = normalizedProbeHost(target)
    let recordType = family.dnsRecordType
    let identity = DNSProbeIdentity(target: host, family: family, recordType: recordType, resolver: resolver)
    let startWallNanos = wallClockNanos()
    guard let query = dnsQueryPacket(host: host, recordType: recordType) else {
        return failedDNSProbe(
            identity: identity,
            startWallNanos: startWallNanos,
            error: "target host cannot be encoded as a DNS query"
        )
    }
    guard let interface = requiredProbeInterface(named: interfaceName, timeout: timeout) else {
        return failedDNSProbe(
            identity: identity,
            startWallNanos: startWallNanos,
            error: "Wi-Fi interface \(interfaceName ?? "unknown") was not available to Network.framework"
        )
    }

    let activePacketRequest = ActiveDNSProbeRequest(
        transactionID: query.id,
        target: host,
        queryType: recordType.rawValue,
        resolver: resolver,
        interfaceName: interfaceName,
        startWallNanos: startWallNanos,
        timeout: timeout
    )
    packetStore?.registerActiveDNSProbe(activePacketRequest)
    defer {
        packetStore?.unregisterActiveDNSProbe(activePacketRequest)
    }

    let exchange = performDNSUDPExchange(query: query, resolver: resolver, selectedInterface: interface, timeout: timeout)
    let packetExchange = packetStore?.dnsExchange(
        for: activePacketRequest,
        finishedWallNanos: exchange.completedWallNanos
    )
    let timing = packetExchange?.timing ?? .networkFramework(start: startWallNanos, finished: exchange.completedWallNanos)
    let rcode = exchange.rcode ?? packetExchange?.response.rcode
    let answerCount = exchange.answerCount ?? packetExchange?.response.answerCount
    return ActiveDNSProbeResult(
        target: host,
        family: family,
        recordType: recordType,
        resolver: resolver,
        transport: "udp",
        ok: rcode == 0 && !exchange.addresses.isEmpty,
        rcode: rcode,
        answerCount: answerCount,
        addresses: exchange.addresses,
        error: exchange.error,
        timing: timing
    )
}

private func failedDNSProbe(
    identity: DNSProbeIdentity,
    startWallNanos: UInt64,
    error: String
) -> ActiveDNSProbeResult {
    let finishedWallNanos = wallClockNanos()
    return ActiveDNSProbeResult(
        target: identity.target,
        family: identity.family,
        recordType: identity.recordType,
        resolver: identity.resolver,
        transport: "udp",
        ok: false,
        rcode: nil,
        answerCount: nil,
        addresses: [],
        error: error,
        timing: .networkFramework(start: startWallNanos, finished: finishedWallNanos)
    )
}

private func performDNSUDPExchange(
    query: DNSQueryPacket,
    resolver: String,
    selectedInterface: NWInterface,
    timeout: TimeInterval
) -> DNSExchangeResult {
    // Resolve through the Wi-Fi interface explicitly. System DNS APIs can pick
    // the default route, which may be Ethernet or VPN on development laptops.
    let parameters = NWParameters.udp
    parameters.requiredInterface = selectedInterface
    let connection = NWConnection(host: NWEndpoint.Host(resolver), port: NWEndpoint.Port(rawValue: 53)!, using: parameters)
    let queue = DispatchQueue(label: "watchme.dns_probe.\(randomHex(bytes: 4))")
    // The probe runner is synchronous, while Network.framework is callback
    // based. Store exactly one result so timeout/cancel races cannot overwrite
    // a packet-timing boundary recorded by an earlier callback.
    let completion = SynchronousCompletion<DNSExchangeResult>()

    func complete(rcode: Int? = nil, answerCount: Int? = nil, addresses: [String] = [], error: String? = nil) {
        completion.complete(DNSExchangeResult(
            rcode: rcode,
            answerCount: answerCount,
            addresses: addresses,
            error: error,
            completedWallNanos: wallClockNanos()
        ))
    }

    connection.stateUpdateHandler = { state in
        switch state {
        case .ready:
            connection.send(content: query.data, completion: .contentProcessed { error in
                if let error {
                    complete(error: error.localizedDescription)
                    return
                }
                connection.receiveMessage { data, _, _, error in
                    if let error {
                        complete(error: error.localizedDescription)
                        return
                    }
                    guard let data else {
                        complete(error: "DNS response was empty")
                        return
                    }
                    guard let response = parseDNSResponseMetadata(
                        data: data,
                        expectedID: query.id,
                        recordType: query.recordType
                    ) else {
                        complete(error: "DNS response could not be parsed")
                        return
                    }
                    complete(rcode: response.rcode, answerCount: response.answerCount, addresses: response.addresses)
                }
            })
        case let .failed(error):
            complete(error: error.localizedDescription)
        case .cancelled:
            complete(error: "connection cancelled")
        default:
            break
        }
    }
    connection.start(queue: queue)

    let result = completion.wait(
        timeout: timeout,
        timeoutValue: DNSExchangeResult(
            rcode: nil,
            answerCount: nil,
            addresses: [],
            error: "DNS probe timed out",
            completedWallNanos: wallClockNanos()
        )
    )
    connection.cancel()
    return result
}

struct DNSQueryPacket {
    let id: UInt16
    let recordType: DNSRecordType
    let data: Data
}

func dnsQueryPacket(
    host: String,
    recordType: DNSRecordType,
    id: UInt16 = UInt16.random(in: 0 ... UInt16.max)
) -> DNSQueryPacket? {
    // This intentionally builds the smallest RFC 1035 query we need. Avoiding
    // libresolv keeps the probe route bound to Network.framework.
    var data = Data()
    data.append(UInt8(id >> 8))
    data.append(UInt8(id & 0x00FF))
    data.append(contentsOf: [0x01, 0x00, 0x00, 0x01, 0x00, 0x00])
    data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
    for label in host.split(separator: ".") {
        guard !label.isEmpty, label.utf8.count <= 63 else {
            return nil
        }
        data.append(UInt8(label.utf8.count))
        data.append(contentsOf: label.utf8)
    }
    data.append(0x00)
    data.append(UInt8(recordType.rawValue >> 8))
    data.append(UInt8(recordType.rawValue & 0x00FF))
    data.append(contentsOf: [0x00, 0x01])
    return DNSQueryPacket(id: id, recordType: recordType, data: data)
}

func parseDNSResponseMetadata(
    data: Data,
    expectedID: UInt16,
    recordType: DNSRecordType = .a
) -> DNSResponseMetadata? {
    let bytes = [UInt8](data)
    guard bytes.count >= 12 else {
        return nil
    }
    let id = readBigUInt16(bytes, offset: 0)
    guard id == expectedID, (bytes[2] & 0x80) != 0 else {
        return nil
    }
    let rcode = Int(bytes[3] & 0x0F)
    let questionCount = Int(readBigUInt16(bytes, offset: 4))
    let answerCount = Int(readBigUInt16(bytes, offset: 6))
    var cursor = 12
    for _ in 0 ..< questionCount {
        guard let parsed = parseDNSName(buffer: bytes, messageOffset: 0, cursor: cursor, packetEnd: bytes.count) else {
            return DNSResponseMetadata(rcode: rcode, answerCount: answerCount, addresses: [])
        }
        cursor = parsed.nextOffset + 4
        guard cursor <= bytes.count else {
            return DNSResponseMetadata(rcode: rcode, answerCount: answerCount, addresses: [])
        }
    }

    var addresses: [String] = []
    for _ in 0 ..< answerCount {
        guard let parsed = parseDNSName(buffer: bytes, messageOffset: 0, cursor: cursor, packetEnd: bytes.count) else {
            break
        }
        cursor = parsed.nextOffset
        guard cursor + 10 <= bytes.count else {
            break
        }
        let answerType = readBigUInt16(bytes, offset: cursor)
        let answerClass = readBigUInt16(bytes, offset: cursor + 2)
        let dataLength = Int(readBigUInt16(bytes, offset: cursor + 8))
        cursor += 10
        guard cursor + dataLength <= bytes.count else {
            break
        }
        if answerClass == 1, answerType == recordType.rawValue, dataLength == recordType.family.addressByteCount {
            let addressBytes = Array(bytes[cursor ..< (cursor + dataLength)])
            switch recordType {
            case .a:
                addresses.append(ipv4String(bytes: addressBytes))
            case .aaaa:
                addresses.append(ipv6String(bytes: addressBytes))
            }
        }
        cursor += dataLength
    }
    return DNSResponseMetadata(rcode: rcode, answerCount: answerCount, addresses: addresses)
}
