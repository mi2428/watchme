import Foundation
import Network
import WatchmeCore

struct ActiveDNSProbeResult {
    let target: String
    let resolver: String
    let transport: String
    let ok: Bool
    let rcode: Int?
    let answerCount: Int?
    let error: String?
    let startWallNanos: UInt64
    let finishedWallNanos: UInt64
    let durationNanos: UInt64
    let timingSource: String
    let timestampSource: String
}

private struct DNSExchangeResult {
    let rcode: Int?
    let answerCount: Int?
    let error: String?
    let completedWallNanos: UInt64
}

func runDNSAProbe(
    target: String,
    resolver: String,
    timeout: TimeInterval,
    interfaceName: String?,
    packetStore: PassivePacketStore? = nil
) -> ActiveDNSProbeResult {
    let host = normalizedTargetURL(target).host ?? target
    let startWallNanos = wallClockNanos()
    guard let query = dnsAQueryPacket(host: host) else {
        return failedDNSProbe(
            target: host,
            resolver: resolver,
            startWallNanos: startWallNanos,
            error: "target host cannot be encoded as a DNS query"
        )
    }
    guard let interface = requiredProbeInterface(named: interfaceName, timeout: timeout) else {
        return failedDNSProbe(
            target: host,
            resolver: resolver,
            startWallNanos: startWallNanos,
            error: "Wi-Fi interface \(interfaceName ?? "unknown") was not available to Network.framework"
        )
    }

    let activePacketRequest = ActiveDNSProbeRequest(
        transactionID: query.id,
        target: host,
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
    let ok = rcode == 0 && (answerCount ?? 0) > 0
    return ActiveDNSProbeResult(
        target: host,
        resolver: resolver,
        transport: "udp",
        ok: ok,
        rcode: rcode,
        answerCount: answerCount,
        error: exchange.error,
        startWallNanos: timing.startWallNanos,
        finishedWallNanos: timing.finishedWallNanos,
        durationNanos: timing.durationNanos,
        timingSource: timing.timingSource,
        timestampSource: timing.timestampSource
    )
}

private func failedDNSProbe(
    target: String,
    resolver: String,
    startWallNanos: UInt64,
    error: String
) -> ActiveDNSProbeResult {
    let finishedWallNanos = wallClockNanos()
    return ActiveDNSProbeResult(
        target: target,
        resolver: resolver,
        transport: "udp",
        ok: false,
        rcode: nil,
        answerCount: nil,
        error: error,
        startWallNanos: startWallNanos,
        finishedWallNanos: finishedWallNanos,
        durationNanos: max(finishedWallNanos - startWallNanos, 1000),
        timingSource: networkFrameworkTimingSource,
        timestampSource: wallClockTimestampSource
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
    let semaphore = DispatchSemaphore(value: 0)
    let completionLock = NSLock()
    var completed = false
    var rcode: Int?
    var answerCount: Int?
    var errorMessage: String?
    var completedWallNanos: UInt64?

    func complete(_ error: String? = nil) {
        completionLock.lock()
        defer { completionLock.unlock() }
        guard !completed else {
            return
        }
        if let error {
            errorMessage = error
        }
        completedWallNanos = completedWallNanos ?? wallClockNanos()
        completed = true
        semaphore.signal()
    }

    connection.stateUpdateHandler = { state in
        switch state {
        case .ready:
            connection.send(content: query.data, completion: .contentProcessed { error in
                if let error {
                    complete(error.localizedDescription)
                    return
                }
                connection.receiveMessage { data, _, _, error in
                    if let error {
                        complete(error.localizedDescription)
                        return
                    }
                    guard let data else {
                        complete("DNS response was empty")
                        return
                    }
                    guard let response = parseDNSResponseMetadata(data: data, expectedID: query.id) else {
                        complete("DNS response could not be parsed")
                        return
                    }
                    rcode = response.rcode
                    answerCount = response.answerCount
                    complete()
                }
            })
        case let .failed(error):
            complete(error.localizedDescription)
        case .cancelled:
            complete("connection cancelled")
        default:
            break
        }
    }
    connection.start(queue: queue)

    if semaphore.wait(timeout: .now() + timeout) == .timedOut {
        complete("DNS probe timed out")
    }
    connection.cancel()

    return DNSExchangeResult(
        rcode: rcode,
        answerCount: answerCount,
        error: errorMessage,
        completedWallNanos: completedWallNanos ?? wallClockNanos()
    )
}

struct DNSQueryPacket {
    let id: UInt16
    let data: Data
}

func dnsAQueryPacket(host: String, id: UInt16 = UInt16.random(in: 0 ... UInt16.max)) -> DNSQueryPacket? {
    // This intentionally builds the smallest RFC 1035 A-record query we need.
    // Avoiding libresolv keeps the probe route bound to Network.framework.
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
    data.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
    return DNSQueryPacket(id: id, data: data)
}

func parseDNSResponseMetadata(data: Data, expectedID: UInt16) -> (rcode: Int, answerCount: Int)? {
    guard data.count >= 12 else {
        return nil
    }
    // Only the DNS header is needed for observability: transaction match,
    // response code, and answer count. Full RR parsing would add risk without
    // improving the Wi-Fi health signal.
    let bytes = [UInt8](data.prefix(12))
    let id = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
    guard id == expectedID, (bytes[2] & 0x80) != 0 else {
        return nil
    }
    let rcode = Int(bytes[3] & 0x0F)
    let answerCount = Int(UInt16(bytes[6]) << 8 | UInt16(bytes[7]))
    return (rcode, answerCount)
}
