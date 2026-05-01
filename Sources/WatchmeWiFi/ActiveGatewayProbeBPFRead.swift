import Darwin
import Foundation
import WatchmeBPF
import WatchmeCore

struct BPFGatewayARPReadResult {
    let ok: Bool
    let error: String?
    let requestWallNanos: UInt64?
    let replyWallNanos: UInt64?
    let gatewayHardwareAddress: String?
}

typealias BPFGatewayNDPReadResult = BPFGatewayARPReadResult

struct BPFGatewayICMPReadResult {
    let ok: Bool
    let error: String?
    let requestWallNanos: UInt64?
    let replyWallNanos: UInt64?
}

struct BPFGatewayICMPPacket {
    let family: InternetAddressFamily
    let type: UInt8
    let code: UInt8
    let sourceIP: String
    let destinationIP: String
    let identifier: UInt16
    let sequence: UInt16
}

struct BPFGatewayNeighborPacket {
    let type: UInt8
    let code: UInt8
    let sourceIP: String
    let destinationIP: String
    let targetAddress: String?
    let sourceLinkLayerAddress: String?
    let targetLinkLayerAddress: String?
    let ethernetSourceAddress: String
}

struct GatewayICMPReadRequest {
    let fd: Int32
    let bufferLength: Int
    let timeout: TimeInterval
    let localIP: String
    let gateway: String
    let identifier: UInt16
    let sequence: UInt16
    let startWallNanos: UInt64
}

func readBPFGatewayARPReply(
    fd: Int32,
    bufferLength: Int,
    timeout: TimeInterval,
    localIP: String,
    gateway: String
) -> BPFGatewayARPReadResult {
    var requestWallNanos: UInt64?
    return readGatewayBPFRecords(
        context: GatewayBPFReadLoopContext(
            fd: fd,
            bufferLength: bufferLength,
            timeout: timeout,
            timeoutError: "BPF gateway ARP reply timed out",
            pollFailurePrefix: "BPF gateway ARP poll failed",
            readFailurePrefix: "BPF gateway ARP read failed"
        ),
        makeFailure: { error in
            BPFGatewayARPReadResult(
                ok: false,
                error: error,
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil,
                gatewayHardwareAddress: nil
            )
        },
        match: { record in
            guard record.caplen >= 14 + 28,
                  record.buffer[record.packetOffset + 12] == 0x08,
                  record.buffer[record.packetOffset + 13] == 0x06,
                  let packet = parseARPPacket(
                      buffer: record.buffer,
                      offset: record.packetOffset + 14,
                      packetEnd: record.packetOffset + record.caplen
                  )
            else {
                return nil
            }
            let isGatewayARPRequest = packet.operation == 1
                && packet.senderProtocolAddress == localIP
                && packet.targetProtocolAddress == gateway
            if isGatewayARPRequest {
                requestWallNanos = requestWallNanos ?? record.packetWallNanos
                return nil
            }
            guard packet.operation == 2,
                  packet.senderProtocolAddress == gateway,
                  packet.targetProtocolAddress == localIP
            else {
                return nil
            }
            return BPFGatewayARPReadResult(
                ok: true,
                error: nil,
                requestWallNanos: requestWallNanos,
                replyWallNanos: record.packetWallNanos,
                gatewayHardwareAddress: packet.senderHardwareAddress
            )
        }
    )
}

func readBPFGatewayNeighborAdvertisement(
    fd: Int32,
    bufferLength: Int,
    timeout: TimeInterval,
    localIP: String,
    gateway: String
) -> BPFGatewayNDPReadResult {
    let normalizedLocalIP = normalizedIPv6Scope(localIP)
    let normalizedGateway = normalizedIPv6Scope(gateway)
    var requestWallNanos: UInt64?
    return readGatewayBPFRecords(
        context: GatewayBPFReadLoopContext(
            fd: fd,
            bufferLength: bufferLength,
            timeout: timeout,
            timeoutError: "BPF gateway NDP reply timed out",
            pollFailurePrefix: "BPF gateway NDP poll failed",
            readFailurePrefix: "BPF gateway NDP read failed"
        ),
        makeFailure: { error in
            BPFGatewayNDPReadResult(
                ok: false,
                error: error,
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil,
                gatewayHardwareAddress: nil
            )
        },
        match: { record in
            guard let packet = parseBPFGatewayNeighborPacket(
                buffer: record.buffer,
                offset: record.packetOffset,
                length: record.caplen
            ) else {
                return nil
            }
            let isLocalNeighborSolicitation = packet.type == 135
                && normalizedIPv6Scope(packet.sourceIP) == normalizedLocalIP
                && packet.targetAddress.map(normalizedIPv6Scope) == normalizedGateway
            if isLocalNeighborSolicitation {
                requestWallNanos = requestWallNanos ?? record.packetWallNanos
                return nil
            }
            guard packet.type == 136,
                  packet.targetAddress.map(normalizedIPv6Scope) == normalizedGateway
            else {
                return nil
            }
            return BPFGatewayNDPReadResult(
                ok: true,
                error: nil,
                requestWallNanos: requestWallNanos,
                replyWallNanos: record.packetWallNanos,
                gatewayHardwareAddress: packet.targetLinkLayerAddress ?? packet.ethernetSourceAddress
            )
        }
    )
}

func readBPFGatewayICMPReply(request: GatewayICMPReadRequest) -> BPFGatewayICMPReadResult {
    var requestWallNanos: UInt64?
    return readGatewayBPFRecords(
        context: GatewayBPFReadLoopContext(
            fd: request.fd,
            bufferLength: request.bufferLength,
            timeout: request.timeout,
            timeoutError: "BPF gateway ICMP echo timed out",
            pollFailurePrefix: "BPF gateway ICMP poll failed",
            readFailurePrefix: "BPF gateway ICMP read failed"
        ),
        makeFailure: { error in
            BPFGatewayICMPReadResult(
                ok: false,
                error: error,
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil
            )
        },
        match: { record in
            guard let packet = parseBPFGatewayICMPPacket(
                buffer: record.buffer,
                offset: record.packetOffset,
                length: record.caplen
            ),
                packet.identifier == request.identifier,
                packet.sequence == request.sequence
            else {
                return nil
            }
            if packet.type == 8, packet.sourceIP == request.localIP, packet.destinationIP == request.gateway {
                requestWallNanos = requestWallNanos ?? record.packetWallNanos
                return nil
            }
            if packet.type == 0, packet.sourceIP == request.gateway, packet.destinationIP == request.localIP {
                return BPFGatewayICMPReadResult(
                    ok: true,
                    error: nil,
                    requestWallNanos: requestWallNanos ?? request.startWallNanos,
                    replyWallNanos: record.packetWallNanos
                )
            }
            guard packet.sourceIP == request.gateway || packet.destinationIP == request.gateway else {
                return nil
            }
            return BPFGatewayICMPReadResult(
                ok: false,
                error: "Unexpected gateway ICMP type \(packet.type) code \(packet.code)",
                requestWallNanos: requestWallNanos,
                replyWallNanos: record.packetWallNanos
            )
        }
    )
}

func readBPFGatewayICMPv6Reply(request: GatewayICMPReadRequest) -> BPFGatewayICMPReadResult {
    let normalizedLocalIP = normalizedIPv6Scope(request.localIP)
    let normalizedGateway = normalizedIPv6Scope(request.gateway)
    var requestWallNanos: UInt64?
    return readGatewayBPFRecords(
        context: GatewayBPFReadLoopContext(
            fd: request.fd,
            bufferLength: request.bufferLength,
            timeout: request.timeout,
            timeoutError: "BPF gateway ICMPv6 echo timed out",
            pollFailurePrefix: "BPF gateway ICMPv6 poll failed",
            readFailurePrefix: "BPF gateway ICMPv6 read failed"
        ),
        makeFailure: { error in
            BPFGatewayICMPReadResult(
                ok: false,
                error: error,
                requestWallNanos: requestWallNanos,
                replyWallNanos: nil
            )
        },
        match: { record in
            guard let packet = parseBPFGatewayICMPv6Packet(
                buffer: record.buffer,
                offset: record.packetOffset,
                length: record.caplen
            ),
                packet.identifier == request.identifier,
                packet.sequence == request.sequence
            else {
                return nil
            }
            let isLocalICMPEchoRequest = packet.type == 128
                && normalizedIPv6Scope(packet.sourceIP) == normalizedLocalIP
                && normalizedIPv6Scope(packet.destinationIP) == normalizedGateway
            if isLocalICMPEchoRequest {
                requestWallNanos = requestWallNanos ?? record.packetWallNanos
                return nil
            }
            let isGatewayICMPEchoReply = packet.type == 129
                && normalizedIPv6Scope(packet.sourceIP) == normalizedGateway
                && normalizedIPv6Scope(packet.destinationIP) == normalizedLocalIP
            if isGatewayICMPEchoReply {
                return BPFGatewayICMPReadResult(
                    ok: true,
                    error: nil,
                    requestWallNanos: requestWallNanos ?? request.startWallNanos,
                    replyWallNanos: record.packetWallNanos
                )
            }
            guard normalizedIPv6Scope(packet.sourceIP) == normalizedGateway
                || normalizedIPv6Scope(packet.destinationIP) == normalizedGateway
            else {
                return nil
            }
            return BPFGatewayICMPReadResult(
                ok: false,
                error: "Unexpected gateway ICMPv6 type \(packet.type) code \(packet.code)",
                requestWallNanos: requestWallNanos,
                replyWallNanos: record.packetWallNanos
            )
        }
    )
}

private struct GatewayBPFReadLoopContext {
    let fd: Int32
    let bufferLength: Int
    let timeout: TimeInterval
    let timeoutError: String
    let pollFailurePrefix: String
    let readFailurePrefix: String
}

private func readGatewayBPFRecords<Result>(
    context: GatewayBPFReadLoopContext,
    makeFailure: (String) -> Result,
    match: (BPFReadBufferRecord) -> Result?
) -> Result {
    let started = DispatchTime.now().uptimeNanoseconds
    let timeoutNanos = UInt64(max(context.timeout, 0.001) * 1_000_000_000)
    var pollDescriptor = pollfd(fd: context.fd, events: Int16(POLLIN), revents: 0)
    var readBuffer = [UInt8](repeating: 0, count: max(context.bufferLength, 4096))

    while true {
        let elapsedNanos = DispatchTime.now().uptimeNanoseconds - started
        guard elapsedNanos < timeoutNanos else {
            return makeFailure(context.timeoutError)
        }
        pollDescriptor.revents = 0
        let ready = poll(&pollDescriptor, 1, Int32(max(1, Int((timeoutNanos - elapsedNanos) / 1_000_000))))
        if ready == 0 {
            return makeFailure(context.timeoutError)
        }
        guard ready > 0 else {
            return makeFailure("\(context.pollFailurePrefix): \(posixErrorString())")
        }

        let bytesRead = readBuffer.withUnsafeMutableBytes { rawBuffer in
            read(context.fd, rawBuffer.baseAddress, rawBuffer.count)
        }
        guard bytesRead > 0 else {
            return makeFailure("\(context.readFailurePrefix): \(posixErrorString())")
        }
        if let result = scanBPFReadBuffer(readBuffer, bytesRead: bytesRead, match: match) {
            return result
        }
    }
}
