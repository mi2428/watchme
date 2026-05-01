import Darwin
import Foundation
import WatchmeBPF
import WatchmeCore

private struct GatewayAttemptFailureContext {
    let sequence: Int
    let identifier: UInt16?
    let icmpSequence: UInt16?
    let startWallNanos: UInt64
}

private struct GatewayAttemptPreflight {
    let interfaceName: String
    let localIP: String
    let sourceMACBytes: [UInt8]
    let gatewayMACBytes: [UInt8]
    let sourceIPBytes: [UInt8]
    let gatewayIPBytes: [UInt8]
}

private enum GatewayAttemptPreflightResult {
    case success(GatewayAttemptPreflight)
    case failure(ActiveGatewayProbeAttempt)
}

private struct GatewayAttemptExecution {
    let family: InternetAddressFamily
    let gateway: String
    let timeout: TimeInterval
    let identifier: UInt16
    let icmpSequence: UInt16
    let startWallNanos: UInt64
    let failureContext: GatewayAttemptFailureContext
    let preflight: GatewayAttemptPreflight
    let frame: [UInt8]
}

struct GatewayResolutionFailureContext {
    let gateway: String
    let family: InternetAddressFamily
    let protocolName: String
    let sourceIP: String?
    let sourceHardwareAddress: String?
    let startWallNanos: UInt64

    static func arp(
        gateway: String,
        sourceIP: String?,
        sourceHardwareAddress: String?,
        startWallNanos: UInt64
    ) -> GatewayResolutionFailureContext {
        GatewayResolutionFailureContext(
            gateway: gateway,
            family: .ipv4,
            protocolName: "arp",
            sourceIP: sourceIP,
            sourceHardwareAddress: sourceHardwareAddress,
            startWallNanos: startWallNanos
        )
    }

    static func ndp(
        gateway: String,
        sourceIP: String?,
        sourceHardwareAddress: String?,
        startWallNanos: UInt64
    ) -> GatewayResolutionFailureContext {
        GatewayResolutionFailureContext(
            gateway: gateway,
            family: .ipv6,
            protocolName: "ndp",
            sourceIP: sourceIP,
            sourceHardwareAddress: sourceHardwareAddress,
            startWallNanos: startWallNanos
        )
    }
}

func runBPFGatewayICMPAttempt(
    sequence: Int,
    gateway: String,
    gatewayHardwareAddress: String,
    timeout: TimeInterval,
    interfaceName: String?
) -> ActiveGatewayProbeAttempt {
    let startWallNanos = wallClockNanos()
    let identifier = UInt16(ProcessInfo.processInfo.processIdentifier & 0xFFFF)
    let icmpSequence = UInt16((wallClockNanos() + UInt64(sequence)) & UInt64(UInt16.max))
    let failureContext = GatewayAttemptFailureContext(
        sequence: sequence,
        identifier: identifier,
        icmpSequence: icmpSequence,
        startWallNanos: startWallNanos
    )
    guard let interfaceName, !interfaceName.isEmpty else {
        return failedGatewayAttempt(
            context: failureContext,
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface was not available for BPF gateway probe"
        )
    }
    let preflight: GatewayAttemptPreflight
    switch gatewayIPv4AttemptPreflight(
        interfaceName: interfaceName,
        gateway: gateway,
        gatewayHardwareAddress: gatewayHardwareAddress,
        failureContext: failureContext
    ) {
    case let .success(value):
        preflight = value
    case let .failure(result):
        return result
    }

    return executeGatewayICMPAttempt(
        GatewayAttemptExecution(
            family: .ipv4,
            gateway: gateway,
            timeout: timeout,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            failureContext: failureContext,
            preflight: preflight,
            frame: ethernetICMPEchoFrame(
                EthernetICMPEchoFrame(
                    sourceMAC: preflight.sourceMACBytes,
                    destinationMAC: preflight.gatewayMACBytes,
                    sourceIP: preflight.sourceIPBytes,
                    destinationIP: preflight.gatewayIPBytes,
                    identifier: identifier,
                    sequence: icmpSequence,
                    payloadSize: 56
                )
            )
        )
    )
}

func runBPFGatewayICMPv6Attempt(
    sequence: Int,
    gateway: String,
    gatewayHardwareAddress: String,
    timeout: TimeInterval,
    interfaceName: String?
) -> ActiveGatewayProbeAttempt {
    let startWallNanos = wallClockNanos()
    let identifier = UInt16(ProcessInfo.processInfo.processIdentifier & 0xFFFF)
    let icmpSequence = UInt16((wallClockNanos() + UInt64(sequence)) & UInt64(UInt16.max))
    let failureContext = GatewayAttemptFailureContext(
        sequence: sequence,
        identifier: identifier,
        icmpSequence: icmpSequence,
        startWallNanos: startWallNanos
    )
    guard let interfaceName, !interfaceName.isEmpty else {
        return failedGatewayAttempt(
            context: failureContext,
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface was not available for BPF IPv6 gateway probe"
        )
    }
    let preflight: GatewayAttemptPreflight
    switch gatewayIPv6AttemptPreflight(
        interfaceName: interfaceName,
        gateway: gateway,
        gatewayHardwareAddress: gatewayHardwareAddress,
        failureContext: failureContext
    ) {
    case let .success(value):
        preflight = value
    case let .failure(result):
        return result
    }

    return executeGatewayICMPAttempt(
        GatewayAttemptExecution(
            family: .ipv6,
            gateway: gateway,
            timeout: timeout,
            identifier: identifier,
            icmpSequence: icmpSequence,
            startWallNanos: startWallNanos,
            failureContext: failureContext,
            preflight: preflight,
            frame: ethernetICMPv6EchoFrame(
                EthernetICMPv6EchoFrame(
                    sourceMAC: preflight.sourceMACBytes,
                    destinationMAC: preflight.gatewayMACBytes,
                    sourceIP: preflight.sourceIPBytes,
                    destinationIP: preflight.gatewayIPBytes,
                    identifier: identifier,
                    sequence: icmpSequence,
                    payloadSize: 56
                )
            )
        )
    )
}

private func executeGatewayICMPAttempt(_ execution: GatewayAttemptExecution) -> ActiveGatewayProbeAttempt {
    let bpf: GatewayBPFDescriptor
    switch openConfiguredGatewayBPF(interfaceName: execution.preflight.interfaceName) {
    case let .success(descriptor):
        bpf = descriptor
    case let .failure(error):
        return failedGatewayAttempt(
            context: execution.failureContext,
            outcome: "bpf_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: error
        )
    }
    defer {
        close(bpf.fd)
    }

    let sent = execution.frame.withUnsafeBytes { frameBuffer in
        write(bpf.fd, frameBuffer.baseAddress, frameBuffer.count)
    }
    guard sent == execution.frame.count else {
        return failedGatewayAttempt(
            context: execution.failureContext,
            outcome: "send_failed",
            timingSource: networkFrameworkTimingSource,
            error: "BPF gateway \(execution.family == .ipv6 ? "ICMPv6" : "ICMP") write failed: \(posixErrorString())"
        )
    }

    let request = GatewayICMPReadRequest(
        fd: bpf.fd,
        bufferLength: bpf.bufferLength,
        timeout: execution.timeout,
        localIP: execution.preflight.localIP,
        gateway: execution.gateway,
        identifier: execution.identifier,
        sequence: execution.icmpSequence,
        startWallNanos: execution.startWallNanos
    )
    let result = execution.family == .ipv6
        ? readBPFGatewayICMPv6Reply(request: request)
        : readBPFGatewayICMPReply(request: request)
    guard result.ok, let replyNanos = result.replyWallNanos else {
        return failedGatewayAttempt(
            context: execution.failureContext,
            outcome: "timeout",
            timingSource: wallClockDeadlineTimingSource,
            error: result.error ?? "BPF gateway \(execution.family == .ipv6 ? "ICMPv6" : "ICMP") echo timed out"
        )
    }

    let timing = result.requestWallNanos.map {
        ActiveProbeTiming.bpfPacket(start: $0, finished: replyNanos)
    } ?? .networkFramework(start: execution.startWallNanos, finished: wallClockNanos())
    return ActiveGatewayProbeAttempt(
        sequence: execution.failureContext.sequence,
        identifier: execution.identifier,
        icmpSequence: execution.icmpSequence,
        reachable: true,
        outcome: "reply",
        error: nil,
        timing: timing
    )
}

private func gatewayIPv4AttemptPreflight(
    interfaceName: String,
    gateway: String,
    gatewayHardwareAddress: String,
    failureContext: GatewayAttemptFailureContext
) -> GatewayAttemptPreflightResult {
    let interfaceState = nativeInterfaceState(interfaceName: interfaceName)
    guard let localIP = interfaceState.ipv4Addresses.first else {
        return .failure(
            failedGatewayAttempt(
                context: failureContext,
                outcome: "interface_unavailable",
                timingSource: networkFrameworkTimingSource,
                error: "Wi-Fi interface \(interfaceName) had no IPv4 address for BPF gateway probe"
            )
        )
    }
    guard let sourceMAC = interfaceState.macAddress,
          let sourceMACBytes = parseMACAddress(sourceMAC),
          let gatewayMACBytes = parseMACAddress(gatewayHardwareAddress),
          let sourceIPBytes = parseIPv4Address(localIP),
          let gatewayIPBytes = parseIPv4Address(gateway)
    else {
        return .failure(
            failedGatewayAttempt(
                context: failureContext,
                outcome: "preflight_failed",
                timingSource: networkFrameworkTimingSource,
                error: "BPF gateway probe could not parse interface or gateway addresses"
            )
        )
    }
    return .success(
        GatewayAttemptPreflight(
            interfaceName: interfaceName,
            localIP: localIP,
            sourceMACBytes: sourceMACBytes,
            gatewayMACBytes: gatewayMACBytes,
            sourceIPBytes: sourceIPBytes,
            gatewayIPBytes: gatewayIPBytes
        )
    )
}

private func gatewayIPv6AttemptPreflight(
    interfaceName: String,
    gateway: String,
    gatewayHardwareAddress: String,
    failureContext: GatewayAttemptFailureContext
) -> GatewayAttemptPreflightResult {
    let interfaceState = nativeInterfaceState(interfaceName: interfaceName)
    guard let localIP = gatewayIPv6SourceAddress(interfaceState: interfaceState, gateway: gateway) else {
        return .failure(
            failedGatewayAttempt(
                context: failureContext,
                outcome: "interface_unavailable",
                timingSource: networkFrameworkTimingSource,
                error: "Wi-Fi interface \(interfaceName) had no IPv6 address for BPF IPv6 gateway probe"
            )
        )
    }
    guard let sourceMAC = interfaceState.macAddress,
          let sourceMACBytes = parseMACAddress(sourceMAC),
          let gatewayMACBytes = parseMACAddress(gatewayHardwareAddress),
          let sourceIPBytes = parseIPv6Address(localIP),
          let gatewayIPBytes = parseIPv6Address(gateway)
    else {
        return .failure(
            failedGatewayAttempt(
                context: failureContext,
                outcome: "preflight_failed",
                timingSource: networkFrameworkTimingSource,
                error: "BPF IPv6 gateway probe could not parse interface or gateway addresses"
            )
        )
    }
    return .success(
        GatewayAttemptPreflight(
            interfaceName: interfaceName,
            localIP: localIP,
            sourceMACBytes: sourceMACBytes,
            gatewayMACBytes: gatewayMACBytes,
            sourceIPBytes: sourceIPBytes,
            gatewayIPBytes: gatewayIPBytes
        )
    )
}

func failedGatewayARPResolution(
    context: GatewayResolutionFailureContext,
    outcome: String,
    timingSource: String,
    error: String
) -> ActiveGatewayARPResult {
    ActiveGatewayARPResult(
        gateway: context.gateway,
        family: context.family,
        protocolName: context.protocolName,
        sourceIP: context.sourceIP,
        sourceHardwareAddress: context.sourceHardwareAddress,
        gatewayHardwareAddress: nil,
        ok: false,
        outcome: outcome,
        error: error,
        timing: ActiveProbeTiming(
            startWallNanos: context.startWallNanos,
            finishedWallNanos: wallClockNanos(),
            timingSource: timingSource,
            timestampSource: wallClockTimestampSource
        )
    )
}

func gatewayAttempt(sequence: Int, result: ActiveICMPProbeResult) -> ActiveGatewayProbeAttempt {
    ActiveGatewayProbeAttempt(
        sequence: sequence,
        identifier: result.identifier,
        icmpSequence: result.sequence,
        reachable: result.ok,
        outcome: result.ok ? "reply" : result.outcome,
        error: result.error,
        timing: result.timing
    )
}

private func failedGatewayAttempt(
    context: GatewayAttemptFailureContext,
    outcome: String,
    timingSource: String,
    error: String
) -> ActiveGatewayProbeAttempt {
    ActiveGatewayProbeAttempt(
        sequence: context.sequence,
        identifier: context.identifier,
        icmpSequence: context.icmpSequence,
        reachable: false,
        outcome: outcome,
        error: error,
        timing: ActiveProbeTiming(
            startWallNanos: context.startWallNanos,
            finishedWallNanos: wallClockNanos(),
            timingSource: timingSource,
            timestampSource: wallClockTimestampSource
        )
    )
}
