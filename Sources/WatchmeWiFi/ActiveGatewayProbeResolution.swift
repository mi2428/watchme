import Darwin
import Foundation
import WatchmeBPF
import WatchmeCore

private struct GatewayResolutionPreflight {
    let interfaceName: String
    let localIP: String
    let sourceMAC: String
    let sourceMACBytes: [UInt8]
    let sourceIPBytes: [UInt8]
    let gatewayIPBytes: [UInt8]
}

private enum GatewayResolutionPreflightResult {
    case success(GatewayResolutionPreflight)
    case failure(ActiveGatewayARPResult)
}

private struct GatewayResolutionSuccess {
    let gateway: String
    let family: InternetAddressFamily
    let protocolName: String
    let preflight: GatewayResolutionPreflight
    let gatewayHardwareAddress: String
    let timing: ActiveProbeTiming
}

private struct GatewayResolutionExecution {
    let gateway: String
    let family: InternetAddressFamily
    let protocolName: String
    let timeout: TimeInterval
    let preflight: GatewayResolutionPreflight
    let frame: [UInt8]
    let startWallNanos: UInt64
}

func runBPFGatewayARPResolution(
    gateway: String,
    timeout: TimeInterval,
    interfaceName: String?,
    bpfIO: GatewayBPFIO = .live
) -> ActiveGatewayARPResult {
    let startWallNanos = wallClockNanos()
    guard let interfaceName, !interfaceName.isEmpty else {
        return failedGatewayARPResolution(
            context: .arp(
                gateway: gateway,
                sourceIP: nil,
                sourceHardwareAddress: nil,
                startWallNanos: startWallNanos
            ),
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface was not available for BPF gateway ARP probe"
        )
    }
    let preflight: GatewayResolutionPreflight
    switch gatewayARPResolutionPreflight(
        gateway: gateway,
        interfaceName: interfaceName,
        startWallNanos: startWallNanos,
        interfaceStateProvider: bpfIO.interfaceState
    ) {
    case let .success(value):
        preflight = value
    case let .failure(result):
        return result
    }

    return executeGatewayResolution(
        GatewayResolutionExecution(
            gateway: gateway,
            family: .ipv4,
            protocolName: "arp",
            timeout: timeout,
            preflight: preflight,
            frame: ethernetARPRequestFrame(
                sourceMAC: preflight.sourceMACBytes,
                sourceIP: preflight.sourceIPBytes,
                targetIP: preflight.gatewayIPBytes
            ),
            startWallNanos: startWallNanos
        ),
        bpfIO: bpfIO
    )
}

func runBPFGatewayNDPResolution(
    gateway: String,
    timeout: TimeInterval,
    interfaceName: String?,
    bpfIO: GatewayBPFIO = .live
) -> ActiveGatewayARPResult {
    let startWallNanos = wallClockNanos()
    guard let interfaceName, !interfaceName.isEmpty else {
        return failedGatewayARPResolution(
            context: .ndp(
                gateway: gateway,
                sourceIP: nil,
                sourceHardwareAddress: nil,
                startWallNanos: startWallNanos
            ),
            outcome: "interface_unavailable",
            timingSource: networkFrameworkTimingSource,
            error: "Wi-Fi interface was not available for BPF gateway NDP probe"
        )
    }
    let preflight: GatewayResolutionPreflight
    switch gatewayNDPResolutionPreflight(
        gateway: gateway,
        interfaceName: interfaceName,
        startWallNanos: startWallNanos,
        interfaceStateProvider: bpfIO.interfaceState
    ) {
    case let .success(value):
        preflight = value
    case let .failure(result):
        return result
    }

    return executeGatewayResolution(
        GatewayResolutionExecution(
            gateway: gateway,
            family: .ipv6,
            protocolName: "ndp",
            timeout: timeout,
            preflight: preflight,
            frame: ethernetIPv6NeighborSolicitationFrame(
                sourceMAC: preflight.sourceMACBytes,
                sourceIP: preflight.sourceIPBytes,
                targetIP: preflight.gatewayIPBytes
            ),
            startWallNanos: startWallNanos
        ),
        bpfIO: bpfIO
    )
}

private func executeGatewayResolution(_ execution: GatewayResolutionExecution, bpfIO: GatewayBPFIO) -> ActiveGatewayARPResult {
    let bpf: GatewayBPFDescriptor
    switch bpfIO.openConfigured(execution.preflight.interfaceName) {
    case let .success(descriptor):
        bpf = descriptor
    case let .failure(error):
        return failedGatewayResolution(execution, outcome: "bpf_unavailable", timingSource: networkFrameworkTimingSource, error: error)
    }
    defer {
        bpfIO.closeDescriptor(bpf)
    }

    let requestWriteWallNanos = wallClockNanos()
    let sent = bpfIO.writeFrame(bpf, execution.frame)
    guard sent == execution.frame.count else {
        return failedGatewayResolution(
            execution,
            outcome: "send_failed",
            timingSource: networkFrameworkTimingSource,
            error: "BPF gateway \(execution.protocolName.uppercased()) write failed: \(posixErrorString())"
        )
    }

    let result = readGatewayResolutionReply(execution, bpf: bpf, bpfIO: bpfIO)
    guard result.ok,
          let replyNanos = result.replyWallNanos,
          let gatewayHardwareAddress = result.gatewayHardwareAddress
    else {
        return failedGatewayResolution(
            execution,
            startWallNanos: result.requestWallNanos ?? requestWriteWallNanos,
            outcome: "timeout",
            timingSource: wallClockDeadlineTimingSource,
            error: result.error ?? "BPF gateway \(execution.protocolName.uppercased()) reply timed out"
        )
    }

    return successfulGatewayResolution(
        GatewayResolutionSuccess(
            gateway: execution.gateway,
            family: execution.family,
            protocolName: execution.protocolName,
            preflight: execution.preflight,
            gatewayHardwareAddress: gatewayHardwareAddress,
            timing: gatewayARPRequestToReplyTiming(
                requestPacketWallNanos: result.requestWallNanos,
                requestWriteWallNanos: requestWriteWallNanos,
                replyWallNanos: replyNanos
            )
        )
    )
}

private func readGatewayResolutionReply(
    _ execution: GatewayResolutionExecution,
    bpf: GatewayBPFDescriptor,
    bpfIO: GatewayBPFIO
) -> BPFGatewayARPReadResult {
    if execution.family == .ipv6 {
        return bpfIO.readNeighborAdvertisement(
            bpf.fd,
            bpf.bufferLength,
            execution.timeout,
            execution.preflight.localIP,
            execution.gateway
        )
    }
    return bpfIO.readARPReply(
        bpf.fd,
        bpf.bufferLength,
        execution.timeout,
        execution.preflight.localIP,
        execution.gateway
    )
}

private func failedGatewayResolution(
    _ execution: GatewayResolutionExecution,
    startWallNanos: UInt64? = nil,
    outcome: String,
    timingSource: String,
    error: String
) -> ActiveGatewayARPResult {
    let context = execution.family == .ipv6
        ? GatewayResolutionFailureContext.ndp(
            gateway: execution.gateway,
            sourceIP: execution.preflight.localIP,
            sourceHardwareAddress: execution.preflight.sourceMAC,
            startWallNanos: startWallNanos ?? execution.startWallNanos
        )
        : GatewayResolutionFailureContext.arp(
            gateway: execution.gateway,
            sourceIP: execution.preflight.localIP,
            sourceHardwareAddress: execution.preflight.sourceMAC,
            startWallNanos: startWallNanos ?? execution.startWallNanos
        )
    return failedGatewayARPResolution(context: context, outcome: outcome, timingSource: timingSource, error: error)
}

private func successfulGatewayResolution(_ success: GatewayResolutionSuccess) -> ActiveGatewayARPResult {
    ActiveGatewayARPResult(
        gateway: success.gateway,
        family: success.family,
        protocolName: success.protocolName,
        sourceIP: success.preflight.localIP,
        sourceHardwareAddress: macAddressString(bytes: success.preflight.sourceMACBytes),
        gatewayHardwareAddress: success.gatewayHardwareAddress,
        ok: true,
        outcome: "reply",
        error: nil,
        timing: success.timing
    )
}

private func gatewayARPResolutionPreflight(
    gateway: String,
    interfaceName: String,
    startWallNanos: UInt64,
    interfaceStateProvider: (String) -> NativeInterfaceState
) -> GatewayResolutionPreflightResult {
    let interfaceState = interfaceStateProvider(interfaceName)
    guard let localIP = interfaceState.ipv4Addresses.first else {
        return .failure(
            failedGatewayARPResolution(
                context: .arp(
                    gateway: gateway,
                    sourceIP: nil,
                    sourceHardwareAddress: interfaceState.macAddress,
                    startWallNanos: startWallNanos
                ),
                outcome: "interface_unavailable",
                timingSource: networkFrameworkTimingSource,
                error: "Wi-Fi interface \(interfaceName) had no IPv4 address for BPF gateway ARP probe"
            )
        )
    }
    guard let sourceMAC = interfaceState.macAddress,
          let sourceMACBytes = parseMACAddress(sourceMAC),
          let sourceIPBytes = parseIPv4Address(localIP),
          let gatewayIPBytes = parseIPv4Address(gateway)
    else {
        return .failure(
            failedGatewayARPResolution(
                context: .arp(
                    gateway: gateway,
                    sourceIP: localIP,
                    sourceHardwareAddress: interfaceState.macAddress,
                    startWallNanos: startWallNanos
                ),
                outcome: "preflight_failed",
                timingSource: networkFrameworkTimingSource,
                error: "BPF gateway ARP probe could not parse interface or gateway addresses"
            )
        )
    }
    return .success(
        GatewayResolutionPreflight(
            interfaceName: interfaceName,
            localIP: localIP,
            sourceMAC: sourceMAC,
            sourceMACBytes: sourceMACBytes,
            sourceIPBytes: sourceIPBytes,
            gatewayIPBytes: gatewayIPBytes
        )
    )
}

private func gatewayNDPResolutionPreflight(
    gateway: String,
    interfaceName: String,
    startWallNanos: UInt64,
    interfaceStateProvider: (String) -> NativeInterfaceState
) -> GatewayResolutionPreflightResult {
    let interfaceState = interfaceStateProvider(interfaceName)
    guard let localIP = gatewayIPv6SourceAddress(interfaceState: interfaceState, gateway: gateway) else {
        return .failure(
            failedGatewayARPResolution(
                context: .ndp(
                    gateway: gateway,
                    sourceIP: nil,
                    sourceHardwareAddress: interfaceState.macAddress,
                    startWallNanos: startWallNanos
                ),
                outcome: "interface_unavailable",
                timingSource: networkFrameworkTimingSource,
                error: "Wi-Fi interface \(interfaceName) had no IPv6 address for BPF gateway NDP probe"
            )
        )
    }
    guard let sourceMAC = interfaceState.macAddress,
          let sourceMACBytes = parseMACAddress(sourceMAC),
          let sourceIPBytes = parseIPv6Address(localIP),
          let gatewayIPBytes = parseIPv6Address(gateway)
    else {
        return .failure(
            failedGatewayARPResolution(
                context: .ndp(
                    gateway: gateway,
                    sourceIP: localIP,
                    sourceHardwareAddress: interfaceState.macAddress,
                    startWallNanos: startWallNanos
                ),
                outcome: "preflight_failed",
                timingSource: networkFrameworkTimingSource,
                error: "BPF gateway NDP probe could not parse interface or gateway addresses"
            )
        )
    }
    return .success(
        GatewayResolutionPreflight(
            interfaceName: interfaceName,
            localIP: localIP,
            sourceMAC: sourceMAC,
            sourceMACBytes: sourceMACBytes,
            sourceIPBytes: sourceIPBytes,
            gatewayIPBytes: gatewayIPBytes
        )
    )
}

func gatewayARPRequestToReplyTiming(
    requestPacketWallNanos: UInt64?,
    requestWriteWallNanos: UInt64,
    replyWallNanos: UInt64
) -> ActiveProbeTiming {
    if let requestPacketWallNanos {
        return .bpfPacket(start: requestPacketWallNanos, finished: replyWallNanos)
    }
    return ActiveProbeTiming(
        startWallNanos: requestWriteWallNanos,
        finishedWallNanos: replyWallNanos,
        timingSource: wallClockPacketBoundaryTimingSource,
        timestampSource: wallClockTimestampSource
    )
}
