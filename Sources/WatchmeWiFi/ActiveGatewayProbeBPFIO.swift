import Darwin
import Foundation
import WatchmeBPF

struct GatewayBPFIO {
    let interfaceState: (String) -> NativeInterfaceState
    let openConfigured: (String) -> GatewayBPFDescriptorOpenResult
    let closeDescriptor: (GatewayBPFDescriptor) -> Void
    let writeFrame: (GatewayBPFDescriptor, [UInt8]) -> Int
    let readARPReply: (Int32, Int, TimeInterval, String, String) -> BPFGatewayARPReadResult
    let readNeighborAdvertisement: (Int32, Int, TimeInterval, String, String) -> BPFGatewayNDPReadResult
    let readICMPReply: (GatewayICMPReadRequest) -> BPFGatewayICMPReadResult
    let readICMPv6Reply: (GatewayICMPReadRequest) -> BPFGatewayICMPReadResult

    static let live = GatewayBPFIO(
        interfaceState: nativeInterfaceState(interfaceName:),
        openConfigured: openConfiguredGatewayBPF(interfaceName:),
        closeDescriptor: { descriptor in
            close(descriptor.fd)
        },
        writeFrame: { descriptor, frame in
            frame.withUnsafeBytes { frameBuffer in
                Darwin.write(descriptor.fd, frameBuffer.baseAddress, frameBuffer.count)
            }
        },
        readARPReply: readBPFGatewayARPReply(fd:bufferLength:timeout:localIP:gateway:),
        readNeighborAdvertisement: readBPFGatewayNeighborAdvertisement(fd:bufferLength:timeout:localIP:gateway:),
        readICMPReply: readBPFGatewayICMPReply(request:),
        readICMPv6Reply: readBPFGatewayICMPv6Reply(request:)
    )
}
