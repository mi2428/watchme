import Darwin
import Foundation
import WatchmeBPF

struct GatewayBPFDescriptor {
    let fd: Int32
    let bufferLength: Int
}

enum GatewayBPFDescriptorOpenResult {
    case success(GatewayBPFDescriptor)
    case failure(String)
}

func openConfiguredGatewayBPF(interfaceName: String) -> GatewayBPFDescriptorOpenResult {
    let openResult = openBPFDevice()
    guard let fd = openResult.fd else {
        return .failure(openResult.error ?? "could not open /dev/bpf for gateway probe")
    }

    var bpfTags: [String: String] = [:]
    guard configureBPF(fd: fd, interfaceName: interfaceName, tags: &bpfTags) else {
        close(fd)
        return .failure(bpfTags["bpf.error"] ?? "could not configure BPF for gateway probe")
    }
    return .success(
        GatewayBPFDescriptor(
            fd: fd,
            bufferLength: Int(bpfTags["bpf.buffer_length"] ?? "4096") ?? 4096
        )
    )
}
