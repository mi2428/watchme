@testable import WatchmeWiFi

struct ARPTestPacket {
    let operation: UInt16
    let senderMAC: String
    let senderIP: String
    let targetMAC: String
    let targetIP: String
}

extension PassivePacketStoreTests {
    func dhcp(
        _ nanos: UInt64,
        xid: UInt32,
        type: UInt8,
        yiaddr: String? = nil,
        server: String? = nil,
        lease: UInt32? = nil
    ) -> DHCPObservation {
        DHCPObservation(
            interfaceName: "en0",
            wallNanos: nanos,
            xid: xid,
            messageType: type,
            yiaddr: yiaddr,
            serverIdentifier: server,
            leaseTimeSeconds: lease
        )
    }

    func icmp(
        _ nanos: UInt64,
        type: UInt8,
        source: String,
        destination: String,
        target: String? = nil,
        routerLifetime: UInt16? = nil,
        sourceLLA: String? = nil,
        targetLLA: String? = nil
    ) -> ICMPv6Observation {
        ICMPv6Observation(
            interfaceName: "en0",
            wallNanos: nanos,
            type: type,
            code: 0,
            sourceIP: source,
            destinationIP: destination,
            targetAddress: target,
            routerLifetimeSeconds: routerLifetime,
            sourceLinkLayerAddress: sourceLLA,
            targetLinkLayerAddress: targetLLA
        )
    }

    func arpRequest(_ nanos: UInt64, targetIP: String) -> ARPObservation {
        ARPObservation(
            interfaceName: "en0",
            wallNanos: nanos,
            operation: 1,
            senderHardwareAddress: "de:ad:be:ef:00:01",
            senderProtocolAddress: "192.168.1.44",
            targetHardwareAddress: "00:00:00:00:00:00",
            targetProtocolAddress: targetIP
        )
    }

    func arpReply(_ nanos: UInt64, senderIP: String, senderMAC: String) -> ARPObservation {
        ARPObservation(
            interfaceName: "en0",
            wallNanos: nanos,
            operation: 2,
            senderHardwareAddress: senderMAC,
            senderProtocolAddress: senderIP,
            targetHardwareAddress: "de:ad:be:ef:00:01",
            targetProtocolAddress: "192.168.1.44"
        )
    }

    func arp(_ nanos: UInt64, packet: ARPTestPacket) -> ARPObservation {
        ARPObservation(
            interfaceName: "en0",
            wallNanos: nanos,
            operation: packet.operation,
            senderHardwareAddress: packet.senderMAC,
            senderProtocolAddress: packet.senderIP,
            targetHardwareAddress: packet.targetMAC,
            targetProtocolAddress: packet.targetIP
        )
    }
}
