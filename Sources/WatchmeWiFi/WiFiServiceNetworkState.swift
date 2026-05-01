import Foundation
import SystemConfiguration
import WatchmeCore

struct WiFiServiceNetworkState {
    let interfaceName: String?
    let serviceID: String?
    let routerIPv4: String?
    let routerHardwareAddress: String?
    let routerIPv6: String?
    let routerIPv6HardwareAddress: String?
    let dnsServers: [String]

    init(
        interfaceName: String?,
        serviceID: String?,
        routerIPv4: String?,
        routerHardwareAddress: String?,
        routerIPv6: String? = nil,
        routerIPv6HardwareAddress: String? = nil,
        dnsServers: [String]
    ) {
        self.interfaceName = interfaceName
        self.serviceID = serviceID
        self.routerIPv4 = routerIPv4
        self.routerHardwareAddress = routerHardwareAddress
        self.routerIPv6 = routerIPv6.map(normalizedIPv6Scope)
        self.routerIPv6HardwareAddress = routerIPv6HardwareAddress
        self.dnsServers = dnsServers
    }

    var traceTags: [String: String] {
        var tags: [String: String] = [
            "network.wifi_dns_servers": dnsServers.joined(separator: ","),
        ]
        setTag(&tags, "network.wifi_interface", interfaceName)
        setTag(&tags, "network.wifi_service", serviceID)
        setTag(&tags, "network.wifi_gateway", routerIPv4)
        setTag(&tags, "network.wifi_gateway_hwaddr", routerHardwareAddress)
        setTag(&tags, "network.wifi_ipv6_gateway", routerIPv6)
        setTag(&tags, "network.wifi_ipv6_gateway_hwaddr", routerIPv6HardwareAddress)
        return tags
    }
}

func currentWiFiServiceNetworkState(interfaceName: String?) -> WiFiServiceNetworkState {
    let serviceIDs = dynamicStoreNetworkServiceIDs()
    return wifiServiceNetworkState(interfaceName: interfaceName, serviceIDs: serviceIDs, valueForKey: dynamicStoreDictionary)
}

func wifiServiceNetworkState(
    interfaceName: String?,
    serviceIDs: [String],
    valueForKey: (String) -> [String: Any]
) -> WiFiServiceNetworkState {
    guard let interfaceName, !interfaceName.isEmpty else {
        return WiFiServiceNetworkState(
            interfaceName: nil,
            serviceID: nil,
            routerIPv4: nil,
            routerHardwareAddress: nil,
            routerIPv6: nil,
            routerIPv6HardwareAddress: nil,
            dnsServers: []
        )
    }

    let candidates = serviceIDs.compactMap { serviceID -> WiFiServiceNetworkState? in
        let ipv4 = valueForKey("State:/Network/Service/\(serviceID)/IPv4")
        let ipv6 = valueForKey("State:/Network/Service/\(serviceID)/IPv6")
        let dns = valueForKey("State:/Network/Service/\(serviceID)/DNS")
        let setupInterface = valueForKey("Setup:/Network/Service/\(serviceID)/Interface")
        // Default-route tags are not enough on Macs with Ethernet or VPN.
        // Match the SystemConfiguration service back to CoreWLAN's interface
        // so active DNS and gateway probes describe the Wi-Fi path itself.
        let serviceInterface =
            stringValue(ipv4["InterfaceName"])
                ?? stringValue(ipv6["InterfaceName"])
                ?? stringValue(setupInterface["DeviceName"])
        guard serviceInterface == interfaceName else {
            return nil
        }
        return WiFiServiceNetworkState(
            interfaceName: interfaceName,
            serviceID: serviceID,
            routerIPv4: stringValue(ipv4["Router"]),
            routerHardwareAddress: stringValue(ipv4["ARPResolvedHardwareAddress"]),
            routerIPv6: stringValue(ipv6["Router"]).map(normalizedIPv6Scope),
            routerIPv6HardwareAddress: routerHardwareAddress(fromNetworkSignature: stringValue(ipv6["NetworkSignature"])),
            dnsServers: stringArrayValue(dns["ServerAddresses"])
        )
    }

    return candidates.first { $0.routerIPv4 != nil || $0.routerIPv6 != nil || !$0.dnsServers.isEmpty }
        ?? candidates.first
        ?? WiFiServiceNetworkState(
            interfaceName: interfaceName,
            serviceID: nil,
            routerIPv4: nil,
            routerHardwareAddress: nil,
            routerIPv6: nil,
            routerIPv6HardwareAddress: nil,
            dnsServers: []
        )
}

func dynamicStoreNetworkServiceIDs() -> [String] {
    let ipv4Keys = (SCDynamicStoreCopyKeyList(nil, "State:/Network/Service/.*/IPv4" as CFString) as? [String]) ?? []
    let ipv6Keys = (SCDynamicStoreCopyKeyList(nil, "State:/Network/Service/.*/IPv6" as CFString) as? [String]) ?? []
    let ids = ipv4Keys.compactMap { serviceID(fromDynamicStoreKey: $0, suffix: "IPv4") }
        + ipv6Keys.compactMap { serviceID(fromDynamicStoreKey: $0, suffix: "IPv6") }
    return Array(Set(ids)).sorted()
}

func serviceID(fromDynamicStoreKey key: String, suffix: String) -> String? {
    let prefix = "State:/Network/Service/"
    let keySuffix = "/\(suffix)"
    guard key.hasPrefix(prefix), key.hasSuffix(keySuffix) else {
        return nil
    }
    return String(key.dropFirst(prefix.count).dropLast(keySuffix.count))
}

func stringArrayValue(_ value: Any?) -> [String] {
    switch value {
    case let values as [String]:
        values.filter { !$0.isEmpty }
    case let values as [Any]:
        values.compactMap(stringValue).filter { !$0.isEmpty }
    case let value as String:
        value.isEmpty ? [] : [value]
    default:
        []
    }
}

func routerHardwareAddress(fromNetworkSignature signature: String?) -> String? {
    guard let signature else {
        return nil
    }
    let prefix = "IPv6.RouterHardwareAddress="
    for component in signature.split(separator: ";") {
        let trimmed = component.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix(prefix) else {
            continue
        }
        let value = String(trimmed.dropFirst(prefix.count)).lowercased()
        return value.isEmpty ? nil : value
    }
    return nil
}
