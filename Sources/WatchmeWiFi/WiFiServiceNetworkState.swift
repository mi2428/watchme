import Foundation
import SystemConfiguration
import WatchmeCore

struct WiFiServiceNetworkState {
    let interfaceName: String?
    let serviceID: String?
    let routerIPv4: String?
    let routerHardwareAddress: String?
    let dnsServers: [String]

    var traceTags: [String: String] {
        var tags: [String: String] = [
            "network.wifi_dns_servers": dnsServers.joined(separator: ","),
        ]
        setTag(&tags, "network.wifi_interface", interfaceName)
        setTag(&tags, "network.wifi_service", serviceID)
        setTag(&tags, "network.wifi_gateway", routerIPv4)
        setTag(&tags, "network.wifi_gateway_hwaddr", routerHardwareAddress)
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
        return WiFiServiceNetworkState(interfaceName: nil, serviceID: nil, routerIPv4: nil, routerHardwareAddress: nil, dnsServers: [])
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
            dnsServers: stringArrayValue(dns["ServerAddresses"])
        )
    }

    return candidates.first { $0.routerIPv4 != nil || !$0.dnsServers.isEmpty }
        ?? candidates.first
        ?? WiFiServiceNetworkState(interfaceName: interfaceName, serviceID: nil, routerIPv4: nil, routerHardwareAddress: nil, dnsServers: [])
}

func dynamicStoreNetworkServiceIDs() -> [String] {
    guard let keys = SCDynamicStoreCopyKeyList(nil, "State:/Network/Service/.*/IPv4" as CFString) as? [String] else {
        return []
    }
    return keys.compactMap { serviceID(fromDynamicStoreKey: $0, suffix: "IPv4") }.sorted()
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
