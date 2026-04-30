import Foundation

struct WiFiConnectivityCheckReadiness: Equatable {
    let ready: Bool
    let skipReason: String?

    static let ready = WiFiConnectivityCheckReadiness(ready: true, skipReason: nil)

    static func skip(_ reason: String) -> WiFiConnectivityCheckReadiness {
        WiFiConnectivityCheckReadiness(ready: false, skipReason: reason)
    }
}

enum WiFiTracePolicy {
    static func isAssociationRecoveryReason(_ reason: String) -> Bool {
        reason == "wifi.join" || reason == "wifi.roam"
    }

    static func shouldRequestConnectivityCheck(snapshot: WiFiSnapshot) -> Bool {
        snapshot.powerOn != false && snapshot.isAssociated
    }

    static func isAddressAcquisition(previous: WiFiSnapshot, current: WiFiSnapshot) -> Bool {
        current.isAssociated && previous.primaryIPv4 == nil && current.primaryIPv4 != nil
    }

    static func shouldSuppressEventTraceDuringAssociation(reason: String) -> Bool {
        !isAssociationRecoveryReason(reason) && reason != "wifi.disconnect"
    }

    static func connectivityCheckReadiness(
        snapshot: WiFiSnapshot,
        networkState: WiFiServiceNetworkState,
        config: WiFiConfig
    ) -> WiFiConnectivityCheckReadiness {
        if snapshot.powerOn == false {
            return .skip("wifi_power_off")
        }
        guard snapshot.isAssociated else {
            return .skip("wifi_not_associated")
        }
        guard snapshot.interfaceName?.isEmpty == false else {
            return .skip("wifi_interface_unknown")
        }
        if requiresWiFiDNS(config: config), networkState.dnsServers.isEmpty {
            return .skip("wifi_dns_unavailable")
        }
        return .ready
    }

    private static func requiresWiFiDNS(config: WiFiConfig) -> Bool {
        config.probeInternetDNS || config.probeInternetICMP || config.probeInternetTCP || config.probeInternetHTTP
    }
}
