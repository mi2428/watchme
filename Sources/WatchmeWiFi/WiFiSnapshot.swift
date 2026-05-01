import CoreWLAN
import Darwin
import Foundation
import WatchmeBPF
import WatchmeCore

struct NativeInterfaceState {
    let isActive: Bool
    let ipv4Addresses: [String]
    let ipv6Addresses: [String]
    let ipv6LinkLocalAddresses: [String]
    let macAddress: String?

    init(
        isActive: Bool,
        ipv4Addresses: [String],
        ipv6Addresses: [String],
        macAddress: String?,
        ipv6LinkLocalAddresses: [String] = []
    ) {
        self.isActive = isActive
        self.ipv4Addresses = ipv4Addresses
        self.ipv6Addresses = ipv6Addresses
        self.ipv6LinkLocalAddresses = ipv6LinkLocalAddresses
        self.macAddress = macAddress
    }
}

struct WiFiSnapshot {
    let capturedWallNanos: UInt64
    let interfaceName: String?
    let ssid: String?
    let ssidEncoding: String?
    let bssid: String?
    let isAssociated: Bool
    let rssiDBM: Int?
    let noiseDBM: Int?
    let txRateMbps: Double?
    let channel: Int?
    let channelBand: String?
    let channelWidth: String?
    let channelWidthMHz: Int?
    let phyMode: String?
    let security: String?
    let interfaceMode: String?
    let countryCode: String?
    let transmitPowerMW: Int?
    let powerOn: Bool?
    let serviceActive: Bool?
    let ipv4Addresses: [String]
    let ipv6Addresses: [String]

    var primaryIPv4: String? {
        ipv4Addresses.first
    }

    var metricLabels: [String: String] {
        // Keep metric attribute cardinality stable. When macOS redacts
        // identity fields, the label keys remain present with "unknown" values.
        [
            "interface": interfaceName ?? "unknown",
            "essid": ssid ?? "unknown",
            "bssid": bssid ?? "unknown",
        ]
    }

    var traceTags: [String: String] {
        var tags: [String: String] = [
            "wifi.associated": isAssociated ? "true" : "false",
            "wifi.identity_available": identityAvailable ? "true" : "false",
            "wifi.identity_status": identityStatus,
            "wifi.essid": ssid ?? "unknown",
            "wifi.ssid": ssid ?? "unknown",
            "wifi.essid_encoding": ssidEncoding ?? "unknown",
            "wifi.bssid": bssid ?? "unknown",
            "wifi.snapshot_epoch_ns": "\(capturedWallNanos)",
            "wifi.snapshot_timestamp_source": "corewlan_getifaddrs_snapshot",
            "wifi.channel_band": channelBand ?? "unknown",
            "wifi.channel_width": channelWidth ?? "unknown",
            "wifi.phy_mode": phyMode ?? "unknown",
            "wifi.security": security ?? "unknown",
            "wifi.interface_mode": interfaceMode ?? "unknown",
            "wifi.country_code": countryCode ?? "unknown",
            "network.ipv4_addresses": ipv4Addresses.joined(separator: ","),
            "network.ipv6_addresses": ipv6Addresses.joined(separator: ","),
        ]
        setTag(&tags, "wifi.interface", interfaceName)
        setTag(&tags, "network.local_ip", primaryIPv4)
        if let rssiDBM {
            tags["wifi.rssi_dbm"] = "\(rssiDBM)"
        }
        if let noiseDBM {
            tags["wifi.noise_dbm"] = "\(noiseDBM)"
        }
        if let txRateMbps {
            tags["wifi.tx_rate_mbps"] = String(format: "%.1f", txRateMbps)
        }
        if let channel {
            tags["wifi.channel"] = "\(channel)"
        }
        if let channelWidthMHz {
            tags["wifi.channel_width_mhz"] = "\(channelWidthMHz)"
        }
        if let transmitPowerMW {
            tags["wifi.transmit_power_mw"] = "\(transmitPowerMW)"
        }
        if let powerOn {
            tags["wifi.power_on"] = powerOn ? "true" : "false"
        }
        if let serviceActive {
            tags["wifi.service_active"] = serviceActive ? "true" : "false"
        }
        return tags
    }

    var identityAvailable: Bool {
        ssid != nil && bssid != nil
    }

    var identityStatus: String {
        if identityAvailable {
            return "available"
        }
        // A live interface with RSSI/IP data but no SSID/BSSID usually means
        // CoreWLAN identity fields are redacted by Location Services policy.
        if isAssociated {
            return "redacted_or_unavailable"
        }
        return "disconnected"
    }

    var signature: String {
        [
            interfaceName ?? "-",
            isAssociated ? "associated" : "disconnected",
            ssid ?? "-",
            bssid ?? "-",
            channel.map(String.init) ?? "-",
            channelBand ?? "-",
            channelWidth ?? "-",
            phyMode ?? "-",
            security ?? "-",
            interfaceMode ?? "-",
            countryCode ?? "-",
            powerOn.map { $0 ? "power_on" : "power_off" } ?? "-",
            serviceActive.map { $0 ? "service_active" : "service_inactive" } ?? "-",
            primaryIPv4 ?? "-",
        ].joined(separator: "|")
    }

    static func capture() -> WiFiSnapshot {
        // Keep this snapshot limited to OS-reported state. Derived quality
        // scores belong in downstream rules where operators can own
        // the scoring policy instead of baking one into WatchMe Agent.
        let interface = CWWiFiClient.shared().interface()
        let interfaceName = interface?.interfaceName ?? nativeWiFiInterfaceName()
        let state =
            interfaceName.map(nativeInterfaceState(interfaceName:))
                ?? NativeInterfaceState(
                    isActive: false,
                    ipv4Addresses: [],
                    ipv6Addresses: [],
                    macAddress: nil
                )
        let ssid = interface?.ssid()
        let ssidData = interface?.ssidData()
        let bssid = interface?.bssid()?.lowercased()
        let powerOn = interface.map { $0.powerOn() }
        let channel = interface?.wlanChannel()
        let isAssociated = wifiSnapshotAssociated(ssid: ssid, bssid: bssid, state: state, powerOn: powerOn)
        let ssidFallback = normalizedSSID(ssid: ssid, ssidData: ssidData)

        return WiFiSnapshot(
            capturedWallNanos: wallClockNanos(),
            interfaceName: interfaceName,
            ssid: ssidFallback.value,
            ssidEncoding: ssidFallback.encoding,
            bssid: bssid,
            isAssociated: isAssociated,
            rssiDBM: interface?.rssiValue(),
            noiseDBM: interface?.noiseMeasurement(),
            txRateMbps: interface?.transmitRate(),
            channel: channel?.channelNumber,
            channelBand: coreWLANChannelBandName(channel?.channelBand),
            channelWidth: coreWLANChannelWidthName(channel?.channelWidth),
            channelWidthMHz: coreWLANChannelWidthMHz(channel?.channelWidth),
            phyMode: coreWLANPHYModeName(interface?.activePHYMode()),
            security: coreWLANSecurityName(interface?.security()),
            interfaceMode: coreWLANInterfaceModeName(interface?.interfaceMode()),
            countryCode: normalizedCountryCode(interface?.countryCode()),
            transmitPowerMW: interface.map { $0.transmitPower() },
            powerOn: powerOn,
            serviceActive: interface.map { $0.serviceActive() },
            ipv4Addresses: state.ipv4Addresses,
            ipv6Addresses: state.ipv6Addresses
        )
    }

    func changedFields(from previous: WiFiSnapshot) -> [String] {
        var fields: [String] = []
        appendChange(&fields, "ssid", previous.ssid, ssid)
        appendChange(&fields, "bssid", previous.bssid, bssid)
        appendChange(&fields, "associated", previous.isAssociated, isAssociated)
        appendChange(&fields, "channel", previous.channel, channel)
        appendChange(&fields, "channel_band", previous.channelBand, channelBand)
        appendChange(&fields, "channel_width", previous.channelWidth, channelWidth)
        appendChange(&fields, "country_code", previous.countryCode, countryCode)
        appendChange(&fields, "phy_mode", previous.phyMode, phyMode)
        appendChange(&fields, "security", previous.security, security)
        appendChange(&fields, "interface_mode", previous.interfaceMode, interfaceMode)
        appendChange(&fields, "power_on", previous.powerOn, powerOn)
        appendChange(&fields, "service_active", previous.serviceActive, serviceActive)
        return fields
    }
}

func wifiSnapshotAssociated(ssid: String?, bssid: String?, state: NativeInterfaceState, powerOn: Bool?) -> Bool {
    if powerOn == false {
        return false
    }
    return ssid != nil || bssid != nil || (state.isActive && !state.ipv4Addresses.isEmpty)
}

func appendChange<T: Equatable>(_ fields: inout [String], _ field: String, _ previous: T?, _ current: T?) {
    if previous != current {
        fields.append(field)
    }
}

func appendChange<T: Equatable>(_ fields: inout [String], _ field: String, _ previous: T, _ current: T) {
    if previous != current {
        fields.append(field)
    }
}

func nativeWiFiInterfaceName() -> String? {
    if let name = CWWiFiClient.shared().interface()?.interfaceName {
        return name
    }
    return CWWiFiClient.shared().interfaceNames()?.sorted().first
}

func nativeInterfaceState(interfaceName: String) -> NativeInterfaceState {
    var addresses: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&addresses) == 0, let first = addresses else {
        return NativeInterfaceState(isActive: false, ipv4Addresses: [], ipv6Addresses: [], macAddress: nil)
    }
    defer { freeifaddrs(addresses) }

    var sawInterface = false
    var flags: UInt32 = 0
    var ipv4: [String] = []
    var ipv6: [String] = []
    var ipv6LinkLocal: [String] = []
    var macAddress: String?

    var cursor: UnsafeMutablePointer<ifaddrs>? = first
    while let current = cursor {
        defer { cursor = current.pointee.ifa_next }

        guard String(cString: current.pointee.ifa_name) == interfaceName else {
            continue
        }
        sawInterface = true
        flags = current.pointee.ifa_flags

        guard let address = current.pointee.ifa_addr else {
            continue
        }
        let family = Int32(address.pointee.sa_family)
        if family == AF_LINK {
            address.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { pointer in
                let linkAddress = pointer.pointee
                let addressLength = Int(linkAddress.sdl_alen)
                guard addressLength == 6 else {
                    return
                }
                let dataOffset = MemoryLayout<sockaddr_dl>.offset(of: \.sdl_data)! + Int(linkAddress.sdl_nlen)
                guard dataOffset + addressLength <= Int(linkAddress.sdl_len) else {
                    return
                }
                let bytes = UnsafeRawPointer(pointer)
                    .advanced(by: dataOffset)
                    .assumingMemoryBound(to: UInt8.self)
                macAddress = macAddressString(bytes: (0 ..< addressLength).map { bytes[$0] })
            }
            continue
        }
        guard family == AF_INET || family == AF_INET6 else {
            continue
        }

        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let rc = getnameinfo(
            address,
            socklen_t(address.pointee.sa_len),
            &host,
            socklen_t(host.count),
            nil,
            0,
            NI_NUMERICHOST
        )
        guard rc == 0 else {
            continue
        }
        let value = normalizedIPv6Scope(String(cString: host))
        if family == AF_INET {
            ipv4.append(value)
        } else if value.hasPrefix("fe80:") {
            ipv6LinkLocal.append(value)
        } else {
            ipv6.append(value)
        }
    }

    let isUp = (flags & UInt32(IFF_UP)) != 0
    let isRunning = (flags & UInt32(IFF_RUNNING)) != 0
    return NativeInterfaceState(
        isActive: sawInterface && isUp && isRunning,
        ipv4Addresses: ipv4,
        ipv6Addresses: ipv6,
        macAddress: macAddress,
        ipv6LinkLocalAddresses: ipv6LinkLocal
    )
}

func normalizedIPv6Scope(_ value: String) -> String {
    guard let percent = value.firstIndex(of: "%") else {
        return value
    }
    return String(value[..<percent])
}
