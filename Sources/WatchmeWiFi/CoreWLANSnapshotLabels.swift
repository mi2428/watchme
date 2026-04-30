import CoreWLAN
import Foundation

func normalizedSSID(ssid: String?, ssidData: Data?) -> (value: String?, encoding: String) {
    if let ssid {
        return (ssid, "utf8")
    }
    guard let ssidData, !ssidData.isEmpty else {
        return (nil, "unknown")
    }
    // CoreWLAN can fail to decode unusual SSID bytes as text while still
    // returning ssidData(). Preserve the ESSID label as deterministic hex.
    return ("hex:\(ssidData.map { String(format: "%02x", $0) }.joined())", "hex")
}

func normalizedCountryCode(_ countryCode: String?) -> String? {
    guard let countryCode, !countryCode.isEmpty else {
        return nil
    }
    return countryCode.lowercased()
}

func coreWLANPHYModeName(_ mode: CWPHYMode?) -> String? {
    guard let mode else {
        return nil
    }
    switch mode.rawValue {
    case 0: return "none"
    case 1: return "11a"
    case 2: return "11b"
    case 3: return "11g"
    case 4: return "11n"
    case 5: return "11ac"
    case 6: return "11ax"
    case 7: return "11be"
    default: return "unknown"
    }
}

func coreWLANInterfaceModeName(_ mode: CWInterfaceMode?) -> String? {
    guard let mode else {
        return nil
    }
    switch mode.rawValue {
    case 0: return "none"
    case 1: return "station"
    case 2: return "ibss"
    case 3: return "host_ap"
    default: return "unknown"
    }
}

func coreWLANSecurityName(_ security: CWSecurity?) -> String? {
    guard let security else {
        return nil
    }
    return [
        0: "open",
        1: "wep",
        2: "wpa_personal",
        3: "wpa_personal_mixed",
        4: "wpa2_personal",
        5: "personal",
        6: "dynamic_wep",
        7: "wpa_enterprise",
        8: "wpa_enterprise_mixed",
        9: "wpa2_enterprise",
        10: "enterprise",
        11: "wpa3_personal",
        12: "wpa3_enterprise",
        13: "wpa3_transition",
        14: "owe",
        15: "owe_transition",
    ][security.rawValue] ?? "unknown"
}

func coreWLANChannelBandName(_ band: CWChannelBand?) -> String? {
    guard let band else {
        return nil
    }
    switch band.rawValue {
    case 0: return "unknown"
    case 1: return "2ghz"
    case 2: return "5ghz"
    case 3: return "6ghz"
    default: return "unknown"
    }
}

func coreWLANChannelWidthName(_ width: CWChannelWidth?) -> String? {
    guard let width else {
        return nil
    }
    switch width.rawValue {
    case 0: return "unknown"
    case 1: return "20mhz"
    case 2: return "40mhz"
    case 3: return "80mhz"
    case 4: return "160mhz"
    default: return "unknown"
    }
}

func coreWLANChannelWidthMHz(_ width: CWChannelWidth?) -> Int? {
    guard let width else {
        return nil
    }
    switch width.rawValue {
    case 1: return 20
    case 2: return 40
    case 3: return 80
    case 4: return 160
    default: return nil
    }
}
