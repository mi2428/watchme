import CoreLocation
import Foundation
import WatchmeCore

func requestWiFiLocationAuthorization(timeout: TimeInterval) -> Int32 {
    guard CLLocationManager.locationServicesEnabled() else {
        logEvent(.error, "location_services_disabled")
        return 2
    }

    let requester = LocationAuthorizationRequester(timeout: timeout)
    let status = requester.request()
    logEvent(.info, "location_authorization_finished", fields: ["status": locationAuthorizationStatusName(status)])

    switch status {
    case .authorizedAlways, .authorizedWhenInUse:
        return 0
    case .notDetermined:
        logEvent(.warn, "location_authorization_timeout", fields: ["timeout_seconds": String(format: "%.1f", timeout)])
        return 2
    case .denied, .restricted:
        return 3
    @unknown default:
        return 3
    }
}

private final class LocationAuthorizationRequester: NSObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    private let timeout: TimeInterval
    private var finished = false

    init(timeout: TimeInterval) {
        self.timeout = max(timeout, 1)
        super.init()
        manager.delegate = self
    }

    func request() -> CLAuthorizationStatus {
        let initialStatus = manager.authorizationStatus
        logEvent(.info, "location_authorization_status", fields: ["status": locationAuthorizationStatusName(initialStatus)])

        guard initialStatus == .notDetermined else {
            return initialStatus
        }

        // CoreWLAN does not trigger the consent sheet by itself when SSID/BSSID
        // are redacted. Request Core Location explicitly from the .app bundle so
        // TCC stores authorization against the same identity that later reads Wi-Fi.
        manager.requestWhenInUseAuthorization()

        let deadline = Date().addingTimeInterval(timeout)
        while !finished, Date() < deadline {
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
        }
        return manager.authorizationStatus
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = manager.authorizationStatus
        logEvent(.debug, "location_authorization_changed", fields: ["status": locationAuthorizationStatusName(status)])
        finished = status != .notDetermined
    }
}

private func locationAuthorizationStatusName(_ status: CLAuthorizationStatus) -> String {
    switch status {
    case .notDetermined:
        "not_determined"
    case .restricted:
        "restricted"
    case .denied:
        "denied"
    case .authorizedAlways:
        "authorized_always"
    case .authorizedWhenInUse:
        "authorized_when_in_use"
    @unknown default:
        "unknown"
    }
}
