// swift-tools-version: 5.9

import Foundation
import PackageDescription

let environment = ProcessInfo.processInfo.environment

func watchmeEnvironmentValue(_ name: String, default defaultValue: String) -> String {
    guard let value = environment[name]?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
        return defaultValue
    }
    return value
}

func cStringLiteral(_ value: String) -> String {
    let escaped = value.map { character in
        switch character {
        case "\\":
            "\\\\"
        case "\"":
            "\\\""
        case "\n":
            "\\n"
        case "\r":
            "\\r"
        case "\t":
            "\\t"
        default:
            String(character)
        }
    }.joined()
    return "\"\(escaped)\""
}

let watchmeBuildInfoCSettings: [CSetting] = [
    .define("WATCHME_PACKAGE_NAME", to: cStringLiteral(watchmeEnvironmentValue("WATCHME_PACKAGE_NAME", default: "watchme"))),
    .define("WATCHME_PACKAGE_VERSION", to: cStringLiteral(watchmeEnvironmentValue("WATCHME_VERSION", default: "0.1.0"))),
    .define("WATCHME_GIT_DESCRIBE", to: cStringLiteral(watchmeEnvironmentValue("WATCHME_GIT_DESCRIBE", default: "unknown"))),
    .define("WATCHME_GIT_COMMIT", to: cStringLiteral(watchmeEnvironmentValue("WATCHME_GIT_COMMIT", default: "unknown"))),
    .define("WATCHME_GIT_COMMIT_DATE", to: cStringLiteral(watchmeEnvironmentValue("WATCHME_GIT_COMMIT_DATE", default: "unknown"))),
    .define("WATCHME_BUILD_DATE", to: cStringLiteral(watchmeEnvironmentValue("WATCHME_BUILD_DATE", default: "unknown"))),
    .define("WATCHME_BUILD_HOST", to: cStringLiteral(watchmeEnvironmentValue("WATCHME_BUILD_HOST", default: "unknown"))),
    .define("WATCHME_BUILD_TARGET", to: cStringLiteral(watchmeEnvironmentValue("WATCHME_BUILD_TARGET", default: "unknown"))),
    .define("WATCHME_BUILD_PROFILE", to: cStringLiteral(watchmeEnvironmentValue("WATCHME_BUILD_PROFILE", default: "debug"))),
]

let package = Package(
    name: "watchme",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(name: "watchme", targets: ["watchme"]),
    ],
    dependencies: [
        .package(url: "https://github.com/open-telemetry/opentelemetry-swift.git", from: "2.3.0"),
        .package(url: "https://github.com/open-telemetry/opentelemetry-swift-core.git", from: "2.3.0"),
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "WatchmeBuildInfoC",
            cSettings: watchmeBuildInfoCSettings
        ),
        .target(
            name: "WatchmeCore",
            dependencies: [
                "WatchmeBuildInfoC",
            ]
        ),
        .target(
            name: "WatchmeTelemetry",
            dependencies: [
                "WatchmeCore",
                .product(name: "OpenTelemetryApi", package: "opentelemetry-swift-core"),
                .product(name: "OpenTelemetrySdk", package: "opentelemetry-swift-core"),
                .product(name: "OpenTelemetryProtocolExporterHTTP", package: "opentelemetry-swift"),
            ]
        ),
        .target(
            name: "WatchmeBPF",
            dependencies: [
                "WatchmeCore",
            ]
        ),
        .target(
            name: "WatchmeWiFi",
            dependencies: [
                "WatchmeBPF",
                "WatchmeCore",
                "WatchmeTelemetry",
            ],
            linkerSettings: [
                .linkedFramework("CoreWLAN"),
                .linkedFramework("CoreLocation"),
                .linkedFramework("Network"),
                .linkedFramework("SystemConfiguration"),
            ]
        ),
        .target(
            name: "WatchmeSystem",
            dependencies: [
                "WatchmeCore",
                "WatchmeTelemetry",
            ],
            linkerSettings: [
                .linkedFramework("IOKit"),
            ]
        ),
        .target(
            name: "WatchmeSelf",
            dependencies: [
                "WatchmeCore",
                "WatchmeTelemetry",
            ]
        ),
        .target(
            name: "WatchmeAgent",
            dependencies: [
                "WatchmeCore",
                "WatchmeSelf",
                "WatchmeSystem",
                "WatchmeWiFi",
            ]
        ),
        .executableTarget(
            name: "watchme",
            dependencies: [
                "WatchmeAgent",
                "WatchmeCore",
            ],
            exclude: ["Info.plist"],
            linkerSettings: [
                .unsafeFlags([
                    "-Xlinker",
                    "-sectcreate",
                    "-Xlinker",
                    "__TEXT",
                    "-Xlinker",
                    "__info_plist",
                    "-Xlinker",
                    "Sources/watchme/Info.plist",
                ]),
            ]
        ),
        .testTarget(
            name: "WatchmeUnitTests",
            dependencies: [
                "WatchmeBPF",
                "WatchmeAgent",
                "WatchmeSelf",
                "WatchmeTelemetry",
                "WatchmeSystem",
                "WatchmeWiFi",
            ]
        ),
    ],
    swiftLanguageVersions: [.v5]
)
