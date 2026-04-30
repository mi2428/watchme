// swift-tools-version: 5.9

import PackageDescription

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
            name: "WatchmeCore"
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
            name: "WatchmeAgent",
            dependencies: [
                "WatchmeCore",
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
                "WatchmeTelemetry",
                "WatchmeSystem",
                "WatchmeWiFi",
            ]
        ),
    ],
    swiftLanguageVersions: [.v5]
)
