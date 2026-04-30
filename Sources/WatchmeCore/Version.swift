import Foundation
import WatchmeBuildInfoC

public struct WatchmeVersionInfo: Equatable {
    public let packageName: String
    public let packageVersion: String
    public let gitDescribe: String
    public let gitCommit: String
    public let gitCommitDate: String
    public let buildDate: String
    public let buildHost: String
    public let buildTarget: String
    public let buildProfile: String

    public init(
        packageName: String,
        packageVersion: String,
        gitDescribe: String,
        gitCommit: String,
        gitCommitDate: String,
        buildDate: String,
        buildHost: String,
        buildTarget: String,
        buildProfile: String
    ) {
        self.packageName = packageName
        self.packageVersion = packageVersion
        self.gitDescribe = gitDescribe
        self.gitCommit = gitCommit
        self.gitCommitDate = gitCommitDate
        self.buildDate = buildDate
        self.buildHost = buildHost
        self.buildTarget = buildTarget
        self.buildProfile = buildProfile
    }
}

public enum WatchmeVersion {
    public static var current: WatchmeVersionInfo {
        WatchmeVersionInfo(
            packageName: stringFromCString(watchme_package_name()),
            packageVersion: stringFromCString(watchme_package_version()),
            gitDescribe: stringFromCString(watchme_git_describe()),
            gitCommit: stringFromCString(watchme_git_commit()),
            gitCommitDate: stringFromCString(watchme_git_commit_date()),
            buildDate: stringFromCString(watchme_build_date()),
            buildHost: stringFromCString(watchme_build_host()),
            buildTarget: stringFromCString(watchme_build_target()),
            buildProfile: stringFromCString(watchme_build_profile())
        )
    }

    public static var longVersion: String {
        renderLong(current)
    }

    public static var versionLine: String {
        render(current)
    }

    public static func render(_ info: WatchmeVersionInfo) -> String {
        "\(info.packageName) \(renderLong(info))\n"
    }

    public static func renderLong(_ info: WatchmeVersionInfo) -> String {
        [
            "\(info.packageVersion) (git \(info.gitDescribe); commit \(info.gitCommit);",
            "commit date \(info.gitCommitDate); built \(info.buildDate); \(info.buildProfile))",
            "on \(info.buildTarget) (host \(info.buildHost))",
        ].joined(separator: " ")
    }
}

private func stringFromCString(_ pointer: UnsafePointer<CChar>?) -> String {
    guard let pointer else {
        return "unknown"
    }
    return String(cString: pointer)
}
