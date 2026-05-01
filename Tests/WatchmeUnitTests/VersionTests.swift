@testable import WatchmeCore
import XCTest

final class VersionTests: XCTestCase {
    func testRenderVersionIncludesBuildMetadataInClockpingStyle() {
        let rendered = WatchmeVersion.render(WatchmeVersionInfo(
            packageName: "watchme",
            packageVersion: "test-version",
            gitDescribe: "vTEST-1-gabc123",
            gitCommit: "abc123",
            gitCommitDate: "2026-04-25T00:00:00+09:00",
            buildDate: "2026-04-25T01:00:00Z",
            buildHost: "aarch64-apple-darwin",
            buildTarget: "x86_64-unknown-linux-gnu",
            buildProfile: "release"
        ))
        let expected = [
            "watchme test-version (git vTEST-1-gabc123; commit abc123;",
            "commit date 2026-04-25T00:00:00+09:00; built 2026-04-25T01:00:00Z; release)",
            "on x86_64-unknown-linux-gnu (host aarch64-apple-darwin)\n",
        ].joined(separator: " ")

        XCTAssertEqual(rendered, expected)
    }

    func testLongVersionMatchesCurrentRenderWithoutBinaryName() {
        let info = WatchmeVersion.current
        let rendered = WatchmeVersion.render(info)
        let longVersion = rendered
            .dropFirst("\(info.packageName) ".count)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        XCTAssertEqual(WatchmeVersion.longVersion, longVersion)
    }
}
