@testable import WatchmeCore
import XCTest

final class CommandLineUtilitiesTests: XCTestCase {
    func testSplitInlineValueSeparatesOnlyTheFirstEqualsSign() {
        XCTAssertEqual(splitInlineValue("--otlp.url=http://host:4318").option, "--otlp.url")
        XCTAssertEqual(splitInlineValue("--otlp.url=http://host:4318").inlineValue, "http://host:4318")
        XCTAssertEqual(splitInlineValue("--flag").option, "--flag")
        XCTAssertNil(splitInlineValue("--flag").inlineValue)
        XCTAssertEqual(splitInlineValue("--label=a=b").inlineValue, "a=b")
    }

    func testRequireOptionValueConsumesNextArgumentOrUsesInlineValue() throws {
        var index = 0
        XCTAssertEqual(
            try requireOptionValue(
                arguments: ["--system.metrics.interval", "2.5"],
                index: &index,
                argument: "--system.metrics.interval",
                inlineValue: nil
            ),
            "2.5"
        )
        XCTAssertEqual(index, 1)

        var inlineIndex = 0
        XCTAssertEqual(
            try requireOptionValue(
                arguments: ["--system.metrics.interval=2.5"],
                index: &inlineIndex,
                argument: "--system.metrics.interval",
                inlineValue: "2.5"
            ),
            "2.5"
        )
        XCTAssertEqual(inlineIndex, 0)
    }

    func testRequireOptionValueRejectsMissingValues() {
        var missingIndex = 0
        XCTAssertThrowsError(
            try requireOptionValue(
                arguments: ["--system.metrics.interval"],
                index: &missingIndex,
                argument: "--system.metrics.interval",
                inlineValue: nil
            )
        )

        var emptyIndex = 0
        XCTAssertThrowsError(
            try requireOptionValue(
                arguments: ["--system.metrics.interval="],
                index: &emptyIndex,
                argument: "--system.metrics.interval",
                inlineValue: ""
            )
        )
    }

    func testValidatedOTLPURLAcceptsHTTPCollectorsWithoutQueryOrFragment() throws {
        XCTAssertEqual(
            try validatedOTLPURL("https://collector.example:4318/otlp", argument: "--otlp.url").absoluteString,
            "https://collector.example:4318/otlp"
        )
        XCTAssertThrowsError(try validatedOTLPURL("ftp://collector.example/otlp", argument: "--otlp.url"))
        XCTAssertThrowsError(try validatedOTLPURL("http://collector.example/otlp?debug=1", argument: "--otlp.url"))
        XCTAssertThrowsError(try validatedOTLPURL("http://collector.example/otlp#debug", argument: "--otlp.url"))
    }

    func testOTLPEndpointURLAppendsEndpointPathToBasePath() throws {
        let baseURL = try XCTUnwrap(URL(string: "http://collector.example:4318/otlp/"))

        XCTAssertEqual(
            otlpEndpointURL(baseURL: baseURL, path: "/v1/metrics").absoluteString,
            "http://collector.example:4318/otlp/v1/metrics"
        )
    }

    func testFormatUsageRowsAlignsDescriptions() {
        XCTAssertEqual(
            formatUsageRows([("--short", "Short option."), ("--longer VALUE", "Long option.")], leftColumnWidth: 16),
            "  --short         Short option.\n  --longer VALUE  Long option."
        )
    }
}
