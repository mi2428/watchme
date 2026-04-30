@testable import WatchmeCore
import XCTest

final class CommandLineUtilitiesTests: XCTestCase {
    func testSplitInlineValueSeparatesOnlyTheFirstEqualsSign() {
        XCTAssertEqual(splitInlineValue("--collector.url=http://host:4318").option, "--collector.url")
        XCTAssertEqual(splitInlineValue("--collector.url=http://host:4318").inlineValue, "http://host:4318")
        XCTAssertEqual(splitInlineValue("--flag").option, "--flag")
        XCTAssertNil(splitInlineValue("--flag").inlineValue)
        XCTAssertEqual(splitInlineValue("--label=a=b").inlineValue, "a=b")
    }

    func testRequireOptionValueConsumesNextArgumentOrUsesInlineValue() throws {
        var index = 0
        XCTAssertEqual(
            try requireOptionValue(
                arguments: ["--metrics.interval", "2.5"],
                index: &index,
                argument: "--metrics.interval",
                inlineValue: nil
            ),
            "2.5"
        )
        XCTAssertEqual(index, 1)

        var inlineIndex = 0
        XCTAssertEqual(
            try requireOptionValue(
                arguments: ["--metrics.interval=2.5"],
                index: &inlineIndex,
                argument: "--metrics.interval",
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
                arguments: ["--metrics.interval"],
                index: &missingIndex,
                argument: "--metrics.interval",
                inlineValue: nil
            )
        )

        var emptyIndex = 0
        XCTAssertThrowsError(
            try requireOptionValue(arguments: ["--metrics.interval="], index: &emptyIndex, argument: "--metrics.interval", inlineValue: "")
        )
    }

    func testValidatedCollectorURLAcceptsHTTPCollectorsWithoutQueryOrFragment() throws {
        XCTAssertEqual(
            try validatedCollectorURL("https://collector.example:4318/otlp", argument: "--collector.url").absoluteString,
            "https://collector.example:4318/otlp"
        )
        XCTAssertThrowsError(try validatedCollectorURL("ftp://collector.example/otlp", argument: "--collector.url"))
        XCTAssertThrowsError(try validatedCollectorURL("http://collector.example/otlp?debug=1", argument: "--collector.url"))
        XCTAssertThrowsError(try validatedCollectorURL("http://collector.example/otlp#debug", argument: "--collector.url"))
    }

    func testCollectorEndpointURLAppendsEndpointPathToBasePath() throws {
        let baseURL = try XCTUnwrap(URL(string: "http://collector.example:4318/otlp/"))

        XCTAssertEqual(
            collectorEndpointURL(baseURL: baseURL, path: "/v1/metrics").absoluteString,
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
