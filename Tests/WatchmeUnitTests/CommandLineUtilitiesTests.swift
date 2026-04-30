@testable import WatchmeCore
import XCTest

final class CommandLineUtilitiesTests: XCTestCase {
    func testSplitInlineValueSeparatesOnlyTheFirstEqualsSign() {
        let option = WatchmeCLI.Option.otlpURL.name

        XCTAssertEqual(splitInlineValue("\(option)=http://host:4318").option, option)
        XCTAssertEqual(splitInlineValue("\(option)=http://host:4318").inlineValue, "http://host:4318")
        XCTAssertEqual(splitInlineValue("--flag").option, "--flag")
        XCTAssertNil(splitInlineValue("--flag").inlineValue)
        XCTAssertEqual(splitInlineValue("--label=a=b").inlineValue, "a=b")
    }

    func testRequireOptionValueConsumesNextArgumentOrUsesInlineValue() throws {
        let option = "--value"
        var index = 0
        XCTAssertEqual(
            try requireOptionValue(
                arguments: [option, "2.5"],
                index: &index,
                argument: option,
                inlineValue: nil
            ),
            "2.5"
        )
        XCTAssertEqual(index, 1)

        var inlineIndex = 0
        XCTAssertEqual(
            try requireOptionValue(
                arguments: ["\(option)=2.5"],
                index: &inlineIndex,
                argument: option,
                inlineValue: "2.5"
            ),
            "2.5"
        )
        XCTAssertEqual(inlineIndex, 0)
    }

    func testRequireOptionValueRejectsMissingValues() {
        let option = "--value"
        var missingIndex = 0
        XCTAssertThrowsError(
            try requireOptionValue(
                arguments: [option],
                index: &missingIndex,
                argument: option,
                inlineValue: nil
            )
        )

        var emptyIndex = 0
        XCTAssertThrowsError(
            try requireOptionValue(
                arguments: ["\(option)="],
                index: &emptyIndex,
                argument: option,
                inlineValue: ""
            )
        )
    }

    func testValidatedOTLPURLAcceptsHTTPCollectorsWithoutQueryOrFragment() throws {
        let option = WatchmeCLI.Option.otlpURL.name

        XCTAssertEqual(
            try validatedOTLPURL("https://collector.example:4318/otlp", argument: option).absoluteString,
            "https://collector.example:4318/otlp"
        )
        XCTAssertThrowsError(try validatedOTLPURL("ftp://collector.example/otlp", argument: option))
        XCTAssertThrowsError(try validatedOTLPURL("http://collector.example/otlp?debug=1", argument: option))
        XCTAssertThrowsError(try validatedOTLPURL("http://collector.example/otlp#debug", argument: option))
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

    func testLogMessageFormattingQuotesMessagesAndNormalizesEventNames() {
        XCTAssertEqual(logMessageText("watchme_system_metrics_exported"), "watchme system metrics exported")
        XCTAssertEqual(logfmtQuoted("watchme system metrics exported"), "\"watchme system metrics exported\"")
        XCTAssertEqual(logfmtQuoted("quote \"value\""), "\"quote \\\"value\\\"\"")
    }
}
