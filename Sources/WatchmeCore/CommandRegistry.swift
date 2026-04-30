import Darwin
import Foundation

public protocol WatchmeCommand {
    static var name: String { get }
    static var summary: String { get }
    init(arguments: [String]) throws
    func run() -> Int32
    static func printUsage()
}

public struct CommandRegistry {
    private let commands: [any WatchmeCommand.Type]

    public init(commands: [any WatchmeCommand.Type]) {
        self.commands = commands
    }

    public func parse(_ arguments: [String]) throws -> any WatchmeCommand {
        guard arguments.count >= 2 else {
            printUsage()
            exit(0)
        }

        let commandName = arguments[1]
        if commandName == WatchmeCLI.Command.help || commandName == WatchmeCLI.Option.help || commandName == WatchmeCLI.Option.shortHelp {
            printUsage()
            exit(0)
        }

        if commandName == WatchmeCLI.Option.version || commandName == WatchmeCLI.Option.shortVersion {
            print(WatchmeVersion.versionLine, terminator: "")
            exit(0)
        }

        guard let command = commands.first(where: { $0.name == commandName }) else {
            throw WatchmeError.invalidArgument("Unknown command: \(commandName)")
        }
        return try command.init(arguments: Array(arguments.dropFirst(2)))
    }

    public func printUsage() {
        let commandList =
            commands
                .map { "      \($0.name.padding(toLength: 11, withPad: " ", startingAt: 0))\($0.summary)" }
                .joined(separator: "\n")
        print(
            """
            \(WatchmeCLI.displayName) - macOS observability

            Usage:
              watchme <command> [options]
              watchme <command> --help
              watchme --version

            Commands:
            \(commandList)
            """
        )
    }
}
