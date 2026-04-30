import Darwin
import Foundation

public protocol WatchmeSubcommand {
    static var name: String { get }
    static var summary: String { get }
    init(arguments: [String]) throws
    func run() -> Int32
    static func printUsage()
}

public struct CommandRegistry {
    private let commands: [any WatchmeSubcommand.Type]

    public init(commands: [any WatchmeSubcommand.Type]) {
        self.commands = commands
    }

    public func parse(_ arguments: [String]) throws -> any WatchmeSubcommand {
        guard arguments.count >= 2 else {
            printUsage()
            exit(0)
        }

        let commandName = arguments[1]
        if commandName == "help" || commandName == "--help" || commandName == "-h" {
            printUsage()
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
            WatchMe - macOS observability agent

            Usage:
              watchme <command> [options]
              watchme <command> --help

            Commands:
            \(commandList)
            """
        )
    }
}
