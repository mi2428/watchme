import Darwin
import Foundation
import WatchmeAgent
import WatchmeCore

let registry = CommandRegistry(commands: [AgentCommand.self])

private func exitWatchme(_ status: Int32) -> Never {
    if Bundle.main.bundlePath.hasSuffix(".app") {
        usleep(250_000)
    }
    exit(status)
}

do {
    let command = try registry.parse(CommandLine.arguments)
    exitWatchme(command.run())
} catch {
    logEvent(.error, "argument_error", fields: ["error": "\(error)"])
    registry.printUsage()
    exitWatchme(2)
}
