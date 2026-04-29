import Darwin
import Foundation
import WatchmeCore
import WatchmeWiFi

let registry = CommandRegistry(commands: [WiFiCommand.self])

do {
    let command = try registry.parse(CommandLine.arguments)
    exit(command.run())
} catch {
    logEvent(.error, "argument_error", fields: ["error": "\(error)"])
    registry.printUsage()
    exit(2)
}
