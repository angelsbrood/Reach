import ArgumentParser
import Foundation
import ReachDaemon

/// Keeping the daemon alive across a restart, which nothing did.
///
/// The design note has said "a launchd service on the Mac today" since
/// before there was one: no plist, no supervisor, no signal handler, and
/// `serve` ending in an infinite sleep that a crash or a reboot simply
/// ended. This is the half that makes the sentence true.
///
/// The plist itself, and why it is an agent rather than a daemon, live in
/// `LaunchAgent` where a test can reach them. This is the IO.
struct Service: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "service",
        abstract: "Install, remove, or report the launchd agent that keeps reachd running.",
        subcommands: [Install.self, Uninstall.self, ServiceStatus.self]
    )

    struct Install: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Write the launchd agent and start it."
        )

        @Option(name: .long, help: "Path to the reachd binary. Defaults to this one.")
        var executable: String?

        @Flag(name: .long, help: "Write the plist but do not load it.")
        var noLoad = false

        func run() async throws {
            let resolved = try LaunchAgent.executablePath(
                executable ?? ProcessInfo.processInfo.arguments[0]
            )
            let plistURL = LaunchAgent.plistURL()
            try FileManager.default.createDirectory(
                at: plistURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try LaunchAgent.plist(executable: resolved)
                .write(to: plistURL, atomically: true, encoding: .utf8)
            print("[reachd] wrote \(plistURL.path)")

            guard !noLoad else {
                print("[reachd] not loaded — run: launchctl bootstrap gui/$(id -u) \(plistURL.path)")
                return
            }
            // Booting out first makes this re-runnable: an install over an
            // older agent otherwise fails with launchd's "service already
            // loaded", which reads as a problem and is not one.
            _ = try? Service.launchctl(["bootout", "gui/\(getuid())/\(LaunchAgent.label)"])
            let result = try Service.launchctl(["bootstrap", "gui/\(getuid())", plistURL.path])
            guard result.status == 0 else {
                throw ServiceError.launchctlRefused(
                    result.output.isEmpty ? "exit \(result.status)" : result.output
                )
            }
            print("[reachd] agent loaded — it starts at login and restarts if it dies")
            print("[reachd] log: \(LaunchAgent.logURL().path)")
            print("[reachd] ⚠️ at login, not at boot: the cluster's identity lives in the login keychain")
            print("[reachd] ⚠️ the mesh road still needs `wg-quick up reach0`, which wants a password and so is not in the agent")
        }
    }

    struct Uninstall: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Stop the launchd agent and remove it."
        )

        func run() async throws {
            _ = try? Service.launchctl(["bootout", "gui/\(getuid())/\(LaunchAgent.label)"])
            let plistURL = LaunchAgent.plistURL()
            if FileManager.default.fileExists(atPath: plistURL.path) {
                try FileManager.default.removeItem(at: plistURL)
                print("[reachd] removed \(plistURL.path)")
            } else {
                print("[reachd] no agent installed at \(plistURL.path)")
            }
        }
    }

    struct ServiceStatus: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "status",
            abstract: "Report whether the agent is installed and loaded."
        )

        func run() async throws {
            let plistURL = LaunchAgent.plistURL()
            let installed = FileManager.default.fileExists(atPath: plistURL.path)
            print("[reachd] plist: \(installed ? plistURL.path : "not installed")")
            let result = try Service.launchctl(["print", "gui/\(getuid())/\(LaunchAgent.label)"])
            if result.status == 0 {
                let state = result.output
                    .split(separator: "\n")
                    .first { $0.contains("state = ") || $0.contains("pid = ") }
                    .map { $0.trimmingCharacters(in: .whitespaces) } ?? "loaded"
                print("[reachd] agent: \(state)")
            } else {
                print("[reachd] agent: not loaded")
            }
        }
    }

    @discardableResult
    static func launchctl(_ arguments: [String]) throws -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}
