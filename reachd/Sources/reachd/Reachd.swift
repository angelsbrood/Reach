import ArgumentParser
import ReachDaemon

@main
struct Reachd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "reachd",
        abstract: "The Reach serving daemon: a slot host fronting self-hosted open weights with the Foundation Models framework's native semantics.",
        subcommands: [Serve.self, Status.self]
    )
}

struct Serve: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Advertise on the local network and serve sessions."
    )

    func run() async throws {
        print("reachd \(DaemonInfo.version) — serve lands with the spine.")
    }
}

struct Status: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Report daemon state."
    )

    func run() async throws {
        print("reachd \(DaemonInfo.version)")
    }
}
