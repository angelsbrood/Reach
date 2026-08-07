import ArgumentParser
import Foundation
import ReachDaemon

/// Everything about this host that the away leg depends on, checked in one
/// command instead of remembered in order.
///
/// The checks themselves live in `HostCheck`, in the daemon library, so they
/// can be asserted. This is the half that talks to a person: it reads the
/// state directory off the options, prints the findings in a column, prints
/// the one check it cannot run, and turns the report into an exit status.
struct Doctor: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "doctor",
        abstract: "Check the host-side preconditions for serving and for the away leg."
    )

    @Option(name: .long, help: "State directory to inspect.")
    var state: String?

    @Option(name: .long, help: "wg-quick config to inspect.")
    var wgConf = HostCheck.defaultWireGuardConf

    /// Opt-in, because every other check here is read-only and this one opens
    /// a real session with a real certificate. Bare `doctor` is unchanged.
    @Flag(name: .long, help: "Open a session against the running daemon and report the road it came in on.")
    var dial = false

    @Option(name: .long, help: "Dial this address instead of loopback — proves one chosen road from the host side.")
    var via: String?

    @Option(name: .long, help: "Seconds the dial gets to complete or refuse.")
    var dialBudget: Double = 10

    func run() async throws {
        let directory = state.map { URL(fileURLWithPath: $0) } ?? DaemonInfo.stateDirectory

        print("reachd \(DaemonInfo.version) doctor — \(directory.path)\n")

        let report = await HostCheck.examine(
            stateDirectory: directory,
            wireGuardConf: wgConf,
            addresses: LocalAddresses.ipv4(),
            dial: dial ? HostCheck.Dial(via: via, budget: .seconds(dialBudget)) : nil
        )

        for finding in report.findings {
            print("\(finding.level.rawValue)  \(finding.title.padding(toLength: max(18, finding.title.count), withPad: " ", startingAt: 0))  \(finding.detail)")
            if let action = finding.action {
                print("      → \(action)")
            }
        }

        print("""

            doctor cannot see the router, and the port map lives there. It has
            gone missing between sessions before, and its absence looks exactly
            like a mesh fault:

                ssh root@<gateway> "nft list ruleset | grep 51820"

            Three lines expected — the DNAT plus two NAT-reflection rules.
            """)

        print("\n\(report.count(.pass)) pass, \(report.count(.warn)) warn, \(report.count(.wait)) waiting, \(report.count(.fail)) fail")
        if !report.isSound {
            throw ExitCode.failure
        }
    }
}
