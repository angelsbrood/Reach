import Foundation
import FoundationModels
import ReachIdentity
import ReachKit
import ReachTransport
import ReachWire
import Testing
@testable import ReachDaemon

/// What a client does when the cluster it was just talking to is gone.
///
/// `ReachExecutor.respond` carries two retry budgets — 120 s when a
/// generation is resident and re-attaching would recover it, 10 s when
/// nothing is and the only honest move is to say so. Which one applies was
/// decided by `session == nil`, and the hub caches a session handle across
/// calls and hands it back without dialling. So a handle belonging to a
/// daemon that had stopped still read as "connected", and a fresh ask with
/// nothing resident spent the whole residency window in silence — measured
/// at **118.6 s** by `reachd selftest --restart --cold-ask`, against a
/// comment in the same function promising exactly that could not happen.
///
/// These stop the daemon rather than killing a process, which is the honest
/// limit of an in-process suite: it proves the budget is *selected* on the
/// right evidence, not that the transport behaves the same way under
/// `SIGKILL`. The process-death half is `selftest --restart`, which cannot
/// live here because `swift test` cannot find the built binary to spawn.
///
/// ⚠️ Ports: 47480–47482, checked clear of the literals scattered across the
/// other suites. `grep -rioE 'port[a-z]*:? ?=? ?47[0-9]{3}'` — a
/// case-sensitive grep misses `sessionPort:`.
@Suite(.serialized) struct RestartBudgetTests {
    /// The residency window. Anything approaching it here is the defect.
    private static let residencyWindow: Duration = .seconds(120)

    private func startDaemon(port: UInt16, cluster: Cluster) async throws -> Daemon {
        var config = DaemonConfig()
        config.port = port
        config.clusterName = "restart-budget"
        config.modelID = ScriptedFilling().modelID
        let daemon = Daemon(
            config: config,
            filling: ScriptedFilling(),
            identity: Daemon.ListenerIdentity(
                identity: cluster.serverIdentity,
                caCertificate: cluster.caCert
            )
        )
        try await daemon.start(advertise: false)
        return daemon
    }

    /// Mints the cluster and the app's credential once, so a second daemon
    /// can be stood up on the same port wearing the same identity — which is
    /// what a restart looks like from the client's side.
    private struct Cluster {
        let ca: ClusterCA
        let serverIdentity: SecIdentity
        let clientIdentity: SecIdentity
        let caCert: SecCertificate
        let label: String
        let discard: @Sendable () -> Void
    }

    private func makeCluster() throws -> Cluster {
        let ca = try ClusterCA.create(commonName: "Reach Restart Budget CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "budget-app", uri: "reach://device/budget-app")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-budget-server-\(UUID())")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-budget-client-\(UUID())")
        // Owned cleanup rather than the global `IdentityTrash` bin, whose
        // `drain()` empties it for every concurrent suite at once.
        let boxes = [IdentityBox(serverIdentity), IdentityBox(clientIdentity)]
        let discard: @Sendable () -> Void = {
            for box in boxes { KeychainIdentity.remove(identity: box.identity) }
        }
        return Cluster(
            ca: ca,
            serverIdentity: serverIdentity,
            clientIdentity: clientIdentity,
            caCert: try IdentityStore.certificate(fromDER: ca.certificateDER()),
            label: "budget-\(UUID().uuidString)",
            discard: discard
        )
    }

    private func configuration(port: UInt16, label: String) -> ReachExecutor.Configuration {
        ReachExecutor.Configuration(
            host: "127.0.0.1",
            port: port,
            modelID: ScriptedFilling().modelID,
            identityLabel: label,
            // Short on purpose: one dial attempt costs the cached dialer's
            // timeout and then the race's, so this bounds a single attempt
            // at roughly four seconds and leaves the budget as the only
            // thing that could stretch the wait.
            connectTimeout: 2
        )
    }

    /// The defect, in the shape a person meets it: the app is idle, the
    /// cluster goes away, the person asks something, and the app says
    /// nothing for two minutes.
    ///
    /// Fails on the old code by timing out — 120 s of retries against a
    /// deadline chosen because a stale cached handle was not nil.
    @Test(.timeLimit(.minutes(1)))
    func aFreshAskWithNothingResidentDoesNotSpendTheResidencyWindow() async throws {
        let port: UInt16 = 47480
        let cluster = try makeCluster()
        defer { cluster.discard() }
        let daemon = try await startDaemon(port: port, cluster: cluster)
        let configuration = configuration(port: port, label: cluster.label)
        await ReachIdentityRegistry.shared.register(
            label: cluster.label,
            material: .init(identity: cluster.clientIdentity, caCertificate: cluster.caCert)
        )

        // Warm the hub so a session handle is cached — the precondition the
        // defect needs, and the ordinary state of any app that has asked once.
        let warm = LanguageModelSession(model: ReachLanguageModel(configuration: configuration))
        _ = try await warm.respond(to: "Go.")

        await daemon.stop()

        let clock = ContinuousClock()
        let asked = clock.now
        let cold = LanguageModelSession(model: ReachLanguageModel(configuration: configuration))
        await #expect(throws: (any Error).self) {
            _ = try await cold.respond(to: "Go again.")
        }
        let waited = clock.now - asked
        #expect(
            waited < Self.residencyWindow / 3,
            "a fresh ask with nothing resident waited \(waited) — the residency window is for generations that are still there"
        )
    }

    /// The recovery nothing tested. A daemon that restarts has an empty
    /// registry, so the session the app still holds is refused — and the app
    /// is meant to notice, discard it, open a fresh one and ask again without
    /// anyone seeing a failure.
    ///
    /// `freshStartRetries` had no test at all before this: it appeared three
    /// times in the tree, all three inside the function that implements it.
    ///
    /// What it does NOT prove: the re-armed cold-open budget. With the
    /// replacement daemon already listening the reopen succeeds first try, so
    /// no deadline is ever consulted. That half is only observable when the
    /// reopen has to retry, which is `selftest --restart`'s ground.
    @Test(.timeLimit(.minutes(1)))
    func aSessionTheClusterForgotIsReopenedWithoutTheAppSeeingIt() async throws {
        let port: UInt16 = 47481
        let cluster = try makeCluster()
        defer { cluster.discard() }
        let first = try await startDaemon(port: port, cluster: cluster)
        let configuration = configuration(port: port, label: cluster.label)
        await ReachIdentityRegistry.shared.register(
            label: cluster.label,
            material: .init(identity: cluster.clientIdentity, caCertificate: cluster.caCert)
        )

        let warm = LanguageModelSession(model: ReachLanguageModel(configuration: configuration))
        _ = try await warm.respond(to: "Go.")
        await first.stop()

        // The same cluster, the same port, a registry that has never heard of
        // the session the app is still holding.
        let second = try await startDaemon(port: port, cluster: cluster)
        defer { Task { await second.stop() } }

        let after = LanguageModelSession(model: ReachLanguageModel(configuration: configuration))
        let answer = try await after.respond(to: "Go again.")
        #expect(
            !answer.content.isEmpty,
            "the app should not have to know its cluster restarted to ask a second question"
        )
    }
}
