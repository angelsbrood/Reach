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
/// other suites. `grep -rn '47[0-9]\{3\}'` — a
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
        let label = "budget-\(UUID().uuidString)"
        // Owned cleanup. This suite declined the old global `IdentityTrash`
        // bin, whose `drain()` emptied it for every concurrent suite at once;
        // the bin is gone and this is now what every suite does.
        //
        // The roads belong to the same closure because they are filed under
        // the same label, and every test here warms the hub on purpose — which
        // is exactly the moment `ClusterRoads.save` runs, so a suite about
        // what happens *after* a cluster goes away was leaving a record of
        // where it had been. 94 `budget-<uuid>` entries, none of them asked
        // for by anything in this file.
        let boxes = [IdentityBox(serverIdentity), IdentityBox(clientIdentity)]
        let discard: @Sendable () -> Void = {
            for box in boxes { KeychainIdentity.remove(identity: box.identity) }
            try? ClusterRoads.forget(for: label)
        }
        return Cluster(
            ca: ca,
            serverIdentity: serverIdentity,
            clientIdentity: clientIdentity,
            caCert: try IdentityStore.certificate(fromDER: ca.certificateDER()),
            label: label,
            discard: discard
        )
    }

    /// The cold-open budget, as `ReachExecutor.respond` sets it. Anything at
    /// or near it here is the promise being kept; anything past it is not.
    private static let coldOpenBudget: Duration = .seconds(10)

    private func configuration(
        port: UInt16,
        label: String,
        connectTimeout: Double = 2
    ) -> ReachExecutor.Configuration {
        ReachExecutor.Configuration(
            host: "127.0.0.1",
            port: port,
            modelID: ScriptedFilling().modelID,
            identityLabel: label,
            // Short by default, because most tests here are about *which*
            // budget gets picked and want the dials out of the way.
            //
            // ⚠️ It was short for a worse reason, and the comment said so: one
            // attempt cost the cached dialer's timeout and then the race's, so
            // 2 held a single attempt to about four seconds "and left the
            // budget as the only thing that could stretch the wait". That is a
            // measurement arranged so the defect it was measuring could not
            // show up in it — rule 6, in the suite that exists to time this.
            // `aColdAskRefusesAtItsBudgetAndNotAtTwiceIt` passes a real one.
            connectTimeout: connectTimeout
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
        let port: UInt16 = TestPorts.port(47480)
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
        var sentence = ""
        do {
            _ = try await cold.respond(to: "Go again.")
            Issue.record("a stopped daemon answered")
        } catch {
            sentence = "\(error)"
        }
        let waited = clock.now - asked
        #expect(
            waited < Self.residencyWindow / 3,
            "a fresh ask with nothing resident waited \(waited) — the residency window is for generations that are still there"
        )
        // The other half of the same moment: what it says when it gives up.
        // `knewStoredRoads` was set only when an entry was seeded from disk,
        // never when the cluster actually answered — so an app that had just
        // streamed tokens was told it had never been answered, and sent to
        // the cluster's own network for a cluster it had been talking to.
        #expect(
            !sentence.contains("has not been answered before"),
            "this app was answered moments ago: \(sentence)"
        )
    }

    /// The budget bounds the attempt, not just the pause before the next one.
    ///
    /// `waitBeforeRetry` checks the deadline before *sleeping*, so a single
    /// attempt could spend far more than the whole budget and never consult
    /// it. `ReachConnectionHub.openStream` tries the cached dialer for the
    /// full `connectTimeout` and then hands the same timeout to every racer,
    /// and `respond` opens twice per iteration — up to 4× the configured
    /// timeout, 80 s at `Configuration`'s default 20, against a 10 s promise.
    ///
    /// The rest of this suite runs at `connectTimeout: 2`, which is small
    /// enough that the doubling fits under every assertion in it. **This one
    /// passes 30 on purpose**: the budget has to be the binding constraint or
    /// the measurement is of nothing. On the old code the wait was ~60 s.
    ///
    /// Warming first is not incidental — the doubling only happens on a
    /// *proven* entry, so an app that has never connected pays one race and a
    /// cold ask after a restart pays two. The second is the shape a person
    /// meets, and the shape the rig measured.
    @Test(.timeLimit(.minutes(2)))
    func aColdAskRefusesAtItsBudgetAndNotAtTwiceIt() async throws {
        let port: UInt16 = TestPorts.port(47483)
        let cluster = try makeCluster()
        defer { cluster.discard() }
        let daemon = try await startDaemon(port: port, cluster: cluster)
        let configuration = configuration(port: port, label: cluster.label, connectTimeout: 30)
        await ReachIdentityRegistry.shared.register(
            label: cluster.label,
            material: .init(identity: cluster.clientIdentity, caCertificate: cluster.caCert)
        )

        let warm = LanguageModelSession(model: ReachLanguageModel(configuration: configuration))
        _ = try await warm.respond(to: "Go.")
        await daemon.stop()

        let clock = ContinuousClock()
        let asked = clock.now
        let cold = LanguageModelSession(model: ReachLanguageModel(configuration: configuration))
        var thrown: (any Error)?
        do {
            _ = try await cold.respond(to: "Go again.")
            Issue.record("a stopped daemon answered")
        } catch {
            thrown = error
        }
        let waited = clock.now - asked

        // Tolerance, not slack: the budget is 10 s and one dial is allowed to
        // be in flight when it expires. Twice the budget is the defect.
        #expect(
            waited < Self.coldOpenBudget * 2,
            "a cold ask with a 10 s budget waited \(waited) against a 30 s connect timeout"
        )
        // What it says at the budget matters as much as when. `.unreachable`
        // is D4's sentence and names which situation this app is in; the two
        // wrong answers are a bare cancellation, which says nothing, and
        // `.transport`, which describes a socket rather than a cluster.
        let error = try #require(thrown)
        #expect(!(error is CancellationError), "the deadline was reported as a cancelled request")
        guard case .unreachable = error as? ReachError else {
            Issue.record("the refusal at the budget was not the one written for it: \(error)")
            return
        }
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
        let port: UInt16 = TestPorts.port(47481)
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

    /// The segment no connect timeout can bound: a cluster that answers the
    /// dial and then says nothing.
    ///
    /// `ReachConnectionHub.session` sends `Hello` and then *reads*, twice, with
    /// no deadline on either — so a listener that completes mTLS and never
    /// speaks holds an app until QUIC's own idle timeout, about 30 s, three
    /// times the cold-open budget. This is why the fix is a deadline around
    /// the open rather than a connect timeout threaded down to the dial:
    /// threading would have left this exactly as it was, while making the
    /// budget look kept.
    ///
    /// The listener here accepts tunnels and drops them on the floor. That is
    /// not a contrived shape — it is a daemon wedged after `start()`, and it
    /// is what a half-open NAT mapping looks like from this side.
    ///
    /// ⚠️ Port 47484.
    @Test(.timeLimit(.minutes(2)))
    func aClusterThatAnswersAndThenGoesQuietStillRefusesAtTheBudget() async throws {
        let port: UInt16 = TestPorts.port(47484)
        let cluster = try makeCluster()
        defer { cluster.discard() }

        let listener = try QUICListener(
            port: port,
            parameters: .reachQUIC(options: TLSBuilder.serverOptions(
                alpn: Wire.alpn,
                identity: cluster.serverIdentity,
                clientTrustRoots: [cluster.caCert]
            ))
        )
        defer { listener.cancel() }
        // Accept everything, answer nothing. Holding the streams is the point:
        // dropping them would close the connection and produce an ending.
        let mute = Task {
            var held: [ReachTransport.QUICStream] = []
            for try await tunnel in listener.tunnels {
                for await stream in tunnel.inboundStreams { held.append(stream) }
            }
        }
        defer { mute.cancel() }

        let configuration = configuration(port: port, label: cluster.label, connectTimeout: 30)
        await ReachIdentityRegistry.shared.register(
            label: cluster.label,
            material: .init(identity: cluster.clientIdentity, caCertificate: cluster.caCert)
        )

        let clock = ContinuousClock()
        let asked = clock.now
        let session = LanguageModelSession(model: ReachLanguageModel(configuration: configuration))
        await #expect(throws: (any Error).self) {
            _ = try await session.respond(to: "Go.")
        }
        let waited = clock.now - asked
        #expect(
            waited < Self.coldOpenBudget * 2,
            "a cluster that went quiet held the app for \(waited) against a 10 s budget"
        )
    }

    /// The daemon used to start deaf and say it was serving.
    ///
    /// `NWListener` does not fail its initializer on a port another process
    /// holds; the refusal arrives later, on the network queue, as `.failed`.
    /// It reached the accept task as one line on stderr *after* `start()` had
    /// returned and the serving line had printed — so the operator's terminal
    /// read `serving … on :47337` while every client read `no road reached
    /// the cluster`, both true-looking and one of them a lie. Racing a dying
    /// process for its port is what a restart is, so this was the daemon's
    /// most likely bad start and the one nothing could see.
    @Test(.timeLimit(.minutes(1)))
    func aDaemonThatCannotTakeThePortSaysSoRatherThanServingNothing() async throws {
        let port: UInt16 = TestPorts.port(47482)
        let cluster = try makeCluster()
        defer { cluster.discard() }
        let holder = try await startDaemon(port: port, cluster: cluster)
        defer { Task { await holder.stop() } }

        do {
            let deaf = try await startDaemon(port: port, cluster: cluster)
            await deaf.stop()
            Issue.record("a second daemon reported success on a port the first already holds")
        } catch {
            let sentence = "\(error)"
            #expect(
                sentence.contains("\(port)"),
                "the refusal has to name the port, since that is the thing to go and free: \(sentence)"
            )
            #expect(
                !sentence.contains("stopped accepting"),
                "never bound and stopped serving are different situations and must not share a sentence: \(sentence)"
            )
        }
    }
}
