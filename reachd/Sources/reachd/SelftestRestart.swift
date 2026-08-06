import ArgumentParser
import Foundation
import FoundationModels
import ReachDaemon
import ReachIdentity
import ReachKit
import ReachWire

/// The restart rig: a real daemon in a real process, killed with `SIGKILL`
/// mid-generation, and what the app is told about it.
///
/// It is a child process rather than a second in-process `Daemon` because the
/// two things worth measuring here — how long a client takes to *notice*, and
/// whether the error survives the framework's wrapping to reach a screen —
/// are properties of process death and of the transport underneath it. An
/// in-process teardown proves neither: it runs the `defer`s a `kill -9` never
/// runs, and it never races the dead process for the port.
///
/// It lives in `selftest` rather than the test suite for the reason `--mlx`
/// does — and one more: `swift test` cannot spawn the built `reachd` because
/// it does not know where it is.
extension Selftest {
    /// The child half. Loads the CA the parent left in the state directory,
    /// mints its own listener leaf, serves, and parks until it is killed.
    func runRestartServe() async throws {
        guard let stateDir else {
            print("[restart-serve] --state-dir is required")
            throw ExitCode.failure
        }
        let directory = URL(fileURLWithPath: stateDir, isDirectory: true)
        let ca = try ClusterCA.load(from: directory.appendingPathComponent("ca", isDirectory: true))
        let server = try ca.issueServer(
            commonName: "localhost",
            dnsNames: ["localhost"],
            ipAddresses: [[127, 0, 0, 1]]
        )
        let identity = try IdentityMaterializer.materialize(server, label: serverLabel)
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var config = DaemonConfig()
        config.port = port
        config.clusterName = "restart-rig"
        config.modelID = RestartFilling.id

        let daemon = Daemon(
            config: config,
            filling: RestartFilling(),
            identity: Daemon.ListenerIdentity(identity: identity, caCertificate: caCert)
        )
        try await daemon.start(advertise: false)
        // Not a readiness claim — the parent gates on the port being held,
        // because a listener that failed to bind reports nothing here.
        print("[restart-serve] pid \(ProcessInfo.processInfo.processIdentifier) on :\(port)")
        while true {
            try await Task.sleep(for: .seconds(3600))
        }
    }

    /// The parent half: stand a daemon up, start a generation, kill the
    /// daemon once tokens have provably reached the caller, and report what
    /// the caller is told and how long it waited to be told it.
    func runRestartRig() async throws {
        let clock = ContinuousClock()
        let run = UUID().uuidString.prefix(8)
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-restart-\(run)", isDirectory: true)
        let clientLabel = "reach-restart-client-\(run)"
        let childLabel = "reach-restart-server-\(run)"

        let ca = try ClusterCA.create(commonName: "Reach Restart CA")
        try ca.save(to: directory.appendingPathComponent("ca", isDirectory: true))
        let client = try ca.issueClient(commonName: "restart-rig", uri: "reach://device/restart-rig")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: clientLabel)
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())
        await ReachIdentityRegistry.shared.register(
            label: clientLabel,
            material: .init(identity: clientIdentity, caCertificate: caCert)
        )

        var child: Process?
        var relaunch: Task<Process?, Never>?
        defer {
            if let child, child.isRunning { kill(child.processIdentifier, SIGKILL) }
            KeychainIdentity.remove(label: clientLabel)
            KeychainIdentity.remove(label: childLabel)
            try? FileManager.default.removeItem(at: directory)
        }

        print("[restart] state \(directory.path)")
        child = try spawnDaemon(stateDir: directory.path, label: childLabel)
        guard await waitForPort(held: true, within: .seconds(20)) else {
            print("[restart] the daemon never took :\(port)")
            throw ExitCode.failure
        }
        print("[restart] daemon up on :\(port), pid \(child!.processIdentifier)")

        let configuration = ReachExecutor.Configuration(
            host: "127.0.0.1",
            port: port,
            modelID: RestartFilling.id,
            identityLabel: clientLabel,
            connectTimeout: 10
        )

        // ── The cold-ask arm ───────────────────────────────────────────────
        // Warm the hub's cached session handle, kill the daemon, then ask a
        // *fresh* question. Nothing is resident, so the answer should be fast
        // and should say the cluster is not there. What it actually does is
        // the measurement.
        if coldAsk {
            let warm = LanguageModelSession(
                model: ReachLanguageModel(configuration: configuration),
                instructions: "You are terse."
            )
            var warmed = 0
            for try await _ in warm.streamResponse(to: "Count slowly.") {
                warmed += 1
                if warmed >= 2 { break }
            }
            print("[restart] session warmed (\(warmed) snapshots), cached handle live")
            if let victim = child {
                kill(victim.processIdentifier, SIGKILL)
                victim.waitUntilExit()
            }
            let asked = clock.now
            let fresh = LanguageModelSession(
                model: ReachLanguageModel(configuration: configuration),
                instructions: "You are terse."
            )
            do {
                for try await _ in fresh.streamResponse(to: "Count slowly.") {}
                print("[restart] cold ask unexpectedly succeeded")
            } catch {
                print("")
                print("[restart] ── the cold ask, daemon down, handle cached ──")
                print("[restart] nothing resident, so this should be fast:")
                print("[restart] time to the ending: \(clock.now - asked)")
                print("[restart] rendered:           \(error)")
                print("")
            }
            print("SELFTEST (restart, cold-ask): OBSERVED")
            return
        }

        // ── The measurement ────────────────────────────────────────────────
        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration),
            instructions: "You are terse."
        )
        var snapshots = 0
        var seen = ""
        var killedAt: ContinuousClock.Instant?
        var ending: String?
        var endingType = "-"

        do {
            for try await snapshot in session.streamResponse(to: "Count slowly.") {
                snapshots += 1
                seen = snapshot.content
                // Kill only once tokens have provably reached the caller —
                // that is the one scenario the client cannot recover from,
                // and the only one worth timing.
                if killedAt == nil, snapshots >= 2, let victim = child {
                    killedAt = clock.now
                    kill(victim.processIdentifier, SIGKILL)
                    victim.waitUntilExit()
                    print("[restart] SIGKILL after \(snapshots) snapshots, \(seen.count) chars on screen")
                    // A supervised host is a different experiment: the daemon
                    // comes back while the client is still retrying, so the
                    // client reaches `GenerateReattach` and is refused, rather
                    // than never reaching anything. Which defect you hit
                    // depends on whether something is restarting the daemon.
                    if relaunchAfter >= 0 {
                        let seconds = relaunchAfter
                        let stateDir = directory.path
                        let label = childLabel
                        relaunch = Task { [self] in
                            try? await Task.sleep(for: .seconds(seconds))
                            let revived = try? spawnDaemon(stateDir: stateDir, label: label)
                            if revived != nil {
                                print("[restart] daemon relaunched \(seconds)s after the kill (supervised case)")
                            }
                            return revived
                        }
                    }
                }
            }
            print("[restart] the stream finished anyway — the kill did not land mid-generation")
        } catch {
            ending = "\(error)"
            endingType = "\(type(of: error))"
        }

        let noticed = killedAt.map { clock.now - $0 }
        print("")
        print("[restart] ── what the app was told ──────────────────────────")
        print("[restart] time from SIGKILL to the ending: \(noticed.map(String.init(describing:)) ?? "never")")
        print("[restart] error type reaching the caller:  \(endingType)")
        print("[restart] rendered:                        \(ending ?? "(no error — stream completed)")")
        print("[restart] partial answer left on screen:   \(seen.isEmpty ? "(none)" : "\"\(seen)\"")")
        print("")

        // ── Does a fresh ask recover once the daemon is back? ──────────────
        if let relaunch {
            child = await relaunch.value
        }
        if child == nil || !(child!.isRunning) {
            _ = await waitForPort(held: false, within: .seconds(5))
            child = try spawnDaemon(stateDir: directory.path, label: childLabel)
        }
        guard await waitForPort(held: true, within: .seconds(20)) else {
            print("[restart] the daemon did not come back on :\(port)")
            throw ExitCode.failure
        }
        print("[restart] daemon relaunched, pid \(child!.processIdentifier)")

        let after = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration),
            instructions: "You are terse."
        )
        let reaskedAt = clock.now
        do {
            var recovered = ""
            for try await snapshot in after.streamResponse(to: "Count slowly.") {
                recovered = snapshot.content
            }
            print("[restart] a fresh ask after the restart RECOVERED in \(clock.now - reaskedAt): \"\(recovered)\"")
        } catch {
            print("[restart] a fresh ask after the restart FAILED in \(clock.now - reaskedAt): \(error)")
        }

        print("")
        print(ending == nil
              ? "SELFTEST (restart): INCONCLUSIVE — the kill did not interrupt a generation"
              : "SELFTEST (restart): OBSERVED")
    }

    private func spawnDaemon(stateDir: String, label: String) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        process.arguments = [
            "selftest", "--restart-serve",
            "--port", "\(port)",
            "--state-dir", stateDir,
            "--server-label", label,
        ]
        try process.run()
        return process
    }

    /// Readiness is the port being held, not a line the daemon printed: a
    /// listener that fails to bind still prints, which is the whole reason
    /// this rig exists.
    private func waitForPort(held: Bool, within limit: Duration) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now + limit
        while clock.now < deadline {
            if HostCheck.probePort(port) == held { return true }
            try? await Task.sleep(for: .milliseconds(100))
        }
        return HostCheck.probePort(port) == held
    }
}

/// Slow on purpose: the rig has to land a `kill -9` *between* two tokens, and
/// the scripted spine's three words in ninety milliseconds cannot be hit.
struct RestartFilling: SlotFilling {
    static let id = "restart-rig"

    let modelID = RestartFilling.id
    let displayName = "Restart rig"
    let capabilities: [String] = []

    func prewarm() async throws {}

    func generate(_ request: ReachWire.WireGenerationRequest) -> AsyncThrowingStream<ReachWire.WireEvent, Error> {
        let (stream, continuation) = AsyncThrowingStream<ReachWire.WireEvent, Error>.makeStream()
        let task = Task {
            for number in 1...120 {
                continuation.yield(.responseAppend(
                    entryID: nil, text: "\(number) ", segmentID: nil, tokenCount: 1
                ))
                try? await Task.sleep(for: .milliseconds(250))
                if Task.isCancelled { break }
            }
            continuation.yield(.finished(.complete))
            continuation.finish()
        }
        continuation.onTermination = { _ in task.cancel() }
        return stream
    }
}
