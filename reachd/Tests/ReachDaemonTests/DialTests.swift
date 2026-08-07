import Foundation
import ReachIdentity
import ReachKit
import ReachTransport
import Security
import Testing
import X509

@testable import ReachDaemon

/// The check that asks the cluster instead of inferring that it would answer.
///
/// ⚠️ **This suite owns 47490–47493.** Hand-picked literals, as everywhere
/// else in this target until the allocator graduates; a new port here means
/// running the roadmap's uniqueness one-liner first.
///
/// The suite is deliberately mixed. Half of it is pure — `dialFindings` and
/// the log reader take values and return values, and every sentence a person
/// reads is assertable without a socket. The other half stands up a real
/// `Daemon` and dials it, because the whole premise of `--dial` is that
/// inference is what failed: five green reports on 6 August described a
/// cluster that could not serve a client.
@Suite(.serialized) struct DialTests {
    // MARK: - Fixtures

    /// A state directory with a real cluster CA in it — the dial mints its
    /// diagnostic identity from whatever is on disk here, so this is not a
    /// stand-in for the CA, it *is* the path production takes.
    private func stateDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-dial-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    /// A daemon serving on `port`, with its listener certificate issued by the
    /// CA saved into `directory`. Returns the discard closure that owns
    /// exactly the identity this call minted — `SpineTests`' ruling, for the
    /// same reason: a global bin empties one bin for every concurrent suite.
    private func startDaemon(
        in directory: URL,
        port: UInt16
    ) async throws -> (Daemon, DaemonConfig, @Sendable () -> Void) {
        let ca = try ClusterCA.create(commonName: "Reach Dial CA")
        try ca.save(to: directory.appendingPathComponent("ca", isDirectory: true))
        let server = try ca.issueServer(
            commonName: "localhost",
            dnsNames: ["localhost"],
            ipAddresses: [[127, 0, 0, 1]]
        )
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-dial-server-\(UUID())")
        let box = IdentityBox(serverIdentity)
        let discard: @Sendable () -> Void = { KeychainIdentity.remove(identity: box.identity) }
        var handedOff = false
        defer { if !handedOff { discard() } }

        var config = DaemonConfig()
        config.port = port
        config.clusterName = "dial"
        config.modelID = "scripted"
        let daemon = Daemon(
            config: config,
            filling: ScriptedFilling(),
            identity: Daemon.ListenerIdentity(
                identity: serverIdentity,
                caCertificate: try IdentityStore.certificate(fromDER: ca.certificateDER())
            )
        )
        try await daemon.start(advertise: false)
        handedOff = true
        return (daemon, config, discard)
    }

    private func config(port: UInt16) -> DaemonConfig {
        var config = DaemonConfig()
        config.port = port
        config.modelID = "scripted"
        return config
    }

    /// An in-process daemon prints to stdout, so no test can read a road out
    /// of a file the way the installed agent's is read. What a test can do is
    /// write the line the daemon writes — `Log.sessionOpened` is that line,
    /// and the reader greps for `Log.roadPrefix`, which the writer is defined
    /// in terms of. So this fixture cannot drift from production without
    /// production drifting with it.
    private func log(_ lines: [String]) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("reachd-\(UUID().uuidString).log")
        try lines.map { "[reachd] \($0)\n" }.joined().write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    // MARK: - The dial, against a real listener

    @Test(.timeLimit(.minutes(1)))
    func aDialAgainstARealListenerOpensASessionAndSaysSo() async throws {
        let directory = try stateDirectory()
        let (daemon, config, discard) = try await startDaemon(in: directory, port: 47490)
        defer { discard() }

        let outcome = await ClusterDial.dial(
            stateDirectory: directory,
            config: config,
            budget: .seconds(20),
            supervision: .log(try log([]), collected: false)
        )
        await daemon.stop()

        guard case .opened = outcome.result else {
            Issue.record("expected a session to open, got \(outcome.result)")
            return
        }
        #expect(outcome.via == "127.0.0.1")
        #expect(outcome.port == 47490)
        #expect(outcome.pinned == false)

        let findings = HostCheck.dialFindings(outcome, daemonUp: true)
        #expect(findings.first?.level == .pass)
        #expect(findings.first?.detail.contains("127.0.0.1:47490") == true)
    }

    /// A daemon that has been stopped does not answer a client.
    ///
    /// ⚠️ **Found by this pass and it was a real defect.** `stop()` cancelled
    /// the listener and the accept task; the per-tunnel work is spawned as a
    /// bare `Task {}` inside the accept loop's body, and an unstructured task
    /// does not care that the task it was created from was cancelled. So every
    /// established tunnel went on being served by a daemon that had been told
    /// to stop.
    ///
    /// It is invisible in production — `stop()` is only ever called by
    /// `selftest`, in a process about to exit — and it surfaced in
    /// `RestartBudgetTests` as **"a stopped daemon answered"**, intermittently,
    /// on runs with enough concurrent load to keep the old tunnel alive. Three
    /// tests there already depended on this being true; none of them asserted
    /// it, so the failure moved around the suite instead of naming itself.
    ///
    /// ⚠️ **Tunnel reuse is the whole probe, and the first draft of this test
    /// missed it.** `ClusterDial` mints a fresh label per run, so two dials in
    /// a row build two hub entries and two dialers and never reuse a tunnel —
    /// that version passed against the unfixed daemon and proved nothing.
    /// What the failing suite actually does is ask *twice through one
    /// configuration*, which is what makes the hub reuse its proven dialer and
    /// the system coalesce the second connection onto the tunnel the daemon is
    /// still serving. So this holds one configuration across the stop.
    @Test(.timeLimit(.minutes(1)))
    func aStoppedDaemonStopsAnsweringClients() async throws {
        let directory = try stateDirectory()
        let (daemon, config, discard) = try await startDaemon(in: directory, port: 47493)
        defer { discard() }

        let label = "reach-dial-stop-\(UUID().uuidString)"
        let material = try ClusterDial.mint(stateDirectory: directory, label: label)
        await ReachIdentityRegistry.shared.register(label: label, material: material)
        defer { try? ClusterRoads.forget(for: label) }

        let configuration = ReachExecutor.Configuration(
            host: "127.0.0.1",
            port: config.port,
            modelID: config.modelID,
            identityLabel: label,
            connectTimeout: 4
        )
        _ = try await ReachConnectionHub.shared.session(for: configuration)

        await daemon.stop()

        // The hub's entry is now proven, so this reuses the dialer rather than
        // racing — which is exactly the path a person takes when they ask a
        // second question after the cluster has gone away.
        await ReachConnectionHub.shared.invalidateSession(for: configuration)
        await #expect(throws: (any Error).self, "a stopped daemon answered") {
            _ = try await ReachConnectionHub.shared.session(for: configuration)
        }
    }

    /// ⚠️ **The headline.** `probePort` binds `INADDR_ANY`, so it reports that
    /// *something* holds the port and can never report that the something
    /// answers — which is exactly how the guard set went green five times on
    /// 6 August over a cluster that could not serve. Here both halves are
    /// asserted in one test: the check that lied still says PASS, and the dial
    /// says FAIL.
    @Test(.timeLimit(.minutes(1)))
    func aPortHeldBySomethingThatIsNotTheClusterPassesTheProbeAndFailsTheDial() async throws {
        let directory = try stateDirectory()
        let ca = try ClusterCA.create(commonName: "Reach Dial CA")
        try ca.save(to: directory.appendingPathComponent("ca", isDirectory: true))

        // Something that is not a daemon, holding the port the daemon would.
        let socket = DeafSocket(port: 47491)
        try socket.hold()
        defer { socket.release() }

        // The green finding, reproduced against the real probe and the real
        // deaf socket. This is what `doctor` said before this pass about a
        // port held by something that will never serve a client: PASS, and
        // sound. Asserted rather than described, so the next person to weaken
        // the dial finds out from this line.
        let ports = HostCheck.checkPorts(config: config(port: 47491), isHeld: HostCheck.probePort)
        let sessionPort = try #require(ports.first)
        #expect(sessionPort.level == .pass, "the port check must still be fooled — that is the premise")
        #expect(sessionPort.detail.contains("held"))
        #expect(HostCheck.Report(findings: [sessionPort]).isSound, "before --dial there was nothing here that could fail")

        let outcome = await ClusterDial.dial(
            stateDirectory: directory,
            config: config(port: 47491),
            budget: .seconds(4),
            supervision: .log(try log([]), collected: false)
        )
        #expect(outcome.result == .noAnswer)

        let findings = HostCheck.dialFindings(outcome, daemonUp: true)
        #expect(findings.first?.level == .fail)
        #expect(findings.first?.detail.contains("nothing answered") == true)
        #expect(!HostCheck.Report(findings: findings).isSound, "and now it can")
    }

    /// The other side of the same result. A daemon nobody started is a runbook
    /// step, not a fault, and only `fail` gates the exit status.
    @Test(.timeLimit(.minutes(1)))
    func aDialWithNoDaemonIsWaitingRatherThanBroken() async throws {
        let directory = try stateDirectory()
        let ca = try ClusterCA.create(commonName: "Reach Dial CA")
        try ca.save(to: directory.appendingPathComponent("ca", isDirectory: true))

        #expect(!HostCheck.probePort(47492), "nothing should hold this port")

        let outcome = await ClusterDial.dial(
            stateDirectory: directory,
            config: config(port: 47492),
            budget: .seconds(4),
            supervision: .log(try log([]), collected: false)
        )
        #expect(outcome.result == .noAnswer)

        let findings = HostCheck.dialFindings(outcome, daemonUp: false)
        #expect(findings.first?.level == .wait)
        #expect(HostCheck.Report(findings: findings).isSound)
    }

    // MARK: - The road: the instrument checking the instrument

    @Test func theRoadIsReadBackOutOfTheDaemonsOwnLog() async throws {
        let session = UUID()
        let url = try log([
            "an app closed its control stream",
            Log.sessionOpened(session, from: "10.86.0.2:51820"),
            "an app closed its control stream",
        ])
        let road = await ClusterDial.road(
            of: session,
            supervision: .log(url, collected: true),
            within: .milliseconds(200)
        )
        #expect(road == .named("10.86.0.2:51820"))
        #expect(HostCheck.roadFindings(road).first?.level == .pass)
    }

    /// A session that opened and left no road behind is the away test's own
    /// instrument failing, and it is one of the five failures this command
    /// exists to name — so it is a `fail`, not a shrug.
    @Test func aRoadThatWasNeverLoggedIsAFaultInTheInstrument() async throws {
        let url = try log([Log.sessionOpened(UUID(), from: "127.0.0.1:1234")])
        let road = await ClusterDial.road(
            of: UUID(),
            supervision: .log(url, collected: true),
            within: .milliseconds(200)
        )
        #expect(road == .missing)
        #expect(HostCheck.roadFindings(road).first?.level == .fail)
    }

    /// A foreground `serve` is a legitimate way to work and every demo has
    /// been shot that way. Its lines are on somebody's terminal, which is not
    /// a fault — the distinction `checkSupervision` already draws, drawn again
    /// here rather than collapsed into the failure above.
    @Test func anUnsupervisedDaemonLeavesTheRoadUnreadRatherThanMissing() async throws {
        let road = await ClusterDial.road(
            of: UUID(),
            supervision: .log(try log([]), collected: false),
            within: .milliseconds(200)
        )
        guard case .unread = road else {
            Issue.record("expected the road to be unread, got \(road)")
            return
        }
        #expect(HostCheck.roadFindings(road).first?.level == .warn)
    }

    @Test func aLogThatIsNotThereIsUnreadAndNotMissing() async throws {
        let absent = FileManager.default.temporaryDirectory
            .appendingPathComponent("no-such-\(UUID().uuidString).log")
        let road = await ClusterDial.road(
            of: UUID(),
            supervision: .log(absent, collected: true),
            within: .milliseconds(200)
        )
        guard case .unread = road else {
            Issue.record("expected the road to be unread, got \(road)")
            return
        }
    }

    // MARK: - The diagnostic identity

    /// D1's boundary, and the reason it is a third authority rather than a
    /// reused one. Nothing has to remember this: the prefix enforces it.
    @Test func aDiagnosticIdentityIsNeverAnAdminDevice() throws {
        let directory = try stateDirectory()
        let ca = try ClusterCA.create(commonName: "Reach Dial CA")
        try ca.save(to: directory.appendingPathComponent("ca", isDirectory: true))

        let material = try ClusterDial.mint(stateDirectory: directory, label: "reach-dial-test-\(UUID())")
        var certificate: SecCertificate?
        #expect(SecIdentityCopyCertificate(material.identity, &certificate) == errSecSuccess)
        let der = try #require(certificate.map { SecCertificateCopyData($0) as Data })

        let uri = try #require(PeerIdentity.uri(fromDER: der))
        #expect(uri.hasPrefix(ClusterDial.diagnosticAuthority))
        #expect(PeerIdentity.deviceID(fromURI: uri) == nil, "a diagnostic must not parse as an enrolled device")
    }

    /// "Minted, used and gone" is a claim about the certificate, not about the
    /// intent. `days:` could not express it — the shortest it can say is a
    /// day — which is why `validFor:` exists.
    @Test func theDiagnosticCertificateExpiresInMinutesRatherThanDays() throws {
        let ca = try ClusterCA.create(commonName: "Reach Dial CA")
        let uri = ClusterDial.diagnosticAuthority + UUID().uuidString

        let ephemeral = try ca.issueClient(commonName: "reachd doctor", uri: uri, validFor: 300)
        let remaining = ephemeral.certificate.notValidAfter.timeIntervalSinceNow
        #expect(remaining > 0)
        #expect(remaining < 600, "a diagnostic identity that outlives the errand is not ephemeral")

        // Both halves, so the test carries its own reason. The shortest thing
        // the day-based form can say is a day, which is why the overload
        // exists — and if someone later folds `validFor:` back into `days:`
        // to tidy up, this is the line that stops them.
        let shortestInDays = try ca.issueClient(commonName: "reachd doctor", uri: uri, days: 1)
        #expect(shortestInDays.certificate.notValidAfter.timeIntervalSinceNow > 600)
    }

    /// A dial that could not get off the ground says nothing about the
    /// cluster, and the finding must not imply otherwise. Every identity in
    /// this project is minted through `SecPKCS12Import`, which fails about
    /// once in two hundred and fifty — so a diagnostic that blamed the cluster
    /// for that would libel a healthy one on a schedule.
    @Test func aDialThatWasNeverAttemptedDoesNotBlameTheCluster() async throws {
        // Real, not simulated: an empty state directory has no CA to mint from.
        let outcome = await ClusterDial.dial(
            stateDirectory: try stateDirectory(),
            config: config(port: 47493),
            budget: .seconds(2),
            supervision: .log(try log([]), collected: false)
        )
        guard case .noClusterCA = outcome.result else {
            Issue.record("expected the missing CA to be named as such, got \(outcome.result)")
            return
        }
        let finding = try #require(HostCheck.dialFindings(outcome, daemonUp: true).first)
        #expect(finding.level == .wait, "a host on its first run is not a fault")

        // And the other half of the same rule, which cannot be produced on
        // demand: a mint that failed is doctor's own, and warns.
        let minted = HostCheck.dialFindings(
            ClusterDial.Outcome(
                result: .notAttempted("\(IdentityError.pkcs12EmptyItemList(bytes: 1234))"),
                elapsed: nil,
                road: .notApplicable,
                via: "127.0.0.1",
                port: 47337,
                pinned: false
            ),
            daemonUp: true
        )
        #expect(minted.first?.level == .warn)
        #expect(minted.first?.action?.contains("says nothing about the cluster") == true)
        #expect(minted.count == 1, "no road finding when no session opened — one fault, counted once")
    }

    // MARK: - What running it corrected

    /// ⚠️ Found by running the thing, 2026-08-07, and it had shipped in the
    /// first draft: with `--via`, `daemonUp` comes from a local `bind` and is
    /// evidence about loopback, not about the road under test. Quoting it
    /// produced "a process holds :47337 and nothing answered on 10.86.0.1" —
    /// two true clauses welded into a false implication.
    @Test func aNamedRoadThatDoesNotAnswerDoesNotQuoteTheLocalPortCheck() {
        let outcome = ClusterDial.Outcome(
            result: .noAnswer,
            elapsed: .seconds(2),
            road: .notApplicable,
            via: "10.86.0.1",
            port: 47337,
            pinned: true
        )
        let finding = HostCheck.dialFindings(outcome, daemonUp: true, addresses: [[10, 86, 0, 1]]).first
        #expect(finding?.level == .fail)
        #expect(finding?.detail.contains("holds") == false, "the local port probe says nothing about a named road")
        #expect(finding?.detail.contains("10.86.0.1:47337") == true)
        // This host's own address is the reading that recurs, so the action
        // has to name what it means rather than send someone to the router.
        #expect(finding?.action?.contains("this host's own addresses") == true)

        let stranger = HostCheck.dialFindings(outcome, daemonUp: true, addresses: [[192, 168, 8, 104]]).first
        #expect(stranger?.action?.contains("this host's own addresses") == false)
    }

    /// Every sentence the dial can put in front of a person names the road it
    /// is talking about. A finding that says a dial failed without saying
    /// which dial is the genre of report this command was written to replace.
    @Test func everyDialFindingNamesWhatItDialed() {
        let outcomes: [ClusterDial.Outcome] = [
            .init(result: .opened(capabilities: ["tools"]), elapsed: .milliseconds(31), road: .named("127.0.0.1:1"), via: "127.0.0.1", port: 47337, pinned: false),
            .init(result: .noAnswer, elapsed: .seconds(5), road: .notApplicable, via: "127.0.0.1", port: 47337, pinned: false),
            .init(result: .noAnswer, elapsed: .seconds(5), road: .notApplicable, via: "10.86.0.1", port: 47337, pinned: true),
            .init(result: .answeredAndFailed("it accepted the connection and then said nothing"), elapsed: .seconds(10), road: .notApplicable, via: "127.0.0.1", port: 47337, pinned: false),
        ]
        for outcome in outcomes {
            for daemonUp in [true, false] {
                let finding = HostCheck.dialFindings(outcome, daemonUp: daemonUp).first
                #expect(
                    finding?.detail.contains("\(outcome.via):\(outcome.port)") == true,
                    "\(outcome.result) with daemonUp \(daemonUp) did not name the road"
                )
            }
        }
    }
}

/// A UDP socket holding a port and answering nothing — the deaf bind, as a
/// fixture. `probePort` cannot tell this from a serving daemon, which is the
/// entire reason `--dial` exists.
private final class DeafSocket: @unchecked Sendable {
    private let port: UInt16
    private var descriptor: Int32 = -1

    init(port: UInt16) {
        self.port = port
    }

    func hold() throws {
        descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = INADDR_ANY
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { throw HeldElsewhere(port: port) }
    }

    func release() {
        if descriptor >= 0 { close(descriptor) }
    }
}

/// A port literal in this target is a claim that no other suite binds it, and
/// when the claim is wrong the failure should say so rather than surface as a
/// dial that mysteriously succeeded.
private struct HeldElsewhere: Error, CustomStringConvertible {
    let port: UInt16
    var description: String {
        ":\(port) could not be held — another suite in this target has it, and this one's premise needs it free"
    }
}
