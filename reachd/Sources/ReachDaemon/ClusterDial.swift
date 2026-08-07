import Foundation
import ReachIdentity
import ReachKit
import ReachTransport

/// Whether the cluster can actually answer a client, established by asking it.
///
/// `HostCheck` proves the host is *dressed*. Everything it looks at is local —
/// the state directory, the config, the CA on disk, the ports being held, the
/// agent being installed — and on 6 August 2026 the full set went green **five
/// separate times over a cluster that could not serve a client**: a daemon
/// bound deaf, the mesh interface down, no road line to read, and a keychain
/// dialog blocking the first handshake, twice. Every one of those is invisible
/// to a check that never dials. `probePort` is the mechanism: it binds
/// `INADDR_ANY` and can only report that *something* holds the port, never
/// that the something answers.
///
/// So this dials. It mints an ephemeral identity from the cluster's own CA,
/// opens a session over the real listener with the ordinary client stack, and
/// reports the road the daemon says the session came in on.
///
/// ## What it deliberately does not do
///
/// It does not ask for a token. `reachd selftest --mlx` already proves
/// generation end to end, and the daemon prewarms *asynchronously at every
/// login* — so a dial that wanted a token inside the reinstall guard sequence
/// would block or fail on a perfectly healthy cluster. The exchange stops at
/// the boundary `selftest` never crosses: the real listener.
public enum ClusterDial {
    /// What one dial found. `via` and `port` are carried so the finding can
    /// name what was actually dialed rather than what was configured.
    public struct Outcome: Sendable {
        public let result: Result
        public let elapsed: Duration?
        public let road: Road
        public let via: String
        public let port: UInt16
        /// Whether the caller named the road. It changes what a failure
        /// *means*: with no road named this is loopback, and the local port
        /// probe is evidence about it; with a road named the probe is
        /// evidence about a different thing entirely and must not be quoted
        /// as though it were not.
        public let pinned: Bool

        public init(result: Result, elapsed: Duration?, road: Road, via: String, port: UInt16, pinned: Bool) {
            self.result = result
            self.elapsed = elapsed
            self.road = road
            self.via = via
            self.port = port
            self.pinned = pinned
        }
    }

    /// Five answers, because "the dial failed" is four different next actions
    /// and two of them are not about the cluster at all.
    public enum Result: Sendable, Equatable {
        /// A session opened. The capabilities are the slot's own.
        case opened(capabilities: [String])
        /// Nothing answered on the address dialed.
        ///
        /// Payload-free on purpose. The client's own `.unreachable` sentence
        /// is written for an app that races several roads and can be told to
        /// go and open itself on the cluster's network once; the dial pins
        /// exactly one road and is being run *by* the cluster's operator, so
        /// passing that sentence through said something false and unactionable
        /// in a report where the road and the port are already named. There is
        /// nothing left to add beyond the fact.
        case noAnswer
        /// Something answered and then would not serve — refused the
        /// handshake, refused the session, or accepted the connection and
        /// went quiet.
        case answeredAndFailed(String)
        /// There is no cluster CA yet, so there is nothing to mint a
        /// diagnostic identity from. A host on its first run, not a fault.
        case noClusterCA(String)
        /// A dial was not attempted because minting the diagnostic identity
        /// failed. This says nothing whatever about the cluster, and saying so
        /// is the whole point of the case being separate.
        case notAttempted(String)
    }

    /// Where the session came in from, as the daemon saw it — which is not
    /// the same fact as where the client dialed, and the difference is the
    /// entire away claim.
    public enum Road: Sendable, Equatable {
        /// The daemon logged this session and named the road.
        case named(String)
        /// No session opened, so there is no road to look for.
        case notApplicable
        /// A session opened and the daemon's own log does not carry the line.
        /// This is the instrument failing its own check.
        case missing
        /// A session opened and there is nowhere to read the daemon's output:
        /// it is not running under the launchd agent, so its lines are on
        /// somebody's terminal.
        case unread(String)
    }

    /// The diagnostic identity's authority, beside `device` and `app`.
    ///
    /// A third authority rather than a reused one, and the reason is
    /// structural rather than tidy: `PeerIdentity.deviceID(fromURI:)` parses
    /// exactly `reach://device/`, so a certificate minted here can never be
    /// read as an enrolled device and can never hold the admin grant. Nothing
    /// has to remember that; the prefix enforces it.
    ///
    /// The M2 interaction is named here on purpose. When attestation and
    /// revocation arrive, this path must stay truthful about what it is
    /// rather than become a bypass anyone else can take.
    public static let diagnosticAuthority = "reach://diagnostic/"

    /// Dials the cluster once.
    ///
    /// - Parameters:
    ///   - via: the address to dial, or nil for loopback. A chosen road is
    ///     how this doubles as the away instrument: `--via` the mesh address
    ///     proves that road from the host side before a phone is asked to.
    ///   - budget: the whole thing completes or refuses inside this. Split in
    ///     half so both halves stay inside it — see `openingBy`.
    public static func dial(
        stateDirectory: URL,
        config: DaemonConfig,
        via: String? = nil,
        budget: Duration = .seconds(10),
        supervision: Supervision = .launchAgent
    ) async -> Outcome {
        let host = via ?? "127.0.0.1"
        let pinned = via != nil

        // A label nothing else will ever use. Not cosmetic: the hub seeds a
        // fresh entry's redial candidates from `ClusterRoads.load(for:)` and
        // `noteCandidates` writes them back under the same label on every
        // success — so a fixed label would make the *second* `--via` run race
        // the roads the first one learned, let the LAN win on latency, and
        // then report that road as the one under test. A dial that names the
        // wrong road is worse than no dial.
        let label = "reach-doctor-dial-\(UUID().uuidString)"

        let material: ReachIdentityRegistry.Material
        do {
            material = try mint(stateDirectory: stateDirectory, label: label)
        } catch let error as CAError {
            return Outcome(
                result: .noClusterCA("\(error)"),
                elapsed: nil,
                road: .notApplicable,
                via: host,
                port: config.port,
                pinned: pinned
            )
        } catch {
            return Outcome(
                result: .notAttempted("\(error)"),
                elapsed: nil,
                road: .notApplicable,
                via: host,
                port: config.port,
                pinned: pinned
            )
        }

        // Minted, used, and gone. `kSecImportToMemoryOnly` keeps the identity
        // out of the keychain (`fbad415`); this keeps the roads out of it too,
        // and is the same line that makes `--via` truthful twice running.
        defer { try? ClusterRoads.forget(for: label) }

        await ReachIdentityRegistry.shared.register(label: label, material: material)

        let configuration = ReachExecutor.Configuration(
            host: host,
            port: config.port,
            modelID: config.modelID,
            identityLabel: label,
            connectTimeout: (budget / 2).seconds
        )

        let clock = ContinuousClock()
        let start = clock.now
        do {
            let handle = try await openingBy(start + budget) {
                try await ReachConnectionHub.shared.session(for: configuration)
            }
            let elapsed = clock.now - start
            return Outcome(
                result: .opened(capabilities: handle.capabilities),
                elapsed: elapsed,
                road: await road(of: handle.sessionID, supervision: supervision),
                via: host,
                port: config.port,
                pinned: pinned
            )
        } catch let error as ReachError {
            return Outcome(
                result: classify(error),
                elapsed: clock.now - start,
                road: .notApplicable,
                via: host,
                port: config.port,
                pinned: pinned
            )
        } catch is DialTimeout {
            return Outcome(
                // The dial itself is bounded by `connectTimeout`, which is
                // half this budget — so reaching the outer one means a
                // connection opened and the exchange on it did not finish.
                result: .answeredAndFailed("it accepted the connection and then said nothing"),
                elapsed: clock.now - start,
                road: .notApplicable,
                via: host,
                port: config.port,
                pinned: pinned
            )
        } catch {
            return Outcome(
                result: .answeredAndFailed("\(error)"),
                elapsed: clock.now - start,
                road: .notApplicable,
                via: host,
                port: config.port,
                pinned: pinned
            )
        }
    }

    /// The client's own sentences travel through rather than being restated.
    /// A reason written once, next to the code that knows it, beats a
    /// parallel vocabulary maintained here.
    static func classify(_ error: ReachError) -> Result {
        switch error {
        case .unreachable:
            .noAnswer
        case .identityNotRegistered:
            // Structurally impossible — this function registers the material
            // one line before dialing — but if it ever happens it is this
            // command's fault and not the cluster's.
            .notAttempted("\(error)")
        case .transport, .sessionRejected, .remote, .generationLost:
            .answeredAndFailed("\(error)")
        }
    }

    // MARK: - The diagnostic identity

    /// Mints a client identity from the cluster's own CA, uses it, and lets
    /// it fall out of scope.
    ///
    /// ⚠️ **This is the ~0.4 %/import PKCS#12 path, every single time.**
    /// `IdentityMaterializer`'s own header records why: `SecItemAdd` wants a
    /// keychain entitlement no plain SwiftPM executable carries, so every
    /// materialization in this project falls through to `viaPKCS12`. Roughly
    /// one dial in two hundred and fifty will die in `SecPKCS12Import` with an
    /// empty item list. That failure is **this command's**, and the caller
    /// reports it as `.notAttempted` — a diagnostic that occasionally libels a
    /// healthy cluster is the exact genre of error it exists to abolish.
    static func mint(stateDirectory: URL, label: String) throws -> ReachIdentityRegistry.Material {
        let ca = try ClusterCA.load(from: stateDirectory.appendingPathComponent("ca", isDirectory: true))
        let issued = try ca.issueClient(
            commonName: "reachd doctor",
            uri: diagnosticAuthority + UUID().uuidString,
            validFor: 300
        )
        return ReachIdentityRegistry.Material(
            identity: try IdentityMaterializer.materialize(issued, label: label),
            caCertificate: try IdentityStore.certificate(fromDER: ca.certificateDER())
        )
    }

    // MARK: - The road

    /// Where the daemon's own output can be read, if anywhere.
    public enum Supervision: Sendable, Equatable {
        /// The ordinary case: read the launchd agent's log, and treat a
        /// missing plist as "nothing collects this daemon's output".
        case launchAgent
        /// A named file, and whether to hold it to the standard. Tests use
        /// this; so could a future `--log` flag.
        case log(URL, collected: Bool)
    }

    /// Reads the road back out of the daemon's own log.
    ///
    /// The road cannot come back over the wire — `SessionOpened` carries no
    /// such field and adding one would be new wire vocabulary for a fact only
    /// this command wants. `ca10213` gave the daemon
    /// `session <id> opened from <road>` on every open, so the honest way to
    /// learn it is to read the line the daemon wrote. Which means this check
    /// is also the instrument checking the instrument: a road that never got
    /// logged is a finding, and it is one of the five.
    ///
    /// ⚠️ The line is written *after* `SessionOpened` is sent, so the client
    /// can and does win that race. `serve` sets stdout line-buffered
    /// (`Reachd.swift`) so it lands promptly, but "promptly" is not
    /// "already" — a single read flakes, and this polls.
    static func road(
        of sessionID: UUID,
        supervision: Supervision,
        within: Duration = .seconds(2)
    ) async -> Road {
        let url: URL
        let collected: Bool
        switch supervision {
        case .launchAgent:
            url = LaunchAgent.logURL()
            // The agent holds the session port, so a daemon answering on it
            // while the agent is installed is the agent. With no plist, the
            // daemon is somebody's foreground `serve` and its lines went to
            // that terminal — which is a fine way to work and not a fault.
            collected = FileManager.default.fileExists(atPath: LaunchAgent.plistURL().path)
        case .log(let logURL, let isCollected):
            url = logURL
            collected = isCollected
        }

        guard collected else {
            return .unread("the daemon is not running under the launchd agent, so nothing collects its output")
        }
        guard FileManager.default.fileExists(atPath: url.path) else {
            return .unread("\(url.path) is not there to read")
        }

        // Not a literal. `Log` owns both halves of this format so the reader
        // and the writer move together — see the note there.
        let needle = Log.roadPrefix(session: sessionID)
        let clock = ContinuousClock()
        let deadline = clock.now + within
        repeat {
            if let road = lastRoad(matching: needle, in: url) {
                return .named(road)
            }
            try? await Task.sleep(for: .milliseconds(50))
        } while clock.now < deadline
        return .missing
    }

    /// The tail of the log is enough: the line being looked for was written
    /// within the last couple of seconds, and reading a log that has been
    /// growing since login in full, forty times a second, is not.
    private static func lastRoad(matching needle: String, in url: URL, tail: Int = 64 * 1024) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        guard let end = try? handle.seekToEnd() else { return nil }
        try? handle.seek(toOffset: end > UInt64(tail) ? end - UInt64(tail) : 0)
        guard let data = try? handle.readToEnd(),
              let text = String(data: data, encoding: .utf8)
        else { return nil }
        for line in text.split(separator: "\n").reversed() {
            if let range = line.range(of: needle) {
                return String(line[range.upperBound...])
            }
        }
        return nil
    }

    // MARK: - The budget

    struct DialTimeout: Error {}

    /// The dial completes or refuses inside its budget, and the budget has to
    /// be imposed right here.
    ///
    /// `ReachExecutor.respond` races its opens against a deadline
    /// (`1c4026c`), but that race lives in the executor and this caller opens
    /// a session directly — so it inherits the hub's own bounds, and those do
    /// not cover everything. `connectTimeout` bounds the dial;
    /// `session(for:)`'s two handshake reads are bounded by nothing but the
    /// QUIC idle timeout, which is thirty seconds. A daemon that accepts a
    /// connection and never speaks is one of the five failures this command
    /// exists to name, and without this it would hold `doctor` for half a
    /// minute and then report a transport error instead of a budget.
    ///
    /// The halves: `connectTimeout` gets the first half of the budget, so
    /// nothing-answered surfaces as the client's own `.unreachable` sentence
    /// well inside it, and this outer deadline catches only the case where
    /// something answered and then stopped.
    static func openingBy<T: Sendable>(
        _ deadline: ContinuousClock.Instant,
        _ open: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await open() }
            group.addTask {
                try await Task.sleep(until: deadline, clock: ContinuousClock())
                throw DialTimeout()
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else { throw DialTimeout() }
            return first
        }
    }
}

extension Duration {
    /// `connectTimeout` is a `Double` of seconds and budgets here are
    /// `Duration`s; converting in one named place beats an attosecond
    /// expression at each call site.
    var seconds: Double {
        Double(components.seconds) + Double(components.attoseconds) / 1e18
    }
}
