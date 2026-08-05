import ArgumentParser
import Foundation
import FoundationModels
import ReachDaemon
import ReachIdentity
import ReachKit
import ReachWire

/// The spine, self-contained: daemon and a real `LanguageModelSession` in
/// one process over loopback with freshly issued certificates. With
/// `--mlx`, real weights serve real tokens — the Phase 1 acceptance minus
/// the second machine, runnable any time the demo needs a sanity check.
struct Selftest: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run the spine end to end in one process (scripted filling, or --mlx for real weights)."
    )

    @Flag(name: .long, help: "Serve real tokens via the MLX filling.")
    var mlx = false

    /// The tool round trip, with real weights, end to end.
    ///
    /// It lives here rather than in the test suite for the same reason
    /// `--mlx` does: MLX's metallib is only locatable in an executable
    /// layout, so `swift test` from a terminal cannot load it at all. A
    /// measurement that can only be run somewhere else is not a measurement.
    @Flag(name: .long, help: "Attach a tool and measure the round trip (use with --mlx).")
    var tools = false

    /// One run per configuration is how false conclusions get drawn — the
    /// pacing sweep's rule, and emission is sampled, so a single run is a coin
    /// toss reported as a fact.
    @Option(name: .long, help: "How many times to run the exchange.")
    var runs = 1

    @Option(name: .long) var port: UInt16 = 47417

    @Option(name: .long, help: "Model id for the MLX filling.")
    var model = "default"

    func run() async throws {
        let clock = ContinuousClock()
        let ca = try ClusterCA.create(commonName: "Reach Selftest CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "selftest", uri: "reach://device/selftest")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-selftest-server")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-selftest-client")
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        let filling: any SlotFilling = mlx ? MLXFilling(modelID: model) : SelftestFilling()
        var config = DaemonConfig()
        config.port = port
        config.clusterName = "selftest"
        config.modelID = filling.modelID
        let daemon = Daemon(
            config: config,
            filling: filling,
            identity: Daemon.ListenerIdentity(identity: serverIdentity, caCertificate: caCert)
        )
        try await daemon.start(advertise: false)
        if mlx {
            print("[selftest] prewarming model…")
            try await filling.prewarm()
        }

        await ReachIdentityRegistry.shared.register(
            label: "selftest",
            material: .init(identity: clientIdentity, caCertificate: caCert)
        )
        if tools {
            try await runToolExchange(port: port, modelID: filling.modelID, clock: clock)
            await daemon.stop()
            return
        }

        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: ReachExecutor.Configuration(
                host: "127.0.0.1",
                port: port,
                modelID: filling.modelID,
                identityLabel: "selftest",
                connectTimeout: 45
            )),
            instructions: "You are terse."
        )
        let start = clock.now
        let stream = session.streamResponse(to: mlx ? "In one short sentence: what is a reach, on a river?" : "Go.")
        var firstSnapshot: Duration?
        var snapshots = 0
        var final = ""
        for try await snapshot in stream {
            if firstSnapshot == nil { firstSnapshot = clock.now - start }
            snapshots += 1
            final = snapshot.content
        }
        print("[selftest] first snapshot \(firstSnapshot.map(String.init(describing:)) ?? "-"), \(snapshots) snapshots")
        print("[selftest] final: \(final)")
        guard !final.isEmpty, snapshots > 1 else {
            print("SELFTEST: FAIL (empty or non-streaming)")
            throw ExitCode.failure
        }
        print(mlx ? "SELFTEST (mlx spine): PASS" : "SELFTEST (scripted spine): PASS")
        await daemon.stop()
    }

    /// A real session, a real tool, real weights behind the wire. What is
    /// being measured is the model's willingness to call — everything between
    /// the app and the slot is already held by tests that need no weights.
    private func runToolExchange(port: UInt16, modelID: String, clock: ContinuousClock) async throws {
        var called = 0
        var timezones: [String] = []
        var prose: [String] = []

        for run in 1...max(1, runs) {
            let ledger = ToolLedger()
            let session = LanguageModelSession(
                model: ReachLanguageModel(configuration: ReachExecutor.Configuration(
                    host: "127.0.0.1",
                    port: port,
                    modelID: modelID,
                    identityLabel: "selftest",
                    connectTimeout: 45
                )),
                tools: [SelftestClock(ledger: ledger)],
                instructions: "Use the tools you are given."
            )
            let start = clock.now
            let reply = try await session.respond(to: "What time is it in Vienna?")
            let elapsed = clock.now - start
            let asked = ledger.timezones
            if asked.isEmpty {
                prose.append(reply.content)
            } else {
                called += 1
                timezones.append(contentsOf: asked)
            }
            let entries = session.transcript.map { entry -> String in
                switch entry {
                case .instructions: "instructions"
                case .prompt: "prompt"
                case .toolCalls: "toolCalls"
                case .toolOutput: "toolOutput"
                case .response: "response"
                case .reasoning: "reasoning"
                @unknown default: "?"
                }
            }
            print("[selftest-tools] run \(run)/\(max(1, runs)) \(asked.isEmpty ? "no call" : "CALLED \(asked)") in \(elapsed)")
            print("[selftest-tools]   transcript: \(entries.joined(separator: " | "))")
            print("[selftest-tools]   reply: \(reply.content.prefix(160))")
        }

        print("[selftest-tools] \(modelID): \(called)/\(max(1, runs)) runs called the tool")
        if !timezones.isEmpty { print("[selftest-tools] arguments chosen: \(Set(timezones).sorted())") }
        if !prose.isEmpty {
            print("[selftest-tools] answered in prose instead: \(prose.map { String($0.prefix(120)) })")
        }
        // A model that declines to call is a finding about the model, not a
        // failure of the path — the pass file's own reading, and why the slot
        // is model-agnostic. A call that came back mangled is the other thing.
        print(called > 0 ? "SELFTEST (tools): CALLED \(called)/\(max(1, runs))" : "SELFTEST (tools): NO CALL in \(max(1, runs))")
    }
}

/// What the app's tool was actually asked, recorded rather than inferred.
private final class ToolLedger: @unchecked Sendable {
    private let lock = NSLock()
    private var asked: [String] = []

    func record(_ timezone: String) {
        lock.lock()
        defer { lock.unlock() }
        asked.append(timezone)
    }

    var timezones: [String] {
        lock.lock()
        defer { lock.unlock() }
        return asked
    }
}

@Generable
private struct SelftestClockArguments {
    @Guide(description: "IANA timezone identifier, for example Europe/Vienna")
    var timezone: String
}

/// Deliberately boring, and deliberately something the model cannot know: a
/// plausible-looking time in the answer is not evidence of anything unless it
/// is *this* clock's.
private struct SelftestClock: Tool {
    let name = "current_time"
    let description = "The current time in a given timezone. Call this whenever the user asks what time it is."
    let ledger: ToolLedger

    func call(arguments: SelftestClockArguments) async throws -> String {
        ledger.record(arguments.timezone)
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        formatter.timeZone = TimeZone(identifier: arguments.timezone) ?? .gmt
        return "\(formatter.string(from: Date())) in \(arguments.timezone)"
    }
}

private struct SelftestFilling: SlotFilling {
    let modelID = "selftest"
    let displayName = "Selftest"
    let capabilities: [String] = []

    func prewarm() async throws {}

    func generate(_ request: ReachWire.WireGenerationRequest) -> AsyncThrowingStream<ReachWire.WireEvent, Error> {
        let (stream, continuation) = AsyncThrowingStream<ReachWire.WireEvent, Error>.makeStream()
        Task {
            for word in ["The ", "spine ", "holds."] {
                continuation.yield(.responseAppend(entryID: nil, text: word, segmentID: nil, tokenCount: 1))
                try? await Task.sleep(for: .milliseconds(30))
            }
            continuation.yield(.finished(.complete))
            continuation.finish()
        }
        return stream
    }
}
