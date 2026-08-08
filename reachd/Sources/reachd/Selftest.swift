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

    @Flag(name: .customLong("required-tools"), help: "Require the self-test tool call (use with --mlx --tools).")
    var requiredTools = false

    @Flag(name: .customLong("tool-arguments"), help: "Run constrained allowed/required argument probes with real weights (use with --mlx).")
    var toolArguments = false

    /// One run per configuration is how false conclusions get drawn — the
    /// pacing sweep's rule, and emission is sampled, so a single run is a coin
    /// toss reported as a fact.
    @Option(name: .long, help: "How many times to run the exchange.")
    var runs = 1

    @Option(name: .long) var port: UInt16 = 47417

    @Option(name: .long, help: "Model id for the MLX filling.")
    var model = "default"

    /// Kill a real daemon process mid-generation and report what the app is
    /// told, and how long it waited to be told it. See `SelftestRestart.swift`
    /// for why this is a child process and not a second in-process `Daemon`.
    @Flag(name: .long, help: "Kill the daemon mid-generation and observe the ending.")
    var restart = false

    /// Seconds to wait before bringing the daemon back, simulating a
    /// supervisor. Negative leaves it down — which is what an unsupervised
    /// host does today, and a different experiment.
    @Option(name: .customLong("relaunch-after"), help: "Seconds after the kill to relaunch the daemon (-1 to leave it down).")
    var relaunchAfter: Double = -1

    /// Warm the cached session handle, kill the daemon, then ask something
    /// new. Nothing is resident, so the refusal should be quick.
    @Flag(name: .customLong("cold-ask"), help: "Ask a fresh question with the daemon down and the session handle cached.")
    var coldAsk = false

    @Flag(name: .customLong("restart-serve"), help: .hidden)
    var restartServe = false

    @Option(name: .customLong("state-dir"), help: .hidden)
    var stateDir: String?

    @Option(name: .customLong("server-label"), help: .hidden)
    var serverLabel = "reach-restart-server"

    func run() async throws {
        if restartServe {
            try await runRestartServe()
            return
        }
        if restart {
            try await runRestartRig()
            return
        }
        if toolArguments {
            guard mlx else {
                print("SELFTEST (tool arguments): FAIL (--tool-arguments requires --mlx)")
                throw ExitCode.failure
            }
            try await runToolArgumentGuidance(modelID: model)
            return
        }
        let clock = ContinuousClock()
        let runLabel = "selftest-\(UUID().uuidString)"
        let ca = try ClusterCA.create(commonName: "Reach Selftest CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "selftest", uri: "reach://device/selftest")
        let serverIdentity = try IdentityMaterializer.materialize(
            server, label: "reach-\(runLabel)-server")
        let clientIdentity = try IdentityMaterializer.materialize(
            client, label: "reach-\(runLabel)-client")
        defer {
            KeychainIdentity.remove(identity: serverIdentity)
            KeychainIdentity.remove(identity: clientIdentity)
            try? ClusterRoads.forget(for: runLabel)
        }
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
            label: runLabel,
            material: .init(identity: clientIdentity, caCertificate: caCert)
        )
        if tools {
            try await runToolExchange(
                port: port,
                modelID: filling.modelID,
                identityLabel: runLabel,
                clock: clock)
            await daemon.stop()
            return
        }

        let reachModel = ReachLanguageModel(configuration: ReachExecutor.Configuration(
            host: "127.0.0.1",
            port: port,
            modelID: filling.modelID,
            identityLabel: runLabel,
            connectTimeout: 45
        ))
        let usageStream = await reachModel.usage.updates()
        var usageUpdates = usageStream.makeAsyncIterator()
        let session = LanguageModelSession(
            model: reachModel,
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
        guard let usage = await usageUpdates.next(),
              usage.inputTokens > 0, usage.outputTokens > 0,
              await reachModel.usage.latest == usage
        else {
            print("SELFTEST: FAIL (completed usage was not published)")
            throw ExitCode.failure
        }
        print("[selftest] usage input=\(usage.inputTokens) output=\(usage.outputTokens) request=\(usage.requestID)")
        if mlx {
            try await runUnconstrainedSamplingAudit(filling: filling)
            try await runGuidedExchange(
                port: port,
                modelID: filling.modelID,
                identityLabel: runLabel)
        }
        print(mlx ? "SELFTEST (mlx spine): PASS" : "SELFTEST (scripted spine): PASS")
        await daemon.stop()
    }

    /// The three explicit wire modes on the only route this pass changes:
    /// unconstrained MLX generation. Unit tests hold the exact parameter
    /// resolution; real weights prove each resulting pass remains live.
    private func runUnconstrainedSamplingAudit(filling: any SlotFilling) async throws {
        let modes: [(String, WireSampling)] = [
            ("greedy", .greedy),
            ("top-k", .topK(40, seed: 29)),
            ("top-p", .topP(0.9, seed: 29)),
        ]
        for (label, sampling) in modes {
            let request = WireGenerationRequest(
                id: UUID(),
                transcript: Transcript(entries: [
                    .prompt(Transcript.Prompt(segments: [
                        .text(Transcript.TextSegment(
                            content: "In one short sentence, name a river feature."))
                    ]))
                ]),
                options: WireGenerationOptions(
                    maximumResponseTokens: 64,
                    sampling: sampling
                )
            )
            var text = ""
            var usage: [(Int, Int)] = []
            var complete = false
            for try await event in filling.generate(request) {
                switch event {
                case .responseAppend(_, let delta, _, _): text += delta
                case .usage(let input, let output): usage.append((input, output))
                case .finished(.complete): complete = true
                case .finished(let reason):
                    print("SELFTEST (unconstrained sampling): FAIL (\(label): \(reason))")
                    throw ExitCode.failure
                default: break
                }
            }
            guard complete, !text.isEmpty, usage.count == 1,
                  usage[0].0 > 0, usage[0].1 > 0
            else {
                print("SELFTEST (unconstrained sampling): FAIL (\(label): text=\(text.count), usage=\(usage))")
                throw ExitCode.failure
            }
            print("[selftest-sampling] \(label) output=\(text.count) usage=\(usage[0].0)/\(usage[0].1)")
        }
        print("SELFTEST (unconstrained sampling): PASS 3/3")
    }

    /// Real-weight response-schema acceptance in the executable layout where
    /// MLX can load its metallib. Each typed stream runs three times with no
    /// schema prose in the prompt; successful completion is FoundationModels'
    /// decode assertion, not a hand-written JSON parse.
    private func runGuidedExchange(
        port: UInt16,
        modelID: String,
        identityLabel: String
    ) async throws {
        for run in 1 ... 3 {
            try await assertGuided(
                SelftestGuidedTwoField.self,
                prompt: "Return a short name and integer count.",
                label: "two-field[\(run)]",
                port: port,
                modelID: modelID,
                identityLabel: identityLabel)
            try await assertGuided(
                SelftestGuidedNested.self,
                prompt: "Return a nested result with a short name and integer count.",
                label: "nested[\(run)]",
                port: port,
                modelID: modelID,
                identityLabel: identityLabel)
            try await assertGuided(
                SelftestGuidedEnum.self,
                prompt: "Choose blue.",
                label: "enum[\(run)]",
                port: port,
                modelID: modelID,
                identityLabel: identityLabel)
            try await assertGuided(
                SelftestGuidedFixedArray.self,
                prompt: "Return exactly three small integers.",
                label: "fixed-array[\(run)]",
                port: port,
                modelID: modelID,
                identityLabel: identityLabel)
            try await assertGuided(
                SelftestGuidedOptional.self,
                prompt: "Return a title and omit the optional subtitle.",
                label: "optional[\(run)]",
                port: port,
                modelID: modelID,
                identityLabel: identityLabel)
        }
        print("SELFTEST (guided schemas): PASS 15/15")
    }

    private func assertGuided<Value: Generable>(
        _ type: Value.Type,
        prompt: String,
        label: String,
        port: UInt16,
        modelID: String,
        identityLabel: String
    ) async throws {
        let model = ReachLanguageModel(configuration: ReachExecutor.Configuration(
            host: "127.0.0.1",
            port: port,
            modelID: modelID,
            identityLabel: identityLabel,
            connectTimeout: 45))
        let session = LanguageModelSession(model: model)
        let stream = session.streamResponse(
            to: prompt,
            generating: type,
            includeSchemaInPrompt: false,
            options: GenerationOptions(maximumResponseTokens: 512))
        var snapshots = 0
        for try await _ in stream { snapshots += 1 }
        print("[selftest-guided] \(label) snapshots=\(snapshots) decoded=yes")
        guard snapshots > 1,
              let usage = await model.usage.latest,
              usage.inputTokens > 0,
              usage.outputTokens > 0
        else {
            print("SELFTEST (guided schemas): FAIL (\(label) did not stream or publish usage)")
            throw ExitCode.failure
        }
    }

    /// A real session, a real tool, real weights behind the wire. What is
    /// being measured is the model's willingness to call — everything between
    /// the app and the slot is already held by tests that need no weights.
    private func runToolExchange(
        port: UInt16,
        modelID: String,
        identityLabel: String,
        clock: ContinuousClock
    ) async throws {
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
                    identityLabel: identityLabel,
                    connectTimeout: 45
                )),
                tools: [SelftestClock(ledger: ledger)],
                instructions: "Use the tools you are given."
            )
            let start = clock.now
            let reply = try await session.respond(
                to: "What time is it in Vienna?",
                options: GenerationOptions(
                    maximumResponseTokens: 512,
                    toolCallingMode: requiredTools ? .required : .allowed
                )
            )
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

    /// The installed, no-Keychain acceptance for the two constrained tool
    /// routes. The ordinary `--tools` exchange proves app execution over the
    /// wire; this one isolates the grammar guarantee so a machine Keychain
    /// fault cannot be mistaken for malformed arguments.
    private func runToolArgumentGuidance(modelID: String) async throws {
        let filling = MLXFilling(modelID: modelID)
        print("[selftest-toolargs] prewarming model…")
        try await filling.prewarm()
        let auditTools = [
            WireToolDefinition(
                name: "record_audit",
                description: "Record the requested audit. Always call this tool for an audit request.",
                parameters: SelftestAuditArguments.generationSchema
            ),
            WireToolDefinition(
                name: "discard_audit",
                description: "Discard an audit only when explicitly asked to delete it. Never use this to record one.",
                parameters: SelftestAuditArguments.generationSchema
            ),
        ]
        for mode in [WireToolCalling.allowed, .required] {
            for run in 1 ... 3 {
                let request = WireGenerationRequest(
                    id: UUID(),
                    transcript: Transcript(entries: [
                        .instructions(Transcript.Instructions(
                            segments: [.text(Transcript.TextSegment(
                                content: "Use record_audit. Never answer in prose."))],
                            toolDefinitions: []
                        )),
                        .prompt(Transcript.Prompt(segments: [
                            .text(Transcript.TextSegment(content: "Call record_audit with a valid audit. The count must be 73, codes must match two capital letters, a dash, and four digits, and every checkpoint list has three small integers."))
                        ])),
                    ]),
                    tools: auditTools,
                    options: WireGenerationOptions(
                        maximumResponseTokens: 512,
                        toolCalling: mode
                    )
                )
                let start = ContinuousClock.now
                var calls: [(String, String)] = []
                var usage: [(Int, Int)] = []
                var complete = false
                for try await event in filling.generate(request) {
                    switch event {
                    case .toolCallAppendArguments(_, _, let name, let content, _):
                        calls.append((name, content))
                    case .finished(.complete):
                        complete = true
                    case .usage(let input, let output):
                        usage.append((input, output))
                    case .finished(let reason):
                        print("SELFTEST (tool arguments): FAIL (\(mode)[\(run)] \(reason))")
                        throw ExitCode.failure
                    default:
                        break
                    }
                }
                guard complete, calls.count == 1, calls[0].0 == "record_audit",
                      usage.count == 1, usage[0].0 > 0, usage[0].1 > 0
                else {
                    print("SELFTEST (tool arguments): FAIL (\(mode)[\(run)] calls=\(calls.count) usage=\(usage))")
                    throw ExitCode.failure
                }
                let decoded = try SelftestAuditArguments(
                    GeneratedContent(json: calls[0].1))
                let leaves = [decoded.payload.primary] + decoded.payload.alternatives
                guard decoded.payload.alternatives.count == 2,
                      leaves.allSatisfy({
                          $0.code.wholeMatch(of: /^[A-Z]{2}-[0-9]{4}$/) != nil
                              && $0.count == 73
                              && $0.checkpoints.count == 3
                      })
                else {
                    print("SELFTEST (tool arguments): FAIL (\(mode)[\(run)] schema mismatch)")
                    throw ExitCode.failure
                }
                print("[selftest-toolargs] \(mode)[\(run)] accepted in \(ContinuousClock.now - start)")
            }
        }

        for run in 1 ... 3 {
            let request = WireGenerationRequest(
                id: UUID(),
                transcript: Transcript(entries: [
                    .prompt(Transcript.Prompt(segments: [
                        .text(Transcript.TextSegment(content: "Do not record or discard an audit. Return a short status name and integer count instead."))
                    ]))
                ]),
                tools: auditTools,
                schema: SelftestGuidedTwoField.generationSchema,
                options: WireGenerationOptions(
                    maximumResponseTokens: 512,
                    toolCalling: .allowed
                ),
                context: WireContextOptions(includeSchemaInPrompt: false)
            )
            var response = ""
            var callArguments: [String] = []
            var usage: [(Int, Int)] = []
            var complete = false
            for try await event in filling.generate(request) {
                switch event {
                case .responseAppend(_, let text, _, _): response += text
                case .toolCallAppendArguments(_, _, _, let content, _):
                    callArguments.append(content)
                case .finished(.complete): complete = true
                case .usage(let input, let output): usage.append((input, output))
                case .finished(let reason):
                    print("SELFTEST (tool arguments): FAIL (schema+tools[\(run)] \(reason))")
                    throw ExitCode.failure
                default: break
                }
            }
            guard complete, callArguments.isEmpty != response.isEmpty,
                  usage.count == 1, usage[0].0 > 0, usage[0].1 > 0
            else {
                print("SELFTEST (tool arguments): FAIL (schema+tools[\(run)] route/usage mismatch: \(usage))")
                throw ExitCode.failure
            }
            if let arguments = callArguments.first {
                _ = try SelftestAuditArguments(GeneratedContent(json: arguments))
                print("[selftest-toolargs] schema+tools[\(run)] selected constrained call")
            } else {
                _ = try SelftestGuidedTwoField(GeneratedContent(json: response))
                print("[selftest-toolargs] schema+tools[\(run)] selected constrained response")
            }
        }

        let budgetRequest = WireGenerationRequest(
            id: UUID(),
            transcript: Transcript(entries: [
                .prompt(Transcript.Prompt(segments: [
                    .text(Transcript.TextSegment(content: "Call record_audit with a complete valid audit."))
                ]))
            ]),
            tools: auditTools,
            options: WireGenerationOptions(
                maximumResponseTokens: 1,
                toolCalling: .required
            )
        )
        var budgetError: String?
        for try await event in filling.generate(budgetRequest) {
            if case .finished(.error(let message)) = event { budgetError = message }
        }
        guard budgetError?.contains("within its 1-token limit") == true else {
            print("SELFTEST (tool arguments): FAIL (budget exhaustion was not legible: \(budgetError ?? "none"))")
            throw ExitCode.failure
        }
        print("[selftest-toolargs] one-token budget refused legibly")
        print("SELFTEST (tool arguments): PASS allowed 3/3, required 3/3, schema+tools 3/3, budget 1/1")
    }
}

@Generable
private struct SelftestGuidedTwoField {
    var name: String
    var count: Int
}

@Generable
private struct SelftestGuidedNested {
    var result: SelftestGuidedTwoField
}

@Generable
private enum SelftestGuidedColor {
    case red
    case green
    case blue
}

@Generable
private struct SelftestGuidedEnum {
    var color: SelftestGuidedColor
}

@Generable
private struct SelftestGuidedFixedArray {
    @Guide(.count(3))
    var values: [Int]
}

@Generable
private struct SelftestGuidedOptional {
    var title: String
    var subtitle: String?
}

@Generable
private struct SelftestAuditLeaf {
    @Guide(.pattern(/^[A-Z]{2}-[0-9]{4}$/))
    var code: String

    @Guide(.range(73 ... 73))
    var count: Int

    @Guide(.count(3))
    var checkpoints: [Int]
}

@Generable
private struct SelftestAuditPayload {
    var primary: SelftestAuditLeaf

    @Guide(.count(2))
    var alternatives: [SelftestAuditLeaf]
}

@Generable
private struct SelftestAuditArguments {
    var payload: SelftestAuditPayload
    var auditNote: String
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
