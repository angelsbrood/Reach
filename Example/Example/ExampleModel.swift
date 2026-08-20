import Foundation
import FoundationModels
import Observation
import ReachIdentity
import ReachKit
import ReachTransport
import ReachWire

/// The Example app links ReachKit and nothing privileged — it stands in
/// for every third-party app. Identity, in preference order: whatever a
/// prior enrollment left in the keychain; a hand-provisioned Phase 1
/// bundle; else the app ASKS — the grant ceremony runs on first send and
/// the sheet appears on the keeper.
@Observable @MainActor
final class ExampleModel {
    /// Launch-environment-only acceptance shape. It is intentionally absent
    /// from the normal UI and does not replace the filmed prompt below.
    @Generable
    struct GuidedAcceptanceProbe {
        var name: String
        var count: Int
    }

    enum IdentityState: Equatable {
        case missing
        /// nil when the identity reloaded but the cluster's name could not be
        /// read back. Optional rather than a placeholder: this used to be a
        /// hardcoded `"enrolled"`, so a relaunched app's header read "Paired with
        /// enrolled" — which looks like a bug on camera because it is one.
        case registered(cluster: String?)
        case failed(String)
    }

    var identityState: IdentityState = .missing
    var clusters: [DiscoveredCluster] = []
    var host = "127.0.0.1"
    var modelID = "gemma-4-e4b"

    /// Whether to offer the cluster this app's clock.
    ///
    /// ⚠️ **Off by default, and that is not timidity.** Offering a tool puts a
    /// declaration block in the rendered template, which changes the prompt
    /// the model actually sees — and the demo's pacing was measured against
    /// the prompt below on this exact model (see `docs/demo.md`, and the
    /// warnings on `prompt`). A default that quietly re-rendered the film's
    /// prompt would invalidate numbers nobody would think to re-measure.
    var offersTool = false

    /// Which timezone the tool was asked for, once it has run. The completion
    /// text cannot establish that the tool ran *here* — this can.
    var toolRan: String?
    static let quickPrompt = "In one sentence, describe the mouth of a river."

    /// The long transition prompt selected from the app's prompt menu.
    ///
    /// The quick one-line default finishes in a sentence, which leaves no
    /// generation running to survive the network switch. Keeping this preset
    /// beside the quick test removes manual retyping while the rig is moving.
    /// `docs/demo.md` records why this shape: a long output from a short ask,
    /// with no natural stopping point early enough to strand the walk.
    ///
    /// ⚠️ The ceiling is NOT what governs the length any more. On gemma-3 it was:
    /// ~3000 words filled 4096 tokens. Measured on gemma-4 (2026-07-31) the model
    /// finished the whole essay in ~2,600 tokens at ~123 tok/s — twenty-one
    /// seconds, which is not enough stream to walk out into.
    ///
    /// ⚠️ Two levers, and the one predicted to work did not. Going from two
    /// paragraphs per reach to four was expected to give ~2.5x and **measured
    /// 1.10x** — this model largely writes what it was going to write. The
    /// stated word count is the other lever. Neither is obvious from reading;
    /// both have to be measured on the model actually being served, which is
    /// why the number lives here next to the reason rather than in someone's
    /// memory of how the last model behaved.
    ///
    /// The closing sentences are the film's last frame. Without them the model
    /// signs off — a question, an offer to expand — and the final image belongs
    /// to a chatbot rather than to the river. Naming all four exits is what it
    /// takes; "no closing question" alone still buys an offer to continue.
    static let transitionPrompt = """
        Write about 3000 words on the life of a river, reach by reach. Take it in \
        order: the spring and the first cut of the channel; the steep young water; \
        the shallows and the pools; the meanders and the oxbows; the confluences \
        where other waters arrive; the slow lowland reach; the tidal reach where \
        the current first answers the sea; and the mouth. Give each reach four \
        full paragraphs — one each on what has changed about the water, the \
        banks, the light, and the life in it since the reach before. \
        End with the last line of the essay itself. Do not add a closing \
        question, an offer to continue or expand, a summary of what you have \
        written, or any remark addressed to the reader.
        """
    var prompt = ExampleModel.quickPrompt
    var output = ""
    var status = ""
    var isStreaming = false

    private var browser: ClusterBrowser?
    private var session: LanguageModelSession?
    private var sessionKey: String?

    static let identityLabel = "reach-example"

    func useQuickPrompt() {
        prompt = Self.quickPrompt
    }

    func useTransitionPrompt() {
        prompt = Self.transitionPrompt
    }

    func bootstrap() async {
        // Identity: a prior enrollment's keychain items first, then the
        // env override (simulator runs point at the host filesystem), then
        // the app's Documents directory.
        if await ReachEnrollment.ensureRegistered(label: Self.identityLabel) {
            // The name comes off the pinned CA's subject, which is where it has
            // always been; nothing else persists it.
            identityState = .registered(
                cluster: await ReachEnrollment.registeredClusterName(label: Self.identityLabel)
            )
        }

        let candidates: [URL] = [
            ProcessInfo.processInfo.environment["REACH_IDENTITY"].map { URL(fileURLWithPath: $0) },
            FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
                .appendingPathComponent("reach-identity.json"),
        ].compactMap { $0 }

        if case .missing = identityState {
            for url in candidates where FileManager.default.fileExists(atPath: url.path) {
                do {
                    let bundle = try ProvisionedIdentity.load(from: url)
                    _ = try await ReachIdentityRegistry.shared.register(label: Self.identityLabel, provisioned: bundle)
                    identityState = .registered(cluster: bundle.clusterName)
                    break
                } catch {
                    identityState = .failed("\(error)")
                }
            }
        }

        let browser = ClusterBrowser()
        self.browser = browser
        let stream = browser.clusters
        Task { [weak self] in
            for await found in stream {
                await MainActor.run { self?.clusters = found }
            }
        }

        // Identity is no longer a precondition — an unregistered autosend
        // walks through the grant ceremony like any first send.
        if ProcessInfo.processInfo.environment["REACH_AUTOSEND"] == "1" {
            send()
        }
    }

    func send() {
        guard !isStreaming else { return }
        let text = prompt
        output = ""
        status = ""
        isStreaming = true
        Task {
            defer { isStreaming = false }
            // No identity is not a dead end: the app asks, the keeper's
            // sheet rules, and the send continues with the granted cert.
            do {
                try await ensureIdentity()
            } catch {
                status = "no grant: \(error)"
                print("[example] enrollment failed: \(error)")
                return
            }
            if ProcessInfo.processInfo.environment["REACH_LIVENESS_PROBE"] == "1" {
                let env = ProcessInfo.processInfo.environment
                let run = env["REACH_LIVENESS_RUN"] ?? "1"
                let mode = env["REACH_LIVENESS_MODE"] ?? "slow"
                let probeHost = env["REACH_LIVENESS_HOST"] ?? "127.0.0.1"
                let probePort = UInt16(env["REACH_LIVENESS_PORT"] ?? "47337") ?? 47337
                let probeIdentity = "\(Self.identityLabel)-liveness-\(run)"
                do {
                    guard let material = await ReachIdentityRegistry.shared.material(
                        for: Self.identityLabel
                    ) else {
                        throw ExampleError.livenessProbeMissingIdentity
                    }
                    await ReachIdentityRegistry.shared.register(
                        label: probeIdentity,
                        material: material
                    )
                    let configuration = ReachExecutor.Configuration(
                        host: probeHost,
                        port: probePort,
                        modelID: modelID,
                        identityLabel: probeIdentity,
                        connectTimeout: 10
                    )
                    try await runLivenessAcceptanceProbe(
                        configuration: configuration,
                        mode: mode,
                        run: run
                    )
                } catch {
                    status = "liveness failed: \(error)"
                    print("[example-liveness] failed mode=\(mode) run=\(run): \(error)")
                }
                return
            }
            // Prefer a discovered cluster (dialed as a Bonjour service,
            // resolved by the system) unless the operator typed a host.
            // The wait belongs HERE and not only in the enrollment path: a
            // granted app never enters that path, and dialling before
            // discovery lands means dialling `host`, which is this phone.
            let wantsDiscovered = host == "127.0.0.1"
            if wantsDiscovered { await awaitDiscovery() }
            let service = wantsDiscovered ? clusters.first?.name : nil
            if ProcessInfo.processInfo.environment["REACH_TOOLARGS_PROBE"] == "1" {
                let configuration = ReachExecutor.Configuration(
                    serviceName: service,
                    host: host,
                    modelID: modelID,
                    identityLabel: Self.identityLabel
                )
                let model = ReachLanguageModel(configuration: configuration)
                do {
                    try await runToolArgumentsAcceptanceProbe(model: model)
                } catch {
                    status = "failed: \(error)"
                    print("[example-toolargs] failed: \(error)")
                }
                return
            }
            if ProcessInfo.processInfo.environment["REACH_USAGE_PROBE"] == "1" {
                let configuration = ReachExecutor.Configuration(
                    serviceName: service,
                    host: host,
                    modelID: modelID,
                    identityLabel: Self.identityLabel
                )
                let model = ReachLanguageModel(configuration: configuration)
                do {
                    try await runUsageAcceptanceProbe(model: model)
                } catch {
                    status = "failed: \(error)"
                    print("[example-usage] failed: \(error)")
                }
                return
            }
            if ProcessInfo.processInfo.environment["REACH_GUIDED_PROBE"] == "1" {
                let configuration = ReachExecutor.Configuration(
                    serviceName: service,
                    host: host,
                    modelID: modelID,
                    identityLabel: Self.identityLabel
                )
                let model = ReachLanguageModel(configuration: configuration)
                do {
                    try await runGuidedAcceptanceProbe(model: model)
                } catch {
                    status = "failed: \(error)"
                    print("[example] failed: \(error)")
                }
                return
            }
            // The tool flag belongs in the key: offering a tool changes the
            // rendered template, so a session built without one cannot be
            // reused after the switch is thrown.
            let key = "\(service ?? host)|\(modelID)|\(offersTool)"
            if session == nil || sessionKey != key {
                let configuration = ReachExecutor.Configuration(
                    serviceName: service,
                    host: host,
                    modelID: modelID,
                    identityLabel: Self.identityLabel
                )
                let model = ReachLanguageModel(configuration: configuration)
                session = offersTool
                    ? LanguageModelSession(
                        model: model,
                        tools: [ClockTool(ran: { [weak self = self] zone in
                            Task { @MainActor in self?.toolRan = zone }
                        })],
                        instructions: "Use the tools you are given."
                    )
                    : LanguageModelSession(model: model)
                sessionKey = key
            }
            toolRan = nil
            guard let session, !session.isResponding else { return }
            status = "streaming…"
            do {
                // Demo pacing: long stories must stream long — the request
                // carries the ceiling and the daemon honors it (its own
                // fallback stays a bounded 512). The ceiling is deliberately
                // NON-binding now. On gemma-3 it was the limit; measured on
                // gemma-4 (2026-07-31) the model finishes the essay at ~2,600
                // tokens and stops, so what governs the length is the ask, and
                // the ceiling only has to stay out of its way.
                let stream = session.streamResponse(
                    to: text,
                    options: GenerationOptions(maximumResponseTokens: 16384)
                )
                for try await snapshot in stream {
                    self.output = snapshot.content
                }
                self.status = "done"
                print("[example] done: \(self.output.count) chars — \(self.output.prefix(80))")
            } catch {
                self.status = "failed: \(error)"
                print("[example] failed: \(error)")
            }
        }
    }

    /// Three deliberately hostile asks against the installed daemon. The
    /// prompt orders plain prose while `includeSchemaInPrompt` is false, so a
    /// completed typed stream proves the wire schema and grammar — not prompt
    /// coaching — won. Normal launches never call this.
    private func runGuidedAcceptanceProbe(model: ReachLanguageModel) async throws {
        var report: [String] = []
        for run in 1 ... 3 {
            let session = LanguageModelSession(model: model)
            let stream = session.streamResponse(
                to: "Reply only with the plain words absolutely not JSON.",
                generating: GuidedAcceptanceProbe.self,
                includeSchemaInPrompt: false,
                options: GenerationOptions(maximumResponseTokens: 512))
            var snapshots = 0
            for try await _ in stream { snapshots += 1 }
            guard snapshots > 1 else {
                throw ExampleError.guidedProbeDidNotStream(run: run, snapshots: snapshots)
            }
            report.append("run \(run): \(snapshots) snapshots")
            print("[example-guided] run=\(run) snapshots=\(snapshots) decoded=yes")
        }
        output = report.joined(separator: "\n")
        status = "guided probe passed 3/3"
    }

    /// A retained-model check for the public Reach-owned usage surface. The
    /// launch environment is the only caller; normal UI and demo behavior do
    /// not know this probe exists.
    private func runUsageAcceptanceProbe(model: ReachLanguageModel) async throws {
        let updates = await model.usage.updates()
        var iterator = updates.makeAsyncIterator()
        let session = LanguageModelSession(model: model)
        let response = try await session.respond(
            to: "In one short sentence, what is a river reach?",
            options: GenerationOptions(maximumResponseTokens: 128)
        )
        guard !response.content.isEmpty,
              let update = await iterator.next(),
              let latest = await model.usage.latest,
              update == latest,
              update.inputTokens > 0,
              update.outputTokens > 0
        else {
            throw ExampleError.usageProbeMissingCompletion
        }
        output = "request \(update.requestID)\ninput \(update.inputTokens) tokens\noutput \(update.outputTokens) tokens"
        status = "usage probe passed"
        print("[example-usage] passed input=\(update.inputTokens) output=\(update.outputTokens)")
    }

    /// The app-facing Tier 1/2 acceptance. A successful ledger entry means
    /// FoundationModels decoded the whole constrained argument object into the
    /// adversarial `@Generable` type and invoked the adopting app's tool.
    private func runToolArgumentsAcceptanceProbe(model: ReachLanguageModel) async throws {
        var report: [String] = []
        let modes: [(label: String, mode: GenerationOptions.ToolCallingMode)] = [
            ("allowed", .allowed),
            ("required", .required),
        ]
        for (label, mode) in modes {
            for run in 1 ... 3 {
                let ledger = ToolArgumentsProbeLedger()
                let session = LanguageModelSession(
                    model: model,
                    tools: [ToolArgumentsProbeTool(ledger: ledger)],
                    instructions: "Use record_audit. Never answer an audit request in prose."
                )
                do {
                    _ = try await session.respond(
                        to: "Call record_audit with a valid audit. The count must be 73, codes must match two capital letters, a dash, and four digits, and every checkpoint list has three small integers.",
                        options: GenerationOptions(
                            maximumResponseTokens: 512,
                            toolCallingMode: mode
                        )
                    )
                } catch {
                    // Both modes stop inside the adopting app immediately
                    // after the typed call. Any other failure remains a
                    // failure unless the ledger proves that call occurred.
                    guard ledger.acceptedCount == 1 else { throw error }
                }
                guard ledger.acceptedCount == 1 else {
                    throw ExampleError.toolArgumentsProbeDidNotCall(
                        mode: label,
                        run: run,
                        calls: ledger.acceptedCount
                    )
                }
                let line = "\(label) run \(run): valid call"
                report.append(line)
                print("[example-toolargs] \(line)")
            }
        }
        output = report.joined(separator: "\n")
        status = "tool argument probe passed 6/6"
    }

    /// Launch-environment-only active-road acceptance. A unique registry
    /// label gives each degradation run an empty calling card: it must begin
    /// through the scheduled proxy, then can learn the daemon's direct roads
    /// from its authenticated hello for liveness-triggered reattach. Normal UI
    /// and the filmed prompt are unchanged when the flag is absent.
    private func runLivenessAcceptanceProbe(
        configuration: ReachExecutor.Configuration,
        mode: String,
        run: String
    ) async throws {
        switch mode {
        case "slow":
            let longContext = String(repeating: "river ", count: 25_000)
            let occupier = Task { try await self.measureLivenessGeneration(
                configuration: configuration,
                prompt: longContext + "\nReply with exactly: occupier answered",
                maximumTokens: 32
            ) }
            try await Task.sleep(for: .milliseconds(250))
            let queued = try await measureLivenessGeneration(
                configuration: configuration,
                prompt: "Reply with exactly: queued generation answered",
                maximumTokens: 32
            )
            let occupied = try await occupier.value
            guard occupied.firstGap >= .seconds(2), queued.firstGap >= .seconds(2) else {
                throw ExampleError.livenessProbeWasNotSilent(
                    first: Self.livenessSeconds(occupied.firstGap),
                    second: Self.livenessSeconds(queued.firstGap)
                )
            }
            output = "occupier first event \(Self.livenessSeconds(occupied.firstGap))s\nqueued first event \(Self.livenessSeconds(queued.firstGap))s"
            status = "liveness slow passed run \(run)"
            print("[example-liveness] slow run=\(run) first=\(Self.livenessSeconds(occupied.firstGap)) queued=\(Self.livenessSeconds(queued.firstGap))")
        case "degradation":
            let result = try await measureLivenessGeneration(
                configuration: configuration,
                prompt: prompt,
                maximumTokens: 4_096
            )
            guard result.snapshots > 1, !result.content.isEmpty else {
                throw ExampleError.livenessProbeDidNotComplete
            }
            output = result.content
            status = "liveness degradation passed run \(run) (\(result.snapshots) snapshots)"
            print("[example-liveness] degradation run=\(run) snapshots=\(result.snapshots) maxGap=\(Self.livenessSeconds(result.maxGap))")
        default:
            throw ExampleError.livenessProbeUnknownMode(mode)
        }
    }

    private struct LivenessGenerationResult {
        var content: String
        var snapshots: Int
        var firstGap: Duration
        var maxGap: Duration
    }

    private func measureLivenessGeneration(
        configuration: ReachExecutor.Configuration,
        prompt: String,
        maximumTokens: Int
    ) async throws -> LivenessGenerationResult {
        let clock = ContinuousClock()
        let began = clock.now
        var previous = began
        var firstGap: Duration?
        var maxGap = Duration.zero
        var snapshots = 0
        var content = ""
        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration)
        )
        let stream = session.streamResponse(
            to: prompt,
            options: GenerationOptions(maximumResponseTokens: maximumTokens)
        )
        for try await snapshot in stream {
            let now = clock.now
            let gap = previous.duration(to: now)
            firstGap = firstGap ?? gap
            maxGap = max(maxGap, gap)
            previous = now
            snapshots += 1
            content = snapshot.content
        }
        return LivenessGenerationResult(
            content: content,
            snapshots: snapshots,
            firstGap: firstGap ?? began.duration(to: clock.now),
            maxGap: maxGap
        )
    }

    private static func livenessSeconds(_ duration: Duration) -> String {
        let components = duration.components
        let seconds = Double(components.seconds) + Double(components.attoseconds) / 1e18
        return String(format: "%.3f", seconds)
    }

    /// The app half of the grant ceremony, run at most once: reload what a
    /// prior enrollment stored, else knock at the discovered cluster's
    /// grant door and wait for the keeper's ruling.
    private func ensureIdentity() async throws {
        if case .registered = identityState { return }
        if await ReachEnrollment.ensureRegistered(label: Self.identityLabel) {
            identityState = .registered(
                cluster: await ReachEnrollment.registeredClusterName(label: Self.identityLabel)
            )
            return
        }
        await awaitDiscovery()
        guard let cluster = clusters.first, let caHash = cluster.txt[Wire.txtCAHashKey] else {
            throw ExampleError.noGrantDoor
        }
        status = "asking your keeper for access…"
        try await ReachEnrollment.enroll(
            clusterName: cluster.name,
            caHashBase64URL: caHash,
            identityLabel: Self.identityLabel
        )
        identityState = .registered(cluster: cluster.name)
    }

    /// Give discovery a breath — a send can land before the first browse
    /// result does.
    ///
    /// ⚠️ Both paths need this, and that is the bug it exists to close. It
    /// used to live inline in `ensureIdentity()`, *below* the early return
    /// for an already-registered app — so a granted app that sent before
    /// Bonjour resolved skipped it entirely, found `clusters` empty, fell
    /// back to `host` (`127.0.0.1`) and dialled the phone itself. It failed
    /// with "no reachable cluster address (1 dialed)", and the count in that
    /// sentence is what identified it. Reproduced 2026-07-31 with
    /// `REACH_AUTOSEND=1`; a human tapping Send within a second of launch
    /// does the same thing.
    ///
    /// Waiting on the dial path costs a granted app nothing once discovery
    /// has landed — the loop exits on its first check.
    private func awaitDiscovery() async {
        for _ in 0..<20 {
            if !clusters.isEmpty || Task.isCancelled { return }
            try? await Task.sleep(for: .milliseconds(250))
        }
    }

    enum ExampleError: LocalizedError {
        case noGrantDoor
        case guidedProbeDidNotStream(run: Int, snapshots: Int)
        case toolArgumentsProbeDidNotCall(mode: String, run: Int, calls: Int)
        case usageProbeMissingCompletion
        case livenessProbeMissingIdentity
        case livenessProbeWasNotSilent(first: String, second: String)
        case livenessProbeDidNotComplete
        case livenessProbeUnknownMode(String)
        var errorDescription: String? {
            switch self {
            case .noGrantDoor:
                "No cluster advertising a grant door was found — is reachd serving?"
            case .guidedProbeDidNotStream(let run, let snapshots):
                "Guided probe run \(run) produced \(snapshots) snapshots; expected a streamed response."
            case .toolArgumentsProbeDidNotCall(let mode, let run, let calls):
                "Tool argument probe \(mode) run \(run) made \(calls) valid calls; expected exactly one."
            case .usageProbeMissingCompletion:
                "Usage probe completed without one matching positive update and latest value."
            case .livenessProbeMissingIdentity:
                "The liveness probe could not alias the registered identity."
            case .livenessProbeWasNotSilent(let first, let second):
                "The measured slow generations were not silent for the watchdog interval (\(first)s, \(second)s)."
            case .livenessProbeDidNotComplete:
                "The degraded generation did not produce a complete streamed answer."
            case .livenessProbeUnknownMode(let mode):
                "Unknown liveness probe mode \(mode)."
            }
        }
    }
}
