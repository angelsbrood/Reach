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
    /// The demo prompt, in the repo rather than in the operator's clipboard.
    ///
    /// The one-line default it replaced finished in a sentence, which left no
    /// generation running to survive the network switch — so every take meant
    /// pasting a long prompt in by hand at the moment the rig was already moving.
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
    var prompt = """
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
    var output = ""
    var status = ""
    var isStreaming = false

    private var browser: ClusterBrowser?
    private var session: LanguageModelSession?
    private var sessionKey: String?

    static let identityLabel = "reach-example"

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
            // Prefer a discovered cluster (dialed as a Bonjour service,
            // resolved by the system) unless the operator typed a host.
            // The wait belongs HERE and not only in the enrollment path: a
            // granted app never enters that path, and dialling before
            // discovery lands means dialling `host`, which is this phone.
            let wantsDiscovered = host == "127.0.0.1"
            if wantsDiscovered { await awaitDiscovery() }
            let service = wantsDiscovered ? clusters.first?.name : nil
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
                        tools: [ClockTool(ran: { [weak self] zone in
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
        var errorDescription: String? {
            "No cluster advertising a grant door was found — is reachd serving?"
        }
    }
}
