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
    var modelID = "gemma-4-e2b"
    /// The demo prompt, in the repo rather than in the operator's clipboard.
    ///
    /// The one-line default it replaced finished in a sentence, which left no
    /// generation running to survive the network switch — so every take meant
    /// pasting a long prompt in by hand at the moment the rig was already moving.
    /// `docs/demo.md` records why this shape: a long output from a short ask, with
    /// no natural stopping point before the 4096-token ceiling below. Asking for
    /// much more than 3000 words buys nothing, because the ceiling binds first.
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
        the current first answers the sea; and the mouth. Give each reach two or \
        three full paragraphs, and for each one say what has changed about the \
        water, the banks, the light, and the life in it since the reach before. \
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
            let service = host == "127.0.0.1" ? clusters.first?.name : nil
            let key = "\(service ?? host)|\(modelID)"
            if session == nil || sessionKey != key {
                let configuration = ReachExecutor.Configuration(
                    serviceName: service,
                    host: host,
                    modelID: modelID,
                    identityLabel: Self.identityLabel
                )
                session = LanguageModelSession(model: ReachLanguageModel(configuration: configuration))
                sessionKey = key
            }
            guard let session, !session.isResponding else { return }
            status = "streaming…"
            do {
                // Demo pacing: long stories must stream long — the request
                // carries the ceiling and the daemon honors it (its own
                // fallback stays a bounded 512).
                let stream = session.streamResponse(
                    to: text,
                    options: GenerationOptions(maximumResponseTokens: 4096)
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
        // Give discovery a breath — a send can land before the first
        // browse result does.
        for _ in 0..<20 where clusters.isEmpty {
            try await Task.sleep(for: .milliseconds(250))
        }
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

    enum ExampleError: LocalizedError {
        case noGrantDoor
        var errorDescription: String? {
            "No cluster advertising a grant door was found — is reachd serving?"
        }
    }
}
