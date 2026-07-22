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
        case registered(cluster: String)
        case failed(String)
    }

    var identityState: IdentityState = .missing
    var clusters: [DiscoveredCluster] = []
    var host = "127.0.0.1"
    var modelID = "gemma-3-1b"
    var prompt = "In one short sentence: what is a reach, on a river?"
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
            identityState = .registered(cluster: "enrolled")
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
                let stream = session.streamResponse(to: text)
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
            identityState = .registered(cluster: "enrolled")
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
