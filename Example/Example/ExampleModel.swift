import Foundation
import FoundationModels
import Observation
import ReachIdentity
import ReachKit
import ReachTransport

/// The Example app links ReachKit and nothing privileged — it stands in
/// for every third-party app. Phase 1 identity arrives as a provisioning
/// bundle (`reachd ca issue-client --name example --out …`); the ceremony
/// replaces that file entirely.
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
        // Identity: env override first (simulator runs point at the host
        // filesystem), then the app's Documents directory.
        let candidates: [URL] = [
            ProcessInfo.processInfo.environment["REACH_IDENTITY"].map { URL(fileURLWithPath: $0) },
            FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
                .appendingPathComponent("reach-identity.json"),
        ].compactMap { $0 }

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

        if ProcessInfo.processInfo.environment["REACH_AUTOSEND"] == "1", case .registered = identityState {
            send()
        }

        let browser = ClusterBrowser()
        self.browser = browser
        let stream = browser.clusters
        Task { [weak self] in
            for await found in stream {
                await MainActor.run { self?.clusters = found }
            }
        }
    }

    func send() {
        guard case .registered = identityState else {
            status = "No identity: issue one with `reachd ca issue-client --name example` and place it at Documents/reach-identity.json (or set REACH_IDENTITY)."
            return
        }
        let key = "\(host)|\(modelID)"
        if session == nil || sessionKey != key {
            let configuration = ReachExecutor.Configuration(
                host: host,
                modelID: modelID,
                identityLabel: Self.identityLabel
            )
            session = LanguageModelSession(model: ReachLanguageModel(configuration: configuration))
            sessionKey = key
        }
        guard let session, !session.isResponding else { return }

        let text = prompt
        output = ""
        status = "streaming…"
        isStreaming = true
        Task {
            do {
                let stream = session.streamResponse(to: text)
                for try await snapshot in stream {
                    self.output = snapshot.content
                }
                self.status = "done"
            } catch {
                self.status = "failed: \(error)"
            }
            self.isStreaming = false
        }
    }
}
