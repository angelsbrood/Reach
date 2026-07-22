import Foundation
import FoundationModels
import ReachIdentity
import ReachKit
import Testing
@testable import ReachDaemon

/// The whole spine with real weights: session → executor → wire → daemon →
/// MLX → tokens back. Needs the model cache (~0.7 GB, downloaded by the
/// spikes); skipped where the GPU or cache is absent by failing prewarm.
@Suite(.serialized) struct MLXIntegrationTests {
    @Test(
        .enabled(if: ProcessInfo.processInfo.environment["REACH_MLX_TESTS"] == "1",
                 "MLX metallib is only locatable in executable layouts; run `reachd selftest --mlx` or set REACH_MLX_TESTS=1 under Xcode"),
        .timeLimit(.minutes(5))
    )
    func realTokensStreamEndToEnd() async throws {
        let filling = MLXFilling(modelID: "gemma-3-1b")
        try await filling.prewarm()

        let ca = try ClusterCA.create(commonName: "Reach MLX CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "mlx-app", uri: "reach://device/mlx-app")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-mlx-server-\(UUID())")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-mlx-client-\(UUID())")
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var config = DaemonConfig()
        config.port = 47416
        config.clusterName = "mlx-spine"
        config.modelID = "gemma-3-1b"
        let daemon = Daemon(
            config: config,
            filling: filling,
            identity: Daemon.ListenerIdentity(identity: serverIdentity, caCertificate: caCert)
        )
        try await daemon.start(advertise: false)
        defer { Task { await daemon.stop() } }

        let label = "mlx-\(UUID().uuidString)"
        await ReachIdentityRegistry.shared.register(
            label: label,
            material: .init(identity: clientIdentity, caCertificate: caCert)
        )
        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: ReachExecutor.Configuration(
                host: "127.0.0.1",
                port: 47416,
                modelID: "gemma-3-1b",
                identityLabel: label,
                connectTimeout: 45
            )),
            instructions: "You are terse."
        )
        let clock = ContinuousClock()
        let start = clock.now
        let stream = session.streamResponse(to: "Name two rivers, one word each.")
        var snapshots = 0
        var firstSnapshot: Duration?
        var final = ""
        for try await snapshot in stream {
            if firstSnapshot == nil { firstSnapshot = clock.now - start }
            snapshots += 1
            final = snapshot.content
        }
        print("[mlx-spine] first snapshot \(firstSnapshot.map(String.init(describing:)) ?? "-"), \(snapshots) snapshots, final: \(final)")
        #expect(!final.isEmpty)
        #expect(snapshots > 1, "expected token-by-token streaming, got a single snapshot")
    }
}
