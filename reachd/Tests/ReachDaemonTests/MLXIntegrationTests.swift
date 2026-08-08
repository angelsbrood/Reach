import Foundation
import FoundationModels
import ReachIdentity
import ReachKit
import Testing
@testable import ReachDaemon

/// The whole spine with real weights: session → executor → wire → daemon →
/// MLX → tokens back. Pinned to the SMALL model deliberately — this exercises
/// the spine, not the weights, and the demo's 26B would make it a 26 GB load.
/// Needs the model cache — **~4.3 GB for gemma-4-e2b**, six
/// times the gemma-3 weights this used to name, so it is a deliberate download
/// and not something to discover on a recording day; skipped where the GPU or
/// cache is absent by failing prewarm.
///
/// ⚠️ Uses 47470, moved off 47416 where it sat on top of `SpineTests`. The
/// clash was invisible for as long as this suite stayed gated: set
/// `REACH_MLX_TESTS=1` and the two race for one port, and the loser reports
/// `ReachError.unreachable` — which reads like a real cold-start failure. The
/// gate that hid it is also what would have made it hardest to believe.
@Suite(.serialized) struct MLXIntegrationTests {
    @Generable
    struct GuidedTwoField {
        var name: String
        var count: Int
    }

    @Generable
    struct GuidedNested {
        var result: GuidedTwoField
    }

    @Generable
    enum GuidedColor {
        case red
        case green
        case blue
    }

    @Generable
    struct GuidedEnum {
        var color: GuidedColor
    }

    @Generable
    struct GuidedFixedArray {
        @Guide(.count(3))
        var values: [Int]
    }

    @Generable
    struct GuidedOptional {
        var title: String
        var subtitle: String?
    }

    @Test(
        .enabled(if: ProcessInfo.processInfo.environment["REACH_MLX_TESTS"] == "1",
                 "MLX metallib is only locatable in executable layouts; run `reachd selftest --mlx` or set REACH_MLX_TESTS=1 under Xcode"),
        .timeLimit(.minutes(5))
    )
    func realTokensStreamEndToEnd() async throws {
        let filling = MLXFilling(modelID: "gemma-4-e2b")
        try await filling.prewarm()

        let ca = try ClusterCA.create(commonName: "Reach MLX CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "mlx-app", uri: "reach://device/mlx-app")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-mlx-server-\(UUID())")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-mlx-client-\(UUID())")
        // Owned rather than the old global bin, whose `drain()` emptied one
        // bin for every concurrent suite at once.
        let boxes = [IdentityBox(serverIdentity), IdentityBox(clientIdentity)]
        defer { for box in boxes { KeychainIdentity.remove(identity: box.identity) } }
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var config = DaemonConfig()
        config.port = TestPorts.port(47470)
        config.clusterName = "mlx-spine"
        config.modelID = "gemma-4-e2b"
        let daemon = Daemon(
            config: config,
            filling: filling,
            identity: Daemon.ListenerIdentity(identity: serverIdentity, caCertificate: caCert)
        )
        try await daemon.start(advertise: false)
        defer { Task { await daemon.stop() } }

        let label = "mlx-\(UUID().uuidString)"
        // The hub writes the cluster's roads under this label the moment the
        // daemon acks the hello, so a run of this test leaves a keychain item
        // behind exactly like the identities above. No `mlx-` entries were
        // found in the login keychain — this suite is gated, so nobody has
        // paid for it yet, which is the only reason it is not on the pile with
        // `spine-`, `tools-` and `budget-`.
        defer { try? ClusterRoads.forget(for: label) }
        await ReachIdentityRegistry.shared.register(
            label: label,
            material: .init(identity: clientIdentity, caCertificate: caCert)
        )
        let modelConfiguration = ReachExecutor.Configuration(
            host: "127.0.0.1",
            port: TestPorts.port(47470),
            modelID: "gemma-4-e2b",
            identityLabel: label,
            connectTimeout: 45)
        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: modelConfiguration),
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

        // The same real listener and session now exercise the response-schema
        // path. Completion of each typed stream is the framework's decode
        // assertion: malformed or schema-incomplete JSON throws before it can
        // finish as that Generable type. `includeSchemaInPrompt: false` makes
        // the grammar, rather than prompt coaching, carry the guarantee.
        for run in 1 ... 3 {
            try await assertGuided(
                GuidedTwoField.self,
                prompt: "Return a short name and the integer 7.",
                label: "two-field[\(run)]",
                configuration: modelConfiguration)
            try await assertGuided(
                GuidedNested.self,
                prompt: "Return a nested result with a short name and integer count.",
                label: "nested[\(run)]",
                configuration: modelConfiguration)
            try await assertGuided(
                GuidedEnum.self,
                prompt: "Choose blue.",
                label: "enum[\(run)]",
                configuration: modelConfiguration)
            try await assertGuided(
                GuidedFixedArray.self,
                prompt: "Return exactly three small integers.",
                label: "fixed-array[\(run)]",
                configuration: modelConfiguration)
            try await assertGuided(
                GuidedOptional.self,
                prompt: "Return a title; omit the optional subtitle.",
                label: "optional[\(run)]",
                configuration: modelConfiguration)
        }
    }

    private func assertGuided<Value: Generable>(
        _ type: Value.Type,
        prompt: String,
        label: String,
        configuration: ReachExecutor.Configuration
    ) async throws {
        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration))
        let stream = session.streamResponse(
            to: prompt,
            generating: type,
            includeSchemaInPrompt: false,
            options: GenerationOptions(maximumResponseTokens: 512))
        var snapshots = 0
        for try await _ in stream { snapshots += 1 }
        print("[mlx-guided] \(label) snapshots=\(snapshots)")
        #expect(snapshots > 1, "\(label) should stream multiple typed snapshots")
    }
}
