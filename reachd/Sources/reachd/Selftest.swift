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

    @Option(name: .long) var port: UInt16 = 47417

    func run() async throws {
        let clock = ContinuousClock()
        let ca = try ClusterCA.create(commonName: "Reach Selftest CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "selftest", uri: "reach://device/selftest")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-selftest-server")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-selftest-client")
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        let filling: any SlotFilling = mlx ? MLXFilling(modelID: "gemma-4-e2b") : SelftestFilling()
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
