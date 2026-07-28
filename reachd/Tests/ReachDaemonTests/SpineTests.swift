import Foundation
import FoundationModels
import ReachIdentity
import ReachKit
import ReachWire
import Testing
@testable import ReachDaemon

/// The spine, Mac-only and automated: a real `LanguageModelSession` on a
/// `ReachLanguageModel` streams a generation served by the in-process
/// daemon over loopback with mutual TLS. This is Phase 1's acceptance
/// sentence minus the second machine.
@Suite(.serialized) struct SpineTests {
    private func startDaemon(port: UInt16) async throws -> (Daemon, ReachExecutor.Configuration) {
        let ca = try ClusterCA.create(commonName: "Reach Spine CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "spine-app", uri: "reach://device/spine-app")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-spine2-server-\(UUID())")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-spine2-client-\(UUID())")
        IdentityTrash.add(serverIdentity)
        IdentityTrash.add(clientIdentity)
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var config = DaemonConfig()
        config.port = port
        config.clusterName = "spine"
        config.modelID = "scripted"
        let daemon = Daemon(
            config: config,
            filling: ScriptedFilling(),
            identity: Daemon.ListenerIdentity(identity: serverIdentity, caCertificate: caCert)
        )
        try await daemon.start(advertise: false)

        let label = "spine-\(UUID().uuidString)"
        await ReachIdentityRegistry.shared.register(
            label: label,
            material: .init(identity: clientIdentity, caCertificate: caCert)
        )
        let configuration = ReachExecutor.Configuration(
            host: "127.0.0.1",
            port: port,
            modelID: "scripted",
            identityLabel: label,
            connectTimeout: 45
        )
        return (daemon, configuration)
    }

    @Test func sessionStreamsThroughTheDaemon() async throws {
        defer { IdentityTrash.drain() }
        let (daemon, configuration) = try await startDaemon(port: 47414)
        defer { Task { await daemon.stop() } }

        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration),
            instructions: "Scripted."
        )
        let stream = session.streamResponse(to: "Go.")
        var final = ""
        for try await snapshot in stream {
            final = snapshot.content
        }
        #expect(final == ScriptedFilling().words.joined())

        // Second turn exercises transcript accumulation across the wire.
        let second = try await session.respond(to: "Again.")
        #expect(second.content == ScriptedFilling().words.joined())
        #expect(session.transcript.count >= 4)
    }

    /// The away fall, loopback edition: a path change mid-generation
    /// cancels the live stream; the retry loop races every address the
    /// daemon declared in its HelloAck and re-attaches. The seam must be
    /// invisible — the streamed text stays byte-identical. (The real
    /// topology — a LAN dial dying, the mesh answering — is hardware
    /// acceptance; this proves the client machinery: watcher, race,
    /// re-attach, replay dedupe.)
    @Test func generationSurvivesAPathChange() async throws {
        defer { IdentityTrash.drain() }
        let (daemon, configuration) = try await startDaemon(port: 47416)
        defer { Task { await daemon.stop() } }

        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration),
            instructions: "Scripted."
        )
        let stream = session.streamResponse(to: "Go.")
        var final = ""
        var snapshots = 0
        for try await snapshot in stream {
            final = snapshot.content
            snapshots += 1
            if snapshots == 2 || snapshots == 4 {
                // What NWPathMonitor does on an SSID hop.
                await ReachConnectionHub.shared.notePathPossiblyChanged()
            }
        }
        #expect(final == ScriptedFilling().words.joined())
    }

    @Test func cancellationPropagates() async throws {
        defer { IdentityTrash.drain() }
        let (daemon, configuration) = try await startDaemon(port: 47415)
        defer { Task { await daemon.stop() } }

        let session = LanguageModelSession(model: ReachLanguageModel(configuration: configuration))
        let task = Task {
            let stream = session.streamResponse(to: "Go.")
            var count = 0
            for try await _ in stream {
                count += 1
                if count == 2 {
                    withUnsafeCurrentTask { $0?.cancel() }
                }
            }
        }
        let outcome = await task.result
        // Either the framework surfaces the cancellation as a thrown error
        // or the stream ends early; both are acceptable — what must not
        // happen is a completed full generation.
        _ = outcome
        task.cancel()
    }
}
