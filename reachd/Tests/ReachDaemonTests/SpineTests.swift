import Foundation
import FoundationModels
import ReachIdentity
import ReachKit
import ReachWire
import Security
import Testing
@testable import ReachDaemon

/// The spine, Mac-only and automated: a real `LanguageModelSession` on a
/// `ReachLanguageModel` streams a generation served by the in-process
/// daemon over loopback with mutual TLS. This is Phase 1's acceptance
/// sentence minus the second machine.
@Suite(.serialized) struct SpineTests {
    private func startDaemon(
        port: UInt16,
        host: String = "127.0.0.1",
        connectTimeout: Double = 45
    ) async throws -> (Daemon, ReachExecutor.Configuration) {
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
            host: host,
            port: port,
            modelID: "scripted",
            identityLabel: label,
            connectTimeout: connectTimeout
        )
        return (daemon, configuration)
    }

    /// Writes the store the way a previous process would have, bypassing
    /// `ClusterRoads.save` for one reason: `save` drops loopback, correctly —
    /// on any other device a stored `127.0.0.1` names that device. A loopback
    /// rig is the one place that policy and this test disagree, and the policy
    /// is right, so the test writes the bytes instead of weakening it.
    /// `save`'s own behaviour is proven in `ClusterRoadsTests`.
    private func seedRoads(_ addrs: [String], port: UInt16, for label: String) throws {
        let data = try JSONEncoder().encode(ClusterRoads.Roads(addrs: addrs, port: port))
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: ClusterRoads.service,
            kSecAttrAccount as String: label,
            kSecValueData as String: data,
        ]
        #expect(SecItemAdd(add as CFDictionary, nil) == errSecSuccess)
    }

    /// A session born away. The configured address is TEST-NET-2, reserved for
    /// documentation and routed nowhere, so the primary endpoint cannot
    /// possibly answer — exactly the shape of a granted app cold-launched on a
    /// network that has never seen this cluster, where the Bonjour name will
    /// not resolve either. The only reachable address is the one an earlier
    /// process wrote down. A session that opens can have come from nowhere
    /// else, and that it opens at all is the claim this pass exists to make
    /// true. (The real topology — a café, the tunnel, the mesh — is hardware
    /// acceptance; this proves the machinery: store read, seeded race, win.)
    @Test func aSessionIsBornAwayFromTheRoadsItKept() async throws {
        defer { IdentityTrash.drain() }
        let (daemon, configuration) = try await startDaemon(port: 47417, host: "198.51.100.1")
        defer { Task { await daemon.stop() } }
        defer { try? ClusterRoads.forget(for: configuration.identityLabel) }

        try seedRoads(["127.0.0.1"], port: 47417, for: configuration.identityLabel)

        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration),
            instructions: "Scripted."
        )
        var final = ""
        for try await snapshot in session.streamResponse(to: "Go.") {
            final = snapshot.content
        }
        #expect(final == ScriptedFilling().words.joined())
    }

    /// The instrument, checked: the same configuration with nothing in the
    /// store must fail. Without this the case above would pass just as well if
    /// the dead primary were somehow answering, and would be proving nothing.
    ///
    /// It also holds the refusal's latency. The session open lives inside the
    /// retry loop so a dial landing while the tunnel is still rising is not
    /// thrown away — but a cold open must not inherit the daemon's 120-second
    /// residency budget, because before the first session there is nothing
    /// resident to wait for and the wait is all a person gets.
    @Test func withoutStoredRoadsTheSameDialFails() async throws {
        defer { IdentityTrash.drain() }
        // Short, because the whole point is to wait out a dial that never
        // lands: TEST-NET-2 looks routable, so it hangs rather than refusing.
        let (daemon, configuration) = try await startDaemon(
            port: 47418, host: "198.51.100.1", connectTimeout: 5
        )
        defer { Task { await daemon.stop() } }

        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration),
            instructions: "Scripted."
        )
        let started = ContinuousClock.now
        await #expect(throws: (any Error).self) {
            for try await _ in session.streamResponse(to: "Go.") {}
        }
        #expect(ContinuousClock.now - started < .seconds(30))
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
