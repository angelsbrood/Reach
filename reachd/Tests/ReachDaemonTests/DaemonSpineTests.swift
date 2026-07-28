import Foundation
import FoundationModels
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Testing
@testable import ReachDaemon

/// Deterministic filling for spine tests: streams words with real delays so
/// a connection can die mid-generation.
struct ScriptedFilling: SlotFilling {
    let modelID = "scripted"
    let displayName = "Scripted"
    let capabilities: [String] = []
    var words: [String] = ["The ", "reach ", "holds ", "between ", "locks ", "and ", "the ", "stream ", "survives."]
    var delayMilliseconds = 40

    func prewarm() async throws {}

    func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, Error> {
        let (stream, continuation) = AsyncThrowingStream<WireEvent, Error>.makeStream()
        let words = self.words
        let delay = delayMilliseconds
        let task = Task {
            for word in words {
                if Task.isCancelled { break }
                continuation.yield(.responseAppend(entryID: nil, text: word, segmentID: nil, tokenCount: 1))
                try? await Task.sleep(for: .milliseconds(delay))
            }
            continuation.yield(.usage(inputTokens: 3, outputTokens: words.count))
            continuation.yield(.finished(Task.isCancelled ? .cancelled : .complete))
            continuation.finish()
        }
        continuation.onTermination = { _ in task.cancel() }
        return stream
    }
}

@Suite struct SessionRegistryTests {
    private func drain(_ stream: AsyncStream<Ev>, until predicate: @escaping ([Ev]) -> Bool) async -> [Ev] {
        var collected: [Ev] = []
        for await ev in stream {
            collected.append(ev)
            if predicate(collected) { break }
        }
        return collected
    }

    @Test func generationSurvivesDetachAndReplaysFromSeq() async throws {
        let registry = SessionRegistry()
        let (sessionID, token) = await registry.openSession(modelID: "scripted")
        try await registry.validate(sessionID: sessionID, token: token)

        let filling = ScriptedFilling()
        let genID = UUID()
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let first = try await registry.begin(sessionID: sessionID, genID: genID) {
            filling.generate(request)
        }

        // Receive a few, ack 2, then the "connection dies".
        let received = await drain(first) { $0.count >= 4 }
        #expect(received.map { $0.seq } == [0, 1, 2, 3])
        await registry.ack(sessionID: sessionID, genID: genID, seq: 2)
        await registry.detach(sessionID: sessionID, genID: genID)

        try? await Task.sleep(for: .milliseconds(120))

        // Re-attach from the last received seq; replay must start at 4.
        let second = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: 3)
        var tail: [Ev] = []
        for await ev in second {
            tail.append(ev)
            if case .finished = ev.event { break }
        }
        #expect(tail.first?.seq == 4)

        let all = received + tail
        let text = all.compactMap { ev -> String? in
            if case .responseAppend(_, let t, _, _) = ev.event { return t }
            return nil
        }.joined()
        #expect(text == ScriptedFilling().words.joined())
    }

    @Test func beginIsIdempotentForKnownGeneration() async throws {
        let registry = SessionRegistry()
        let (sessionID, _) = await registry.openSession(modelID: "scripted")
        let genID = UUID()
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let filling = ScriptedFilling()

        let first = try await registry.begin(sessionID: sessionID, genID: genID) { filling.generate(request) }
        _ = await drain(first) { $0.count >= 2 }

        // A duplicated GenerateBegin (first-frame loss) must not start a
        // second generation; it re-attaches from 0.
        let again = try await registry.begin(sessionID: sessionID, genID: genID) {
            Issue.record("second filling start for the same genID")
            return filling.generate(request)
        }
        var seqs: [UInt64] = []
        for await ev in again {
            seqs.append(ev.seq)
            if case .finished = ev.event { break }
        }
        #expect(seqs.first == 0)
        #expect(seqs.sorted() == seqs)
    }

    @Test func residencyWindowReapsDetachedGenerations() async throws {
        var limits = SessionRegistry.Limits()
        limits.residencyWindow = .milliseconds(60)
        let registry = SessionRegistry(limits: limits)
        let (sessionID, _) = await registry.openSession(modelID: "scripted")
        let genID = UUID()
        var slow = ScriptedFilling()
        slow.delayMilliseconds = 500
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let stream = try await registry.begin(sessionID: sessionID, genID: genID) { [slow] in slow.generate(request) }
        _ = await drain(stream) { $0.count >= 1 }
        await registry.detach(sessionID: sessionID, genID: genID)

        try? await Task.sleep(for: .milliseconds(150))
        let reaped = await registry.sweep()
        #expect(reaped == 1)
        await #expect(throws: SessionRegistry.RegistryError.self) {
            _ = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: nil)
        }
    }

    @Test func badTokenRejected() async throws {
        let registry = SessionRegistry()
        let (sessionID, _) = await registry.openSession(modelID: "scripted")
        await #expect(throws: SessionRegistry.RegistryError.self) {
            try await registry.validate(sessionID: sessionID, token: "wrong")
        }
    }
}

@Suite(.serialized) struct DaemonResumeTests {
    /// The resume test: a generation's transport dies mid-stream; the
    /// client reconnects (any path) and re-attaches; the concatenated text
    /// is byte-identical to an uninterrupted run.
    @Test func killedConnectionResumesByteIdentically() async throws {
        let ca = try ClusterCA.create(commonName: "Reach Spine CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "spine-client", uri: "reach://device/spine")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-spine-server-\(UUID())")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-spine-client-\(UUID())")
        IdentityTrash.add(serverIdentity)
        IdentityTrash.add(clientIdentity)
        defer { IdentityTrash.drain() }
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var config = DaemonConfig()
        config.port = 47413
        config.clusterName = "spine-test"
        let daemon = Daemon(
            config: config,
            filling: ScriptedFilling(),
            identity: Daemon.ListenerIdentity(identity: serverIdentity, caCertificate: caCert)
        )
        try await daemon.start(advertise: false)
        defer { Task { await daemon.stop() } }

        let clientOptions = TLSBuilder.clientOptions(
            alpn: Wire.alpn,
            identity: clientIdentity,
            serverTrustRoots: [caCert]
        )
        let dialer = QUICDialer(
            endpoint: .hostPort(host: "127.0.0.1", port: 47413),
            parameters: .reachQUIC(options: clientOptions)
        )

        // Control stream: hello + session open.
        let control = try await dialer.openStream(timeout: 45)
        var controlFrames = control.frames.makeAsyncIterator()
        try await control.send(Hello(client: "spine-test"))
        let ack = try await controlFrames.next()!.decode(HelloAck.self)
        // The daemon declares every address it answers on — the away fall's
        // redial candidates.
        #expect(ack.addrs?.isEmpty == false)
        #expect(ack.port == 47413)
        try await control.send(SessionOpen(modelID: "scripted"))
        let opened = try await controlFrames.next()!.decode(SessionOpened.self)

        // Generation stream: collect a few events, then kill the transport.
        let genID = UUID()
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let gen1 = try await dialer.openStream(timeout: 45)
        try await gen1.send(GenerateBegin(sessionID: opened.sessionID, genID: genID, request: request))
        var head: [Ev] = []
        for try await raw in gen1.frames {
            guard raw.type == .ev else { continue }
            let ev = try raw.decode(Ev.self)
            head.append(ev)
            if head.count == 3 {
                try await gen1.send(EvAck(seq: ev.seq))
                break
            }
        }
        gen1.cancel()   // the walk out the door

        try? await Task.sleep(for: .milliseconds(200))

        // Reconnect and re-attach from the last received seq.
        let gen2 = try await dialer.openStream(timeout: 45)
        try await gen2.send(GenerateReattach(
            sessionID: opened.sessionID,
            token: opened.token,
            genID: genID,
            fromSeq: head.last!.seq
        ))
        var tail: [Ev] = []
        for try await raw in gen2.frames {
            guard raw.type == .ev else { continue }
            let ev = try raw.decode(Ev.self)
            tail.append(ev)
            if case .finished = ev.event { break }
        }

        #expect(tail.first?.seq == head.last!.seq + 1)
        let text = (head + tail).compactMap { ev -> String? in
            if case .responseAppend(_, let t, _, _) = ev.event { return t }
            return nil
        }.joined()
        #expect(text == ScriptedFilling().words.joined())

        // And the streamed transcript is complete: a fresh, uninterrupted
        // run produces the same text.
        let gen3 = try await dialer.openStream(timeout: 45)
        try await gen3.send(GenerateBegin(sessionID: opened.sessionID, genID: UUID(), request: request))
        var reference = ""
        for try await raw in gen3.frames {
            guard raw.type == .ev else { continue }
            let ev = try raw.decode(Ev.self)
            if case .responseAppend(_, let t, _, _) = ev.event { reference += t }
            if case .finished = ev.event { break }
        }
        #expect(text == reference)
        control.cancel()
    }
}
