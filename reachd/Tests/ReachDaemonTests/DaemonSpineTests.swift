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
    /// Does a cancelled generation actually reach a terminal state?
    ///
    /// `docs/wire.md` says "the generation finishes `.cancelled` rather than
    /// vanishing". `cancel` only cancels the ingest task, and a cancelled
    /// `for await` stops iterating — so whether `.finished(.cancelled)` is
    /// ever ingested is a question about the filling, not about `cancel`.
    @Test func aCancelledGenerationReachesATerminalState() async throws {
        let registry = SessionRegistry()
        let (sessionID, token) = await registry.openSession()
        let genID = UUID()
        let filling = ScriptedFilling(words: Array(repeating: "tick ", count: 60), delayMilliseconds: 40)
        let (stream, epoch) = try await registry.begin(
            sessionID: sessionID, genID: genID, events: { filling.generate(.init(id: UUID(), transcript: .init())) }
        )
        var seen = 0
        for await _ in stream {
            seen += 1
            if seen == 2 { break }
        }
        await registry.cancel(sessionID: sessionID, genID: genID, epoch: epoch)
        try await Task.sleep(for: .milliseconds(500))
        let status = try await registry.resumeStatus(sessionID: sessionID, token: token)
        #expect(status.count == 1)
        #expect(status.first?.state != .streaming, "a cancelled generation is still reported as streaming: \(String(describing: status.first?.state))")
    }

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
        let (sessionID, token) = await registry.openSession()
        try await registry.validate(sessionID: sessionID, token: token)

        let filling = ScriptedFilling()
        let genID = UUID()
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let (first, epoch) = try await registry.begin(sessionID: sessionID, genID: genID) {
            filling.generate(request)
        }

        // Receive a few, ack 2, then the "connection dies".
        let received = await drain(first) { $0.count >= 4 }
        #expect(received.map { $0.seq } == [0, 1, 2, 3])
        await registry.ack(sessionID: sessionID, genID: genID, seq: 2, epoch: epoch)
        await registry.detach(sessionID: sessionID, genID: genID, epoch: epoch)

        try? await Task.sleep(for: .milliseconds(120))

        // Re-attach from the last received seq; replay must start at 4.
        let (second, _) = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: 3)
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

    /// Does this attachment reach `.finished` before the deadline? A stream
    /// that has been quietly killed never will, and never ending is the
    /// symptom — so the wait is bounded and a timeout reads as a failure.
    private func finishes(_ stream: AsyncStream<Ev>, within: Duration = .seconds(5)) async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                for await ev in stream {
                    if case .finished = ev.event { return true }
                }
                return false
            }
            group.addTask {
                try? await Task.sleep(for: within)
                return false
            }
            let result = await group.next() ?? false
            group.cancelAll()
            return result
        }
    }

    /// The walk-out's real shape: the client re-attaches over the mesh while
    /// the dead LAN connection is still blocked on its own receive loop. That
    /// connection's pump wakes up at the daemon's QUIC idle timeout — about
    /// 30 s later, because a close cannot be delivered over an interface that
    /// is gone — and detaches. Keyed only on the generation, that detach ends
    /// the continuation the MESH is streaming through, and the viewer sees a
    /// second unexplained freeze half a minute after the door.
    ///
    /// Loopback could never have caught it: the close arrives instantly there,
    /// so the stale pump always detaches BEFORE the re-attach rather than
    /// after.
    @Test func aStaleConnectionsLateDetachCannotEndTheLiveOne() async throws {
        let registry = SessionRegistry()
        let (sessionID, token) = await registry.openSession()
        try await registry.validate(sessionID: sessionID, token: token)

        let filling = ScriptedFilling()
        let genID = UUID()
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let (first, firstEpoch) = try await registry.begin(sessionID: sessionID, genID: genID) {
            filling.generate(request)
        }
        _ = await drain(first) { $0.count >= 2 }

        // The phone comes back over the mesh.
        let (second, _) = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: 0)

        // Now the LAN connection finally notices it is dead.
        await registry.detach(sessionID: sessionID, genID: genID, epoch: firstEpoch)

        // The mesh attachment must still be live and must still finish.
        // Bounded: without the guard the continuation is ended (or the task
        // cancelled) and `.finished` never arrives, so an unbounded wait
        // would hang instead of failing.
        #expect(await finishes(second), "a stale connection's detach ended the live mesh attachment")
    }

    /// Same shape, worse consequence: a cancel arriving from the connection
    /// that already lost the generation would kill it outright.
    @Test func aStaleConnectionCannotCancelTheLiveGeneration() async throws {
        let registry = SessionRegistry()
        let (sessionID, token) = await registry.openSession()
        try await registry.validate(sessionID: sessionID, token: token)

        let filling = ScriptedFilling()
        let genID = UUID()
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let (first, firstEpoch) = try await registry.begin(sessionID: sessionID, genID: genID) {
            filling.generate(request)
        }
        _ = await drain(first) { $0.count >= 2 }
        let (second, _) = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: 0)

        await registry.cancel(sessionID: sessionID, genID: genID, epoch: firstEpoch)

        #expect(await finishes(second), "a stale connection's cancel killed the live generation")
    }

    @Test func beginIsIdempotentForKnownGeneration() async throws {
        let registry = SessionRegistry()
        let (sessionID, _) = await registry.openSession()
        let genID = UUID()
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let filling = ScriptedFilling()

        let (first, _) = try await registry.begin(sessionID: sessionID, genID: genID) { filling.generate(request) }
        _ = await drain(first) { $0.count >= 2 }

        // A duplicated GenerateBegin (first-frame loss) must not start a
        // second generation; it re-attaches from 0.
        let (again, _) = try await registry.begin(sessionID: sessionID, genID: genID) {
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

    /// The sweep reaped generations and left the session holding them.
    ///
    /// Nothing observed this because a `SessionRecord` with an empty
    /// generations table costs almost nothing and there is no file it shows
    /// up in — but every `SessionOpen` a daemon ever served left one, for
    /// the life of the process, including sessions the client abandoned and
    /// re-opened after a `begin-rejected`. `lastSeen` was already being
    /// written on open and on every validate; nothing read it.
    @Test func aSessionWithNothingLeftInItStopsBeingResident() async throws {
        var limits = SessionRegistry.Limits()
        limits.idleSessionRetention = .milliseconds(40)
        let registry = SessionRegistry(limits: limits)

        for _ in 0..<5 { _ = await registry.openSession() }
        #expect(await registry.residentSessions == 5)

        // Not yet: a session is addressable until it has been idle its whole
        // window, or a client pausing between generations would lose one.
        await registry.sweep()
        #expect(await registry.residentSessions == 5)

        try await Task.sleep(for: .milliseconds(120))
        await registry.sweep()
        #expect(await registry.residentSessions == 0)
    }

    /// …and a session still holding a generation is not swept out from
    /// under it, however long it has been since anyone said hello.
    @Test func aSessionStillHoldingAGenerationSurvivesTheSweep() async throws {
        var limits = SessionRegistry.Limits()
        limits.idleSessionRetention = .milliseconds(20)
        limits.completedRetention = .seconds(600)
        let registry = SessionRegistry(limits: limits)
        let (sessionID, _) = await registry.openSession()

        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let filling = ScriptedFilling()
        let (stream, _) = try await registry.begin(sessionID: sessionID, genID: UUID()) {
            filling.generate(request)
        }
        _ = await drain(stream) { $0.contains { if case .finished = $0.event { return true }; return false } }

        try await Task.sleep(for: .milliseconds(60))
        await registry.sweep()
        #expect(await registry.residentSessions == 1)
    }

    @Test func residencyWindowReapsDetachedGenerations() async throws {
        var limits = SessionRegistry.Limits()
        limits.residencyWindow = .milliseconds(60)
        let registry = SessionRegistry(limits: limits)
        let (sessionID, _) = await registry.openSession()
        let genID = UUID()
        var slow = ScriptedFilling()
        slow.delayMilliseconds = 500
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let (stream, epoch) = try await registry.begin(sessionID: sessionID, genID: genID) { [slow] in slow.generate(request) }
        _ = await drain(stream) { $0.count >= 1 }
        await registry.detach(sessionID: sessionID, genID: genID, epoch: epoch)

        try? await Task.sleep(for: .milliseconds(150))
        let reaped = await registry.sweep()
        #expect(reaped == 1)
        await #expect(throws: SessionRegistry.RegistryError.self) {
            _ = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: nil)
        }
    }

    @Test func badTokenRejected() async throws {
        let registry = SessionRegistry()
        let (sessionID, _) = await registry.openSession()
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

    /// A stream that opens and never speaks, twice — once closed cleanly, once
    /// reset — and then a real session on the same listener.
    ///
    /// `serve`'s opening read used to return on the clean close without
    /// cancelling, leaking the connection, and let the reset throw into its
    /// catch, which logged `stream ended: <socket>` at error level for a
    /// session that never existed. Neither is a fault: a cancelled dial, an app
    /// that went away between connect and send, and a probe all look like this.
    ///
    /// What is assertable is that the listener survives both — the log level is
    /// not, because the daemon has no sink a test can read.
    @Test func aStreamThatNeverSpeaksDoesNotDisturbTheListener() async throws {
        let ca = try ClusterCA.create(commonName: "Reach Silent CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "silent-client", uri: "reach://device/silent")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-silent-server-\(UUID())")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-silent-client-\(UUID())")
        IdentityTrash.add(serverIdentity)
        IdentityTrash.add(clientIdentity)
        defer { IdentityTrash.drain() }
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var config = DaemonConfig()
        config.port = 47454
        config.clusterName = "silent-test"
        let daemon = Daemon(
            config: config,
            filling: ScriptedFilling(),
            identity: Daemon.ListenerIdentity(identity: serverIdentity, caCertificate: caCert)
        )
        try await daemon.start(advertise: false)
        defer { Task { await daemon.stop() } }

        let dialer = QUICDialer(
            endpoint: .hostPort(host: "127.0.0.1", port: 47454),
            parameters: .reachQUIC(
                options: TLSBuilder.clientOptions(alpn: Wire.alpn, identity: clientIdentity, serverTrustRoots: [caCert])
            )
        )

        // The clean close: half-close without ever sending a frame.
        let mute = try await dialer.openStream(timeout: 45)
        mute.finishSending()
        try await Task.sleep(for: .milliseconds(200))

        // The reset: cancel outright, which is the ending that used to throw.
        let reset = try await dialer.openStream(timeout: 45)
        reset.cancel()
        try await Task.sleep(for: .milliseconds(200))

        // The listener still serves.
        let control = try await dialer.openStream(timeout: 45)
        defer { control.cancel() }
        var frames = control.frames.makeAsyncIterator()
        try await control.send(Hello(client: "silent-test"))
        let ack = try (try #require(try await frames.next())).decode(HelloAck.self)
        #expect(ack.cluster == "silent-test")
        try await control.send(SessionOpen(modelID: "scripted"))
        let opened = try (try #require(try await frames.next())).decode(SessionOpened.self)
        #expect(opened.token.isEmpty == false)
    }
}
