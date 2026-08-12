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
    var initialDelayMilliseconds = 0
    var pauseAfterFirstMilliseconds = 0

    func prewarm() async throws {}

    func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, Error> {
        let (stream, continuation) = AsyncThrowingStream<WireEvent, Error>.makeStream()
        let words = self.words
        let delay = delayMilliseconds
        let initialDelay = initialDelayMilliseconds
        let pauseAfterFirst = pauseAfterFirstMilliseconds
        let task = Task {
            if initialDelay > 0 {
                try? await Task.sleep(for: .milliseconds(initialDelay))
            }
            for (index, word) in words.enumerated() {
                if Task.isCancelled { break }
                continuation.yield(.responseAppend(entryID: nil, text: word, segmentID: nil, tokenCount: 1))
                let pause = index == 0 && pauseAfterFirst > 0 ? pauseAfterFirst : delay
                try? await Task.sleep(for: .milliseconds(pause))
            }
            continuation.yield(.usage(inputTokens: 3, outputTokens: words.count))
            continuation.yield(.finished(Task.isCancelled ? .cancelled : .complete))
            continuation.finish()
        }
        continuation.onTermination = { _ in task.cancel() }
        return stream
    }
}

struct ScriptedToolFilling: SlotFilling {
    let modelID = "scripted-tools"
    let displayName = "Scripted Tools"
    let capabilities: [String] = []

    func prewarm() async throws {}

    func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, Error> {
        AsyncThrowingStream { continuation in
            guard request.options.toolCalling == .required,
                  request.tools.map(\.name) == ["record"]
            else {
                continuation.yield(.finished(.error("required tool request changed in transit")))
                continuation.finish()
                return
            }
            continuation.yield(.toolCallAppendArguments(
                entryID: "calls",
                id: "first",
                name: "record",
                content: #"{"value":1}"#,
                tokenCount: 1
            ))
            continuation.yield(.toolCallAppendArguments(
                entryID: "calls",
                id: "second",
                name: "record",
                content: #"{"value":2}"#,
                tokenCount: 1
            ))
            continuation.yield(.usage(inputTokens: 7, outputTokens: 11))
            continuation.yield(.finished(.complete))
            continuation.finish()
        }
    }
}

private final class GenerationReceiptRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [GenerationReceipt] = []

    func record(_ receipt: GenerationReceipt) {
        lock.lock()
        storage.append(receipt)
        lock.unlock()
    }

    var receipts: [GenerationReceipt] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

@Suite struct SessionRegistryTests {
    @Test func receiptCopyAndSourceCategoriesAreExactAndPrivacySafe() {
        let sessionID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let genID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        #expect(GenerationReceipt.Source(remoteEndpointDescription: "127.0.0.1:47337") == .loopback)
        #expect(GenerationReceipt.Source(remoteEndpointDescription: "10.86.0.2:49152") == .reachMesh)
        #expect(GenerationReceipt.Source(remoteEndpointDescription: "192.168.8.225:49153") == .privateLAN)
        #expect(GenerationReceipt.Source(remoteEndpointDescription: "100.103.193.21:49154") == .sharedAddressSpace)
        #expect(GenerationReceipt.Source(remoteEndpointDescription: "203.0.113.4:49155") == .publicNetwork)
        #expect(GenerationReceipt.Source(remoteEndpointDescription: "169.254.1.2:49156") == .unknown)
        #expect(GenerationReceipt.Source(remoteEndpointDescription: "not-an-endpoint") == .unknown)
        #expect(GenerationReceipt.Source(remoteEndpointDescription: nil) == .unknown)

        let accepted = GenerationReceipt.accepted(
            sessionID: sessionID,
            genID: genID,
            source: .privateLAN
        ).message
        #expect(accepted == "generation 22222222-2222-2222-2222-222222222222 accepted on session 11111111-1111-1111-1111-111111111111 from private-lan at seq 0")
        #expect(!accepted.contains("192.168.8.225"))
        #expect(!accepted.contains("49153"))

        let terminal = GenerationReceipt.terminal(
            sessionID: sessionID,
            genID: genID,
            finalSequence: 17,
            ending: .error
        ).message
        #expect(terminal == "generation 22222222-2222-2222-2222-222222222222 on session 11111111-1111-1111-1111-111111111111 finished at seq 17 ending error")
    }

    @Test func ordinaryCompletionProducesOneOrderedReceiptPair() async throws {
        let recorder = GenerationReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record)
        let (sessionID, _) = await registry.openSession()
        let genID = UUID()
        let events = AsyncThrowingStream<WireEvent, Error> { continuation in
            continuation.yield(.responseAppend(entryID: nil, text: "safe output", segmentID: nil, tokenCount: 1))
            continuation.finish()
        }
        let (stream, _, _) = try await registry.begin(
            sessionID: sessionID,
            genID: genID,
            receiptSource: .loopback,
            events: { events }
        )
        _ = await drain(stream) { $0.contains { if case .finished = $0.event { return true }; return false } }

        #expect(recorder.receipts == [
            .accepted(sessionID: sessionID, genID: genID, source: .loopback),
            .terminal(sessionID: sessionID, genID: genID, finalSequence: 1, ending: .complete),
        ])
    }

    @Test func duplicateBeginReplayAndCleanupDoNotDuplicateReceipts() async throws {
        let recorder = GenerationReceiptRecorder()
        var limits = SessionRegistry.Limits()
        limits.completedRetention = .milliseconds(20)
        let registry = SessionRegistry(limits: limits, receiptSink: recorder.record)
        let (sessionID, _) = await registry.openSession()
        let genID = UUID()
        let filling = ScriptedFilling(words: ["one"], delayMilliseconds: 0)
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())

        let (first, _, _) = try await registry.begin(
            sessionID: sessionID,
            genID: genID,
            receiptSource: .privateLAN,
            events: { filling.generate(request) }
        )
        _ = await drain(first) { $0.contains { if case .finished = $0.event { return true }; return false } }

        let (duplicate, _, _) = try await registry.begin(sessionID: sessionID, genID: genID) {
            Issue.record("a duplicate begin started another filling")
            return filling.generate(request)
        }
        _ = await drain(duplicate) { $0.contains { if case .finished = $0.event { return true }; return false } }

        let (replay, _, _) = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: nil)
        _ = await drain(replay) { $0.contains { if case .finished = $0.event { return true }; return false } }

        try await Task.sleep(for: .milliseconds(60))
        #expect(await registry.sweep() == 1)
        #expect(recorder.receipts == [
            .accepted(sessionID: sessionID, genID: genID, source: .privateLAN),
            .terminal(sessionID: sessionID, genID: genID, finalSequence: 2, ending: .complete),
        ])
    }

    @Test func detachAndReattachKeepOneReceiptPair() async throws {
        let recorder = GenerationReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record)
        let (sessionID, _) = await registry.openSession()
        let genID = UUID()
        let filling = ScriptedFilling(words: ["one", "two", "three"], delayMilliseconds: 20)
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let (first, epoch, _) = try await registry.begin(
            sessionID: sessionID,
            genID: genID,
            receiptSource: .reachMesh,
            events: { filling.generate(request) }
        )
        let head = await drain(first) { $0.count == 1 }
        await registry.detach(sessionID: sessionID, genID: genID, epoch: epoch)
        let (second, _, _) = try await registry.attach(
            sessionID: sessionID,
            genID: genID,
            fromSeq: head.last?.seq
        )
        _ = await drain(second) { $0.contains { if case .finished = $0.event { return true }; return false } }

        #expect(recorder.receipts == [
            .accepted(sessionID: sessionID, genID: genID, source: .reachMesh),
            .terminal(sessionID: sessionID, genID: genID, finalSequence: 4, ending: .complete),
        ])
    }

    @Test func cancellationAndFillingErrorsExposeOnlyTheirCategories() async throws {
        enum SecretFailure: Error { case transcriptContainedPrivateWords }

        let recorder = GenerationReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record)
        let (sessionID, _) = await registry.openSession()
        let cancelledID = UUID()
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let filling = ScriptedFilling(words: ["one", "two"], delayMilliseconds: 500)
        let (cancelledStream, epoch, _) = try await registry.begin(
            sessionID: sessionID,
            genID: cancelledID,
            receiptSource: .sharedAddressSpace,
            events: { filling.generate(request) }
        )
        _ = await drain(cancelledStream) { $0.count == 1 }
        await registry.cancel(sessionID: sessionID, genID: cancelledID, epoch: epoch)

        let failedID = UUID()
        let failedEvents = AsyncThrowingStream<WireEvent, Error> { continuation in
            continuation.finish(throwing: SecretFailure.transcriptContainedPrivateWords)
        }
        let (failedStream, _, _) = try await registry.begin(
            sessionID: sessionID,
            genID: failedID,
            receiptSource: .publicNetwork,
            events: { failedEvents }
        )
        _ = await drain(failedStream) { $0.contains { if case .finished = $0.event { return true }; return false } }

        #expect(recorder.receipts == [
            .accepted(sessionID: sessionID, genID: cancelledID, source: .sharedAddressSpace),
            .terminal(sessionID: sessionID, genID: cancelledID, finalSequence: 1, ending: .cancelled),
            .accepted(sessionID: sessionID, genID: failedID, source: .publicNetwork),
            .terminal(sessionID: sessionID, genID: failedID, finalSequence: 0, ending: .error),
        ])
        #expect(!recorder.receipts.map(\.message).joined().contains("transcriptContainedPrivateWords"))
    }

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
        let (stream, epoch, _) = try await registry.begin(
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
        let (first, epoch, _) = try await registry.begin(sessionID: sessionID, genID: genID) {
            filling.generate(request)
        }

        // Receive a few, ack 2, then the "connection dies".
        let received = await drain(first) { $0.count >= 4 }
        #expect(received.map { $0.seq } == [0, 1, 2, 3])
        await registry.ack(sessionID: sessionID, genID: genID, seq: 2, epoch: epoch)
        await registry.detach(sessionID: sessionID, genID: genID, epoch: epoch)

        try? await Task.sleep(for: .milliseconds(120))

        // Re-attach from the last received seq; replay must start at 4.
        let (second, _, _) = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: 3)
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

    /// Runs a generation whose events outgrow `cap` with nothing acked, and
    /// hands back what a re-attaching client would hold: the generation, and
    /// the last seq it was issued.
    ///
    /// **No acks anywhere in here on purpose** — un-acked is the whole
    /// precondition. An ack trims the buffer legitimately, and a run that
    /// acked would never reach the cap at all.
    private func overflowed(
        cap: Int
    ) async throws -> (registry: SessionRegistry, sessionID: UUID, genID: UUID, lastSeq: UInt64) {
        var limits = SessionRegistry.Limits()
        limits.bufferCapBytes = cap
        let registry = SessionRegistry(limits: limits)
        let (sessionID, token) = await registry.openSession()
        try await registry.validate(sessionID: sessionID, token: token)

        let genID = UUID()
        let filling = ScriptedFilling(words: Array(repeating: "tick ", count: 20), delayMilliseconds: 0)
        let (stream, _, _) = try await registry.begin(sessionID: sessionID, genID: genID) {
            filling.generate(WireGenerationRequest(id: UUID(), transcript: Transcript()))
        }
        var lastSeq: UInt64 = 0
        for await ev in stream {
            lastSeq = ev.seq
            if case .finished = ev.event { break }
        }
        return (registry, sessionID, genID, lastSeq)
    }

    /// The silent truncation, stated as the invariant rather than as a number.
    ///
    /// Past the buffer cap the registry drops the **oldest** un-acked event,
    /// and the client's dedupe only skips seqs at or below what it already has
    /// — so it accepted the far side of a gap without noticing one and rendered
    /// a short answer as a whole one. Nothing in the tree exercised the cap at
    /// all: `bufferCapBytes` had zero test references, so this branch was, as
    /// far as the suite was concerned, dead code.
    ///
    /// Sweeping every `fromSeq` states the property exactly and needs no
    /// arithmetic against `approximateSize`, which would rot: **a replay is
    /// either refused or contiguous, never served with a hole.** The two
    /// counts at the end are what stop it passing vacuously — a guard that
    /// refuses everything and a guard that refuses nothing both fail here.
    ///
    /// Fails on the old code, which serves the gapped replays.
    @Test func aReplayThatWouldSkipAHoleIsRefusedRatherThanServed() async throws {
        let (registry, sessionID, genID, lastSeq) = try await overflowed(cap: 200)

        var refused = 0
        var served = 0
        for fromSeq in 0..<lastSeq {
            do {
                let (replay, _, _) = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: fromSeq)
                var seqs: [UInt64] = []
                for await ev in replay { seqs.append(ev.seq) }
                served += 1
                #expect(
                    seqs == Array((fromSeq + 1)...lastSeq),
                    "a replay served from \(fromSeq) had a hole in it: \(seqs)"
                )
            } catch SessionRegistry.RegistryError.replayOutgrewTheBuffer {
                refused += 1
            }
        }
        #expect(refused > 0, "nothing was refused, so the buffer never overflowed and this proved nothing")
        #expect(served > 0, "every replay was refused, so the guard is not telling a hole from a buffer")
    }

    /// The positive control at the top of the buffer: the last event issued is
    /// never the one dropped, so a client holding everything but it must be
    /// served — and served exactly it.
    ///
    /// Passes on the old code too, deliberately. It is not evidence of the fix;
    /// it is what stops the fix being "refuse every re-attach", which would
    /// satisfy the test above on its own.
    @Test func aReplayThatIsStillWholeIsServedUnchanged() async throws {
        let (registry, sessionID, genID, lastSeq) = try await overflowed(cap: 200)
        let (replay, _, _) = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: lastSeq - 1)
        var seqs: [UInt64] = []
        for await ev in replay { seqs.append(ev.seq) }
        #expect(seqs == [lastSeq], "the top of the buffer was refused or came back wrong: \(seqs)")
    }

    /// An acked span is not a hole, and the buffer cannot tell you which it is.
    ///
    /// After an ack and after a cap drop, `buffer.first!.seq` reads exactly the
    /// same — above zero, with events missing below it. The difference is that
    /// an acked event is one the client already holds. So the floor has to be
    /// recorded at the drop site and nowhere else; anything that infers it from
    /// the buffer, or that lets `ack` write it, turns every ordinary re-attach
    /// after an ack into a refusal.
    ///
    /// Also passes on the old code — this one guards the new code against the
    /// mistake, rather than evidencing the defect.
    @Test func anAckedSpanIsNotAHole() async throws {
        let registry = SessionRegistry()
        let (sessionID, token) = await registry.openSession()
        try await registry.validate(sessionID: sessionID, token: token)

        let filling = ScriptedFilling()
        let genID = UUID()
        let (first, epoch, _) = try await registry.begin(sessionID: sessionID, genID: genID) {
            filling.generate(WireGenerationRequest(id: UUID(), transcript: Transcript()))
        }
        let received = await drain(first) { $0.count >= 4 }
        #expect(received.map(\.seq) == [0, 1, 2, 3])

        // Everything at or below 2 is received, so the registry trims it —
        // and the client's next re-attach names 3, the last one it took.
        await registry.ack(sessionID: sessionID, genID: genID, seq: 2, epoch: epoch)
        await registry.detach(sessionID: sessionID, genID: genID, epoch: epoch)

        let (second, _, _) = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: 3)
        var tail: [Ev] = []
        for await ev in second {
            tail.append(ev)
            if case .finished = ev.event { break }
        }
        #expect(tail.first?.seq == 4, "a trimmed buffer was read as a lost one")
        let text = (received + tail).compactMap { ev -> String? in
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
        let (first, firstEpoch, _) = try await registry.begin(sessionID: sessionID, genID: genID) {
            filling.generate(request)
        }
        _ = await drain(first) { $0.count >= 2 }

        // The phone comes back over the mesh.
        let (second, _, _) = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: 0)

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
        let (first, firstEpoch, _) = try await registry.begin(sessionID: sessionID, genID: genID) {
            filling.generate(request)
        }
        _ = await drain(first) { $0.count >= 2 }
        let (second, _, _) = try await registry.attach(sessionID: sessionID, genID: genID, fromSeq: 0)

        await registry.cancel(sessionID: sessionID, genID: genID, epoch: firstEpoch)

        #expect(await finishes(second), "a stale connection's cancel killed the live generation")
    }

    @Test func beginIsIdempotentForKnownGeneration() async throws {
        let registry = SessionRegistry()
        let (sessionID, _) = await registry.openSession()
        let genID = UUID()
        let request = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let filling = ScriptedFilling()

        let (first, _, _) = try await registry.begin(sessionID: sessionID, genID: genID) { filling.generate(request) }
        _ = await drain(first) { $0.count >= 2 }

        // A duplicated GenerateBegin (first-frame loss) must not start a
        // second generation; it re-attaches from 0.
        let (again, _, _) = try await registry.begin(sessionID: sessionID, genID: genID) {
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
        let (stream, _, _) = try await registry.begin(sessionID: sessionID, genID: UUID()) {
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
        let (stream, epoch, _) = try await registry.begin(sessionID: sessionID, genID: genID) { [slow] in slow.generate(request) }
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

    @Test func generationStreamsKeepTheSessionsNegotiatedVersion() async throws {
        let registry = SessionRegistry()
        let (sessionID, token) = await registry.openSession(version: 7)
        let genID = UUID()
        let (stream, _, begunVersion) = try await registry.begin(
            sessionID: sessionID,
            genID: genID
        ) {
            AsyncThrowingStream { continuation in
                continuation.yield(.finished(.complete))
                continuation.finish()
            }
        }
        for await _ in stream {}
        #expect(begunVersion == 7)

        try await registry.validate(sessionID: sessionID, token: token)
        let (replay, _, attachedVersion) = try await registry.attach(
            sessionID: sessionID,
            genID: genID,
            fromSeq: nil
        )
        for await _ in replay {}
        #expect(attachedVersion == 7)
    }
}

@Suite(.serialized) struct DaemonResumeTests {
    @Test func requiredToolArgumentsStayWholeAndOrderedAcrossLoopback() async throws {
        let ca = try ClusterCA.create(commonName: "Reach Tool Wire CA")
        let server = try ca.issueServer(
            commonName: "localhost",
            dnsNames: ["localhost"],
            ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(
            commonName: "tool-wire-client",
            uri: "reach://device/tool-wire")
        let serverIdentity = try IdentityMaterializer.materialize(
            server, label: "reach-tool-wire-server-\(UUID())")
        let clientIdentity = try IdentityMaterializer.materialize(
            client, label: "reach-tool-wire-client-\(UUID())")
        let boxes = [IdentityBox(serverIdentity), IdentityBox(clientIdentity)]
        defer { for box in boxes { KeychainIdentity.remove(identity: box.identity) } }
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var config = DaemonConfig()
        config.port = TestPorts.port(47479)
        config.clusterName = "tool-wire-test"
        let daemon = Daemon(
            config: config,
            filling: ScriptedToolFilling(),
            identity: Daemon.ListenerIdentity(
                identity: serverIdentity,
                caCertificate: caCert)
        )
        try await daemon.start(advertise: false)
        defer { Task { await daemon.stop() } }

        let dialer = QUICDialer(
            endpoint: .hostPort(
                host: "127.0.0.1",
                port: .init(rawValue: TestPorts.port(47479))!),
            parameters: .reachQUIC(options: TLSBuilder.clientOptions(
                alpn: Wire.alpn,
                identity: clientIdentity,
                serverTrustRoots: [caCert]))
        )
        let control = try await dialer.openStream(timeout: 45)
        defer { control.cancel() }
        var controlFrames = control.frames.makeAsyncIterator()
        try await control.send(Hello(client: "tool-wire-test"))
        _ = try (try #require(try await controlFrames.next())).decode(HelloAck.self)
        try await control.send(SessionOpen(modelID: "scripted-tools"))
        let opened = try (try #require(try await controlFrames.next()))
            .decode(SessionOpened.self)

        let stream = try await dialer.openStream(timeout: 45)
        defer { stream.cancel() }
        let tool = WireToolDefinition(
            name: "record",
            description: "Record a value.",
            parameters: GenerationSchema(type: GeneratedContent.self, properties: [])
        )
        try await stream.send(GenerateBegin(
            sessionID: opened.sessionID,
            genID: UUID(),
            request: WireGenerationRequest(
                id: UUID(),
                transcript: Transcript(),
                tools: [tool],
                options: WireGenerationOptions(toolCalling: .required)
            )
        ))
        var received: [WireEvent] = []
        for try await raw in stream.frames where raw.type == .ev {
            let event = try raw.decode(Ev.self).event
            received.append(event)
            if case .finished = event { break }
        }
        let calls = received.compactMap { event -> (String, String, String)? in
            if case .toolCallAppendArguments(_, let id, let name, let content, _) = event {
                return (id, name, content)
            }
            return nil
        }
        #expect(calls.map(\.0) == ["first", "second"])
        #expect(calls.map(\.1) == ["record", "record"])
        #expect(calls.map(\.2) == [#"{"value":1}"#, #"{"value":2}"#])
        #expect(received.contains { if case .finished(.complete) = $0 { true } else { false } })
    }

    /// The resume test: a generation's transport dies mid-stream; the
    /// client reconnects (any path) and re-attaches; the concatenated text
    /// is byte-identical to an uninterrupted run.
    @Test func killedConnectionResumesByteIdentically() async throws {
        let ca = try ClusterCA.create(commonName: "Reach Spine CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "spine-client", uri: "reach://device/spine")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-spine-server-\(UUID())")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-spine-client-\(UUID())")
        // Owned rather than the old global bin, whose `drain()` emptied one
        // bin for every concurrent suite at once.
        let boxes = [IdentityBox(serverIdentity), IdentityBox(clientIdentity)]
        defer { for box in boxes { KeychainIdentity.remove(identity: box.identity) } }
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var config = DaemonConfig()
        config.port = TestPorts.port(47413)
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
            endpoint: .hostPort(host: "127.0.0.1", port: .init(rawValue: TestPorts.port(47413))!),
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
        #expect(ack.port == TestPorts.port(47413))
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
        // Owned rather than the old global bin, whose `drain()` emptied one
        // bin for every concurrent suite at once.
        let boxes = [IdentityBox(serverIdentity), IdentityBox(clientIdentity)]
        defer { for box in boxes { KeychainIdentity.remove(identity: box.identity) } }
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var config = DaemonConfig()
        config.port = TestPorts.port(47454)
        config.clusterName = "silent-test"
        let daemon = Daemon(
            config: config,
            filling: ScriptedFilling(),
            identity: Daemon.ListenerIdentity(identity: serverIdentity, caCertificate: caCert)
        )
        try await daemon.start(advertise: false)
        defer { Task { await daemon.stop() } }

        let dialer = QUICDialer(
            endpoint: .hostPort(host: "127.0.0.1", port: .init(rawValue: TestPorts.port(47454))!),
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

    /// The truncation, over a real wire, as the app meets it.
    ///
    /// The registry half is held at `SessionRegistryTests`; this is the rest of
    /// the path — that the refusal reaches a client as `reattach-rejected` with
    /// the sentence intact, which is what makes the client render
    /// `ReachError.generationLost` rather than a bare case name. `Daemon`
    /// accepts an injected registry, so the cap can be small enough to reach in
    /// a test without a filling that produces four megabytes.
    ///
    /// The client here acks **nothing**, which is the precondition — and is a
    /// thing a real client does, since it acks in batches of sixteen and this
    /// generation is longer than that between one ack and the walk-out.
    ///
    /// ⚠️ Port 47455, checked clear. `grep -rn '47[0-9]\{3\}'`
    /// — a case-sensitive grep misses `sessionPort:`.
    @Test func aReattachPastTheBufferIsRefusedInWordsAndNotServedShort() async throws {
        let ca = try ClusterCA.create(commonName: "Reach Truncation CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "trunc-client", uri: "reach://device/trunc")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-trunc-server-\(UUID())")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-trunc-client-\(UUID())")
        let boxes = [IdentityBox(serverIdentity), IdentityBox(clientIdentity)]
        defer { for box in boxes { KeychainIdentity.remove(identity: box.identity) } }
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var limits = SessionRegistry.Limits()
        limits.bufferCapBytes = 200
        var config = DaemonConfig()
        config.port = TestPorts.port(47455)
        config.clusterName = "trunc-test"
        let daemon = Daemon(
            config: config,
            // Long enough to outgrow the cap several times over while the
            // client is away, slow enough that the client gets a head first.
            filling: ScriptedFilling(words: Array(repeating: "tick ", count: 40), delayMilliseconds: 10),
            identity: Daemon.ListenerIdentity(identity: serverIdentity, caCertificate: caCert),
            registry: SessionRegistry(limits: limits)
        )
        try await daemon.start(advertise: false)
        defer { Task { await daemon.stop() } }

        let dialer = QUICDialer(
            endpoint: .hostPort(host: "127.0.0.1", port: .init(rawValue: TestPorts.port(47455))!),
            parameters: .reachQUIC(
                options: TLSBuilder.clientOptions(alpn: Wire.alpn, identity: clientIdentity, serverTrustRoots: [caCert])
            )
        )
        let control = try await dialer.openStream(timeout: 45)
        defer { control.cancel() }
        var controlFrames = control.frames.makeAsyncIterator()
        try await control.send(Hello(client: "trunc-test"))
        _ = try (try #require(try await controlFrames.next())).decode(HelloAck.self)
        try await control.send(SessionOpen(modelID: "scripted"))
        let opened = try (try #require(try await controlFrames.next())).decode(SessionOpened.self)

        let genID = UUID()
        let gen1 = try await dialer.openStream(timeout: 45)
        var head: [Ev] = []
        try await gen1.send(GenerateBegin(
            sessionID: opened.sessionID,
            genID: genID,
            request: WireGenerationRequest(id: UUID(), transcript: Transcript())
        ))
        for try await raw in gen1.frames {
            guard raw.type == .ev else { continue }
            head.append(try raw.decode(Ev.self))
            if head.count == 3 { break }
        }
        gen1.cancel()   // the walk out the door, with nothing acked

        // Long enough for the rest of the answer to arrive and push the head
        // out of the buffer.
        try await Task.sleep(for: .milliseconds(900))

        let gen2 = try await dialer.openStream(timeout: 45)
        defer { gen2.cancel() }
        try await gen2.send(GenerateReattach(
            sessionID: opened.sessionID,
            token: opened.token,
            genID: genID,
            fromSeq: head.last!.seq
        ))
        var refusal: ErrorFrame?
        var served: [Ev] = []
        for try await raw in gen2.frames {
            if raw.type == .errorFrame {
                refusal = try raw.decode(ErrorFrame.self)
                break
            }
            if raw.type == .ev { served.append(try raw.decode(Ev.self)) }
        }

        #expect(served.isEmpty, "the answer was served short instead of refused: \(served.map(\.seq))")
        let frame = try #require(refusal, "nothing came back at all")
        // The code is what routes the client to `generationLost` rather than
        // to the generic "the cluster refused this".
        #expect(frame.code == "reattach-rejected")
        #expect(
            frame.message == "\(SessionRegistry.RegistryError.replayOutgrewTheBuffer)",
            "the sentence did not survive the wire: \(frame.message)"
        )
    }
}
