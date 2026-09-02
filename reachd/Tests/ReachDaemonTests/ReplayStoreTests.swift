import Foundation
import ReachWire
import Testing
@testable import ReachHost

@Suite(.serialized) struct ReplayStoreTests {
    private let key = ReplayStore.Key(sessionID: UUID(), generationID: UUID())

    @Test func exactFramedBytesAreStoredAndDecoded() throws {
        let event = Self.text(sequence: 7, bytes: 1_024)
        let exact = try FrameCodec.encode(event).count
        var store = ReplayStore(policy: .init(
            perGenerationBytes: exact,
            processBytes: exact
        ))

        let result = try store.append(event, for: key)
        #expect(result.stored)
        #expect(result.newlyExhausted.isEmpty)
        #expect(store.retainedBytes(for: key) == exact)
        #expect(store.counters.currentBytes == exact)
        #expect(store.counters.highWaterBytes == exact)
        #expect(try store.replay(for: key, after: nil) == [event])
    }

    @Test func toolUsageAndTerminalFramesReplayByteIdentically() throws {
        let events = [
            Ev(seq: 0, event: .toolCallAppendArguments(
                entryID: "entry",
                id: "call",
                name: "record_river",
                content: #"{"count":3,"name":"mouth"}"#,
                tokenCount: 8
            )),
            Ev(seq: 1, event: .usage(inputTokens: 12, outputTokens: 8)),
            Ev(seq: 2, event: .finished(.complete)),
        ]
        let exact = try events.map { try FrameCodec.encode($0).count }.reduce(0, +)
        var store = ReplayStore(policy: .init(
            perGenerationBytes: exact,
            processBytes: exact
        ))
        for event in events { _ = try store.append(event, for: key) }

        let replay = try store.replay(for: key, after: nil)
        #expect(replay == events)
        let replayBytes = try replay.map { try FrameCodec.encode($0) }
        let originalBytes = try events.map { try FrameCodec.encode($0) }
        #expect(replayBytes == originalBytes)
        #expect(store.counters.currentBytes == exact)
    }

    @Test func oneMaximumFrameFitsAndFourWindowsBoundTheProcess() throws {
        let maximumEncoded = Int(FrameCodec.maxFrameLength) + 4
        let empty = Self.text(sequence: 0, bytes: 0)
        let overhead = try FrameCodec.encode(empty).count
        let maximal = Self.text(sequence: 0, bytes: maximumEncoded - overhead)
        #expect(try FrameCodec.encode(maximal).count == maximumEncoded)

        var store = ReplayStore(policy: .init(
            perGenerationBytes: maximumEncoded,
            processBytes: maximumEncoded * 4
        ))
        var keys: [ReplayStore.Key] = []
        for _ in 0 ..< 4 {
            let key = ReplayStore.Key(sessionID: UUID(), generationID: UUID())
            keys.append(key)
            #expect(try store.append(maximal, for: key).stored)
        }
        #expect(store.counters.currentBytes == maximumEncoded * 4)

        let fifthKey = ReplayStore.Key(sessionID: UUID(), generationID: UUID())
        let fifth = try store.append(Self.text(sequence: 0, bytes: 1), for: fifthKey)
        #expect(!fifth.stored)
        #expect(fifth.newlyExhausted == [.processWide])
        #expect(store.counters.currentBytes == maximumEncoded * 4)
        #expect(keys.allSatisfy { store.retainedBytes(for: $0) == maximumEncoded })
    }

    @Test func oneByteBelowTheExactFrameRefusesReplayButNotLiveDelivery() throws {
        let event = Self.text(sequence: 0, bytes: 1_024)
        let exact = try FrameCodec.encode(event).count
        var store = ReplayStore(policy: .init(
            perGenerationBytes: exact - 1,
            processBytes: exact * 4
        ))

        let result = try store.append(event, for: key)
        #expect(!result.stored)
        #expect(result.newlyExhausted == [.perGeneration])
        #expect(store.counters.currentBytes == 0)
        #expect(store.counters.droppedEvents == 1)
        #expect(throws: ReplayStore.ReplayError.unavailable) {
            _ = try store.replay(for: key, after: nil)
        }
        #expect(try store.replay(for: key, after: 0).isEmpty)
    }

    @Test func perGenerationPressureDropsOnlyAnOldPrefix() throws {
        let first = Self.text(sequence: 0, bytes: 512)
        let second = Self.text(sequence: 1, bytes: 512)
        let third = Self.text(sequence: 2, bytes: 512)
        let cap = try FrameCodec.encode(first).count + FrameCodec.encode(second).count
        var store = ReplayStore(policy: .init(
            perGenerationBytes: cap,
            processBytes: cap * 4
        ))

        _ = try store.append(first, for: key)
        _ = try store.append(second, for: key)
        _ = try store.append(third, for: key)

        #expect(store.droppedThrough(for: key) == 0)
        #expect(throws: ReplayStore.ReplayError.unavailable) {
            _ = try store.replay(for: key, after: nil)
        }
        #expect(try store.replay(for: key, after: 0) == [second, third])
    }

    @Test func processPressureNeverEvictsAnotherGeneration() throws {
        let otherKey = ReplayStore.Key(sessionID: UUID(), generationID: UUID())
        let eventA = Self.text(sequence: 0, bytes: 512)
        let eventB = Self.text(sequence: 0, bytes: 512)
        let exact = try FrameCodec.encode(eventA).count
        var store = ReplayStore(policy: .init(
            perGenerationBytes: exact * 2,
            processBytes: exact
        ))

        _ = try store.append(eventA, for: key)
        let blocked = try store.append(eventB, for: otherKey)

        #expect(!blocked.stored)
        #expect(blocked.newlyExhausted == [.processWide])
        #expect(try store.replay(for: key, after: nil) == [eventA])
        #expect(throws: ReplayStore.ReplayError.unavailable) {
            _ = try store.replay(for: otherKey, after: nil)
        }
    }

    @Test func processPressureMayReclaimOnlyTheAppendingWindow() throws {
        let otherKey = ReplayStore.Key(sessionID: UUID(), generationID: UUID())
        let a0 = Self.text(sequence: 0, bytes: 256)
        let a1 = Self.text(sequence: 1, bytes: 256)
        let b0 = Self.text(sequence: 0, bytes: 256)
        let exact = try FrameCodec.encode(a0).count
        var store = ReplayStore(policy: .init(
            perGenerationBytes: exact * 2,
            processBytes: exact * 2
        ))

        _ = try store.append(a0, for: key)
        _ = try store.append(b0, for: otherKey)
        _ = try store.append(a1, for: key)

        #expect(try store.replay(for: otherKey, after: nil) == [b0])
        #expect(try store.replay(for: key, after: 0) == [a1])
        #expect(store.droppedThrough(for: key) == 0)
    }

    @Test func oneAppendCanReportBothCapacityClassesExactlyOnce() throws {
        let first = Self.text(sequence: 0, bytes: 256)
        let second = Self.text(sequence: 1, bytes: 256)
        let exact = try FrameCodec.encode(first).count
        var store = ReplayStore(policy: .init(
            perGenerationBytes: exact,
            processBytes: exact
        ))

        _ = try store.append(first, for: key)
        let crossed = try store.append(second, for: key)
        #expect(crossed.stored)
        #expect(Set(crossed.newlyExhausted) == [.perGeneration, .processWide])

        let third = try store.append(Self.text(sequence: 2, bytes: 256), for: key)
        #expect(third.newlyExhausted.isEmpty)
        #expect(store.counters.capacityExhaustions == 2)
    }

    @Test func cumulativeAckReleasesExactBytesWithoutCreatingAHole() throws {
        let events = (0 ... 3).map { Self.text(sequence: UInt64($0), bytes: 128 + $0) }
        let exact = try events.map { try FrameCodec.encode($0).count }.reduce(0, +)
        let released = try events.prefix(3).map { try FrameCodec.encode($0).count }.reduce(0, +)
        var store = ReplayStore(policy: .init(
            perGenerationBytes: exact,
            processBytes: exact
        ))
        for event in events { _ = try store.append(event, for: key) }

        store.acknowledge(for: key, through: 2)

        #expect(store.counters.currentBytes == exact - released)
        #expect(store.physicallyOwnedFrameBytesForTesting == store.counters.currentBytes)
        #expect(store.counters.acknowledgedEvents == 3)
        #expect(store.droppedThrough(for: key) == nil)
        #expect(try store.replay(for: key, after: 2) == [events[3]])
    }

    @Test func capacityDropsDestroyPoppedPayloadBeforeMetadataCompaction() throws {
        let payloadBytes = 1_048_576
        let cap = try FrameCodec.encode(Self.text(sequence: 63, bytes: payloadBytes)).count
        var store = ReplayStore(policy: .init(
            perGenerationBytes: cap,
            processBytes: cap * 4
        ))

        for sequence in 0 ..< 64 {
            let event = Self.text(sequence: UInt64(sequence), bytes: payloadBytes)
            let exact = try FrameCodec.encode(event).count
            #expect(try store.append(event, for: key).stored)
            #expect(store.counters.currentBytes == exact)
            #expect(store.retainedBytes(for: key) == exact)
            #expect(store.physicallyOwnedFrameBytesForTesting == exact)
        }

        store.acknowledge(for: key, through: 63)
        #expect(store.counters.currentBytes == 0)
        #expect(store.physicallyOwnedFrameBytesForTesting == 0)
    }

    @Test func corruptTypeOrSequenceIsNeverServed() throws {
        let event = Self.text(sequence: 4, bytes: 64)
        var store = ReplayStore(policy: .init(
            perGenerationBytes: 4_096,
            processBytes: 16_384
        ))
        _ = try store.append(event, for: key)
        #expect(store.replaceFrameForTesting(
            for: key,
            sequence: 4,
            with: try FrameCodec.encode(Ping(nonce: 9))
        ))

        #expect(throws: ReplayStore.ReplayError.corrupt) {
            _ = try store.replay(for: key, after: nil)
        }
        #expect(store.counters.corruptions == 1)
        #expect(store.counters.currentBytes == 0)
        #expect(store.droppedThrough(for: key) == 4)

        var wrongSequence = ReplayStore(policy: .init(
            perGenerationBytes: 4_096,
            processBytes: 16_384
        ))
        _ = try wrongSequence.append(event, for: key)
        #expect(wrongSequence.replaceFrameForTesting(
            for: key,
            sequence: 4,
            with: try FrameCodec.encode(Self.text(sequence: 5, bytes: 64))
        ))
        #expect(throws: ReplayStore.ReplayError.corrupt) {
            _ = try wrongSequence.replay(for: key, after: nil)
        }
    }

    @Test func removalAndShutdownReleaseAccountingExactlyOnce() throws {
        let otherKey = ReplayStore.Key(sessionID: UUID(), generationID: UUID())
        var store = ReplayStore(policy: .init(
            perGenerationBytes: 8_192,
            processBytes: 16_384
        ))
        _ = try store.append(Self.text(sequence: 0, bytes: 256), for: key)
        _ = try store.append(Self.text(sequence: 0, bytes: 256), for: otherKey)
        let initial = store.counters.currentBytes

        store.remove(key)
        let afterOne = store.counters.currentBytes
        store.remove(key)
        #expect(store.counters.currentBytes == afterOne)
        #expect(afterOne > 0)

        store.removeAll()
        #expect(store.counters.currentBytes == 0)
        #expect(store.counters.releasedBytes == initial)
        store.removeAll()
        #expect(store.counters.releasedBytes == initial)
    }

    @Test func defaultRegistryPolicyIsOneMaximumFrameAndFourWindows() async {
        let registry = SessionRegistry(receiptSink: { _ in })
        let message = await registry.replayStartupMessage
        #expect(SessionRegistry.Limits().bufferCapBytes == Int(FrameCodec.maxFrameLength) + 4)
        #expect(message.contains("one maximum-frame window"))
        #expect(message.contains("four-window process budget"))
    }

    @Test func overLimitEventBecomesALegibleTerminalInsteadOfPoisoningTheStream() async throws {
        let recorder = ReplayReceiptRecorder()
        let registry = SessionRegistry(
            receiptSink: recorder.record,
            replayEventSink: { _ in }
        )
        let session = await registry.openSession()
        let genID = UUID()
        let oversized = String(repeating: "x", count: Int(FrameCodec.maxFrameLength))
        let opened = try await registry.begin(sessionID: session.sessionID, genID: genID) {
            AsyncThrowingStream { continuation in
                continuation.yield(.responseAppend(
                    entryID: nil,
                    text: oversized,
                    segmentID: nil,
                    tokenCount: 1
                ))
                continuation.finish()
            }
        }

        var events: [Ev] = []
        for await event in opened.stream { events.append(event) }
        let only = try #require(events.first)
        #expect(events.count == 1)
        #expect(only.seq == 0)
        guard case .finished(.error(let copy)) = only.event else {
            Issue.record("oversized event did not become an error terminal")
            return
        }
        #expect(copy == "the cluster produced a generation event larger than the wire's 16 MiB frame limit")
        #expect(try FrameCodec.encode(only).count <= Int(FrameCodec.maxFrameLength) + 4)
        #expect(recorder.receipts.last == .terminal(
            sessionID: session.sessionID,
            genID: genID,
            finalSequence: 0,
            ending: .error
        ))
    }

    @Test func admittedOverLimitEventReleasesTheSlotAsAnError() async throws {
        let logs = ReplayLogRecorder()
        let admission = SlotAdmission(eventSink: logs.record)
        let registry = SessionRegistry(
            receiptSink: { _ in },
            replayEventSink: { _ in }
        )
        let session = await registry.openSession()
        let genID = UUID()
        let oversized = String(repeating: "x", count: Int(FrameCodec.maxFrameLength))
        let opened = try await registry.begin(
            sessionID: session.sessionID,
            genID: genID,
            receiptSource: .loopback,
            admission: admission,
            events: {
                AsyncThrowingStream { continuation in
                    continuation.yield(.responseAppend(
                        entryID: nil,
                        text: oversized,
                        segmentID: nil,
                        tokenCount: 1
                    ))
                    continuation.finish()
                }
            }
        )

        let terminal = try #require(await opened.stream.first { event in
            if case .finished = event.event { return true }
            return false
        })
        guard case .finished(.error) = terminal.event else {
            Issue.record("oversized admitted event did not finish as an error")
            return
        }
        #expect(await Self.eventually {
            logs.messages.contains {
                $0 == "provider admission released the active slot after error; active=0 waiting=0"
            }
        })
        #expect(!logs.messages.contains {
            $0.contains("released the active slot after completion")
        })
    }

    @Test func replayCapacityLossDoesNotInterruptLiveDelivery() async throws {
        var limits = SessionRegistry.Limits()
        limits.bufferCapBytes = 200
        let registry = SessionRegistry(
            limits: limits,
            receiptSink: { _ in },
            replayEventSink: { _ in }
        )
        let session = await registry.openSession()
        let genID = UUID()
        let opened = try await registry.begin(sessionID: session.sessionID, genID: genID) {
            AsyncThrowingStream { continuation in
                continuation.yield(.responseAppend(
                    entryID: nil,
                    text: String(repeating: "river", count: 256),
                    segmentID: nil,
                    tokenCount: 1
                ))
                continuation.yield(.finished(.complete))
                continuation.finish()
            }
        }

        var live: [Ev] = []
        for await event in opened.stream { live.append(event) }
        #expect(live.count == 2)
        #expect(live.map(\.seq) == [0, 1])
        #expect(live.last?.event == .finished(.complete))
        await #expect(throws: SessionRegistry.RegistryError.replayOutgrewTheBuffer) {
            _ = try await registry.attach(sessionID: session.sessionID, genID: genID, fromSeq: nil)
        }
        let terminalOnly = try await registry.attach(
            sessionID: session.sessionID,
            genID: genID,
            fromSeq: 0
        )
        var replay: [Ev] = []
        for await event in terminalOnly.stream { replay.append(event) }
        #expect(replay == [live[1]])
    }

    @Test func queuedGenerationConsumesNoReplayUntilItEmits() async throws {
        let registry = SessionRegistry(receiptSink: { _ in })
        let admission = SlotAdmission(eventSink: { _ in })
        let firstSession = await registry.openSession()
        let secondSession = await registry.openSession()
        let firstID = UUID()
        let secondID = UUID()
        let first = try await registry.begin(
            sessionID: firstSession.sessionID,
            genID: firstID,
            receiptSource: .loopback,
            admission: admission,
            events: { Self.delayedCompletion() }
        )
        let second = try await registry.begin(
            sessionID: secondSession.sessionID,
            genID: secondID,
            receiptSource: .loopback,
            admission: admission,
            events: { Self.delayedCompletion() }
        )

        let queued = await Self.eventually {
            let counters = await admission.counters
            return counters.active == 1 && counters.waiting == 1
        }
        #expect(queued)
        #expect(await registry.replayCounters.currentBytes == 0)

        await registry.cancel(
            sessionID: secondSession.sessionID,
            genID: secondID,
            epoch: second.epoch,
            admission: admission
        )
        await registry.cancel(
            sessionID: firstSession.sessionID,
            genID: firstID,
            epoch: first.epoch,
            admission: admission
        )
        await admission.shutdown()
    }

    @Test func terminalRetentionReapAndDaemonShutdownReleaseReplay() async throws {
        var limits = SessionRegistry.Limits()
        limits.completedRetention = .zero
        let registry = SessionRegistry(limits: limits, receiptSink: { _ in })
        let session = await registry.openSession()
        let genID = UUID()
        let opened = try await registry.begin(sessionID: session.sessionID, genID: genID) {
            AsyncThrowingStream { continuation in
                continuation.yield(.responseAppend(entryID: nil, text: "river", segmentID: nil, tokenCount: 1))
                continuation.yield(.finished(.complete))
                continuation.finish()
            }
        }
        for await _ in opened.stream {}
        #expect(await registry.replayCounters.currentBytes > 0)

        try await Task.sleep(for: .milliseconds(1))
        #expect(await registry.sweep() == 1)
        #expect(await registry.replayCounters.currentBytes == 0)

        let second = await registry.openSession()
        let secondID = UUID()
        let active = try await registry.begin(sessionID: second.sessionID, genID: secondID) {
            AsyncThrowingStream { continuation in
                continuation.yield(.responseAppend(entryID: nil, text: "held", segmentID: nil, tokenCount: 1))
            }
        }
        _ = await active.stream.first { _ in true }
        #expect(await registry.replayCounters.currentBytes > 0)
        await registry.shutdown()
        #expect(await registry.replayCounters.currentBytes == 0)
    }

    private static func text(sequence: UInt64, bytes: Int) -> Ev {
        Ev(
            seq: sequence,
            event: .responseAppend(
                entryID: nil,
                text: String(repeating: "r", count: bytes),
                segmentID: nil,
                tokenCount: 1
            )
        )
    }

    private static func delayedCompletion() -> AsyncThrowingStream<WireEvent, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                try? await Task.sleep(for: .seconds(5))
                continuation.yield(.finished(.complete))
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    private static func eventually(
        timeout: Duration = .seconds(2),
        condition: @escaping @Sendable () async -> Bool
    ) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline {
            if await condition() { return true }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return await condition()
    }
}

private final class ReplayReceiptRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [GenerationReceipt] = []

    func record(_ receipt: GenerationReceipt) {
        lock.withLock { storage.append(receipt) }
    }

    var receipts: [GenerationReceipt] {
        lock.withLock { storage }
    }
}

private final class ReplayLogRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    func record(_ message: String) {
        lock.withLock { storage.append(message) }
    }

    var messages: [String] {
        lock.withLock { storage }
    }
}
