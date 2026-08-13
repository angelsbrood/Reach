import Foundation
import FoundationModels
import ReachIdentity
import ReachTransport
import ReachWire
import Testing
@testable import ReachDaemon

private final class SlotReceiptRecorder: @unchecked Sendable {
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

private final class AdmissionExecutionProbe: @unchecked Sendable {
    typealias Continuation = AsyncThrowingStream<WireEvent, any Error>.Continuation

    private let lock = NSLock()
    private var order: [String] = []
    private var continuations: [String: Continuation] = [:]
    private var executions = 0
    private var active = 0
    private var peak = 0

    func stream(_ label: String) -> AsyncThrowingStream<WireEvent, any Error> {
        let (stream, continuation) = AsyncThrowingStream<WireEvent, any Error>.makeStream()
        lock.lock()
        order.append(label)
        executions += 1
        active += 1
        peak = max(peak, active)
        continuations[label] = continuation
        lock.unlock()
        continuation.onTermination = { [weak self] _ in self?.terminated(label) }
        return stream
    }

    func finish(_ label: String, reason: WireFinishReason = .complete) {
        lock.lock()
        let continuation = continuations.removeValue(forKey: label)
        if continuation != nil { active -= 1 }
        lock.unlock()
        continuation?.yield(.finished(reason))
        continuation?.finish()
    }

    var snapshot: (order: [String], executions: Int, active: Int, peak: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (order, executions, active, peak)
    }

    private func terminated(_ label: String) {
        lock.lock()
        if continuations.removeValue(forKey: label) != nil { active -= 1 }
        lock.unlock()
    }
}

private actor QueuedCancellationBarrier {
    private var entered = false
    private var released = false
    private var entryWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiter: CheckedContinuation<Void, Never>?

    func pauseAfterCommit() async {
        entered = true
        let waiters = entryWaiters
        entryWaiters.removeAll()
        for waiter in waiters { waiter.resume() }
        guard !released else { return }
        await withCheckedContinuation { releaseWaiter = $0 }
    }

    func waitUntilCommitted() async {
        guard !entered else { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func resumeCancellation() {
        released = true
        releaseWaiter?.resume()
        releaseWaiter = nil
    }
}

private func slotEventually(
    attempts: Int = 300,
    _ predicate: @escaping @Sendable () async -> Bool
) async -> Bool {
    for _ in 0 ..< attempts {
        if await predicate() { return true }
        try? await Task.sleep(for: .milliseconds(5))
    }
    return false
}

private func slotTerminal(_ stream: AsyncStream<Ev>) async -> Ev? {
    for await event in stream {
        if case .finished = event.event { return event }
    }
    return nil
}

private struct HoldingSlotFilling: SlotFilling {
    let modelID = "holding-slot"
    let displayName = "Holding Slot"
    let capabilities: [String] = []
    let probe: AdmissionExecutionProbe

    func prewarm() async throws {}

    func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, any Error> {
        probe.stream(request.id.uuidString)
    }
}

@Suite(.serialized) struct SlotAdmissionTests {
    @Test func providerCapabilityDefaultsToOneAndCanOptIn() {
        struct DefaultFilling: SlotFilling {
            let modelID = "default"
            let displayName = "Default"
            let capabilities: [String] = []
            func prewarm() async throws {}
            func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, any Error> {
                AsyncThrowingStream { $0.finish() }
            }
        }
        struct ParallelFilling: SlotFilling {
            let modelID = "parallel"
            let displayName = "Parallel"
            let capabilities: [String] = []
            let maximumConcurrentGenerations = 2
            func prewarm() async throws {}
            func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, any Error> {
                AsyncThrowingStream { $0.finish() }
            }
        }

        #expect(DefaultFilling().maximumConcurrentGenerations == 1)
        #expect(ParallelFilling().maximumConcurrentGenerations == 2)
    }

    @Test func oneActiveAndThreeFIFOReservationsRefuseTheFifth() async throws {
        let admission = SlotAdmission(eventSink: { _ in })
        let keys = (0 ..< 5).map { _ in
            SlotAdmission.Key(sessionID: UUID(), generationID: UUID())
        }
        let reservations = try await (0 ..< 4).asyncMap { index in
            try await admission.reserve(keys[index])
        }

        await #expect(throws: SlotAdmission.AdmissionError.waitingRoomFull) {
            try await admission.reserve(keys[4])
        }
        let duplicate = try await admission.reserve(keys[1])
        #expect(duplicate == reservations[1])
        var counters = await admission.counters
        #expect(counters == .init(active: 1, waiting: 3, admitted: 4, refused: 1))

        var lease = try await admission.acquire(reservations[0])
        for index in 1 ..< 4 {
            let task = Task { try await admission.acquire(reservations[index]) }
            await admission.release(lease, outcome: .complete)
            lease = try await task.value
            counters = await admission.counters
            #expect(counters.active == 1)
            #expect(counters.waiting == 3 - index)
        }
        await admission.release(lease, outcome: .complete)
        let released = await slotEventually {
            let snapshot = await admission.counters
            return snapshot.active == 0 && snapshot.waiting == 0
        }
        #expect(released)
        counters = await admission.counters
    }

    @Test func aSessionMayHaveOnlyOneGenerationWaiting() async throws {
        let admission = SlotAdmission(eventSink: { _ in })
        let sessionID = UUID()
        let active = try await admission.reserve(.init(sessionID: sessionID, generationID: UUID()))
        _ = try await admission.reserve(.init(sessionID: sessionID, generationID: UUID()))

        await #expect(throws: SlotAdmission.AdmissionError.sessionAlreadyWaiting) {
            try await admission.reserve(.init(sessionID: sessionID, generationID: UUID()))
        }
        let counters = await admission.counters
        #expect(counters.active == 1)
        #expect(counters.waiting == 1)
        #expect(counters.refused == 1)

        let lease = try await admission.acquire(active)
        await admission.release(lease, outcome: .complete)
    }

    @Test func queuedCancellationIsRemovedAndAStaleEntryCannotTakeTheSlot() async throws {
        let admission = SlotAdmission(eventSink: { _ in })
        let first = try await admission.reserve(.init(sessionID: UUID(), generationID: UUID()))
        let stale = try await admission.reserve(.init(sessionID: UUID(), generationID: UUID()))
        let next = try await admission.reserve(.init(sessionID: UUID(), generationID: UUID()))
        let firstLease = try await admission.acquire(first)
        let staleTask = Task { try await admission.acquire(stale) }
        let nextTask = Task { try await admission.acquire(next) }
        staleTask.cancel()
        await #expect(throws: CancellationError.self) { try await staleTask.value }

        await admission.release(firstLease, outcome: .complete)
        let nextLease = try await nextTask.value
        var counters = await admission.counters
        #expect(counters.active == 1)
        #expect(counters.waiting == 0)
        #expect(counters.cancelled == 1)
        await admission.release(nextLease, outcome: .cancelled)
        counters = await admission.counters
        #expect(counters.cancelled == 2)
    }

    @Test func queuedTimeoutUsesExactCopyAndDoesNotConsumeCapacity() async throws {
        let admission = SlotAdmission(
            policy: .init(maximumWait: .milliseconds(20)),
            eventSink: { _ in }
        )
        let first = try await admission.reserve(.init(sessionID: UUID(), generationID: UUID()))
        let waiting = try await admission.reserve(.init(sessionID: UUID(), generationID: UUID()))
        let lease = try await admission.acquire(first)
        try await Task.sleep(for: .milliseconds(50))

        await #expect(throws: SlotAdmission.AdmissionError.timedOut) {
            try await admission.acquire(waiting)
        }
        #expect(SlotAdmission.AdmissionError.timedOut.description ==
            "the cluster stayed reachable, but this generation waited 120 seconds without reaching its model slot — ask again when current work finishes")
        let counters = await admission.counters
        #expect(counters.active == 1)
        #expect(counters.waiting == 0)
        #expect(counters.timedOut == 1)
        await admission.release(lease, outcome: .complete)
    }

    @Test func shutdownRejectsNewWorkAndWakesWaiters() async throws {
        let admission = SlotAdmission(eventSink: { _ in })
        let first = try await admission.reserve(.init(sessionID: UUID(), generationID: UUID()))
        let waiting = try await admission.reserve(.init(sessionID: UUID(), generationID: UUID()))
        let lease = try await admission.acquire(first)
        let waiter = Task { try await admission.acquire(waiting) }
        await admission.shutdown()
        await #expect(throws: SlotAdmission.AdmissionError.shuttingDown) { try await waiter.value }
        await #expect(throws: SlotAdmission.AdmissionError.shuttingDown) {
            try await admission.reserve(.init(sessionID: UUID(), generationID: UUID()))
        }
        await admission.release(lease, outcome: .complete)
        let counters = await admission.counters
        #expect(counters.active == 0)
        #expect(counters.waiting == 0)
        #expect(counters.refused == 1)
    }

    @Test func refusalCopyIsExactAndActionable() {
        #expect(SlotAdmission.AdmissionError.waitingRoomFull.description ==
            "the cluster is reachable, but its model slot and three-place waiting room are full — ask again when current work finishes")
        #expect(SlotAdmission.AdmissionError.sessionAlreadyWaiting.description ==
            "the cluster is reachable, but this session already has a generation waiting for its model slot — let it finish or cancel it before asking again")
    }
}

@Suite(.serialized) struct SlotAdmissionRegistryTests {
    @Test func queuedResidencyDuplicateBeginAndReattachKeepOneLease() async throws {
        let recorder = SlotReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record)
        let admission = SlotAdmission(eventSink: { _ in })
        let probe = AdmissionExecutionProbe()
        let (firstSession, _) = await registry.openSession()
        let (secondSession, _) = await registry.openSession()
        let firstID = UUID()
        let secondID = UUID()

        let (firstStream, firstEpoch, _) = try await registry.begin(
            sessionID: firstSession,
            genID: firstID,
            receiptSource: .loopback,
            admission: admission,
            events: { probe.stream("first") }
        )
        let (secondStream, secondEpoch, _) = try await registry.begin(
            sessionID: secondSession,
            genID: secondID,
            receiptSource: .privateLAN,
            admission: admission,
            events: { probe.stream("second") }
        )
        let startedOne = await slotEventually { probe.snapshot.executions == 1 }
        #expect(startedOne)
        #expect(probe.snapshot.order == ["first"])
        var counters = await admission.counters
        #expect(counters.active == 1)
        #expect(counters.waiting == 1)

        await registry.detach(sessionID: firstSession, genID: firstID, epoch: firstEpoch)
        let (firstReattached, _, _) = try await registry.attach(
            sessionID: firstSession,
            genID: firstID,
            fromSeq: nil
        )
        counters = await admission.counters
        #expect(counters.active == 1)
        #expect(counters.waiting == 1)
        #expect(probe.snapshot.executions == 1)

        let (duplicate, duplicateEpoch, _) = try await registry.begin(
            sessionID: secondSession,
            genID: secondID,
            receiptSource: .publicNetwork,
            admission: admission,
            events: {
                Issue.record("duplicate begin executed another filling")
                return probe.stream("duplicate")
            }
        )
        await registry.detach(sessionID: secondSession, genID: secondID, epoch: duplicateEpoch)
        let (reattached, _, _) = try await registry.attach(
            sessionID: secondSession,
            genID: secondID,
            fromSeq: nil
        )
        counters = await admission.counters
        #expect(counters.active == 1)
        #expect(counters.waiting == 1)
        #expect(probe.snapshot.executions == 1)

        probe.finish("first")
        _ = await slotTerminal(firstReattached)
        let promoted = await slotEventually { probe.snapshot.order == ["first", "second"] }
        #expect(promoted)
        #expect(probe.snapshot.peak == 1)
        probe.finish("second")
        _ = await slotTerminal(reattached)
        let released = await slotEventually {
            let snapshot = await admission.counters
            return snapshot.active == 0 && snapshot.waiting == 0
        }
        #expect(released)

        let (replayOnly, _, _) = try await registry.attach(
            sessionID: secondSession,
            genID: secondID,
            fromSeq: nil
        )
        _ = await slotTerminal(replayOnly)
        counters = await admission.counters
        #expect(counters.active == 0)
        #expect(counters.waiting == 0)
        #expect(probe.snapshot.executions == 2)

        let accepted = recorder.receipts.compactMap { receipt -> UUID? in
            if case .accepted(_, let genID, _) = receipt { return genID }
            return nil
        }
        #expect(accepted == [firstID, secondID])
        #expect(recorder.receipts.count == 4)
        _ = firstStream
        _ = secondStream
        _ = duplicate
        _ = secondEpoch
    }

    @Test func roomFullRefusalCreatesNoResidentRecordOrReceipt() async throws {
        let recorder = SlotReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record)
        let admission = SlotAdmission(eventSink: { _ in })
        let probe = AdmissionExecutionProbe()
        var sessions: [(id: UUID, token: String)] = []
        for _ in 0 ..< 5 {
            let opened = await registry.openSession()
            sessions.append((opened.sessionID, opened.token))
        }
        var streams: [AsyncStream<Ev>] = []
        for index in 0 ..< 4 {
            let result = try await registry.begin(
                sessionID: sessions[index].id,
                genID: UUID(),
                receiptSource: .loopback,
                admission: admission,
                events: { probe.stream("\(index)") }
            )
            streams.append(result.stream)
        }

        await #expect(throws: SlotAdmission.AdmissionError.waitingRoomFull) {
            _ = try await registry.begin(
                sessionID: sessions[4].id,
                genID: UUID(),
                receiptSource: .loopback,
                admission: admission,
                events: { probe.stream("refused") }
            )
        }
        let status = try await registry.resumeStatus(
            sessionID: sessions[4].id,
            token: sessions[4].token
        )
        #expect(status.isEmpty)
        #expect(recorder.receipts.count == 4)
        let activeBegan = await slotEventually { probe.snapshot.executions == 1 }
        #expect(activeBegan)

        for index in 0 ..< 4 {
            let began = await slotEventually { probe.snapshot.executions == index + 1 }
            #expect(began)
            probe.finish("\(index)")
            _ = await slotTerminal(streams[index])
        }
    }

    @Test func queuedTimeoutTerminatesWithoutExecutingTheFilling() async throws {
        let registry = SessionRegistry()
        let admission = SlotAdmission(
            policy: .init(maximumWait: .milliseconds(50)),
            eventSink: { _ in }
        )
        let probe = AdmissionExecutionProbe()
        let (firstSession, _) = await registry.openSession()
        let (secondSession, _) = await registry.openSession()
        let firstGenID = UUID()
        let (first, firstEpoch, _) = try await registry.begin(
            sessionID: firstSession,
            genID: firstGenID,
            receiptSource: .loopback,
            admission: admission,
            events: { probe.stream("first") }
        )
        let (waiting, _, _) = try await registry.begin(
            sessionID: secondSession,
            genID: UUID(),
            receiptSource: .loopback,
            admission: admission,
            events: { probe.stream("timed-out") }
        )
        let terminal = try #require(await slotTerminal(waiting))
        guard case .finished(.error(let message)) = terminal.event else {
            Issue.record("queued timeout did not become a generation error")
            return
        }
        #expect(message == SlotAdmission.AdmissionError.timedOut.description)
        #expect(probe.snapshot.order == ["first"])
        let counters = await admission.counters
        #expect(counters.timedOut == 1)
        await registry.cancel(sessionID: firstSession, genID: firstGenID, epoch: firstEpoch)
        _ = first
    }

    @Test func aFillingErrorReleasesExactlyOnceAndPromotesTheNextGeneration() async throws {
        let registry = SessionRegistry()
        let admission = SlotAdmission(eventSink: { _ in })
        let probe = AdmissionExecutionProbe()
        let (firstSession, _) = await registry.openSession()
        let (secondSession, _) = await registry.openSession()
        let (first, _, _) = try await registry.begin(
            sessionID: firstSession,
            genID: UUID(),
            receiptSource: .loopback,
            admission: admission,
            events: { probe.stream("error") }
        )
        let (second, _, _) = try await registry.begin(
            sessionID: secondSession,
            genID: UUID(),
            receiptSource: .loopback,
            admission: admission,
            events: { probe.stream("next") }
        )
        let began = await slotEventually { probe.snapshot.order == ["error"] }
        #expect(began)
        probe.finish("error", reason: .error("deliberate"))
        let firstTerminal = try #require(await slotTerminal(first))
        guard case .finished(.error(let message)) = firstTerminal.event else {
            Issue.record("filling error did not cross as an error terminal")
            return
        }
        #expect(message == "deliberate")
        let promoted = await slotEventually { probe.snapshot.order == ["error", "next"] }
        #expect(promoted)
        #expect(probe.snapshot.peak == 1)
        probe.finish("next")
        _ = await slotTerminal(second)
        let released = await slotEventually {
            let counters = await admission.counters
            return counters.active == 0
        }
        #expect(released)
    }

    @Test func aSecondWaiterFromOneSessionIsRefusedWithoutResidency() async throws {
        let recorder = SlotReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record)
        let admission = SlotAdmission(eventSink: { _ in })
        let probe = AdmissionExecutionProbe()
        let (sessionID, token) = await registry.openSession()
        var streams: [AsyncStream<Ev>] = []
        for index in 0 ..< 2 {
            let result = try await registry.begin(
                sessionID: sessionID,
                genID: UUID(),
                receiptSource: .loopback,
                admission: admission,
                events: { probe.stream("\(index)") }
            )
            streams.append(result.stream)
        }

        await #expect(throws: SlotAdmission.AdmissionError.sessionAlreadyWaiting) {
            _ = try await registry.begin(
                sessionID: sessionID,
                genID: UUID(),
                receiptSource: .loopback,
                admission: admission,
                events: { probe.stream("refused") }
            )
        }
        let status = try await registry.resumeStatus(sessionID: sessionID, token: token)
        #expect(status.count == 2)
        #expect(recorder.receipts.count == 2)
        let activeStarted = await slotEventually { probe.snapshot.order == ["0"] }
        #expect(activeStarted)

        probe.finish("0")
        _ = await slotTerminal(streams[0])
        let promoted = await slotEventually { probe.snapshot.order == ["0", "1"] }
        #expect(promoted)
        probe.finish("1")
        _ = await slotTerminal(streams[1])
    }

    @Test func cancellingAQueuedGenerationFreesItsSessionsPlaceBeforeTheTerminal() async throws {
        let recorder = SlotReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record)
        let admission = SlotAdmission(eventSink: { _ in })
        let probe = AdmissionExecutionProbe()
        let (activeSession, _) = await registry.openSession()
        let (waitingSession, _) = await registry.openSession()
        let activeID = UUID()
        let cancelledID = UUID()
        let replacementID = UUID()

        let (active, _, _) = try await registry.begin(
            sessionID: activeSession,
            genID: activeID,
            receiptSource: .loopback,
            admission: admission,
            events: { probe.stream("active") }
        )
        let (waiting, waitingEpoch, _) = try await registry.begin(
            sessionID: waitingSession,
            genID: cancelledID,
            receiptSource: .loopback,
            admission: admission,
            events: { probe.stream("must-not-execute") }
        )
        try #require(await slotEventually { probe.snapshot.order == ["active"] })
        #expect((await admission.counters).waiting == 1)

        await registry.cancel(
            sessionID: waitingSession,
            genID: cancelledID,
            epoch: waitingEpoch,
            admission: admission
        )
        let cancelled = try #require(await slotTerminal(waiting))
        #expect(cancelled.event == .finished(.cancelled))

        // No yield or retry belongs between the visible terminal and this
        // begin. It is the regression: the old waiter must already be gone.
        let (replacement, _, _) = try await registry.begin(
            sessionID: waitingSession,
            genID: replacementID,
            receiptSource: .loopback,
            admission: admission,
            events: { probe.stream("replacement") }
        )
        var counters = await admission.counters
        #expect(counters.waiting == 1)
        #expect(counters.cancelled == 1)
        #expect(probe.snapshot.order == ["active"])

        probe.finish("active")
        _ = await slotTerminal(active)
        try #require(await slotEventually {
            probe.snapshot.order == ["active", "replacement"]
        })
        probe.finish("replacement")
        _ = await slotTerminal(replacement)
        try #require(await slotEventually {
            let snapshot = await admission.counters
            return snapshot.active == 0 && snapshot.waiting == 0
        })
        counters = await admission.counters
        #expect(counters.cancelled == 1)
        #expect(!probe.snapshot.order.contains("must-not-execute"))

        let receipts = recorder.receipts
        let cancelledTerminal = try #require(receipts.firstIndex { receipt in
            if case .terminal(_, let genID, _, .cancelled) = receipt {
                return genID == cancelledID
            }
            return false
        })
        let replacementAccepted = try #require(receipts.firstIndex { receipt in
            if case .accepted(_, let genID, _) = receipt {
                return genID == replacementID
            }
            return false
        })
        #expect(cancelledTerminal < replacementAccepted)
    }

    @Test func queuedCancellationCrossingReattachCannotOrphanTheGeneration() async throws {
        let recorder = SlotReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record)
        let barrier = QueuedCancellationBarrier()
        let admission = SlotAdmission(
            eventSink: { _ in },
            queuedCancellationDidCommit: { await barrier.pauseAfterCommit() }
        )
        let probe = AdmissionExecutionProbe()
        let (activeSession, _) = await registry.openSession()
        let (waitingSession, waitingToken) = await registry.openSession()
        let activeID = UUID()
        let waitingID = UUID()

        let (active, _, _) = try await registry.begin(
            sessionID: activeSession,
            genID: activeID,
            receiptSource: .loopback,
            admission: admission,
            events: { probe.stream("active") }
        )
        let (_, waitingEpoch, _) = try await registry.begin(
            sessionID: waitingSession,
            genID: waitingID,
            receiptSource: .loopback,
            admission: admission,
            events: { probe.stream("must-not-execute") }
        )
        try #require(await slotEventually { probe.snapshot.order == ["active"] })
        #expect((await admission.counters).waiting == 1)

        let cancellation = Task {
            await registry.cancel(
                sessionID: waitingSession,
                genID: waitingID,
                epoch: waitingEpoch,
                admission: admission
            )
        }
        await barrier.waitUntilCommitted()

        // The admission reservation is gone while the cancelling registry
        // call is suspended. Reattach now bumps the epoch and replaces the
        // live continuation at the exact point that used to orphan it.
        let (reattached, reattachedEpoch, _) = try await registry.attach(
            sessionID: waitingSession,
            genID: waitingID,
            fromSeq: nil
        )
        #expect(reattachedEpoch > waitingEpoch)
        let terminalTask = Task { await slotTerminal(reattached) }

        await barrier.resumeCancellation()
        await cancellation.value
        let terminalRecorded = await slotEventually {
            recorder.receipts.contains { receipt in
                if case .terminal(_, let genID, _, .cancelled) = receipt {
                    return genID == waitingID
                }
                return false
            }
        }
        #expect(terminalRecorded)
        if !terminalRecorded { terminalTask.cancel() }
        let terminal = await terminalTask.value
        #expect(terminal?.event == .finished(.cancelled))

        let statuses = try await registry.resumeStatus(
            sessionID: waitingSession,
            token: waitingToken
        )
        let status = try #require(statuses.first { $0.genID == waitingID })
        #expect(status.state == .cancelled)
        #expect(status.eventsIssued == 1)
        var counters = await admission.counters
        #expect(counters.active == 1)
        #expect(counters.waiting == 0)
        #expect(counters.cancelled == 1)
        #expect(!probe.snapshot.order.contains("must-not-execute"))

        let waitingReceipts = recorder.receipts.filter { receipt in
            switch receipt {
            case .accepted(_, let genID, _), .terminal(_, let genID, _, _):
                genID == waitingID
            }
        }
        #expect(waitingReceipts.count == 2)

        probe.finish("active")
        _ = await slotTerminal(active)
        try #require(await slotEventually {
            let snapshot = await admission.counters
            return snapshot.active == 0 && snapshot.waiting == 0
        })
        counters = await admission.counters
        #expect(counters.cancelled == 1)
    }
}

@Suite(.serialized) struct SlotAdmissionWireTests {
    @Test func overloadIsClusterBusyAndCancellationPromotesFIFOWithoutRoadFailure() async throws {
        let ca = try ClusterCA.create(commonName: "Reach Slot Admission CA")
        let server = try ca.issueServer(
            commonName: "localhost",
            dnsNames: ["localhost"],
            ipAddresses: [[127, 0, 0, 1]]
        )
        let client = try ca.issueClient(commonName: "slot-client", uri: "reach://device/slot-client")
        let serverIdentity = try IdentityMaterializer.materialize(
            server,
            label: "reach-slot-server-\(UUID())"
        )
        let clientIdentity = try IdentityMaterializer.materialize(
            client,
            label: "reach-slot-client-\(UUID())"
        )
        let boxes = [IdentityBox(serverIdentity), IdentityBox(clientIdentity)]
        defer { for box in boxes { KeychainIdentity.remove(identity: box.identity) } }
        let caCertificate = try IdentityStore.certificate(fromDER: ca.certificateDER())

        let recorder = SlotReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record)
        let probe = AdmissionExecutionProbe()
        var config = DaemonConfig()
        config.port = TestPorts.port(47469)
        config.clusterName = "slot-admission"
        let daemon = Daemon(
            config: config,
            filling: HoldingSlotFilling(probe: probe),
            identity: .init(identity: serverIdentity, caCertificate: caCertificate),
            registry: registry
        )
        try await daemon.start(advertise: false)
        defer { Task { await daemon.stop() } }

        func makeDialer() -> QUICDialer {
            QUICDialer(
                endpoint: .hostPort(
                    host: "127.0.0.1",
                    port: .init(rawValue: TestPorts.port(47469))!
                ),
                parameters: .reachQUIC(options: TLSBuilder.clientOptions(
                    alpn: Wire.alpn,
                    identity: clientIdentity,
                    serverTrustRoots: [caCertificate]
                ))
            )
        }

        func openSession(_ index: Int) async throws -> (QUICDialer, QUICStream, SessionOpened) {
            let dialer = makeDialer()
            let control = try await dialer.openStream(timeout: 45)
            var frames = control.frames.makeAsyncIterator()
            try await control.send(Hello(client: "slot-\(index)"))
            _ = try (try #require(try await frames.next())).decode(HelloAck.self)
            try await control.send(SessionOpen(modelID: "holding-slot"))
            let opened = try (try #require(try await frames.next())).decode(SessionOpened.self)
            return (dialer, control, opened)
        }

        var dialers: [QUICDialer] = []
        var controls: [QUICStream] = []
        var sessions: [SessionOpened] = []
        for index in 0 ..< 5 {
            let (dialer, control, opened) = try await openSession(index)
            dialers.append(dialer)
            controls.append(control)
            sessions.append(opened)
        }

        let generationIDs = (0 ..< 5).map { _ in UUID() }
        let requests = (0 ..< 5).map { _ in
            WireGenerationRequest(id: UUID(), transcript: Transcript())
        }
        var generationStreams: [QUICStream] = []

        // Establish the active request before any waiter exists. Separate
        // QUIC streams do not promise that sequential sends are delivered to
        // the daemon in send order, so using array index zero as "active"
        // without this gate made the cancellation half nondeterministic.
        let activeStream = try await dialers[0].openStream(timeout: 45)
        try await activeStream.send(GenerateBegin(
            sessionID: sessions[0].sessionID,
            genID: generationIDs[0],
            request: requests[0]
        ))
        generationStreams.append(activeStream)
        try #require(await slotEventually(attempts: 2_000) {
            probe.snapshot.order == [requests[0].id.uuidString]
        })

        // Admit each waiter before sending the next so the test asserts the
        // actor's FIFO contract rather than Network.framework scheduling.
        for index in 1 ..< 4 {
            let stream = try await dialers[index].openStream(timeout: 45)
            try await stream.send(GenerateBegin(
                sessionID: sessions[index].sessionID,
                genID: generationIDs[index],
                request: requests[index]
            ))
            generationStreams.append(stream)
            try #require(await slotEventually(attempts: 2_000) {
                recorder.receipts.compactMap { receipt -> UUID? in
                    if case .accepted(_, let genID, _) = receipt { return genID }
                    return nil
                } == Array(generationIDs.prefix(index + 1))
            })
        }
        // This is an end-to-end QUIC assertion, not an actor micro-benchmark.
        // A full suite can leave Network.framework callbacks behind other
        // independent 10-second budget tests, so wait on the state transition
        // with a bounded network-scale window instead of assuming an idle-host
        // 1.5-second scheduler window. The focused actor tests retain the
        // tighter default.
        #expect(probe.snapshot.executions == 1)
        #expect(probe.snapshot.peak == 1)

        let refusedStream = try await dialers[4].openStream(timeout: 45)
        defer { refusedStream.cancel() }
        try await refusedStream.send(GenerateBegin(
            sessionID: sessions[4].sessionID,
            genID: generationIDs[4],
            request: requests[4]
        ))
        var refusedFrames = refusedStream.frames.makeAsyncIterator()
        let refusal = try (try #require(try await refusedFrames.next())).decode(ErrorFrame.self)
        #expect(refusal.code == "cluster-busy")
        #expect(refusal.message == SlotAdmission.AdmissionError.waitingRoomFull.description)
        #expect(recorder.receipts.compactMap { receipt -> UUID? in
            if case .accepted(_, let genID, _) = receipt { return genID }
            return nil
        } == Array(generationIDs.prefix(4)))

        try await generationStreams[0].send(GenerateCancel(genID: generationIDs[0]))
        for index in 1 ..< 4 {
            let promoted = await slotEventually(attempts: 2_000) {
                probe.snapshot.executions == index + 1
            }
            #expect(promoted)
            #expect(probe.snapshot.peak == 1)
            probe.finish(requests[index].id.uuidString)
        }
        let terminalsArrived = await slotEventually(attempts: 2_000) {
            recorder.receipts.reduce(into: 0) { count, receipt in
                if case .terminal = receipt { count += 1 }
            } == 4
        }
        #expect(terminalsArrived)
        #expect(!recorder.receipts.contains { receipt in
            if case .accepted(_, let genID, _) = receipt { return genID == generationIDs[4] }
            return false
        })

        // `cluster-busy` is a service refusal, not a road failure. The same
        // authenticated session and dialer must remain usable once capacity
        // returns instead of forcing ReachKit onto another road or session.
        let recoveredID = UUID()
        let recoveredRequest = WireGenerationRequest(id: UUID(), transcript: Transcript())
        let recoveredStream = try await dialers[4].openStream(timeout: 45)
        try await recoveredStream.send(GenerateBegin(
            sessionID: sessions[4].sessionID,
            genID: recoveredID,
            request: recoveredRequest
        ))
        let recoveredExecution = await slotEventually(attempts: 2_000) {
            probe.snapshot.executions == 5
        }
        #expect(recoveredExecution)
        probe.finish(recoveredRequest.id.uuidString)
        var recoveredFrames = recoveredStream.frames.makeAsyncIterator()
        var recoveredComplete = false
        while let raw = try await recoveredFrames.next() {
            guard raw.type == .ev else { continue }
            let event = try raw.decode(Ev.self)
            if case .finished(.complete) = event.event {
                recoveredComplete = true
                break
            }
        }
        #expect(recoveredComplete)
        #expect(recorder.receipts.contains { receipt in
            if case .accepted(_, let genID, _) = receipt { return genID == recoveredID }
            return false
        })
        recoveredStream.cancel()

        for stream in generationStreams { stream.cancel() }
        for control in controls { control.cancel() }
    }
}

private extension Collection {
    func asyncMap<T: Sendable>(
        _ transform: (Element) async throws -> T
    ) async rethrows -> [T] {
        var values: [T] = []
        for element in self { values.append(try await transform(element)) }
        return values
    }
}
