import Foundation

/// Volatile provider admission for public generations.
///
/// A reservation is keyed by session and generation so retransmitted
/// `GenerateBegin` frames are idempotent. The reservation becomes a lease
/// before any model work begins, and that single lease covers every internal
/// pass until the generation reaches a wire terminal.
package actor SlotAdmission {
    package struct Policy: Sendable, Equatable {
        package var capacity: Int
        package var waitingRoomCapacity: Int
        package var maximumWait: Duration

        package init(
            capacity: Int = 1,
            waitingRoomCapacity: Int = 3,
            maximumWait: Duration = .seconds(120)
        ) {
            self.capacity = max(1, capacity)
            self.waitingRoomCapacity = max(0, waitingRoomCapacity)
            self.maximumWait = maximumWait
        }
    }

    package struct Key: Sendable, Hashable {
        package var sessionID: UUID
        package var generationID: UUID

        package init(sessionID: UUID, generationID: UUID) {
            self.sessionID = sessionID
            self.generationID = generationID
        }
    }

    package struct Reservation: Sendable, Hashable {
        fileprivate var id: UUID
        package var key: Key
    }

    package struct Lease: Sendable, Hashable {
        fileprivate var id: UUID
        package var key: Key
    }

    package enum AdmissionError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
        case waitingRoomFull
        case sessionAlreadyWaiting
        case timedOut
        case shuttingDown

        package var description: String {
            switch self {
            case .waitingRoomFull:
                "the cluster is reachable, but its model slot and three-place waiting room are full — ask again when current work finishes"
            case .sessionAlreadyWaiting:
                "the cluster is reachable, but this session already has a generation waiting for its model slot — let it finish or cancel it before asking again"
            case .timedOut:
                "the cluster stayed reachable, but this generation waited 120 seconds without reaching its model slot — ask again when current work finishes"
            case .shuttingDown:
                "the cluster stopped while this generation was waiting for its model slot"
            }
        }

        package var errorDescription: String? { description }

        package var isImmediateRefusal: Bool {
            switch self {
            case .waitingRoomFull, .sessionAlreadyWaiting: true
            case .timedOut, .shuttingDown: false
            }
        }
    }

    package enum ReleaseOutcome: Sendable, Equatable {
        case complete
        case cancelled
        case error

        fileprivate var logWord: String {
            switch self {
            case .complete: "completion"
            case .cancelled: "cancellation"
            case .error: "error"
            }
        }
    }

    package struct Counters: Sendable, Equatable {
        package var active: Int = 0
        package var waiting: Int = 0
        package var admitted: UInt64 = 0
        package var refused: UInt64 = 0
        package var cancelled: UInt64 = 0
        package var timedOut: UInt64 = 0
    }

    package typealias EventSink = @Sendable (String) -> Void
    package typealias QueuedCancellationDidCommit = @Sendable () async -> Void

    private enum Phase: Equatable {
        case ready
        case waiting
        case leased

        var isWaiting: Bool {
            if case .waiting = self { return true }
            return false
        }
    }

    private struct Entry {
        var reservation: Reservation
        var phase: Phase
        var enqueuedAt: ContinuousClock.Instant?
        var continuation: CheckedContinuation<Lease, any Error>?
        var timeout: Task<Void, Never>?
    }

    private let policy: Policy
    private let eventSink: EventSink
    private let queuedCancellationDidCommit: QueuedCancellationDidCommit
    private let clock = ContinuousClock()
    private var entries: [UUID: Entry] = [:]
    private var reservationByKey: [Key: UUID] = [:]
    private var terminalErrors: [UUID: AdmissionError] = [:]
    private var queue: [UUID] = []
    private var admitted: UInt64 = 0
    private var refused: UInt64 = 0
    private var cancelled: UInt64 = 0
    private var timedOut: UInt64 = 0
    private var shuttingDown = false

    package init(
        policy: Policy = Policy(),
        eventSink: @escaping EventSink = { Log.info($0) },
        queuedCancellationDidCommit: @escaping QueuedCancellationDidCommit = {}
    ) {
        self.policy = policy
        self.eventSink = eventSink
        self.queuedCancellationDidCommit = queuedCancellationDidCommit
    }

    package var startupMessage: String {
        let noun = policy.capacity == 1 ? "generation" : "generations"
        return "provider admission ready: \(policy.capacity) active \(noun), \(policy.waitingRoomCapacity)-place FIFO waiting room, \(Self.seconds(policy.maximumWait))-second deadline"
    }

    /// Idempotently reserves either an executing place or a FIFO waiting
    /// place. Refusals happen here, before the registry creates residency or
    /// emits a generation receipt.
    package func reserve(_ key: Key) throws -> Reservation {
        if let id = reservationByKey[key], let entry = entries[id] {
            return entry.reservation
        }
        guard !shuttingDown else {
            refused += 1
            eventSink("provider admission refused work because the daemon is stopping")
            throw AdmissionError.shuttingDown
        }

        let active = activeCount
        let reservation = Reservation(id: UUID(), key: key)
        if active < policy.capacity {
            entries[reservation.id] = Entry(reservation: reservation, phase: .ready)
            reservationByKey[key] = reservation.id
            admitted += 1
            eventSink("provider admission gave a generation the active slot; active=\(active + 1) waiting=\(queue.count)")
            return reservation
        }

        if entries.values.contains(where: {
            $0.reservation.key.sessionID == key.sessionID && $0.phase.isWaiting
        }) {
            refused += 1
            eventSink("provider admission refused a second waiter from one session; active=\(active) waiting=\(queue.count)")
            throw AdmissionError.sessionAlreadyWaiting
        }
        guard queue.count < policy.waitingRoomCapacity else {
            refused += 1
            eventSink("provider admission refused work because the waiting room is full; active=\(active) waiting=\(queue.count)")
            throw AdmissionError.waitingRoomFull
        }

        var entry = Entry(
            reservation: reservation,
            phase: .waiting,
            enqueuedAt: clock.now
        )
        let maximumWait = policy.maximumWait
        entry.timeout = Task { [weak self] in
            try? await Task.sleep(for: maximumWait)
            guard !Task.isCancelled else { return }
            await self?.expire(reservation.id)
        }
        entries[reservation.id] = entry
        reservationByKey[key] = reservation.id
        queue.append(reservation.id)
        admitted += 1
        eventSink("provider admission queued a generation at position \(queue.count); active=\(active) waiting=\(queue.count)")
        return reservation
    }

    /// Waits until the reservation owns provider capacity. Model preparation
    /// must not be invoked before this returns.
    package func acquire(_ reservation: Reservation) async throws -> Lease {
        guard let entry = entries[reservation.id], entry.reservation == reservation else {
            if let error = terminalErrors.removeValue(forKey: reservation.id) { throw error }
            if shuttingDown { throw AdmissionError.shuttingDown }
            throw CancellationError()
        }
        switch entry.phase {
        case .ready:
            entries[reservation.id]!.phase = .leased
            return Lease(id: reservation.id, key: reservation.key)
        case .leased:
            return Lease(id: reservation.id, key: reservation.key)
        case .waiting:
            return try await withTaskCancellationHandler {
                try await waitForLease(reservation.id)
            } onCancel: {
                Task { await self.cancelWaitingReservation(reservation.id) }
            }
        }
    }

    /// Removes a still-queued reservation before its generation publishes a
    /// cancellation terminal. The daemon awaits this package-only path so an
    /// immediate replacement from the same session cannot observe the old
    /// waiter after the person has already seen it finish as cancelled.
    @discardableResult
    package func cancelQueued(_ key: Key) async -> Bool {
        guard let id = reservationByKey[key],
              let entry = entries[id],
              entry.phase == .waiting
        else { return false }
        cancelWaitingReservation(id)
        // Production uses the empty callback. Tests can suspend exactly after
        // the irreversible removal so registry re-attachment races are proved
        // deterministically rather than sampled from scheduler luck.
        await queuedCancellationDidCommit()
        return true
    }

    /// Releases provider capacity exactly once and promotes the oldest live
    /// waiter. Stale queue entries are skipped rather than consuming a slot.
    package func release(_ lease: Lease, outcome: ReleaseOutcome) {
        guard let entry = entries[lease.id],
              entry.reservation.key == lease.key,
              entry.phase == .leased || entry.phase == .ready
        else { return }
        remove(lease.id)
        if outcome == .cancelled { cancelled += 1 }
        promote()
        eventSink("provider admission released the active slot after \(outcome.logWord); active=\(activeCount) waiting=\(queue.count)")
    }

    /// Reverses a reservation when the registry cannot create the promised
    /// resident record. This is not a user cancellation and does not alter
    /// the cancellation counter.
    package func abandon(_ reservation: Reservation) {
        guard let entry = entries[reservation.id], entry.reservation == reservation else { return }
        let occupiedCapacity = entry.phase == .ready || entry.phase == .leased
        remove(reservation.id)
        if occupiedCapacity { promote() }
    }

    package func shutdown() {
        guard !shuttingDown else { return }
        shuttingDown = true
        let pending = entries.values.filter { $0.phase != .leased }
        for entry in pending {
            if entry.continuation == nil {
                terminalErrors[entry.reservation.id] = .shuttingDown
            }
            entry.continuation?.resume(throwing: AdmissionError.shuttingDown)
            remove(entry.reservation.id)
        }
        eventSink("provider admission shut down; active=\(activeCount) waiting=\(queue.count)")
    }

    package var counters: Counters {
        Counters(
            active: activeCount,
            waiting: queue.count,
            admitted: admitted,
            refused: refused,
            cancelled: cancelled,
            timedOut: timedOut
        )
    }

    private var activeCount: Int {
        entries.values.reduce(into: 0) { count, entry in
            if entry.phase == .ready || entry.phase == .leased { count += 1 }
        }
    }

    private func waitForLease(_ id: UUID) async throws -> Lease {
        try await withCheckedThrowingContinuation { continuation in
            guard var entry = entries[id], entry.phase == .waiting else {
                if let error = terminalErrors.removeValue(forKey: id) {
                    continuation.resume(throwing: error)
                    return
                }
                if shuttingDown {
                    continuation.resume(throwing: AdmissionError.shuttingDown)
                    return
                }
                continuation.resume(throwing: CancellationError())
                return
            }
            entry.continuation = continuation
            entries[id] = entry
        }
    }

    private func cancelWaitingReservation(_ id: UUID) {
        guard let entry = entries[id], entry.phase == .waiting else { return }
        entry.continuation?.resume(throwing: CancellationError())
        remove(id)
        cancelled += 1
        eventSink("provider admission cancelled queued work; active=\(activeCount) waiting=\(queue.count)")
    }

    private func expire(_ id: UUID) {
        guard let entry = entries[id], entry.phase == .waiting else { return }
        if entry.continuation == nil { terminalErrors[id] = .timedOut }
        entry.continuation?.resume(throwing: AdmissionError.timedOut)
        remove(id)
        timedOut += 1
        eventSink("provider admission timed out queued work; active=\(activeCount) waiting=\(queue.count)")
    }

    private func promote() {
        guard !shuttingDown, activeCount < policy.capacity else { return }
        while !queue.isEmpty, activeCount < policy.capacity {
            let id = queue.removeFirst()
            guard var entry = entries[id], entry.phase == .waiting else { continue }
            entry.timeout?.cancel()
            entry.timeout = nil
            let waited = entry.enqueuedAt.map { Self.seconds($0.duration(to: clock.now)) } ?? "0.000"
            entry.enqueuedAt = nil
            if let continuation = entry.continuation {
                entry.continuation = nil
                entry.phase = .leased
                entries[id] = entry
                continuation.resume(returning: Lease(id: id, key: entry.reservation.key))
            } else {
                entry.phase = .ready
                entries[id] = entry
            }
            eventSink("provider admission promoted the oldest waiter after \(waited) seconds; active=\(activeCount) waiting=\(queue.count)")
        }
    }

    private func remove(_ id: UUID) {
        guard let entry = entries.removeValue(forKey: id) else { return }
        entry.timeout?.cancel()
        reservationByKey[entry.reservation.key] = nil
        queue.removeAll { $0 == id }
    }

    private static func seconds(_ duration: Duration) -> String {
        let components = duration.components
        let value = Double(components.seconds) + Double(components.attoseconds) / 1e18
        return String(format: "%.3f", value)
    }
}
