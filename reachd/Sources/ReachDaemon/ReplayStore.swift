import Foundation
import ReachWire

/// Volatile, exact-byte replay storage for generation events.
///
/// The store owns only frames that have not been cumulatively acknowledged.
/// Its byte counters are the encoded v0 envelope bytes that would be written
/// to QUIC, not an estimate of Swift object or string storage. Nothing here is
/// persisted: daemon death deliberately loses every window.
package struct ReplayStore: Sendable {
    package struct Key: Hashable, Sendable {
        package var sessionID: UUID
        package var generationID: UUID

        package init(sessionID: UUID, generationID: UUID) {
            self.sessionID = sessionID
            self.generationID = generationID
        }
    }

    package struct Policy: Sendable, Equatable {
        package var perGenerationBytes: Int
        package var processBytes: Int

        package init(perGenerationBytes: Int, processBytes: Int) {
            self.perGenerationBytes = max(0, perGenerationBytes)
            self.processBytes = max(0, processBytes)
        }
    }

    package enum Exhaustion: String, Sendable, Hashable {
        case perGeneration
        case processWide
    }

    package enum ReplayError: Error, Sendable, Equatable {
        case unavailable
        case corrupt
    }

    package struct AppendResult: Sendable, Equatable {
        package var stored: Bool
        /// Capacity classes this generation crossed for the first time. The
        /// caller may log these without revealing byte or cursor totals.
        package var newlyExhausted: [Exhaustion]
    }

    package struct Counters: Sendable, Equatable {
        package var currentBytes = 0
        package var highWaterBytes = 0
        package var appendedEvents = 0
        package var acknowledgedEvents = 0
        package var droppedEvents = 0
        package var capacityExhaustions = 0
        package var corruptions = 0
        package var releasedBytes = 0
    }

    private struct Entry: Sendable {
        var sequence: UInt64
        var frame: Data
    }

    private struct RemovedEntry: Sendable {
        var sequence: UInt64
        var bytes: Int
    }

    private struct Window: Sendable {
        var entries: [Entry] = []
        var head = 0
        var retainedBytes = 0
        var droppedThrough: UInt64?
        var reportedExhaustions: Set<Exhaustion> = []

        var firstSequence: UInt64? {
            head < entries.count ? entries[head].sequence : nil
        }

        var retainedEntries: ArraySlice<Entry> {
            entries[head...]
        }

        mutating func append(_ entry: Entry) {
            entries.append(entry)
            retainedBytes += entry.frame.count
        }

        mutating func popFirst() -> RemovedEntry? {
            guard head < entries.count else { return nil }
            let removed = RemovedEntry(
                sequence: entries[head].sequence,
                bytes: entries[head].frame.count
            )
            // Advancing `head` alone leaves the array owning the popped
            // payload until metadata compaction. Destroy the Data now so the
            // physical frame storage and exact-byte accounting remain equal.
            entries[head].frame = Data()
            head += 1
            retainedBytes -= removed.bytes
            compactIfNeeded()
            return removed
        }

        mutating func acknowledge(through sequence: UInt64) -> (events: Int, bytes: Int) {
            var events = 0
            var bytes = 0
            while let firstSequence, firstSequence <= sequence {
                guard let removed = popFirst() else { break }
                events += 1
                bytes += removed.bytes
            }
            return (events, bytes)
        }

        mutating func markDropped(through sequence: UInt64) {
            droppedThrough = max(droppedThrough ?? sequence, sequence)
        }

        mutating func removeAllEntries() -> Int {
            let removed = retainedBytes
            entries.removeAll(keepingCapacity: false)
            head = 0
            retainedBytes = 0
            return removed
        }

        private mutating func compactIfNeeded() {
            guard head >= 256, head * 2 >= entries.count else { return }
            entries.removeFirst(head)
            head = 0
        }
    }

    package let policy: Policy
    private var windows: [Key: Window] = [:]
    package private(set) var counters = Counters()

    package init(policy: Policy) {
        self.policy = policy
    }

    /// Stores the deterministic, complete framed representation of `event`.
    /// Capacity pressure may discard only this same generation's older
    /// entries. When that is insufficient, the new event remains live-only.
    package mutating func append(_ event: Ev, for key: Key) throws -> AppendResult {
        let frame = try FrameCodec.encode(event)
        var window = windows.removeValue(forKey: key) ?? Window()
        var encountered: Set<Exhaustion> = []

        while true {
            let exceedsGeneration = Self.wouldExceed(
                current: window.retainedBytes,
                adding: frame.count,
                limit: policy.perGenerationBytes
            )
            let exceedsProcess = Self.wouldExceed(
                current: counters.currentBytes,
                adding: frame.count,
                limit: policy.processBytes
            )
            guard exceedsGeneration || exceedsProcess else { break }

            if exceedsGeneration { encountered.insert(.perGeneration) }
            if exceedsProcess { encountered.insert(.processWide) }
            guard let removed = window.popFirst() else { break }
            window.markDropped(through: removed.sequence)
            counters.currentBytes -= removed.bytes
            counters.droppedEvents += 1
        }

        let exceedsGeneration = Self.wouldExceed(
            current: window.retainedBytes,
            adding: frame.count,
            limit: policy.perGenerationBytes
        )
        let exceedsProcess = Self.wouldExceed(
            current: counters.currentBytes,
            adding: frame.count,
            limit: policy.processBytes
        )
        if exceedsGeneration { encountered.insert(.perGeneration) }
        if exceedsProcess { encountered.insert(.processWide) }

        let stored: Bool
        if exceedsGeneration || exceedsProcess {
            window.markDropped(through: event.seq)
            counters.droppedEvents += 1
            stored = false
        } else {
            window.append(Entry(sequence: event.seq, frame: frame))
            counters.currentBytes += frame.count
            counters.highWaterBytes = max(counters.highWaterBytes, counters.currentBytes)
            counters.appendedEvents += 1
            stored = true
        }

        if !encountered.isEmpty {
            counters.capacityExhaustions += 1
        }
        let newlyExhausted = encountered
            .filter { window.reportedExhaustions.insert($0).inserted }
            .sorted { $0.rawValue < $1.rawValue }
        windows[key] = window
        return AppendResult(stored: stored, newlyExhausted: newlyExhausted)
    }

    /// Returns a whole replay or refuses. Every stored frame is decoded and
    /// checked against its index at the moment it crosses back into serving.
    package mutating func replay(for key: Key, after sequence: UInt64?) throws -> [Ev] {
        guard let window = windows[key] else { return [] }
        let whole = sequence.map { held in
            window.droppedThrough.map { held >= $0 } ?? true
        } ?? (window.droppedThrough == nil)
        guard whole else { throw ReplayError.unavailable }

        do {
            return try window.retainedEntries.compactMap { entry in
                guard sequence.map({ entry.sequence > $0 }) ?? true else { return nil }
                let decoded = try Self.decode(entry.frame)
                guard decoded.seq == entry.sequence else { throw ReplayError.corrupt }
                return decoded
            }
        } catch {
            invalidateCorruptWindow(for: key)
            throw ReplayError.corrupt
        }
    }

    package mutating func acknowledge(for key: Key, through sequence: UInt64) {
        guard var window = windows.removeValue(forKey: key) else { return }
        let removed = window.acknowledge(through: sequence)
        counters.currentBytes -= removed.bytes
        counters.acknowledgedEvents += removed.events
        counters.releasedBytes += removed.bytes
        windows[key] = window
    }

    /// Marks an event that could not itself be encoded. Live delivery may use
    /// a small replacement terminal, but no future attachment may infer that
    /// the absent sequence was acknowledged.
    package mutating func recordLiveOnly(sequence: UInt64, for key: Key) {
        var window = windows.removeValue(forKey: key) ?? Window()
        window.markDropped(through: sequence)
        counters.droppedEvents += 1
        windows[key] = window
    }

    package mutating func remove(_ key: Key) {
        guard let window = windows.removeValue(forKey: key) else { return }
        counters.currentBytes -= window.retainedBytes
        counters.releasedBytes += window.retainedBytes
    }

    package mutating func removeAll() {
        counters.releasedBytes += counters.currentBytes
        counters.currentBytes = 0
        windows.removeAll(keepingCapacity: false)
    }

    package func retainedBytes(for key: Key) -> Int {
        windows[key]?.retainedBytes ?? 0
    }

    /// Test-only backing-storage invariant. Tombstoned metadata may remain
    /// until compaction, but it must own no encoded frame payload.
    package var physicallyOwnedFrameBytesForTesting: Int {
        windows.values.reduce(into: 0) { total, window in
            total += window.entries.reduce(into: 0) { $0 += $1.frame.count }
        }
    }

    package func droppedThrough(for key: Key) -> UInt64? {
        windows[key]?.droppedThrough
    }

    /// Corruption seam for deterministic tests. Product code never rewrites a
    /// stored frame.
    package mutating func replaceFrameForTesting(
        for key: Key,
        sequence: UInt64,
        with frame: Data
    ) -> Bool {
        guard var window = windows.removeValue(forKey: key) else { return false }
        guard let index = window.entries[window.head...].firstIndex(where: { $0.sequence == sequence }) else {
            windows[key] = window
            return false
        }
        let difference = frame.count - window.entries[index].frame.count
        window.entries[index].frame = frame
        window.retainedBytes += difference
        counters.currentBytes += difference
        counters.highWaterBytes = max(counters.highWaterBytes, counters.currentBytes)
        windows[key] = window
        return true
    }

    private static func decode(_ data: Data) throws -> Ev {
        guard data.count >= 5 else { throw ReplayError.corrupt }
        let declared = data.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard Int(declared) + 4 == data.count else { throw ReplayError.corrupt }
        var reassembler = FrameReassembler()
        let frames = try reassembler.feed(data)
        guard frames.count == 1, frames[0].type == .ev else { throw ReplayError.corrupt }
        return try frames[0].decode(Ev.self)
    }

    private static func wouldExceed(current: Int, adding: Int, limit: Int) -> Bool {
        current > limit || adding > limit - current
    }

    private mutating func invalidateCorruptWindow(for key: Key) {
        guard var window = windows.removeValue(forKey: key) else { return }
        let lastSequence = window.retainedEntries.last?.sequence
        if let lastSequence { window.markDropped(through: lastSequence) }
        let removed = window.removeAllEntries()
        counters.currentBytes -= removed
        counters.releasedBytes += removed
        counters.corruptions += 1
        windows[key] = window
    }
}
