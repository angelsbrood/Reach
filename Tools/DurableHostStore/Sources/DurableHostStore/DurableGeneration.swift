import Foundation
import ResumableMLXProvider

/// Local host adapter. Publication uses store replay only after synced commitment;
/// delivery acknowledgement is a surviving caller assertion, not durable EvAck.
public final class DurableGeneration {
    public let store: DurableHostStore
    private var provider: ResumableMLXProvider?
    public private(set) var deliveredThrough: UInt64 = 0
    public private(set) var failed = false
    private init(store: DurableHostStore, provider: ResumableMLXProvider?) { self.store = store; self.provider = provider }
    public static func start(store: DurableHostStore, runtime: () throws -> ProviderRuntime) throws -> DurableGeneration {
        guard try store.snapshot().candidate == nil else { throw StoreError.invalid("generation already accepted") }
        try store.reserve()
        let live = try ResumableMLXProvider.prepare(binding: store.identity.provider, runtime: runtime(), owner: store.ownerToken, credit: ResumableMLXProvider.reservationBytes)
        let generation = DurableGeneration(store: store, provider: live)
        do {
            guard let c0 = try live.pendingCandidate() else { throw StoreError.invalid("missing C0") }
            try generation.commitAndAcknowledge(c0); return generation
        } catch { live.close(); throw error }
    }
    public static func recover(store: DurableHostStore, runtime: () throws -> ProviderRuntime) throws -> DurableGeneration {
        let state = try store.snapshot()
        guard let candidate = state.candidate else { throw StoreError.noCommittedGeneration }
        if state.terminal { return .init(store: store, provider: nil) }
        try store.reserve()
        let provider = try ResumableMLXProvider.restore(committed: candidate, expected: store.identity.provider, runtime: runtime(), owner: store.ownerToken)
        return .init(store: store, provider: provider)
    }
    public func replay(after cursor: UInt64) throws -> [StoreReplayFrame] { try store.replay(after: cursor) }
    public func acknowledgeDelivery(through cursor: UInt64) throws {
        let state = try store.snapshot()
        guard cursor >= deliveredThrough, cursor <= state.high else { throw StoreError.invalid("stale/above-high delivery cursor") }
        deliveredThrough = cursor
    }
    @discardableResult public func advance(cancel: Bool = false) throws -> StoreSnapshot? {
        guard !failed else { throw StoreError.closed }
        let state = try store.snapshot()
        if state.terminal { return nil }
        guard deliveredThrough == state.high else { throw StoreError.replayRequired }
        guard let provider, let current = state.candidate?.commit, provider.acceptedCommit == current else { throw StoreError.stale }
        try store.reserve()
        do {
            let candidate = try cancel ? provider.cancel(owner: store.ownerToken, current: current, credit: ResumableMLXProvider.reservationBytes)
                : provider.advance(owner: store.ownerToken, current: current, credit: ResumableMLXProvider.reservationBytes)
            guard let candidate else { throw StoreError.invalid("missing active transition") }
            try commitAndAcknowledge(candidate); return try store.snapshot()
        } catch { failed = true; provider.close(); self.provider = nil; throw error }
    }
    private func commitAndAcknowledge(_ candidate: ProviderCandidate) throws {
        try store.commit(candidate)
        try store.fault(.afterCommitBeforeAck)
        guard let provider else { throw StoreError.closed }
        try provider.acceptCommit(candidate.commit, owner: store.ownerToken)
        try store.fault(.afterAckBeforePublication)
    }
    public func close() { failed = true; provider?.close(); provider = nil; store.close() }
}
