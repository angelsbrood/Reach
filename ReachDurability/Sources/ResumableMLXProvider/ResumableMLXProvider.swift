import Foundation
import ReachWire

/// One synchronous owner, one accepted descriptor and at most one frozen pending
/// candidate. Host acknowledgements/owner tokens are local caller assertions.
public final class ResumableMLXProvider {
    public static let reservationBytes = ProviderCandidate.maximumBytes
    private let binding: ProviderBinding
    private let owner: Data
    private var child: ProviderChild?
    private var pending: ProviderCandidate?
    public private(set) var acceptedCommit: ProviderCommit?
    public private(set) var isTerminal = false
    public private(set) var isClosed = false
    // Internal injection point for proving post-work serialization failure isolation.
    // It is not a public adapter/plugin API; normal operation freezes this encoder.
    var encodeEvents: ([WireEvent]) throws -> Data = ProviderEvents.encode
    private init(binding: ProviderBinding, owner: String, child: ProviderChild) {
        self.binding = binding; self.owner = Data(owner.utf8); self.child = child
    }
    public static func assess(_ binding: ProviderBinding) -> ProviderAssessment {
        do { try binding.validateDeclaration(); return .supported(reservationBytes: reservationBytes) }
        catch { return .unsupported(String(describing: error)) }
    }
    public static func prepare(binding: ProviderBinding, runtime: ProviderRuntime, owner: String, credit: Int) throws -> ResumableMLXProvider {
        try providerID(owner)
        guard credit >= reservationBytes else { throw ProviderError.credit }
        try binding.validateDeclaration()
        guard runtime.route == binding.lane.route else { throw ProviderError.unsupported("runtime route") }
        let child = try ProviderChild.prepare(binding, runtime)
        let live = ResumableMLXProvider(binding: binding, owner: owner, child: child)
        do { try live.freeze(events: [], ordinal: 0, previousID: nil); return live }
        catch { live.close(); throw error }
    }
    /// The caller selects an authoritative committed record. This API does not
    /// inspect disk state or promote a later uncommitted record on the host's behalf.
    public static func restore(committed: ProviderCandidate, expected: ProviderBinding, runtime: ProviderRuntime, owner: String) throws -> ResumableMLXProvider {
        try providerID(owner); try expected.validateDeclaration()
        let checked = try ProviderCandidate(data: committed.data), checkpoint = try checked.checkpoint()
        guard try providerEncode(expected) == providerEncode(checkpoint.binding), runtime.route == expected.lane.route else { throw ProviderError.commit }
        let child = try ProviderChild.restore(checkpoint, runtime)
        let live = ResumableMLXProvider(binding: expected, owner: owner, child: child)
        do {
            // Retained native state is restored even at terminal. Stored events are
            // outer-owned history and are not delivered or reconstructed here.
            guard child.phase == checkpoint.phase, try child.capture() == checkpoint.child else { throw ProviderError.invalid("restored child phase/bytes") }
            try child.validateTerminal(checkpoint.terminal)
            live.acceptedCommit = checked.commit; live.isTerminal = checkpoint.terminal != nil
            return live
        } catch { live.close(); throw error }
    }
    public func pendingCandidate() throws -> ProviderCandidate? {
        guard !isClosed else { throw ProviderError.closed }; return pending
    }
    public func acceptCommit(_ commit: ProviderCommit, owner: String) throws {
        try checkOwner(owner)
        // Check the retained accepted identity first: a lost acknowledgement reply
        // can be retried while a newer candidate remains pending, without consuming it.
        if commit == acceptedCommit { return }
        guard let pending, pending.commit == commit else { throw ProviderError.commit }
        acceptedCommit = commit; isTerminal = try commit.descriptor().terminal != nil; self.pending = nil
    }
    public func advance(owner: String, current: ProviderCommit, credit: Int) throws -> ProviderCandidate? {
        try step(owner: owner, current: current, credit: credit, cancel: false)
    }
    public func cancel(owner: String, current: ProviderCommit, credit: Int) throws -> ProviderCandidate? {
        try step(owner: owner, current: current, credit: credit, cancel: true)
    }
    private func checkOwner(_ token: String) throws {
        guard !isClosed else { throw ProviderError.closed }
        guard owner == Data(token.utf8) else { throw ProviderError.owner }
    }
    private func step(owner: String, current: ProviderCommit, credit: Int, cancel: Bool) throws -> ProviderCandidate? {
        try checkOwner(owner)
        guard pending == nil else { throw ProviderError.pending }
        guard acceptedCommit == current else { throw ProviderError.commit }
        if isTerminal { return nil }
        guard credit >= Self.reservationBytes else { throw ProviderError.credit }
        let next = try current.descriptor().ordinal.addingReportingOverflow(1)
        guard !next.overflow else { throw ProviderError.overflow }
        guard let child else { throw ProviderError.closed }
        do {
            let events = try child.step(cancel: cancel)
            try freeze(events: events, ordinal: next.partialValue, previousID: current.identity)
            return pending
        } catch { close(); throw error }
    }
    private func freeze(events: [WireEvent], ordinal: UInt64, previousID: String?) throws {
        guard let child else { throw ProviderError.closed }
        let terminal = try ProviderEvents.ending(events)
        try child.validateTerminal(terminal)
        let bytes = try encodeEvents(events)
        let checkpoint = try ProviderCheckpointDocument(binding: binding, ordinal: ordinal, previousID: previousID,
            phase: child.phase, terminal: terminal, child: child.capture())
        let frozen = try ProviderCandidate(checkpoint: checkpoint, events: bytes)
        pending = frozen
    }
    public func close() { isClosed = true; child?.close(); child = nil; pending = nil }
}
