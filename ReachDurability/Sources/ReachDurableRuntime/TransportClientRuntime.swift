import Foundation
import ReachWire
import DurableClientReceipts
import DurableClientWireAdapter
import DurableStoreBootstrap
import WireAdapterContract
import HostClientContract
import RequestPreparationContract

/// Client acquisition deliberately has no host owner, native factory, artifact
/// loader, or MLX call. Its portable descriptor comes from its own confirmation.
final class TransportClientRuntime {
    let selection: TransportSelectionBinding, identity: TransportIdentity
    private let acquired: AcquiredTransportRoot, owner: DurableClientReceipts, root: String, policy: RequestPolicy
    private var adapter: DurableClientWireAdapter?, token: UUID?, closed = false
    private var peers: [String] = [], connections = 0, before: [[HandoffBatch]] = []
    private(set) var accepted: DurableGenerationAcceptedPayload?, reconnects = 0
    init(root: String) throws {
        let acquired = try AcquiredTransportRoot(root, role: .client)
        self.root = root; self.acquired = acquired; selection = acquired.selection
        policy = try RequestPolicy(descriptor: acquired.selection.descriptor)
        try acquired.audit.journal(.client)
        let clock = SystemClientClock()
        let owner = try DurableClientReceipts(path: root + "/bootstrap/client", create: false, environment: .init(rootID: acquired.core.clientID, clock: clock, quota: acquired.core.policy.clientQuota), metadataKey: acquired.keys.key(.clientMetadata).use { $0 }, clock: clock)
        self.owner = owner
        do { identity = try TransportIdentity(root: root, selection: acquired.selection, audit: acquired.audit) }
        catch { owner.close(); throw error }
    }
    func requireEmpty() throws {
        guard try owner.discover(binding: BootstrapRecoveryBinding.make(acquired.core), authorization: selection.pins.clientAuthorization).isEmpty else { throw TransportRuntimeError.reserved }
    }
    /// Presence alone is insufficient: require a fully registered, authenticated
    /// recovery join including the original encrypted ticket sidecar.
    func registered() throws -> Bool {
        let binding = try BootstrapRecoveryBinding.make(acquired.core)
        let selections = try owner.discover(binding: binding, authorization: selection.pins.clientAuthorization)
        if selections.isEmpty { return false }
        guard selections.count == 1 else { throw TransportRuntimeError.invalid }
        _ = try owner.recoverHostJoin(selections[0], in: root, binding: binding, authorization: selection.pins.clientAuthorization)
        return true
    }
    func remainingAuthority() throws -> Duration {
        let binding = try BootstrapRecoveryBinding.make(acquired.core)
        let selections = try owner.discover(binding: binding, authorization: selection.pins.clientAuthorization)
        guard selections.count == 1 else { throw TransportRuntimeError.unavailable }
        let join = try owner.recoverHostJoin(selections[0], in: root, binding: binding, authorization: selection.pins.clientAuthorization)
        let now = try SystemClientClock().now(), expiry = join.client.authority.context.expires
        guard now < expiry else { throw TransportRuntimeError.expired }
        return .nanoseconds(Int64(clamping: expiry - now))
    }
    private func inbox() throws -> [HandoffBatch] {
        let binding = try BootstrapRecoveryBinding.make(acquired.core)
        let selections = try owner.discover(binding: binding, authorization: selection.pins.clientAuthorization)
        guard !selections.isEmpty else { return [] }
        guard selections.count == 1 else { throw TransportRuntimeError.invalid }
        let value = try owner.resolve(selections[0], binding: binding, authorization: selection.pins.clientAuthorization)
        return try owner.hostInbox(value.handle, authority: value.authority, authorization: selection.pins.clientAuthorization)
    }
    func connect(_ token: UUID, peer: String, begin: Bool) throws {
        guard !closed, self.token == nil, peer == selection.pins.hostLeaf else { throw TransportRuntimeError.peer }
        adapter = try .init(configuration: .init(dialect: 2, model: selection.descriptor.model, optIn: true, ready: true), owner: owner, authorization: selection.pins.clientAuthorization, core: acquired.core, parent: root, allowNew: begin, requestPolicy: policy)
        self.token = token; connections += 1
        if !peers.contains(peer) { peers.append(peer) }
    }
    private func current(_ token: UUID) throws -> DurableClientWireAdapter {
        guard !closed, self.token == token, let adapter else { throw TransportRuntimeError.stale }; return adapter
    }
    @discardableResult func receive(_ raw: RawFrame, token: UUID) throws -> DurableMessage {
        let adapter = try current(token), message = try DurableMessage.decode(raw, version: 2)
        if case .refused = message { throw TransportRuntimeError.protocolRefused }
        let bytes = try TransportConnection.bytes(raw)
        for start in stride(from: 0, to: bytes.count, by: 65536) { try adapter.receive(Data(bytes[start..<min(start + 65536, bytes.count)])) }
        if case .accepted(let value) = message { accepted = value.payload }
        return message
    }
    func open(_ token: UUID) throws -> Data { try current(token).open(requestID: "transport-open") }
    func begin(_ request: WireGenerationRequest, token: UUID) throws -> Data {
        let id = request.id.uuidString.lowercased()
        return try current(token).begin(requestID: "transport-begin", generation: "generation-" + id, operation: "operation-" + id, request: request)
    }
    func recover(_ token: UUID) throws -> Data {
        guard try registered() else { throw TransportRuntimeError.unavailable }
        // Diagnostics retain one bounded prefix, not one full inbox per retry.
        if before.isEmpty { before.append(try inbox()) }
        return try current(token).recover(requestID: "transport-recover")
    }
    func receipt(_ token: UUID) throws -> Data {
        let adapter = try current(token)
        guard try !adapter.witness().terminal else { throw TransportRuntimeError.protocolRefused }
        return try adapter.receipt(requestID: "transport-receipt")
    }
    func witness(_ token: UUID) throws -> HandoffWitness { try current(token).witness() }
    func disconnect(_ token: UUID) { if self.token == token { adapter = nil; self.token = nil } }
    func retried() { reconnects += 1 }
    func report(stage: String) throws -> TransportClientReport {
        let batches = try inbox()
        // Read the durable witness even after discarding protocol attachment.
        let binding = try BootstrapRecoveryBinding.make(acquired.core)
        let selections = try owner.discover(binding: binding, authorization: selection.pins.clientAuthorization)
        var high: UInt64 = 0, terminal = false
        if let selected = selections.first {
            let value = try owner.resolve(selected, binding: binding, authorization: selection.pins.clientAuthorization)
            let witness = try owner.hostWitness(value.handle, authority: value.authority, authorization: selection.pins.clientAuthorization)
            high = witness.high; terminal = witness.terminal
        }
        return .init(stage: stage, acquisition: acquired.audit.snapshot, peerDigests: peers, connections: connections, reconnects: reconnects, registered: (try? registered()) ?? false, high: high, terminal: terminal, inbox: batches, beforeRecovery: before, accepted: accepted)
    }
    func close() { if !closed { owner.close(); closed = true } }
    deinit { close() }
}
