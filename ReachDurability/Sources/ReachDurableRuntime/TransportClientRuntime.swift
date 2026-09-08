import Foundation
import RecoveryContract
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
    private let acquired: TransportResources, owner: DurableClientReceipts, root: String, policy: RequestPolicy
    private var adapter: DurableClientWireAdapter?, token: UUID?, closed = false, established = false
    private var peers: [String] = [], connections = 0, before: [[HandoffBatch]] = []
    private(set) var accepted: DurableGenerationAcceptedPayload?, reconnects = 0
    init(root: String, independent: Bool = false) throws {
        let acquired = try TransportResources(root: root, role: .client, independent: independent)
        self.root = root; self.acquired = acquired; selection = acquired.selection
        policy = try RequestPolicy(descriptor: acquired.selection.descriptor)
        try acquired.audit.journal(.client)
        let clock = acquired.clientClock
        let owner = try DurableClientReceipts(path: root + "/bootstrap/client", create: false, environment: acquired.clientEnvironment(), metadataKey: acquired.keys.key(.clientMetadata).use { $0 }, clock: clock)
        self.owner = owner
        do { identity = try TransportIdentity(root: root, selection: acquired.selection, audit: acquired.audit) }
        catch { owner.close(); throw error }
    }
    private func requiredBinding() throws -> RecoveryContract.RecoveryBinding {
        guard let value = acquired.recovery else { throw TransportRuntimeError.invalid }; return value
    }
    func requireEmpty() throws {
        guard try owner.discover(binding: requiredBinding(), authorization: selection.clientAuthorization).isEmpty else { throw TransportRuntimeError.reserved }
    }
    /// Presence alone is insufficient: require a fully registered, authenticated
    /// recovery join including the original encrypted ticket sidecar.
    func registered() throws -> Bool {
        let binding = try requiredBinding()
        let selections = try owner.discover(binding: binding, authorization: selection.clientAuthorization)
        if selections.isEmpty {
            if established && acquired.agreement != nil { throw TransportRuntimeError.expired }
            return false
        }
        guard selections.count == 1 else { throw TransportRuntimeError.invalid }
        _ = try owner.recoverHostJoin(selections[0], in: root, binding: binding, authorization: selection.clientAuthorization)
        established = true
        return true
    }
    func remainingAuthority() throws -> Duration {
        let binding = try requiredBinding()
        let selections = try owner.discover(binding: binding, authorization: selection.clientAuthorization)
        if selections.isEmpty && established && acquired.agreement != nil { throw TransportRuntimeError.expired }
        guard selections.count == 1 else { throw TransportRuntimeError.unavailable }
        let join = try owner.recoverHostJoin(selections[0], in: root, binding: binding, authorization: selection.clientAuthorization)
        let now = try acquired.clientClock.now(), expiry = join.client.authority.localExpires
        guard now < expiry else { throw TransportRuntimeError.expired }
        return .nanoseconds(Int64(clamping: expiry - now))
    }
    private func inbox() throws -> [HandoffBatch] {
        let binding = try requiredBinding()
        let selections = try owner.discover(binding: binding, authorization: selection.clientAuthorization)
        guard !selections.isEmpty else { return [] }
        guard selections.count == 1 else { throw TransportRuntimeError.invalid }
        let value = try owner.resolve(selections[0], binding: binding, authorization: selection.clientAuthorization)
        return try owner.hostInbox(value.handle, authority: value.authority, authorization: selection.clientAuthorization)
    }
    func connect(_ token: UUID, peer: String, begin: Bool) throws {
        guard !closed, self.token == nil, peer == selection.pins.hostLeaf else { throw TransportRuntimeError.peer }
        adapter = try .init(configuration: .init(dialect: 2, model: selection.descriptor.model, profile: selection.profile, optIn: true, ready: true), owner: owner, authorization: selection.clientAuthorization, binding: requiredBinding(), parent: root, allowNew: begin, requestPolicy: policy, legacyCore: acquired.legacyCore)
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
    func publishReport(stage: String, to path: String?) throws {
        try TransportClientReportPublication.write({ try self.report(stage: stage) }, to: path,
            independent: acquired.agreement != nil, owner: owner, root: root,
            binding: requiredBinding(), authorization: selection.clientAuthorization, clock: acquired.clientClock)
    }
    private func report(stage: String) throws -> TransportClientReport {
        let batches = try inbox()
        // Read the durable witness even after discarding protocol attachment.
        let binding = try requiredBinding()
        let selections = try owner.discover(binding: binding, authorization: selection.clientAuthorization)
        var high: UInt64 = 0, terminal = false
        var retention: ClientLocalRetention?
        if let selected = selections.first {
            let value = try owner.resolve(selected, binding: binding, authorization: selection.clientAuthorization)
            let witness = try owner.hostWitness(value.handle, authority: value.authority, authorization: selection.clientAuthorization)
            high = witness.high; terminal = witness.terminal; retention = value.authority.retention
        }
        return .init(retention: retention, stage: stage, acquisition: acquired.audit.snapshot, peerDigests: peers, connections: connections, reconnects: reconnects, registered: (try? registered()) ?? false, high: high, terminal: terminal, inbox: batches, beforeRecovery: before, accepted: accepted)
    }
    func close() { if !closed { owner.close(); closed = true } }
    deinit { close() }
}

/// Cached recovery/acceptance bytes are content too. Revalidate authenticated
/// local authority after assembly and encoding, immediately before the sink.
/// Refusal leaves earlier reports alone and publishes no new report content.
enum TransportClientReportPublication {
    static func write(_ assemble: () throws -> TransportClientReport, to path: String?,
                      independent: Bool, owner: DurableClientReceipts, root: String,
                      binding: RecoveryContract.RecoveryBinding, authorization: ClientAuthorization,
                      clock: any ClientClock) throws {
        try TransportContract.write(assemble(), to: path, beforePublication: {
            guard independent else { return }
            let selections = try owner.discover(binding: binding, authorization: authorization)
            guard selections.count == 1 else { throw TransportRuntimeError.expired }
            let join = try owner.recoverHostJoin(selections[0], in: root, binding: binding, authorization: authorization)
            let now = try clock.now(), authority = join.client.authority
            guard now >= authority.localIssued, now < authority.localExpires else { throw TransportRuntimeError.expired }
        })
    }
}
