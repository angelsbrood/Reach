import Foundation
import MLX
import ReachWire
import DurableRootKeys
import DurableSessionLifecycle
import DurableHostWireAdapter
import WireAdapterContract
import HostClientContract
import ResumableMLXProvider
import RequestPreparationContract

/// Synchronous host-only state. The endpoint runs every method on its dedicated
/// serial native queue; transport callbacks never advance this owner directly.
final class TransportHostRuntime {
    let selection: TransportSelectionBinding, identity: TransportIdentity
    private let acquired: TransportResources, owner: DurableSessionLifecycle, profile: SelectedArtifactProfile, admission: TransportHostAdmission
    private var adapter: DurableHostWireAdapter?, token: UUID?, lastTicket: SessionTicket?, lastReference: DurableGenerationReference?, lastStatus: LifecycleStatus?
    private var storedBinding: ProviderBinding?, retainedBatches: [HandoffBatch] = []
    private var connectionCount = 0, issueCount = 0, beginCount = 0, recoveryCount = 0, authenticatedPeer: String?
    private var pendingHigh: UInt64?, terminalSent = false, closed = false
    init(root: String, independent: Bool = false) throws {
        let acquired = try TransportResources(root: root, role: .host, independent: independent)
        self.acquired = acquired; selection = acquired.selection
        try acquired.audit.journal(.host)
        let clock = acquired.hostClock
        let owner = try DurableSessionLifecycle.reopen(at: root + "/bootstrap/host", identity: .init(incarnation: acquired.hostID, clock: clock, quota: acquired.hostQuota), keys: LocalRuntimeOwner.hostKeys(acquired.keys), clock: clock)
        self.owner = owner
        do {
            admission = try TransportHostAdmission(root: root, selection: acquired.selection, reference: acquired.catalogReference!, key: acquired.keys.key(.hostCatalog))
            try acquired.audit.model()
            let profile = try SelectedArtifactProfile(at: root + "/model")
            guard profile.manifestDigest == acquired.selection.profileDigest, profile.preparer.policy.descriptor == acquired.selection.descriptor else { throw TransportRuntimeError.invalid }
            self.profile = profile
            identity = try TransportIdentity(root: root, selection: acquired.selection, audit: acquired.audit)
        } catch { owner.close(); throw error }
    }
    func connect(_ token: UUID, peerDigest: String) throws -> Data {
        guard !closed, self.token == nil, peerDigest == selection.pins.clientLeaf else { throw TransportRuntimeError.peer }
        let configuration = AdapterConfiguration(dialect: 2, model: selection.descriptor.model, profile: selection.profile, optIn: true, ready: !owner.uncertain)
        let profile = self.profile, admission = self.admission
        adapter = try .init(configuration: configuration, owner: owner, authorization: selection.hostAuthorization, expectedClientRoot: acquired.clientID, allowNew: admission.reservation == nil,
            prepare: { request, reference, configuration in
                let route = try profile.preparer.policy.route(request)
                let digest = try profile.preparer.policy.requestBinding(request, configuration: configuration, route: route)
                try admission.reserve(reference, requestDigest: PreparationEncoding.hash(Data(digest.utf8))) // Durable before original preparation.
                return try profile.preparer.prepare(request, reference: reference, configuration: configuration)
            }, runtime: { try profile.runtime($0, configuration: $1) }, requestPolicy: profile.preparer.policy,
            validatePrepared: { try profile.preparer.validateStored($0, configuration: $1) })
        self.token = token; authenticatedPeer = peerDigest; connectionCount += 1; pendingHigh = nil; terminalSent = false
        return try adapter!.capabilities()
    }
    private func current(_ token: UUID) throws -> DurableHostWireAdapter {
        guard !closed, self.token == token, let adapter else { throw TransportRuntimeError.stale }; return adapter
    }
    func receive(_ raw: RawFrame, token: UUID) throws -> [Data] {
        let adapter = try current(token), message = try DurableMessage.decode(raw, version: 2)
        switch message {
        case .receipt(let value):
            guard !value.payload.witness.terminal, let pendingHigh, value.payload.witness.high == pendingHigh else { throw TransportRuntimeError.protocolRefused }
        case .open, .begin, .recover:
            guard pendingHigh == nil, !terminalSent else { throw TransportRuntimeError.protocolRefused }
        default: throw TransportRuntimeError.protocolRefused
        }
        var responses: [Data] = []
        let bytes = try TransportConnection.bytes(raw)
        for start in stride(from: 0, to: bytes.count, by: 65536) { responses += try adapter.receive(Data(bytes[start..<min(start + 65536, bytes.count)])) }
        guard responses.count == 1 else { throw TransportRuntimeError.protocolRefused }
        let response = try TransportConnection.message(responses[0])
        if case .refused = response { return responses }
        switch response {
        case .opened(let value): lastTicket = try SessionTicket(data: value.payload.ticket)
        case .accepted(let value):
            if case .recover(let input) = message { lastTicket = try SessionTicket(data: input.payload.ticket) }
            lastReference = value.payload.reference
            guard let lastTicket else { throw TransportRuntimeError.invalid }
            storedBinding = try owner.wireProviderBinding(ticket: lastTicket, authorization: selection.hostAuthorization, generation: value.payload.reference.generationID)
        case .receiptAccepted: pendingHigh = nil
        default: break
        }
        lastStatus = adapter.status
        return responses
    }
    struct Publication {
        let bytes: Data?, terminal: Bool, high: UInt64, nativeCalls: Int
        var checkpoint: String? = nil
    }
    func publication(_ token: UUID, observe: Bool) throws -> Publication {
        let adapter = try current(token)
        guard lastReference != nil, adapter.status != nil, pendingHigh == nil else { throw TransportRuntimeError.protocolRefused }
        // Re-read from the adapter's newly acknowledged clientHigh every time.
        // The accepted replay workset remains bounded; only its first batch is sent.
        if let bytes = try adapter.replayNext() {
            guard case .batch(let frame) = try TransportConnection.message(bytes) else { throw TransportRuntimeError.invalid }
            let events = try JSONDecoder().decode([WireEvent].self, from: frame.payload.bytes)
            let terminal = events.contains { if case .finished = $0 { return true }; return false }
            let high = frame.payload.first + UInt64(frame.payload.count - 1)
            if terminal { terminalSent = true } else { pendingHigh = high }
            return .init(bytes: bytes, terminal: terminal, high: high, nativeCalls: calls)
        }
        if adapter.status?.phase == .terminal { return .init(bytes: nil, terminal: true, high: adapter.status?.high ?? 0, nativeCalls: calls) }
        lastStatus = try adapter.step()
        guard Memory.peakMemory <= 128 << 20 else { throw TransportRuntimeError.invalid }
        var phase: String?
        if observe, let lastTicket, let attachment = lastStatus?.attachment {
            phase = try owner.wireNativeCheckpointPhase(ticket: lastTicket, authorization: selection.hostAuthorization, attachment: attachment)
        }
        return .init(bytes: nil, terminal: false, high: lastStatus?.high ?? 0, nativeCalls: calls, checkpoint: phase)
    }
    func disconnect(_ token: UUID) throws {
        let adapter = try current(token)
        issueCount += adapter.issues; beginCount += adapter.begins; recoveryCount += adapter.recoveries
        defer { self.token = nil; self.adapter = nil; pendingHigh = nil; terminalSent = false }
        guard let lastTicket, let attachment = adapter.status?.attachment else { return }
        retainedBatches = try owner.replayForClient(ticket: lastTicket, authorization: selection.hostAuthorization, attachment: attachment, after: 0)
        try owner.detach(ticket: lastTicket, authorization: selection.hostAuthorization, attachment: attachment)
        lastStatus = adapter.status
    }
    func cancelLocal() throws {
        guard token == nil else { throw TransportRuntimeError.unavailable }
        guard let reservation = admission.reservation else { throw TransportRuntimeError.unavailable }
        lastStatus = try owner.wireCancelLocalReservation(namespace: reservation.reference.session.sessionID, generation: reservation.reference.generationID, requestDigest: reservation.requestDigest, authorization: selection.hostAuthorization)
        guard lastStatus != nil else { throw TransportRuntimeError.unavailable }
    }
    var calls: Int { profile.observations.reduce(0) { $0 + $1.calls } }
    func report(stage: String) -> TransportHostReport {
        let tokenizer = profile.tokenizer
        return .init(stage: stage, acquisition: acquired.audit.snapshot, peerDigests: authenticatedPeer.map { [$0] } ?? [], connections: connectionCount, reserved: admission.reservation != nil,
            phase: lastStatus?.phase.rawValue, disposition: lastStatus?.disposition, providerEnding: lastStatus?.providerEnding, high: lastStatus?.high ?? 0,
            nativeCalls: calls, modelPrepares: profile.observations.reduce(0) { $0 + $1.prepares }, requestPreparations: profile.preparer.preparations,
            templateCalls: tokenizer.renders, requestTokenizations: tokenizer.requestTokenizations, repairEncodes: tokenizer.repairEncodes, nativeEncodes: tokenizer.encodes - tokenizer.requestTokenizations - tokenizer.repairEncodes,
            issues: issueCount + (adapter?.issues ?? 0), begins: beginCount + (adapter?.begins ?? 0), recoveries: recoveryCount + (adapter?.recoveries ?? 0),
            binding: storedBinding, batches: retainedBatches, nativePeak: Memory.peakMemory, traces: profile.observations)
    }
    func close() { if !closed { owner.close(); closed = true } }
    deinit { close() }
}
