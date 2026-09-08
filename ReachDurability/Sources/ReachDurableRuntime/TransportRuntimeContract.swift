import Foundation
import Darwin
import ReachWire
import DurableRootKeys
import DurableStoreBootstrap
import DurableSessionLifecycle
import DurableClientReceipts
import RequestPreparationContract
import HostClientContract
import ResumableMLXProvider

public enum TransportRuntimeError: Error { case invalid, unavailable, peer, protocolRefused, reserved, stale, unknownLost, reconnectExhausted, expired }
public enum TransportRole: String, Codable, Sendable { case host, client }
public enum TransportContract {
    public static let revision = "s94-same-boot-loopback-v1"
    public static let application = "reach.durable-transport.loopback.v1"
    public static let model = "local-llama-258-v1"
    public static let archivePassphrase = "reach-s94-local" // Non-secret file-container transport convention.
    static func currentUser() throws {
        guard getuid() == geteuid(), getgid() == getegid() else { throw TransportRuntimeError.invalid }
    }
    static func encode<T: Encodable>(_ value: T) throws -> Data { try PreparationEncoding.encode(value) }
    static func write<T: Encodable>(_ value: T, to path: String?, beforePublication: () throws -> Void = {}) throws {
        let bytes = try encode(value)
        guard bytes.count <= 16 << 20 else { throw TransportRuntimeError.invalid }
        try beforePublication()
        if let path { try LocalFiles.writeNew(bytes, to: path) }
        else { try FileHandle.standardOutput.write(contentsOf: bytes + Data([10])) }
    }
}
public struct TransportTLSProvision {
    public let caDER: Data, hostDER: Data, clientDER: Data
    public init(caDER: Data, hostDER: Data, clientDER: Data) { self.caDER = caDER; self.hostDER = hostDER; self.clientDER = clientDER }
}
struct TransportPins: Codable, Equatable {
    let caDER: Data, caDigest: String, hostLeaf: String, clientLeaf: String
    init(_ value: TransportTLSProvision) throws {
        guard [value.caDER, value.hostDER, value.clientDER].allSatisfy({ !$0.isEmpty && $0.count <= 65536 }), value.hostDER != value.clientDER else { throw TransportRuntimeError.invalid }
        caDER = value.caDER; caDigest = PreparationEncoding.hash(value.caDER)
        hostLeaf = PreparationEncoding.hash(value.hostDER); clientLeaf = PreparationEncoding.hash(value.clientDER)
    }
    func validate() throws {
        guard !caDER.isEmpty, caDER.count <= 65536, caDigest == PreparationEncoding.hash(caDER), [hostLeaf, clientLeaf].allSatisfy(PreparationEncoding.isDigest), hostLeaf != clientLeaf else { throw TransportRuntimeError.invalid }
    }
    var hostAuthorization: LifecycleAuthorization { .init(caller: .init(principal: caDigest, device: clientLeaf, app: TransportContract.application), allowed: true) }
    var clientAuthorization: ClientAuthorization { .init(caller: .init(principal: caDigest, device: clientLeaf, app: TransportContract.application), allowed: true) }
}
struct TransportSelectionBinding: Codable {
    let revision: String, role: TransportRole, bootstrap: String, profileDigest: String, archiveDigest: String
    let executable: FrozenWorker, descriptor: RequestPreparationContract.ModelDescriptor, pins: TransportPins, port: UInt16
    var profile: String { revision == IndependentContract.revision ? DurableWire.independentProfile : DurableWire.profile }
    var application: String { revision == IndependentContract.revision ? IndependentContract.application : TransportContract.application }
    var hostAuthorization: LifecycleAuthorization { .init(caller:.init(principal:pins.caDigest,device:pins.clientLeaf,app:application),allowed:true) }
    var clientAuthorization: ClientAuthorization { .init(caller:.init(principal:pins.caDigest,device:pins.clientLeaf,app:application),allowed:true) }
    func validate(role: TransportRole) throws {
        try descriptor.validate(); try pins.validate()
        guard [TransportContract.revision, IndependentContract.revision].contains(revision), self.role == role, descriptor.model == TransportContract.model,
              descriptor.revision == RequestPreparationContract.ModelDescriptor.schemaToolRevision,
              [bootstrap, profileDigest, archiveDigest].allSatisfy(PreparationEncoding.isDigest), (49152...65535).contains(port) else { throw TransportRuntimeError.invalid }
    }
}
struct TransportSelection: Codable { let binding: TransportSelectionBinding, confirmation: Data }

/// Admission guards around actual role-specific acquisition sites. Violations
/// throw before opening the forbidden role; counters describe invoked work.
final class TransportRoleAudit {
    let role: TransportRole
    private(set) var storageLoads: [String] = [], journalOpens = 0, modelLoads = 0, tlsImports = 0
    init(_ role: TransportRole) { self.role = role }
    func load(_ key: RootKeyRole) throws {
        guard (role == .host && [.hostCatalog, .hostTicket].contains(key)) || (role == .client && key == .clientMetadata) else { throw TransportRuntimeError.invalid }
        storageLoads.append(key.rawValue)
    }
    func journal(_ role: TransportRole) throws { guard self.role == role else { throw TransportRuntimeError.invalid }; journalOpens += 1 }
    func model() throws { guard role == .host else { throw TransportRuntimeError.invalid }; modelLoads += 1 }
    func tls() { tlsImports += 1 }
    var snapshot: TransportAcquisitionReport { .init(role: role.rawValue, storageLoads: storageLoads, hostJournalOpens: role == .host ? journalOpens : 0, clientJournalOpens: role == .client ? journalOpens : 0, modelLoads: modelLoads, tlsImports: tlsImports) }
}
public struct TransportAcquisitionReport: Encodable {
    public let role: String, storageLoads: [String], hostJournalOpens: Int, clientJournalOpens: Int, modelLoads: Int, tlsImports: Int
}
public struct TransportProgress: Encodable {
    public let role: String, stage: String, high: UInt64, nativeCalls: Int, connection: Int, checkpoint: String?
    public init(role: String, stage: String, high: UInt64 = 0, nativeCalls: Int = 0, connection: Int = 0, checkpoint: String? = nil) { self.role = role; self.stage = stage; self.high = high; self.nativeCalls = nativeCalls; self.connection = connection; self.checkpoint = checkpoint }
}
public struct TransportHostReport: Encodable {
    public let stage: String, acquisition: TransportAcquisitionReport, peerDigests: [String], connections: Int, reserved: Bool
    public let phase: String?, disposition: String?, providerEnding: WireFinishReason?, high: UInt64
    public let nativeCalls: Int, modelPrepares: Int, requestPreparations: Int, templateCalls: Int, requestTokenizations: Int, repairEncodes: Int, nativeEncodes: Int, issues: Int, begins: Int, recoveries: Int
    public let binding: ProviderBinding?, batches: [HandoffBatch], nativePeak: Int
    let traces: [NativeObservation]
}
public struct TransportClientReport: Encodable {
    public var retention: ClientLocalRetention? = nil
    public let stage: String, acquisition: TransportAcquisitionReport, peerDigests: [String], connections: Int, reconnects: Int, registered: Bool
    public let high: UInt64, terminal: Bool, inbox: [HandoffBatch], beforeRecovery: [[HandoffBatch]], accepted: DurableGenerationAcceptedPayload?
    public let hostKeys = 0, hostJournalOpens = 0, modelLoads = 0, nativeCalls = 0, requestPreparations = 0
}
