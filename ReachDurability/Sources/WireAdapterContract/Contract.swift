import Foundation
import ReachWire
import HostClientContract
import RecoveryContract
import DurableClientReceipts
import DurableRootKeys
import DurableStoreBootstrap

public enum AdapterError: Error { case disabled, incompatible, invalid, unavailable, unauthorized, oversized }
/// Trusted local selection. Peer frames cannot select a new request policy.
/// Concrete portable policies must not depend on a native model runtime.
public protocol AdapterRequestPolicy {
    var requiresPreparedValidation:Bool { get }
    func validate(_ configuration:AdapterConfiguration) throws
    func route(_ request:WireGenerationRequest) throws -> String
    func requestBinding(_ request:WireGenerationRequest,configuration:AdapterConfiguration,route:String) throws -> String
    func validateContext(_ context:ClientContext,configuration:AdapterConfiguration) throws
}
public struct AdapterConfiguration: Codable {
    public let dialect: UInt8, model: String, profile: String
    public var optIn: Bool, ready: Bool
    public init(dialect: UInt8 = 0, model: String, profile: String = DurableWire.profile, optIn: Bool = false, ready: Bool = false) {
        self.dialect=dialect; self.model=model; self.profile=profile; self.optIn=optIn; self.ready=ready
    }
    public func validate() throws {
        guard optIn && ready else { throw AdapterError.disabled }
        guard dialect == 2, !model.isEmpty && model.utf8.count<=256, [DurableWire.profile, DurableWire.independentProfile].contains(profile) else { throw AdapterError.incompatible }
    }
}
public enum AdapterContract {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        try RecoveryCodec.encode(value,maximum:16<<20)
    }
    public static func same<T: Encodable>(_ a:T,_ b:T) throws -> Bool { try encode(a)==encode(b) }
    public static func require(_ value:Bool) throws { if !value { throw AdapterError.invalid } }
    public static func checkReference(_ r:DurableGenerationReference, configuration:AdapterConfiguration,policy:any AdapterRequestPolicy) throws {
        try policy.validate(configuration); try r.validate()
        try require(r.session.modelID==configuration.model && r.session.profile==configuration.profile)
    }
    public static func witness(_ w:HandoffWitness) throws -> DurableWitness { try JSONDecoder().decode(DurableWitness.self,from:encode(w)) }
    public static func witness(_ w:DurableWitness) throws -> HandoffWitness { try w.validate(); return try JSONDecoder().decode(HandoffWitness.self,from:encode(w)) }
    public static func batch(_ b:DurableBatchPayload) -> HandoffBatch { .init(first:b.first,count:b.count,commit:b.commit,bytes:b.bytes,skip:b.skip) }
    public static func context(_ bytes:Data, reference:DurableGenerationReference, configuration:AdapterConfiguration,policy:any AdapterRequestPolicy) throws -> ClientAuthority {
        try checkReference(reference,configuration:configuration,policy:policy)
        let a=try ClientAuthority(HandoffContract.decode(ClientContext.self,bytes,maximum:HandoffContract.context)),c=a.context
        try require(a.bytes==bytes && c.namespace==reference.session.sessionID && c.generation==reference.generationID && c.operation==reference.operationID && c.revision==HandoffContract.revision)
        try policy.validateContext(c,configuration:configuration)
        return a
    }
    public static func call(_ batches:[Data]) throws -> ToolBinding {
        var calls:[ToolBinding]=[]
        for bytes in batches { for event in try ClientEvents.decode(bytes) {
            if case .toolCallAppendArguments(_,let id,let name,let arguments,_) = event {
                calls.append(try .init(id:Data(id.utf8),name:Data(name.utf8),arguments:Data(arguments.utf8)))
            }
        } }
        guard calls.count==1 else { throw AdapterError.unavailable }; return calls[0]
    }
    /// Read-only consistency of a peer report with retained call/context. This
    /// does not attest effect execution or grant a local S83 permission.
    public static func checkKnowledge(_ value:DurableToolKnowledgePayload, authority:ClientAuthority, call:ToolBinding) throws {
        try value.validate()
        try require(value.contextDigest==RecoveryCodec.hash(authority.bytes) && value.callID==call.id && value.name==call.name && value.arguments==call.arguments)
        if let outcome=value.outcome {
            let expected=try ClientOutcome.make(kind:outcome.kind == .success ? .success : .failure,result:outcome.result,binding:call,authority:authority)
            try require(encode(expected)==encode(outcome))
        }
    }
}

/// Bounded actual-frame reassembly. No durable content travels as private JSON.
public struct AdapterFrames {
    private var reassembler=FrameReassembler()
    public init() {}
    public mutating func receive(_ input:Data, version:UInt8) throws -> [DurableMessage] {
        guard input.count<=65_536 else { throw AdapterError.oversized }
        let frames=try reassembler.feed(input)
        guard frames.count<=16 else { throw AdapterError.oversized }
        return try frames.map { try DurableMessage.decode($0,version:version) }
    }
    public static func raw(_ message:DurableMessage) throws -> RawFrame {
        var r=FrameReassembler(); return try r.feed(message.encode(version:2))[0]
    }
}

/// Pure recovery projection of the authenticated bootstrap, without fixture paths.
public enum BootstrapRecoveryBinding {
    public static func make(_ core:BootstrapCore) throws -> RecoveryBinding {
        try .init(bootstrap:core.identifier,core:core.binding(),clientRoot:core.clientID,host:core.hostID,boot:core.policy.boot,hostPolicy:core.policy.hostClock,clientPolicy:core.policy.clientClock)
    }
}
