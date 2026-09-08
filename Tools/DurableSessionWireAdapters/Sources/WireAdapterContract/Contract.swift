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
public struct FixedAdapterRequestPolicy:AdapterRequestPolicy {
    public init() {}
    public var requiresPreparedValidation:Bool { false }
    public func validate(_ configuration:AdapterConfiguration) throws { try configuration.validate() }
    public func route(_ request:WireGenerationRequest) throws -> String { try AdapterContract.route(request) }
    public func requestBinding(_ request:WireGenerationRequest,configuration:AdapterConfiguration,route:String) throws -> String {
        try AdapterContract.requestBinding(request,configuration:configuration,route:route)
    }
    public func validateContext(_ context:ClientContext,configuration:AdapterConfiguration) throws {
        let original=try AdapterContract.request(context.route)
        try AdapterContract.require(context.request==AdapterContract.requestBinding(original,configuration:configuration,route:context.route))
    }
}
public struct AdapterConfiguration: Codable {
    public let dialect: UInt8, model: String, profile: String
    public var optIn: Bool, ready: Bool
    public init(dialect: UInt8 = 0, model: String = "s88-tiny-native", profile: String = DurableWire.profile, optIn: Bool = false, ready: Bool = false) {
        self.dialect=dialect; self.model=model; self.profile=profile; self.optIn=optIn; self.ready=ready
    }
    public func validate() throws {
        guard optIn && ready else { throw AdapterError.disabled }
        guard dialect == 2, model == "s88-tiny-native", profile == DurableWire.profile else { throw AdapterError.incompatible }
    }
}
public enum AdapterContract {
    public static let revision = "s88-fixed-request-adapter-v1"
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        try RecoveryCodec.encode(value,maximum:16<<20)
    }
    public static func same<T: Encodable>(_ a:T,_ b:T) throws -> Bool { try encode(a)==encode(b) }
    public static func require(_ value:Bool) throws { if !value { throw AdapterError.invalid } }
    /// These two requests are explicit fixture mappings, not general prompt preparation.
    public static func request(_ route:String) throws -> WireGenerationRequest {
        guard ["ordinary","required"].contains(route) else { throw AdapterError.unavailable }
        let schema=try WireGenerationSchema(jsonValue:.object(["title":.string("Alpha"),"type":.string("object"),
            "properties":.object(["n":.object(["type":.string("integer"),"enum":.array([.integer(7)])])]),
            "required":.array([.string("n")]),"x-order":.array([.string("n")]),"additionalProperties":.bool(false)]))
        return WireGenerationRequest(id:UUID(uuidString:route == "ordinary" ? "00000000-0000-0000-0000-000000000088" : "00000000-0000-0000-0000-000000000089")!,
            portableTranscript:.init(entries:[.prompt(.init(id:"s88-prompt",segments:[.text(.init(id:"s88-text",content:"S88 deterministic "+route))]))]),
            tools:route == "required" ? [.init(name:"alpha",description:"S88 counted fake effect",portableParameters:schema)] : [],
            options:.init(toolCalling:route == "required" ? .required : .disallowed))
    }
    public static func route(_ request:WireGenerationRequest) throws -> String {
        for route in ["ordinary","required"] { if try same(request,self.request(route)) { return route } }
        throw AdapterError.unavailable
    }
    /// Persisted S82 provider request identity binds every canonical wire-request
    /// byte, its original UUID, configuration, route and this fixture revision.
    public static func requestBinding(_ request:WireGenerationRequest, configuration:AdapterConfiguration, route:String) throws -> String {
        try configuration.validate()
        struct Bound: Encodable { let model:String, profile:String, route:String, revision:String; let request:WireGenerationRequest }
        let bytes=try encode(Bound(model:configuration.model,profile:configuration.profile,route:route,revision:revision,request:request))
        return "s88:"+request.id.uuidString.lowercased()+":"+RecoveryCodec.hash(Data("S88/wire-request/v1\0".utf8)+bytes)
    }
    public static func checkReference(_ r:DurableGenerationReference, configuration:AdapterConfiguration,policy:any AdapterRequestPolicy = FixedAdapterRequestPolicy()) throws {
        try policy.validate(configuration); try r.validate()
        try require(r.session.modelID==configuration.model && r.session.profile==configuration.profile)
    }
    public static func witness(_ w:HandoffWitness) throws -> DurableWitness { try JSONDecoder().decode(DurableWitness.self,from:encode(w)) }
    public static func witness(_ w:DurableWitness) throws -> HandoffWitness { try w.validate(); return try JSONDecoder().decode(HandoffWitness.self,from:encode(w)) }
    public static func batch(_ b:DurableBatchPayload) -> HandoffBatch { .init(first:b.first,count:b.count,commit:b.commit,bytes:b.bytes,skip:b.skip) }
    public static func context(_ bytes:Data, reference:DurableGenerationReference, configuration:AdapterConfiguration,policy:any AdapterRequestPolicy = FixedAdapterRequestPolicy()) throws -> ClientAuthority {
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

/// Local fixture controls contain no ticket/context/root-key or nested frame.
public struct WireControl: Codable {
    public var action:String
    public var root:String?, container:String?, password:String?, slot:String?, workers:[FrozenWorker]?
    public var optIn:Bool?, fresh:Bool?, caller:ClientCaller?, allowed:Bool?, time:UInt64?, boundary:String?
    public var dialect:UInt8?, model:String?, profile:String?, route:String?
    public var bootstrapID:String?,hostID:String?,clientID:String?,boot:String?,origin:String?,seedFieldsAbsent:Bool?
    public var stage:String?,code:Int32?,keyCreates:Int?,keyLoads:Int?,calls:Int?,factories:Int?,prefills:Int?,peak:Int?
    public var issues:Int?,begins:Int?,recoveries:Int?,peerReports:Int?
    public var high:UInt64?,terminal:Bool?,phase:String?,disposition:String?,state:String?,result:Data?
    public var metadataPreserved:Bool?,registrationAbsent:Bool?
    public init(_ action:String) { self.action=action }
    public static func failure(_ error:Error) -> Self {
        var r=Self("refused"); r.stage="validation"
        if case RootKeyError.os(let stage,let code)=error { r.stage=stage;r.code=code }
        return r
    }
}
public enum WireLane {
    public enum Input { case control(WireControl), bytes(Data) }
    private static func exact(_ count:Int) throws -> Data {
        var result=Data()
        while result.count<count {
            guard let part=try FileHandle.standardInput.read(upToCount:min(65_536,count-result.count)),!part.isEmpty else { throw HandoffError.closed }
            result.append(part)
        };return result
    }
    public static func read() throws -> Input {
        let h=try exact(5);guard h[0]<=1 else { throw AdapterError.invalid }
        let size=h.dropFirst().reduce(UInt32(0)) { ($0<<8)|UInt32($1) }
        guard size>0,size<=(h[0]==0 ? 2<<20 : (16<<20)+4) else { throw AdapterError.oversized }
        let bytes=try exact(Int(size))
        if h[0]==1 { return .bytes(bytes) }
        return .control(try RecoveryCodec.decode(WireControl.self,bytes,maximum:2<<20))
    }
    public static func control() throws -> WireControl {
        guard case .control(let c)=try read() else { throw AdapterError.invalid };return c
    }
    private static func write(_ bytes:Data,kind:UInt8) throws {
        guard bytes.count>0,bytes.count<=(kind==0 ? 2<<20 : (16<<20)+4) else { throw AdapterError.oversized }
        var n=UInt32(bytes.count).bigEndian
        try FileHandle.standardOutput.write(contentsOf:Data([kind])+withUnsafeBytes(of:&n){Data($0)})
        try FileHandle.standardOutput.write(contentsOf:bytes)
    }
    public static func write(_ control:WireControl) throws { try write(RecoveryCodec.encode(control,maximum:2<<20),kind:0) }
    public static func writeFrame(_ bytes:Data) throws { try write(bytes,kind:1) }
}
public enum WireFixture {
    public static func base() throws -> String {
        guard let p=ProcessInfo.processInfo.environment["S88_FIXTURES"],p.hasPrefix("/private/tmp/reach-durable-session-wire-adapters."),p.hasSuffix("/private/fixtures") else { throw BootstrapError.invalid }
        try RootKeyCodec.directory(p);try RootKeyCodec.require(RootKeyCodec.canonicalExisting(p)==p);return p
    }
    public static func pair(_ path:String) throws {
        try RootKeyCodec.require(RootKeyCodec.parent(path)==base())
        let leaf=String(path.split(separator:"/").last ?? "")
        try RootKeyCodec.require(!leaf.isEmpty && leaf.utf8.count<=80 && leaf.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0==45 })
    }
    public static func container() throws -> String { try base()+"/containers/primary.keychain-db" }
    public static func access(_ workers:[FrozenWorker]) throws -> [RootKeyRole:[FrozenWorker]] {
        let names=["HostWireWorker","ClientWireWorker","KeychainWorker"],prefix=try String(base().dropLast("fixtures".count))
        try RootKeyCodec.require(workers.count==3 && Set(workers.map { String($0.path.split(separator:"/").last ?? "") })==Set(names))
        for worker in workers { try RootKeyCodec.require(worker.path.hasPrefix(prefix));try worker.validate() }
        let host=workers.filter { !$0.path.hasSuffix("/ClientWireWorker") }
        return [.hostCatalog:host,.hostTicket:host,.clientMetadata:workers]
    }
    public static func binding(_ core:BootstrapCore) throws -> RecoveryBinding {
        try .init(bootstrap:core.identifier,core:core.binding(),clientRoot:core.clientID,host:core.hostID,boot:core.policy.boot,hostPolicy:core.policy.hostClock,clientPolicy:core.policy.clientClock)
    }
}
public final class WireKeyMetrics {
    public var creates=0,loads=0
    public init() {}
    public func provider(_ core:BootstrapCore,access:[RootKeyRole:[FrozenWorker]]=[:]) throws -> any RootKeyProvider {
        try RootKeyCodec.require(core.container==WireFixture.container())
        return Metered(MacKeychainProvider(container:try .openExisting(at:core.container),initialAccess:access),self)
    }
    private final class Metered:RootKeyProvider {
        let wrapped:any RootKeyProvider,metrics:WireKeyMetrics
        init(_ p:any RootKeyProvider,_ m:WireKeyMetrics){wrapped=p;metrics=m}
        func create(_ r:RootKeyReference,binding:String) throws -> RootKeyMaterial { metrics.creates+=1;return try wrapped.create(r,binding:binding) }
        func load(_ r:RootKeyReference,binding:String) throws -> RootKeyMaterial { metrics.loads+=1;return try wrapped.load(r,binding:binding) }
    }
}
