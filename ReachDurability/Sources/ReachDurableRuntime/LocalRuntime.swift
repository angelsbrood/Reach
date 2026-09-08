import Foundation
import MLX
import ReachWire
import DurableRootKeys
import DurableStoreBootstrap
import DurableSessionLifecycle
import DurableClientReceipts
import DurableHostWireAdapter
import DurableClientWireAdapter
import WireAdapterContract
import HostClientContract
import RecoveryContract
import RequestPreparationContract
import ResumableMLXProvider

public struct LocalRuntimeReport:Encodable {
    public let stage:String,phase:String?,disposition:String?,providerEnding:WireFinishReason?
    public let high:UInt64,terminal:Bool,nativeCalls:Int,modelPrepares:Int,requestPreparations:Int,templateCalls:Int,requestTokenizations:Int,repairEncodes:Int,nativeEncodes:Int,issues:Int,begins:Int,recoveries:Int
    public let beforeInbox:[HandoffBatch],inbox:[HandoffBatch],binding:ProviderBinding?,accepted:DurableGenerationAcceptedPayload?
    let traces:[NativeObservation]
    public let nativePeak:Int
}
/// Serial local runtime. Command inputs cannot provide clocks, callers, keys,
/// readiness, native factories, or an effect executor.
public final class LocalDurableRuntime {
    private let root:String,core:BootstrapCore,profile:SelectedArtifactProfile,hostOwner:DurableSessionLifecycle,clientOwner:DurableClientReceipts
    private let hostAuthorization:LifecycleAuthorization,clientAuthorization:ClientAuthorization,host:DurableHostWireAdapter,client:DurableClientWireAdapter
    private var accepted:DurableGenerationAcceptedPayload?,binding:ProviderBinding?,beforeInbox:[HandoffBatch]=[]
    private var ticket:SessionTicket?,attachment:LifecycleAttachment?,latest:LifecycleStatus?
    private var closed=false
    public init(root:String,allowBegin:Bool) throws {
        let acquired=try AcquiredLocalRoot(root),invocation=try LocalInvocation(),core=acquired.core,hostClock=SystemLifecycleClock(),clientClock=SystemClientClock()
        self.root=root;self.core=core;profile=acquired.profile;hostAuthorization=invocation.host;clientAuthorization=invocation.client
        let owner=try DurableSessionLifecycle.reopen(at:root+"/bootstrap/host",identity:.init(incarnation:core.hostID,clock:hostClock,quota:core.policy.hostQuota),keys:LocalRuntimeOwner.hostKeys(acquired.hostKeys),clock:hostClock)
        hostOwner=owner
        do {
            let clientOwner=try DurableClientReceipts(path:root+"/bootstrap/client",create:false,environment:.init(rootID:core.clientID,clock:clientClock,quota:core.policy.clientQuota),metadataKey:acquired.clientKeys.key(.clientMetadata).use{$0},clock:clientClock)
            self.clientOwner=clientOwner
            do {
                let selection=profile
                // Reaching this point proves selected artifacts, bootstrap/key
                // confirmation and both exclusive lifecycle owners are available.
                let configuration=AdapterConfiguration(dialect:2,model:selection.preparer.policy.descriptor.model,optIn:true,ready:!owner.uncertain)
                host=try .init(configuration:configuration,owner:owner,authorization:hostAuthorization,expectedClientRoot:core.clientID,allowNew:allowBegin,
                    prepare:{try selection.preparer.prepare($0,reference:$1,configuration:$2)},runtime:{try selection.runtime($0,configuration:$1)},requestPolicy:selection.preparer.policy,
                    validatePrepared:{try selection.preparer.validateStored($0,configuration:$1)})
                client=try .init(configuration:configuration,owner:clientOwner,authorization:clientAuthorization,core:core,parent:root,allowNew:allowBegin,requestPolicy:selection.preparer.policy)
            } catch { clientOwner.close();throw error }
        } catch { owner.close();throw error }
    }
    public static func withCPU<T>(_ body:() throws -> T) rethrows -> T {
        try Device.withDefaultDevice(Device(.cpu)) { Memory.cacheLimit=16<<20;Memory.memoryLimit=128<<20;return try body() }
    }
    public static func writeReport(_ bytes:Data,to path:String?) throws {
        guard bytes.count<=16<<20 else { throw LocalRuntimeError.invalid }
        if let path { try LocalFiles.writeNew(bytes,to:path) }
        else { try FileHandle.standardOutput.write(contentsOf:bytes+Data([10])) }
    }
    public static func request(from path:String) throws -> WireGenerationRequest {
        let bytes=try LocalFiles.read(path,maximum:65536)
        guard let object=try JSONSerialization.jsonObject(with:bytes) as? [String:Any],Set(object.keys).isSubset(of:["id","transcript","tools","schema","options","context"]) else { throw LocalRuntimeError.invalid }
        return try JSONDecoder().decode(WireGenerationRequest.self,from:bytes)
    }
    private func toHost(_ bytes:Data) throws -> [Data] {
        var result:[Data]=[]
        for start in stride(from:0,to:bytes.count,by:65536) { result+=try host.receive(Data(bytes[start..<min(start+65536,bytes.count)])) }
        return result
    }
    private func toClient(_ bytes:Data) throws {
        for start in stride(from:0,to:bytes.count,by:65536) { try client.receive(Data(bytes[start..<min(start+65536,bytes.count)])) }
    }
    private func exchange(_ bytes:Data) throws -> DurableMessage {
        let responses=try toHost(bytes);guard responses.count==1 else { throw LocalRuntimeError.invalid }
        var reassembler=FrameReassembler();let messages=try reassembler.feed(responses[0]);guard messages.count==1 else { throw LocalRuntimeError.invalid }
        let message=try DurableMessage.decode(messages[0],version:2)
        if case .refused=message { throw LocalRuntimeError.refused }
        try toClient(responses[0]);return message
    }
    public func begin(_ request:WireGenerationRequest) throws {
        guard !closed,accepted==nil else { throw LocalRuntimeError.invalid }
        // One generation per explicitly initialized root. Existing selected
        // inboxes require recovery, never a replacement begin.
        guard try clientOwner.discover(binding:BootstrapRecoveryBinding.make(core),authorization:clientAuthorization).isEmpty else { throw LocalRuntimeError.refused }
        try toClient(host.capabilities())
        guard case .opened(let opened)=try exchange(client.open(requestID:"local-open")) else { throw LocalRuntimeError.invalid }
        ticket=try .init(data:opened.payload.ticket)
        let id=request.id.uuidString.lowercased()
        guard case .accepted(let value)=try exchange(client.begin(requestID:"local-begin",generation:"generation-"+id,operation:"operation-"+id,request:request)) else { throw LocalRuntimeError.invalid }
        accepted=value.payload;latest=host.status;attachment=host.status?.attachment
        binding=try hostOwner.wireProviderBinding(ticket:ticket!,authorization:hostAuthorization,generation:value.payload.reference.generationID)
    }
    public func recover() throws {
        guard !closed,accepted==nil else { throw LocalRuntimeError.invalid }
        let recovery=try BootstrapRecoveryBinding.make(core),selections=try clientOwner.discover(binding:recovery,authorization:clientAuthorization)
        guard selections.count==1 else { throw LocalRuntimeError.refused }
        let selected=try clientOwner.resolve(selections[0],binding:recovery,authorization:clientAuthorization)
        beforeInbox=try clientOwner.hostInbox(selected.handle,authority:selected.authority,authorization:clientAuthorization)
        let join=try clientOwner.recoverHostJoin(selections[0],in:root,binding:recovery,authorization:clientAuthorization)
        ticket=try .init(data:join.ticket)
        try toClient(host.capabilities())
        guard case .accepted(let value)=try exchange(client.recover(requestID:"local-recover")) else { throw LocalRuntimeError.invalid }
        accepted=value.payload;latest=host.status;attachment=host.status?.attachment
        binding=try hostOwner.wireProviderBinding(ticket:ticket!,authorization:hostAuthorization,generation:value.payload.reference.generationID)
        // Replay occurs before any native step. A retained native terminal is
        // recovered entirely from committed state, with no model factory.
        try replay()
    }
    private func replay() throws { for bytes in try host.replay() { try toClient(bytes) } }
    public var terminal:Bool { (try? client.witness().terminal) ?? false }
    public func step() throws {
        guard !closed,accepted != nil,!terminal else { throw LocalRuntimeError.invalid }
        _=try exchange(client.receipt(requestID:"local-receipt"))
        latest=try host.step();attachment=latest?.attachment
        try replay()
        guard Memory.peakMemory<=128<<20 else { throw LocalRuntimeError.unsupported }
    }
    public func cancel() throws {
        guard !closed,let ticket,let attachment else { throw LocalRuntimeError.invalid }
        latest=try hostOwner.cancel(ticket:ticket,authorization:hostAuthorization,attachment:attachment)
        // Cancellation is an outer retirement disposition. The committed inbox
        // and any native terminal are kept; no synthetic WireEvent is appended.
    }
    private func inbox() throws -> [HandoffBatch] {
        let recovery=try BootstrapRecoveryBinding.make(core),selected=try clientOwner.discover(binding:recovery,authorization:clientAuthorization)
        guard selected.count==1 else { return [] }
        let client=try clientOwner.resolve(selected[0],binding:recovery,authorization:clientAuthorization)
        return try clientOwner.hostInbox(client.handle,authority:client.authority,authorization:clientAuthorization)
    }
    public func report(stage:String) throws -> LocalRuntimeReport {
        guard !closed else { throw LocalRuntimeError.invalid }
        let t=profile.tokenizer,w=try? client.witness()
        return try .init(stage:stage,phase:latest?.phase.rawValue,disposition:latest?.disposition,providerEnding:latest?.providerEnding,high:w?.high ?? 0,terminal:w?.terminal ?? false,
            nativeCalls:profile.observations.reduce(0){$0+$1.calls},modelPrepares:profile.observations.reduce(0){$0+$1.prepares},requestPreparations:profile.preparer.preparations,templateCalls:t.renders,requestTokenizations:t.requestTokenizations,
            repairEncodes:t.repairEncodes,nativeEncodes:t.encodes-t.requestTokenizations-t.repairEncodes,issues:host.issues,begins:host.begins,recoveries:host.recoveries,
            beforeInbox:beforeInbox,inbox:inbox(),binding:binding,accepted:accepted,traces:profile.observations,nativePeak:Memory.peakMemory)
    }
    public func close() { if !closed { clientOwner.close();hostOwner.close();closed=true } }
    deinit { close() }
}
