import Foundation
import ReachWire
import DurableClientReceipts
import DurableStoreBootstrap
import RecoveryContract
import HostClientContract
import WireAdapterContract

/// Local selected-journal adapter. A caller-authenticated local host byte lane
/// is a configuration prerequisite; decoding does not authenticate a remote peer.
public final class DurableClientWireAdapter {
    public var configuration:AdapterConfiguration
    public let owner:DurableClientReceipts,authorization:ClientAuthorization,core:BootstrapCore
    public let requestPolicy:any AdapterRequestPolicy
    public var publicationHook:() throws -> Void = {}
    public private(set) var negotiation:DurableNegotiation
    public private(set) var peerReports=0,recoveryEntries=0
    private var frames=AdapterFrames(),ticket:Data?,reference:DurableGenerationReference?,authority:ClientAuthority?,handle:ClientHandle?
    private var beginRequestBinding:String?
    private let parent:String,binding:RecoveryBinding,allowNew:Bool,frozenCaller:Data
    public init(configuration:AdapterConfiguration,owner:DurableClientReceipts,authorization:ClientAuthorization,core:BootstrapCore,parent:String,allowNew:Bool,requestPolicy:any AdapterRequestPolicy = FixedAdapterRequestPolicy()) throws {
        try requestPolicy.validate(configuration);self.requestPolicy=requestPolicy
        self.configuration=configuration;self.owner=owner;self.authorization=authorization;self.core=core;self.parent=parent;self.allowNew=allowNew
        binding=try WireFixture.binding(core);frozenCaller=try AdapterContract.encode(authorization.caller)
        negotiation=try .init(selectedDialect:configuration.dialect,modelID:configuration.model,localOptIn:configuration.optIn)
        try gate()
    }
    private func gate() throws {
        try requestPolicy.validate(configuration)
        guard authorization.allowed,try AdapterContract.encode(authorization.caller)==frozenCaller else { throw AdapterError.unauthorized }
    }
    private func check(_ a:ClientAuthority,_ r:DurableGenerationReference) throws {
        try gate();_=try AdapterContract.context(a.bytes,reference:r,configuration:configuration,policy:requestPolicy)
        try AdapterContract.require(a.context.host==core.hostID && a.context.store==core.hostID && AdapterContract.encode(a.context.caller)==frozenCaller)
    }
    private func current() throws -> (ClientAuthority,ClientHandle,DurableGenerationReference) {
        try gate();guard let authority,let handle,let reference else { throw AdapterError.unavailable }
        try check(authority,reference);return (authority,handle,reference)
    }
    private func publishCheck() throws {
        try publicationHook();try gate()
        if let authority,let handle { _=try owner.hostWitness(handle,authority:authority,authorization:authorization) }
    }
    public func open(requestID:String) throws -> Data {
        try gate();guard allowNew else { throw AdapterError.unavailable }
        return try negotiation.send(.open(.init(.init(requestID:requestID,modelID:configuration.model,profile:configuration.profile,durable:true))))
    }
    public func begin(requestID:String,generation:String,operation:String,request:WireGenerationRequest) throws -> Data {
        try gate();guard allowNew,let ticket,let selected=reference?.session else { throw AdapterError.unavailable }
        let route=try requestPolicy.route(request)
        let expected=try requestPolicy.requestBinding(request,configuration:configuration,route:route)
        let r=DurableGenerationReference(session:selected,generationID:generation,operationID:operation)
        let bytes=try negotiation.send(.begin(.init(.init(requestID:requestID,reference:r,ticket:ticket,request:request))))
        reference=r;beginRequestBinding=expected;return bytes
    }
    public func receive(_ input:Data) throws {
        try gate()
        for message in try frames.receive(input,version:configuration.dialect) {
            var next=negotiation;_=try next.receive(AdapterFrames.raw(message))
            switch message {
            case .capabilities:break
            case .opened(let f):
                guard allowNew else { throw AdapterError.unavailable }
                let p=f.payload,claims=try RecoveryTicketClaims.parse(p.ticket)
                try AdapterContract.require(claims.incarnation==core.hostID && claims.boot==core.policy.boot && claims.policy==core.policy.hostClock && claims.namespace==p.session.sessionID && AdapterContract.encode(claims.caller)==frozenCaller)
                ticket=p.ticket
                reference = .init(session:p.session,generationID:"pending",operationID:"pending")
            case .accepted(let f):
                let p=f.payload,a=try AdapterContract.context(p.context,reference:p.reference,configuration:configuration,policy:requestPolicy)
                try check(a,p.reference);try AdapterContract.require(p.contextDigest==RecoveryCodec.hash(a.bytes))
                if p.kind == .begin {
                    guard allowNew,let ticket else { throw AdapterError.unavailable }
                    // Correlate the complete locally sent request/configuration,
                    // not a different supported mapping selected by the reply.
                    guard let beginRequestBinding,a.context.request==beginRequestBinding else { throw AdapterError.invalid }
                    let h=try owner.open(a,authorization:authorization)
                    try owner.enrollRecovery(in:parent,binding:binding)
                    guard let selection=try owner.discover(binding:binding,authorization:authorization).first(where:{$0.contextDigest==p.contextDigest}) else { throw AdapterError.unavailable }
                    try owner.registerRecoveryTicket(ticket,selection:selection,in:parent,binding:binding,authorization:authorization)
                    authority=a;handle=h;reference=p.reference
                } else {
                    guard let authority,let reference,try AdapterContract.same(reference,p.reference),authority.bytes==p.context else { throw AdapterError.invalid }
                }
            case .batch(let f):
                let (a,h,r)=try current(),p=f.payload
                try AdapterContract.require(AdapterContract.same(r,p.reference) && p.contextDigest==RecoveryCodec.hash(a.bytes))
                let cursor=try owner.hostWitness(h,authority:a,authorization:authorization).high
                _=try owner.acceptHostBatch(AdapterContract.batch(p),requestedCursor:cursor,handle:h,authority:a,authorization:authorization)
            case .receiptAccepted(let f):
                let (a,h,_)=try current()
                let witness=try owner.hostWitness(h,authority:a,authorization:authorization)
                try AdapterContract.require(AdapterContract.same(AdapterContract.witness(witness),f.payload.witness))
            case .knowledge(let f):
                let (a,h,r)=try current()
                try AdapterContract.require(AdapterContract.same(r,f.payload.reference))
                try AdapterContract.checkKnowledge(f.payload,authority:a,call:AdapterContract.call(owner.inbox(h,authority:a,authorization:authorization)))
                peerReports+=1 // No intent, permission, outcome write or tool invocation.
            case .refused:break
            default:throw AdapterError.invalid
            }
            try publishCheck();negotiation=next
        }
    }
    /// Fresh local entry has no credential arguments: selected encrypted disk
    /// state is the sole source of original ticket/context/request identity.
    public func recover(requestID:String) throws -> Data {
        try gate();guard !allowNew else { throw AdapterError.invalid }
        let summaries=try owner.discover(binding:binding,authorization:authorization)
        guard summaries.count==1 else { throw AdapterError.unavailable }
        let selected=summaries[0]
        _=try owner.resolve(selected,binding:binding,authorization:authorization)
        let join=try owner.recoverHostJoin(selected,in:parent,binding:binding,authorization:authorization)
        let c=join.client.authority.context
        let r=DurableGenerationReference(session:.init(modelID:configuration.model,profile:configuration.profile,sessionID:c.namespace),generationID:c.generation,operationID:c.operation)
        try check(join.client.authority,r)
        var next=negotiation
        let bytes=try next.send(.recover(.init(.init(requestID:requestID,reference:r,ticket:join.ticket,context:join.client.authority.bytes,
            contextDigest:RecoveryCodec.hash(join.client.authority.bytes),clientRoot:core.clientID,witness:AdapterContract.witness(join.witness)))))
        authority=join.client.authority;handle=join.client.handle;reference=r;ticket=join.ticket
        try publishCheck();negotiation=next;recoveryEntries+=1;return bytes
    }
    public func receipt(requestID:String) throws -> Data {
        let (a,h,r)=try current(),w=try owner.hostWitness(h,authority:a,authorization:authorization)
        var next=negotiation
        let bytes=try next.send(.receipt(.init(.init(requestID:requestID,reference:r,witness:AdapterContract.witness(w)))))
        try publishCheck();negotiation=next;return bytes
    }
    public func witness() throws -> HandoffWitness {
        let (a,h,_)=try current();return try owner.hostWitness(h,authority:a,authorization:authorization)
    }
    public func knowledge() throws -> Data {
        let (a,h,r)=try current(),call=try AdapterContract.call(owner.inbox(h,authority:a,authorization:authorization))
        let state=try owner.effect(call,handle:h,authority:a,authorization:authorization)
        let outcome:DurableOutcome?
        switch state {
        case .unbegun:throw AdapterError.unavailable
        case .unknown:outcome=nil
        case .known(let value):outcome=try JSONDecoder().decode(DurableOutcome.self,from:AdapterContract.encode(value))
        }
        let message=DurableMessage.knowledge(.init(.init(reference:r,contextDigest:RecoveryCodec.hash(a.bytes),callID:call.id,name:call.name,arguments:call.arguments,state:outcome==nil ? .unknown : .known,outcome:outcome)))
        var next=negotiation;let bytes=try next.send(message)
        try publishCheck();negotiation=next;return bytes
    }
    public func localKnowledge() throws -> EffectKnowledge {
        try gate()
        if authority==nil {
            let selected=try owner.discover(binding:binding,authorization:authorization)
            guard selected.count==1 else { throw AdapterError.unavailable }
            let client=try owner.resolve(selected[0],binding:binding,authorization:authorization),c=client.authority.context
            let r=DurableGenerationReference(session:.init(modelID:configuration.model,profile:configuration.profile,sessionID:c.namespace),generationID:c.generation,operationID:c.operation)
            try check(client.authority,r);authority=client.authority;handle=client.handle;reference=r
        }
        let (a,h,_)=try current(),call=try AdapterContract.call(owner.inbox(h,authority:a,authorization:authorization))
        return try owner.effect(call,handle:h,authority:a,authorization:authorization)
    }
    /// Trusted LOCAL operations, deliberately separate from peer-report receipt.
    public func beginLocalEffect() throws -> BeginEffectResult {
        let (a,h,_)=try current(),call=try AdapterContract.call(owner.inbox(h,authority:a,authorization:authorization))
        return try owner.beginEffect(call,handle:h,authority:a,authorization:authorization)
    }
    public func recordLocalOutcome(_ result:Data) throws {
        let (a,h,_)=try current(),call=try AdapterContract.call(owner.inbox(h,authority:a,authorization:authorization))
        let outcome=try ClientOutcome.make(kind:.success,result:result,binding:call,authority:a)
        _=try owner.recordOutcome(outcome,binding:call,handle:h,authority:a,authorization:authorization)
    }
}
