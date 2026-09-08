import Foundation
import ReachWire
import DurableSessionLifecycle
import ResumableMLXProvider
import DurableClientReceipts
import HostClientContract
import RecoveryContract
import WireAdapterContract

/// Serial local host adapter. Current authorization/configuration is supplied
/// outside the wire. These fixtures do not authenticate a remote transport.
public final class DurableHostWireAdapter {
    public var configuration:AdapterConfiguration
    public let owner:DurableSessionLifecycle, authorization:LifecycleAuthorization, expectedClientRoot:String
    public let requestPolicy:any AdapterRequestPolicy
    public var publicationHook:() throws -> Void = {}
    public private(set) var status:LifecycleStatus?
    public private(set) var peerReports=0, issues=0, begins=0, recoveries=0
    public private(set) var clientHigh:UInt64=0
    private let allowNew:Bool, frozenCaller:Data
    private let prepare:(WireGenerationRequest,DurableGenerationReference,AdapterConfiguration) throws -> ProviderBinding
    private let runtime:(ProviderBinding,AdapterConfiguration) throws -> ProviderRuntime
    private let validatePrepared:((ProviderBinding,AdapterConfiguration) throws -> Void)?
    private var frames=AdapterFrames(),ticket:SessionTicket?,reference:DurableGenerationReference?,attachment:LifecycleAttachment?,context:Data?
    public init(configuration:AdapterConfiguration,owner:DurableSessionLifecycle,authorization:LifecycleAuthorization,expectedClientRoot:String,allowNew:Bool,
                prepare:@escaping (WireGenerationRequest,DurableGenerationReference,AdapterConfiguration) throws -> ProviderBinding,
                runtime:@escaping (ProviderBinding,AdapterConfiguration) throws -> ProviderRuntime,
                requestPolicy:any AdapterRequestPolicy = FixedAdapterRequestPolicy(),
                validatePrepared:((ProviderBinding,AdapterConfiguration) throws -> Void)? = nil) throws {
        try requestPolicy.validate(configuration)
        guard !requestPolicy.requiresPreparedValidation || validatePrepared != nil else { throw AdapterError.unavailable }
        self.requestPolicy=requestPolicy;self.validatePrepared=validatePrepared
        self.configuration=configuration;self.owner=owner;self.authorization=authorization;self.expectedClientRoot=expectedClientRoot
        self.allowNew=allowNew;self.prepare=prepare;self.runtime=runtime;frozenCaller=try AdapterContract.encode(authorization.caller)
        try gate()
    }
    private func gate() throws {
        try requestPolicy.validate(configuration)
        guard authorization.allowed,try AdapterContract.encode(authorization.caller)==frozenCaller else { throw AdapterError.unauthorized }
    }
    private func session(_ r:DurableSessionReference,_ ticket:SessionTicket) throws {
        try gate();try r.validate()
        try AdapterContract.require(r.modelID==configuration.model && r.profile==configuration.profile)
        guard r.sessionID == (try owner.wireSessionID(ticket:ticket,authorization:authorization)) else { throw AdapterError.invalid }
    }
    private func live(_ r:DurableGenerationReference) throws -> (SessionTicket,LifecycleAttachment,Data) {
        try gate();guard let ticket,let reference,let attachment,let context,try AdapterContract.same(reference,r) else { throw AdapterError.unavailable }
        try session(r.session,ticket)
        let original=try owner.exportClientContext(ticket:ticket,authorization:authorization,attachment:attachment)
        try AdapterContract.require(original==context);return (ticket,attachment,context)
    }
    private func publish(_ message:DurableMessage,ticket:SessionTicket?=nil) throws -> Data {
        let bytes=try message.encode(version:configuration.dialect)
        if let ticket { _=try owner.wireSessionID(ticket:ticket,authorization:authorization,publicationHook:publicationHook) }
        else { try publicationHook() }
        try gate() // Ticket/caller/clock verification does not establish current adapter readiness.
        return bytes
    }
    public func capabilities() throws -> Data {
        try gate();return try publish(.capabilities(.init(.init(modelID:configuration.model,profiles:[configuration.profile]))))
    }
    public func receive(_ input:Data) throws -> [Data] {
        try gate()
        let messages=try frames.receive(input,version:configuration.dialect)
        var output:[Data]=[]
        for message in messages {
            do { output.append(contentsOf:try process(message)) }
            catch {
                let correlation:DurableCorrelation
                switch message {
                case .open(let f):correlation = .init(requestID:f.payload.requestID,operation:.open)
                case .begin(let f):correlation = .init(requestID:f.payload.requestID,operation:.begin,sessionID:f.payload.reference.session.sessionID,generationID:f.payload.reference.generationID)
                case .recover(let f):correlation = .init(requestID:f.payload.requestID,operation:.recover,sessionID:f.payload.reference.session.sessionID,generationID:f.payload.reference.generationID)
                case .receipt(let f):correlation = .init(requestID:f.payload.requestID,operation:.receipt,sessionID:f.payload.reference.session.sessionID,generationID:f.payload.reference.generationID)
                default:throw error
                }
                let reason:DurableRefusalReason
                switch error {
                case LifecycleError.expired,ClientError.expired:reason = .expired
                case LifecycleError.unauthorized,AdapterError.unauthorized:reason = .unauthorized
                case LifecycleError.full,LifecycleError.busy:reason = .busyOrFull
                case AdapterError.unavailable,LifecycleError.nonResumable:reason = .unavailable
                default:reason = .invalid
                }
                output.append(try DurableMessage.refused(.init(.init(correlation:correlation,reason:reason))).encode(version:2))
            }
        }
        guard output.reduce(0,{$0+$1.count})<=32<<20,output.count<=16 else { throw AdapterError.oversized };return output
    }
    private func process(_ message:DurableMessage) throws -> [Data] {
        try gate()
        switch message {
        case .open(let f):
            let p=f.payload
            guard allowNew,ticket==nil,reference==nil,p.modelID==configuration.model,p.profile==configuration.profile else { throw AdapterError.unavailable }
            let issued=try owner.issueTicket(authorization:authorization)
            let id=try owner.wireSessionID(ticket:issued,authorization:authorization)
            let reply=try publish(.opened(.init(.init(requestID:p.requestID,session:.init(modelID:configuration.model,profile:configuration.profile,sessionID:id),ticket:issued.data))),ticket:issued)
            ticket=issued;issues+=1;return [reply]
        case .begin(let f):
            let p=f.payload
            guard allowNew,let ticket,ticket.data==p.ticket else { throw AdapterError.unavailable }
            try session(p.reference.session,ticket)
            if let reference { try AdapterContract.require(AdapterContract.same(reference,p.reference)) }
            _=try requestPolicy.route(p.request) // Admission precedes fixture/native preparation.
            let binding=try prepare(p.request,p.reference,configuration)
            try gate();try session(p.reference.session,ticket)
            try AdapterContract.require(binding.operationID==p.reference.operationID && binding.requestID==requestPolicy.requestBinding(p.request,configuration:configuration,route:binding.lane.route.rawValue))
            try validatePrepared?(binding,configuration)
            let state=try owner.begin(ticket:ticket,authorization:authorization,generation:p.reference.generationID,provider:binding)
            guard let attached=state.attachment else { throw AdapterError.unavailable }
            let bytes=try owner.exportClientContext(ticket:ticket,authorization:authorization,attachment:attached)
            let reply=try publish(.accepted(.init(.init(requestID:p.requestID,reference:p.reference,kind:.begin,context:bytes,contextDigest:RecoveryCodec.hash(bytes)))),ticket:ticket)
            reference=p.reference;attachment=attached;context=bytes;status=state;begins+=1;return [reply]
        case .recover(let f):
            let p=f.payload,incoming=try SessionTicket(data:p.ticket)
            if let ticket { try AdapterContract.require(ticket.data==p.ticket) }
            if let reference { try AdapterContract.require(AdapterContract.same(reference,p.reference)) }
            try session(p.reference.session,incoming)
            try AdapterContract.require(p.clientRoot==expectedClientRoot && p.witness.clientRoot==expectedClientRoot)
            let stored=try owner.wireProviderBinding(ticket:incoming,authorization:authorization,generation:p.reference.generationID)
            try validatePrepared?(stored,configuration) // Selected policy is checked before attach or acceptance.
            let original=try owner.wireOriginalClientContext(ticket:incoming,authorization:authorization,generation:p.reference.generationID)
            let a=try AdapterContract.context(original,reference:p.reference,configuration:configuration,policy:requestPolicy)
            try AdapterContract.require(stored.operationID==p.reference.operationID && a.bytes==p.context && RecoveryCodec.hash(original)==p.contextDigest)
            let state=try owner.attachClient(ticket:incoming,authorization:authorization,generation:p.reference.generationID,
                witness:AdapterContract.witness(p.witness),expectedClientRoot:expectedClientRoot)
            guard let attached=state.attachment else { throw AdapterError.unavailable }
            let exported=try owner.exportClientContext(ticket:incoming,authorization:authorization,attachment:attached)
            try AdapterContract.require(exported==original)
            let reply=try publish(.accepted(.init(.init(requestID:p.requestID,reference:p.reference,kind:.recover,context:exported,contextDigest:p.contextDigest))),ticket:incoming)
            ticket=incoming;reference=p.reference;attachment=attached;context=exported;status=state;clientHigh=p.witness.high;recoveries+=1;return [reply]
        case .receipt(let f):
            let p=f.payload
            guard let ticket,let reference,try AdapterContract.same(reference,p.reference) else { throw AdapterError.unavailable }
            try session(reference.session,ticket)
            // Do not require live request/context export: S84's authenticated
            // tombstone fingerprint is the authority for an exact receipt retry.
            let state=try owner.acceptClientWitness(AdapterContract.witness(p.witness),expectedClientRoot:expectedClientRoot,ticket:ticket,
                authorization:authorization,generation:reference.generationID,attachment:attachment,publicationHook:publicationHook)
            let reply=try publish(.receiptAccepted(.init(.init(requestID:p.requestID,reference:p.reference,witness:p.witness))),ticket:ticket)
            status=state;clientHigh=p.witness.high;return [reply]
        case .knowledge(let f):
            let p=f.payload,(ticket,attachment,bytes)=try live(p.reference)
            let batches=try owner.replayForClient(ticket:ticket,authorization:authorization,attachment:attachment,after:0)
            let authority=try AdapterContract.context(bytes,reference:p.reference,configuration:configuration,policy:requestPolicy)
            try AdapterContract.checkKnowledge(p,authority:authority,call:AdapterContract.call(batches.map(\.bytes)))
            _=try owner.exportClientContext(ticket:ticket,authorization:authorization,attachment:attachment,publicationHook:publicationHook)
            try gate()
            peerReports+=1;return [] // A checked report is neither an outcome store nor effect permission.
        default:throw AdapterError.invalid
        }
    }
    public func step() throws -> LifecycleStatus {
        guard let reference else { throw AdapterError.unavailable }
        let (ticket,attachment,_)=try live(reference)
        let stored=try owner.wireProviderBinding(ticket:ticket,authorization:authorization,generation:reference.generationID)
        try validatePrepared?(stored,configuration)
        let state=try owner.step(ticket:ticket,authorization:authorization,attachment:attachment) { try self.runtime(stored,self.configuration) }
        _=try owner.wireSessionID(ticket:ticket,authorization:authorization,publicationHook:publicationHook)
        try gate()
        status=state;return state
    }
    public func replay() throws -> [Data] {
        guard let reference else { throw AdapterError.unavailable }
        let (ticket,attachment,context)=try live(reference)
        let batches=try owner.replayForClient(ticket:ticket,authorization:authorization,attachment:attachment,after:clientHigh)
        guard batches.count<=4096,batches.reduce(0,{$0+$1.bytes.count})<=16<<20 else { throw AdapterError.oversized }
        let output=try batches.map { b in try publish(.batch(.init(.init(reference:reference,contextDigest:RecoveryCodec.hash(context),first:b.first,count:b.count,commit:b.commit,skip:b.skip,bytes:b.bytes))),ticket:ticket) }
        try gate();return output
    }
}
