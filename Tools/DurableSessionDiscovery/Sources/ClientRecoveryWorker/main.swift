import Foundation
import Darwin
import DurableClientReceipts
import DurableRootKeys
import DurableStoreBootstrap
import RecoveryContract
import RecoveryFixtures
import HostClientContract

do {
    let config=try RecoveryPipe.read()
    guard ["setup","recover"].contains(config.action) else { throw RecoveryError.invalid }
    guard config.optIn==true else {
        var off=RecoveryMessage("disabled"); off.keyCreates=0; off.keyLoads=0; try RecoveryPipe.write(off); exit(0)
    }
    guard let path=config.root, let suppliedCaller=config.caller, config.password==nil, config.workers==nil,
          config.action != "recover" || (config.ticket==nil && config.context==nil && config.fresh==false) else { throw RecoveryError.invalid }
    try RecoveryFixture.pair(path)
    let auth=ClientAuthorization(caller:suppliedCaller,allowed:config.allowed ?? true)
    guard auth.allowed, [suppliedCaller.principal,suppliedCaller.device,suppliedCaller.app].allSatisfy({ !$0.isEmpty && $0.utf8.count<=256 }) else { throw RecoveryError.unauthorized }
    let metrics=KeyAccessMetrics(), policy=try RecoveryFixture.policy(config)
    let fixtureClock=try config.time.map { try FixtureClientClock(id:"s86-client",time:$0) }
    let clock:any ClientClock=fixtureClock ?? SystemClientClock()
    guard clock.policy==policy.clientClock else { throw RecoveryError.invalid }
    guard let acquired=try DurableStoreBootstrap.acquire(optIn:true,at:path,role:.client,policy:policy,provider:{ try metrics.provider($0) }) else { throw RecoveryError.unavailable }
    let core=acquired.descriptor.core, binding=try RecoveryFixture.binding(core), parent=try RecoveryFixture.base()
    var authority:ClientAuthority?, handle:ClientHandle?, registrationTicket:Data?
    if config.action=="setup" {
        guard let bytes=config.context, let ticket=config.ticket else { throw RecoveryError.invalid }
        let a=try ClientAuthority(HandoffContract.decode(ClientContext.self,bytes,maximum:HandoffContract.context))
        let now=try clock.now()
        guard a.bytes==bytes, try RecoveryCodec.encode(a.context.caller)==RecoveryCodec.encode(suppliedCaller),
              a.context.host==core.hostID,a.context.store==core.hostID,now>=a.context.issued,now<a.context.expires else { throw RecoveryError.invalid }
        authority=a; registrationTicket=ticket
    }
    let environment=try ClientEnvironment(rootID:core.clientID,clock:clock,quota:core.policy.clientQuota)
    guard environment.boot==core.policy.boot else { throw RecoveryError.invalid }
    let owner=try acquired.keys.key(.clientMetadata).use { try DurableClientReceipts(path:acquired.journal,create:false,environment:environment,metadataKey:$0,clock:clock) }
    defer { owner.close() }
    if let authority {
        handle=try owner.open(authority,authorization:auth) // Explicit original setup only.
        if config.fresh==true { try owner.enrollRecovery(in:parent,binding:binding) }
    }
    var boundary=""
    func pause(_ point:String) throws {
        if boundary==point {
            var message=RecoveryMessage("boundary"); message.boundary=point; try RecoveryPipe.write(message)
            guard try RecoveryPipe.read().action=="continue" else { throw RecoveryError.invalid }
        }
    }
    func selection() throws -> RecoverySummary {
        guard let authority else { throw RecoveryError.invalid }
        guard let value=try owner.discover(binding:binding,authorization:auth).first(where:{$0.contextDigest==RecoveryCodec.hash(authority.bytes)}) else { throw RecoveryError.unavailable }; return value
    }
    func tool(_ a:ClientAuthority,_ h:ClientHandle) throws -> ToolBinding {
        for bytes in try owner.inbox(h,authority:a,authorization:auth) {
            for event in try ClientEvents.decode(bytes) {
                if case .toolCallAppendArguments(_,let id,let name,let arguments,_)=event {
                    return try .init(id:Data(id.utf8),name:Data(name.utf8),arguments:Data(arguments.utf8))
                }
            }
        }
        throw RecoveryError.unavailable
    }
    func seedKnowledge(_ original:ClientAuthority) throws {
        // Separate synthetic S83 fixture. These records are never represented as native host output.
        for kind in ["unknown","known"] {
            let c=original.context
            let a=try ClientAuthority(.init(caller:c.caller,host:c.host,store:c.store,namespace:c.namespace,
                generation:"s86-knowledge-"+kind,request:"s86-synthetic-request-"+kind,operation:"s86-synthetic-operation-"+kind,
                upstreamDigest:RecoveryCodec.hash(Data(("S86/synthetic-knowledge/"+kind).utf8)),route:"required",revision:c.revision,issued:c.issued,expires:c.expires))
            let h=try owner.open(a,authorization:auth)
            let bytes=try ClientEvents.encode([.toolCallAppendArguments(entryID:"s86-entry",id:"s86-call",name:"fake",content:"{}",tokenCount:1),
                .usage(inputTokens:1,outputTokens:1),.finished(.complete)])
            _=try owner.acceptHostBatch(.init(first:1,count:3,commit:RecoveryCodec.hash(Data(("S86/batch/"+kind).utf8)),bytes:bytes),requestedCursor:0,handle:h,authority:a,authorization:auth)
            let t=try tool(a,h)
            guard case .fresh=try owner.beginEffect(t,handle:h,authority:a,authorization:auth) else { throw RecoveryError.invalid }
            if kind=="known" {
                try RecoveryPipe.write(.init("fake-effect")); guard try RecoveryPipe.read().action=="effect-recorded" else { throw RecoveryError.invalid }
                let outcome=try ClientOutcome.make(kind:.success,result:Data("s86-known-result".utf8),binding:t,authority:a)
                _=try owner.recordOutcome(outcome,binding:t,handle:h,authority:a,authorization:auth)
            }
        }
    }
    var ready=RecoveryFixture.identity(core,metrics:metrics)
    ready.seedFieldsAbsent=config.context==nil && config.ticket==nil
    if config.action=="recover" {
        ready.summaries=try owner.discover(binding:binding,authorization:auth); ready.origin="selected-client-manifest"
    } else if let authority,let handle { ready.witness=try owner.hostWitness(handle,authority:authority,authorization:auth) }
    try RecoveryPipe.write(ready)
    while true {
        let request=try RecoveryPipe.read(); boundary=request.boundary ?? ""
        if request.action=="close" { try RecoveryPipe.write(.init("closed")); break }
        do {
            // Original ticket/context seeds can enter only the explicit setup entry above.
            guard request.ticket==nil,request.context==nil,request.password==nil,request.workers==nil else { throw RecoveryError.invalid }
            if let caller=request.caller { auth.caller=caller }
            if let allowed=request.allowed { auth.allowed=allowed }
            if let time=request.time { guard let fixtureClock else { throw RecoveryError.invalid }; fixtureClock.time=time }
            var response=RecoveryMessage("ok")
            switch request.action {
            case "discover": response.summaries=try owner.discover(binding:binding,authorization:auth,hook:{ try pause($0.rawValue) })
            case "resolve":
                guard let selected=request.selection else { throw RecoveryError.invalid }
                let client=try owner.resolve(selected,binding:binding,authorization:auth,hook:{ try pause($0.rawValue) })
                authority=client.authority; handle=client.handle
                response.context=client.authority.bytes; response.witness=try owner.hostWitness(client.handle,authority:client.authority,authorization:auth)
                _=try owner.resolve(selected,binding:binding,authorization:auth) // Final publication check after witness IO.
                response.origin="selected-client-snapshot"
            case "recover-ticket":
                let join=try owner.recoverHostJoin(selection(),in:parent,binding:binding,authorization:auth,hook:{ try pause($0.rawValue) })
                authority=join.client.authority; handle=join.client.handle
                response.context=join.client.authority.bytes; response.ticket=join.ticket; response.witness=join.witness
                response.generation=join.client.authority.context.generation; response.route=join.client.authority.context.route
                response.origin="selected-client-record-and-ticket-envelope"
            case "register":
                guard config.action=="setup",let registrationTicket else { throw RecoveryError.invalid }
                try owner.registerRecoveryTicket(registrationTicket,selection:selection(),in:parent,binding:binding,authorization:auth,hook:{ try pause($0.rawValue) })
                response.state="recovery-ready"
            case "seed-knowledge":
                guard config.action=="setup",let authority else { throw RecoveryError.invalid }; try seedKnowledge(authority); response.calls=2
            case "maintenance": try owner.maintainRecovery(in:parent,binding:binding,hook:{ try pause($0.rawValue) })
            case "inspect": response=RecoveryFixture.identity(core,metrics:metrics)
            default:
                guard let authority,let handle else { throw RecoveryError.invalid }
                switch request.action {
                case "accept":
                    guard let frame=request.frame,let cursor=request.cursor else { throw RecoveryError.invalid }
                    response.witness=try owner.acceptHostBatch(frame,requestedCursor:cursor,handle:handle,authority:authority,authorization:auth)
                case "witness": response.witness=try owner.hostWitness(handle,authority:authority,authorization:auth)
                case "state":
                    switch try owner.effect(tool(authority,handle),handle:handle,authority:authority,authorization:auth) {
                    case .unbegun: response.state="unbegun"
                    case .unknown: response.state="unknown"
                    case .known(let value): response.state="known"; response.result=value.result
                    }
                case "begin", "effect":
                    if case .unbegun=try owner.effect(tool(authority,handle),handle:handle,authority:authority,authorization:auth) { throw RecoveryError.invalid }
                    switch try owner.beginEffect(tool(authority,handle),handle:handle,authority:authority,authorization:auth) {
                    case .fresh: throw RecoveryError.invalid // This recovery path never executes a new fake effect.
                    case .unknown: response.state="unknown"
                    case .known(let value): response.state="known"; response.result=value.result
                    }
                default: throw RecoveryError.invalid
                }
            }
            try RecoveryPipe.write(response)
        } catch { try RecoveryPipe.write(.failure(error)) }
    }
} catch { var result=RecoveryMessage.failure(error); result.action="unavailable"; try? RecoveryPipe.write(result); exit(1) }
