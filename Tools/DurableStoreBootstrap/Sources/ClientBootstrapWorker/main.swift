import Foundation
import Darwin
import DurableClientReceipts
import DurableRootKeys
import DurableStoreBootstrap
import HostClientContract
import BootstrapFixtures

do {
    let config = try BootstrapPipe.read()
    guard config.action == "open" else { throw BootstrapError.invalid }
    guard config.optIn == true else {
        var off = BootstrapMessage("disabled"); off.keyCreates = 0; off.keyLoads = 0; try BootstrapPipe.write(off); exit(0)
    }
    guard let path = config.root, config.fresh == false, config.password == nil, config.workers == nil else { throw BootstrapError.invalid }
    try BootstrapFixture.pair(path)
    let metrics = KeyAccessMetrics(), policy = try BootstrapFixture.policy(config)
    let fixtureClock = try config.time.map { try FixtureClientClock(id:"s85-client",time:$0) }
    let clock: any ClientClock = fixtureClock ?? SystemClientClock()
    try RootKeyCodec.require(clock.policy == policy.clientClock)
    guard let acquired = try DurableStoreBootstrap.acquire(optIn:true,at:path,role:.client,policy:policy,provider:{ try metrics.provider($0) }) else { throw BootstrapError.disabled }
    let core = acquired.descriptor.core
    let authority = try config.context.map { try ClientAuthority(HandoffContract.decode(ClientContext.self,$0,maximum:HandoffContract.context)) }
    let auth = authority.map { ClientAuthorization(caller:$0.context.caller,allowed:config.allowed ?? true) }
    if let authority, let auth {
        try RootKeyCodec.require(Data(authority.context.host.utf8) == Data(core.hostID.utf8) && Data(authority.context.store.utf8) == Data(core.hostID.utf8) && authority.context.revision == HandoffContract.revision)
        let now = try clock.now()
        try RootKeyCodec.require(auth.allowed && now >= authority.context.issued && now < authority.context.expires)
    }
    let environment = try ClientEnvironment(rootID:core.clientID,clock:clock,quota:core.policy.clientQuota)
    try RootKeyCodec.require(environment.boot == core.policy.boot)
    var boundary = ""
    func pause(_ point: String) throws {
        if boundary == point {
            var message = BootstrapMessage("boundary"); message.boundary = point; try BootstrapPipe.write(message)
            guard try BootstrapPipe.read().action == "continue" else { throw BootstrapError.invalid }
        }
    }
    let owner = try acquired.keys.key(.clientMetadata).use {
        try DurableClientReceipts(path:acquired.journal,create:false,environment:environment,metadataKey:$0,clock:clock) { try pause($0.rawValue) }
    }
    defer { owner.close() }
    let handle = try authority.map { try owner.open($0,authorization:auth!) }
    func tool(_ handle: ClientHandle, _ a: ClientAuthority, _ auth: ClientAuthorization) throws -> ToolBinding {
        for bytes in try owner.inbox(handle,authority:a,authorization:auth) {
            for event in try ClientEvents.decode(bytes) {
                if case .toolCallAppendArguments(_,let id,let name,let args,_) = event {
                    return try .init(id:Data(id.utf8),name:Data(name.utf8),arguments:Data(args.utf8))
                }
            }
        }
        throw BootstrapError.invalid
    }
    var ready = BootstrapFixture.identity(core,metrics:metrics)
    if let handle, let authority, let auth { ready.witness = try owner.hostWitness(handle,authority:authority,authorization:auth) }
    try BootstrapPipe.write(ready)
    while true {
        let request = try BootstrapPipe.read(); boundary = request.boundary ?? ""
        if request.action == "close" { try BootstrapPipe.write(.init("closed")); break }
        do {
            if let time = request.time { guard let fixtureClock else { throw BootstrapError.invalid }; fixtureClock.time = time }
            if let allowed = request.allowed { auth?.allowed = allowed }
            var response = BootstrapMessage("ok")
            if request.action == "inspect" { response = BootstrapFixture.identity(core,metrics:metrics) }
            else if request.action == "maintenance" { try owner.maintenance() }
            else {
                guard let handle, let a = authority, let auth else { throw BootstrapError.invalid }
                switch request.action {
                case "seed-knowledge":
                    // Separate synthetic S83 effect fixture; never represents native host output.
                    try RootKeyCodec.require(a.context.generation == "s85-knowledge-fixture" && a.context.operation == "s85-knowledge-operation" &&
                        a.context.request == "s85-knowledge-request" && a.context.route == "required" &&
                        a.context.upstreamDigest == RootKeyCodec.hash(Data("S85/knowledge-fixture/v1".utf8)+Data(core.identifier.utf8)))
                    try RootKeyCodec.require(owner.hostWitness(handle,authority:a,authorization:auth).high == 0)
                    let bytes = try ClientEvents.encode([.toolCallAppendArguments(entryID:"s85-fake-entry",id:"s85-fake-call",name:"fake",content:"{}",tokenCount:1),
                        .usage(inputTokens:1,outputTokens:1),.finished(.complete)])
                    let frame = HandoffBatch(first:1,count:3,commit:RootKeyCodec.hash(Data("S85/synthetic-knowledge-batch/v1".utf8)),bytes:bytes)
                    response.witness = try owner.acceptHostBatch(frame,requestedCursor:0,handle:handle,authority:a,authorization:auth)
                case "accept":
                    guard let frame = request.frame, let cursor = request.cursor else { throw BootstrapError.invalid }
                    response.witness = try owner.acceptHostBatch(frame,requestedCursor:cursor,handle:handle,authority:a,authorization:auth)
                case "witness": response.witness = try owner.hostWitness(handle,authority:a,authorization:auth)
                case "begin", "effect":
                    let binding = try tool(handle,a,auth)
                    switch try owner.beginEffect(binding,handle:handle,authority:a,authorization:auth) {
                    case .fresh:
                        response.state = "fresh"
                        if request.action == "effect" {
                            try BootstrapPipe.write(.init("fake-effect"))
                            guard try BootstrapPipe.read().action == "effect-recorded" else { throw BootstrapError.invalid }
                            try pause("afterFakeEffect")
                            let outcome = try ClientOutcome.make(kind:.success,result:Data("s85-known-result".utf8),binding:binding,authority:a)
                            _ = try owner.recordOutcome(outcome,binding:binding,handle:handle,authority:a,authorization:auth)
                            response.state = "known"; response.result = outcome.result
                        }
                    case .unknown: response.state = "unknown"
                    case .known(let outcome): response.state = "known"; response.result = outcome.result
                    }
                case "state":
                    switch try owner.effect(tool(handle,a,auth),handle:handle,authority:a,authorization:auth) {
                    case .unbegun: response.state = "unbegun"
                    case .unknown: response.state = "unknown"
                    case .known(let outcome): response.state = "known"; response.result = outcome.result
                    }
                default: throw BootstrapError.invalid
                }
            }
            try BootstrapPipe.write(response)
        } catch { try BootstrapPipe.write(.failure(error)) }
    }
} catch { var result = BootstrapMessage.failure(error); result.action = "unavailable"; try? BootstrapPipe.write(result); exit(1) }
