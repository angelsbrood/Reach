import Foundation
import Darwin
import MLX
import LifecycleFixtures
import DurableSessionLifecycle
import DurableClientReceipts
import DurableRootKeys
import DurableStoreBootstrap
import HostClientContract
import RecoveryFixtures

do {
    let config = try RecoveryPipe.read()
    guard ["setup","recover"].contains(config.action) else { throw BootstrapError.invalid }
    guard config.optIn == true else {
        var off = RecoveryMessage("disabled"); off.keyCreates = 0; off.keyLoads = 0; try RecoveryPipe.write(off); exit(0)
    }
    guard let path = config.root, let fresh = config.fresh, config.password == nil, config.ticket == nil, config.context == nil, let currentCaller=config.caller,
          config.action != "recover" || !fresh else { throw BootstrapError.invalid }
    try RecoveryFixture.pair(path)
    let metrics = KeyAccessMetrics(), policy = try RecoveryFixture.policy(config)
    let fixtureClock = try config.time.map { try FixtureLifecycleClock(id:"s86-host",time:$0) }
    let clock: any LifecycleClock = fixtureClock ?? SystemLifecycleClock()
    let clientClock: any ClientClock = try config.time.map { try FixtureClientClock(id:"s86-client",time:$0) } ?? SystemClientClock()
    try RootKeyCodec.require(clock.policy == policy.hostClock && clientClock.policy == policy.clientClock)
    var boundary = config.boundary ?? ""
    func pause(_ point: String) throws {
        if boundary == point {
            var message = RecoveryMessage("boundary"); message.boundary = point; try RecoveryPipe.write(message)
            guard try RecoveryPipe.read().action == "continue" else { throw BootstrapError.invalid }
        }
    }
    func hostIdentity(_ core: BootstrapCore) throws -> LifecycleIdentity {
        let identity = try LifecycleIdentity(incarnation:core.hostID,clock:clock,quota:core.policy.hostQuota)
        try RootKeyCodec.require(identity.boot == core.policy.boot); return identity
    }
    func hostKeys(_ keys: BootstrapKeys) throws -> LifecycleKeys {
        try keys.key(.hostCatalog).use { catalog in try keys.key(.hostTicket).use { try LifecycleKeys(catalog:catalog,ticket:$0) } }
    }
    if fresh {
        guard let container = config.container, let workers = config.workers, config.ticket == nil else { throw BootstrapError.invalid }
        try RootKeyCodec.require(container == RecoveryFixture.container())
        let access = try RecoveryFixture.access(workers)
        _ = try DurableStoreBootstrap.create(optIn:true,at:path,container:container,policy:policy,
            provider:{ try metrics.provider($0,access:access) },initializeStores:{ core,keys in
                let host = try DurableSessionLifecycle.initialize(at:path+"/host",identity:hostIdentity(core),keys:hostKeys(keys),clock:clock)
                host.close()
                let environment = try ClientEnvironment(rootID:core.clientID,clock:clientClock,quota:core.policy.clientQuota)
                try RootKeyCodec.require(environment.boot == core.policy.boot)
                let client = try keys.key(.clientMetadata).use {
                    try DurableClientReceipts(path:path+"/client",create:true,environment:environment,metadataKey:$0,clock:clientClock)
                }
                client.close()
            },hook:{ try pause($0.rawValue) })
    } else { try RootKeyCodec.require(config.workers == nil) }
    guard let acquired = try DurableStoreBootstrap.acquire(optIn:true,at:path,role:.host,policy:policy,provider:{ try metrics.provider($0) }) else { throw BootstrapError.disabled }
    let core = acquired.descriptor.core
    let owner = try DurableSessionLifecycle.reopen(at:acquired.journal,identity:hostIdentity(core),keys:hostKeys(acquired.keys),clock:clock)
    defer { owner.close() }; boundary = ""
    let auth = LifecycleAuthorization(caller:.init(principal:currentCaller.principal,device:currentCaller.device,app:currentCaller.app),allowed:config.allowed ?? true)
    owner.fault = { try pause($0.rawValue) }
    var ticket:SessionTicket?, attachment: LifecycleAttachment?, setup: PFSetup?
    func status(_ value: LifecycleStatus) -> RecoveryMessage {
        var result = RecoveryMessage("ok"); result.high = value.high; result.terminal = value.providerEnding != nil
        result.phase = value.phase.rawValue; result.disposition = value.disposition; result.calls = setup?.calls ?? 0
        result.factories = setup?.factories ?? 0; result.peak = Memory.peakMemory; return result
    }
    var ready=RecoveryFixture.identity(core,metrics:metrics); ready.seedFieldsAbsent=true; ready.origin="bootstrap-only-host-entry"
    try RecoveryPipe.write(ready)
    while true {
        let request = try RecoveryPipe.read(); boundary = request.boundary ?? ""
        if request.action == "close" { try RecoveryPipe.write(.init("closed")); break }
        do {
            if let time = request.time { guard let fixtureClock else { throw BootstrapError.invalid }; fixtureClock.time = time }
            if let allowed = request.allowed { auth.allowed = allowed }
            var response = RecoveryMessage("ok")
            if request.action == "issue" {
                guard config.action == "setup", ticket == nil else { throw BootstrapError.invalid }
                ticket = try owner.issueTicket(authorization:auth); response.ticket = ticket!.data
            } else if request.action == "inspect" {
                response = RecoveryFixture.identity(core,metrics:metrics)
            } else if request.action == "maintenance" { try owner.maintenance() }
            else {
                if request.action == "attach-recovered" {
                    guard config.action == "recover", ticket == nil, let bytes=request.ticket, request.context != nil, request.origin == "selected-client-record-and-ticket-envelope" else { throw BootstrapError.invalid }
                    ticket=try SessionTicket(data:bytes)
                }
                guard let ticket else { throw BootstrapError.invalid }
                switch request.action {
                case "begin", "attach-recovered":
                    guard let name=request.generation, request.route=="ordinary", auth.allowed else { throw BootstrapError.invalid }
                    let state:LifecycleStatus
                    if request.action=="begin" {
                        guard config.action=="setup" else { throw BootstrapError.invalid }
                        setup=try Device.withDefaultDevice(Device(.cpu)) { try PFSetup("ordinary") }
                        setup!.binding.operationID="s86-operation:"+name; setup!.binding.requestID="s86-request:"+name
                        state=try owner.begin(ticket:ticket,authorization:auth,generation:name,provider:setup!.binding)
                    } else {
                        guard let witness=request.witness else { throw BootstrapError.invalid }
                        state=try owner.attachClient(ticket:ticket,authorization:auth,generation:name,witness:witness,expectedClientRoot:core.clientID)
                    }
                    attachment=state.attachment
                    if let attachment {
                        let context=try owner.exportClientContext(ticket:ticket,authorization:auth,attachment:attachment)
                        if request.action=="attach-recovered" {
                            guard request.context==context else { throw BootstrapError.invalid }
                            // No native setup until existing host MAC/auth/context/witness validation succeeds.
                            setup=try Device.withDefaultDevice(Device(.cpu)) { try PFSetup("ordinary") }
                            setup!.binding.operationID="s86-operation:"+name; setup!.binding.requestID="s86-request:"+name
                        }
                        response=status(state); response.context=context
                    } else { response=status(state) }
                case "step":
                    guard let attachment, let setup else { throw BootstrapError.invalid }
                    response = try status(owner.step(ticket:ticket,authorization:auth,attachment:attachment) { setup.runtime })
                    try pause("afterStep")
                case "replay":
                    guard let attachment, let cursor = request.cursor else { throw BootstrapError.invalid }
                    for frame in try owner.replayForClient(ticket:ticket,authorization:auth,attachment:attachment,after:cursor) {
                        var part = RecoveryMessage("batch"); part.frame = frame; try RecoveryPipe.write(part)
                        guard try RecoveryPipe.read().action == "next" else { throw BootstrapError.invalid }
                    }
                    response.action = "replay-end"
                case "receipt":
                    guard let witness = request.witness, let generation = request.generation else { throw BootstrapError.invalid }
                    response = try status(owner.acceptClientWitness(witness,expectedClientRoot:core.clientID,ticket:ticket,
                        authorization:auth,generation:generation,attachment:attachment))
                case "validate":
                    guard let attachment, let setup else { throw BootstrapError.invalid }
                    try assertOutcome(owner.replay(ticket:ticket,authorization:auth,attachment:attachment,after:0),setup:setup)
                default: throw BootstrapError.invalid
                }
            }
            try RootKeyCodec.require(Memory.peakMemory <= 128<<20); try RecoveryPipe.write(response)
        } catch { try RecoveryPipe.write(.failure(error)) }
    }
} catch { var result = RecoveryMessage.failure(error); result.action = "unavailable"; try? RecoveryPipe.write(result); exit(1) }
