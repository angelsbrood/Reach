import Foundation
import Darwin
import MLX
import LifecycleFixtures
import DurableSessionLifecycle
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
    guard let path = config.root, let fresh = config.fresh, config.password == nil else { throw BootstrapError.invalid }
    try BootstrapFixture.pair(path)
    let metrics = KeyAccessMetrics(), policy = try BootstrapFixture.policy(config)
    let fixtureClock = try config.time.map { try FixtureLifecycleClock(id:"s85-host",time:$0) }
    let clock: any LifecycleClock = fixtureClock ?? SystemLifecycleClock()
    let clientClock: any ClientClock = try config.time.map { try FixtureClientClock(id:"s85-client",time:$0) } ?? SystemClientClock()
    try RootKeyCodec.require(clock.policy == policy.hostClock && clientClock.policy == policy.clientClock)
    var boundary = config.boundary ?? ""
    func pause(_ point: String) throws {
        if boundary == point {
            var message = BootstrapMessage("boundary"); message.boundary = point; try BootstrapPipe.write(message)
            guard try BootstrapPipe.read().action == "continue" else { throw BootstrapError.invalid }
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
        try RootKeyCodec.require(container == BootstrapFixture.container())
        let access = try BootstrapFixture.access(workers)
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
    let auth = caller(); auth.allowed = config.allowed ?? true
    owner.fault = { try pause($0.rawValue) }
    var ticket = try config.ticket.map(SessionTicket.init(data:)), attachment: LifecycleAttachment?, setup: PFSetup?
    func status(_ value: LifecycleStatus) -> BootstrapMessage {
        var result = BootstrapMessage("ok"); result.high = value.high; result.terminal = value.providerEnding != nil
        result.phase = value.phase.rawValue; result.disposition = value.disposition; result.calls = setup?.calls ?? 0
        result.factories = setup?.factories ?? 0; result.peak = Memory.peakMemory; return result
    }
    try BootstrapPipe.write(BootstrapFixture.identity(core,metrics:metrics))
    while true {
        let request = try BootstrapPipe.read(); boundary = request.boundary ?? ""
        if request.action == "close" { try BootstrapPipe.write(.init("closed")); break }
        do {
            if let time = request.time { guard let fixtureClock else { throw BootstrapError.invalid }; fixtureClock.time = time }
            if let allowed = request.allowed { auth.allowed = allowed }
            var response = BootstrapMessage("ok")
            if request.action == "issue" {
                guard ticket == nil else { throw BootstrapError.invalid }
                ticket = try owner.issueTicket(authorization:auth); response.ticket = ticket!.data
            } else if request.action == "inspect" {
                response = BootstrapFixture.identity(core,metrics:metrics)
            } else if request.action == "maintenance" { try owner.maintenance() }
            else {
                guard let ticket else { throw BootstrapError.invalid }
                switch request.action {
                case "begin", "attach":
                    guard let name = request.generation, request.route == "ordinary" else { throw BootstrapError.invalid }
                    setup = try Device.withDefaultDevice(Device(.cpu)) { try PFSetup("ordinary") }
                    setup!.binding.operationID = "s85-operation:"+name; setup!.binding.requestID = "s85-request:"+name
                    let state: LifecycleStatus
                    if request.action == "begin" { state = try owner.begin(ticket:ticket,authorization:auth,generation:name,provider:setup!.binding) }
                    else {
                        guard let witness = request.witness else { throw BootstrapError.invalid }
                        state = try owner.attachClient(ticket:ticket,authorization:auth,generation:name,witness:witness,expectedClientRoot:core.clientID)
                    }
                    attachment = state.attachment; response = status(state)
                    if let attachment { response.context = try owner.exportClientContext(ticket:ticket,authorization:auth,attachment:attachment) }
                case "step":
                    guard let attachment, let setup else { throw BootstrapError.invalid }
                    response = try status(owner.step(ticket:ticket,authorization:auth,attachment:attachment) { setup.runtime })
                    try pause("afterStep")
                case "replay":
                    guard let attachment, let cursor = request.cursor else { throw BootstrapError.invalid }
                    for frame in try owner.replayForClient(ticket:ticket,authorization:auth,attachment:attachment,after:cursor) {
                        var part = BootstrapMessage("batch"); part.frame = frame; try BootstrapPipe.write(part)
                        guard try BootstrapPipe.read().action == "next" else { throw BootstrapError.invalid }
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
            try RootKeyCodec.require(Memory.peakMemory <= 128<<20); try BootstrapPipe.write(response)
        } catch { try BootstrapPipe.write(.failure(error)) }
    }
} catch { var result = BootstrapMessage.failure(error); result.action = "unavailable"; try? BootstrapPipe.write(result); exit(1) }
