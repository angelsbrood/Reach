import Foundation
import Darwin
import MLX
import DurableSessionLifecycle
import DurableClientReceipts
import DurableRootKeys
import DurableStoreBootstrap
import WireAdapterContract
import WireAdapterFixtures
import DurableHostWireAdapter

do {
    let config=try WireLane.control()
    guard ["setup","recover"].contains(config.action) else { throw AdapterError.invalid }
    let configuration=AdapterConfiguration(dialect:config.dialect ?? 0,model:config.model ?? "s88-tiny-native",profile:config.profile ?? "reach-durable-session-v1",optIn:config.optIn ?? false,ready:true)
    if !configuration.optIn { var off=WireControl("disabled");off.keyCreates=0;off.keyLoads=0;try WireLane.write(off);exit(0) }
    try configuration.validate() // Before path, bootstrap, Keychain or native entry.
    guard let path=config.root,let caller=config.caller,let fresh=config.fresh,config.password==nil,config.allowed != false,
          config.action != "recover" || (!fresh && config.workers==nil && config.container==nil && config.route==nil && config.result==nil) else { throw AdapterError.invalid }
    try WireFixture.pair(path)
    let authorization=LifecycleAuthorization(caller:.init(principal:caller.principal,device:caller.device,app:caller.app),allowed:true)
    let clock:any LifecycleClock=try config.time.map { try FixtureLifecycleClock(id:"s88-host",time:$0) } ?? SystemLifecycleClock()
    let clientClock:any ClientClock=try config.time.map { try FixtureClientClock(id:"s88-client",time:$0) } ?? SystemClientClock()
    let policy=try BootstrapPolicy(boot:RootKeyCodec.boot(),hostClock:clock.policy,clientClock:clientClock.policy)
    let metrics=WireKeyMetrics()
    func identity(_ core:BootstrapCore) throws -> LifecycleIdentity { try .init(incarnation:core.hostID,clock:clock,quota:core.policy.hostQuota) }
    func keys(_ k:BootstrapKeys) throws -> LifecycleKeys { try k.key(.hostCatalog).use { c in try k.key(.hostTicket).use { try .init(catalog:c,ticket:$0) } } }
    if fresh {
        guard config.action=="setup",let container=config.container,let workers=config.workers,container == (try WireFixture.container()) else { throw BootstrapError.invalid }
        let access=try WireFixture.access(workers)
        _=try DurableStoreBootstrap.create(optIn:true,at:path,container:container,policy:policy,provider:{try metrics.provider($0,access:access)},initializeStores:{ core,material in
            let host=try DurableSessionLifecycle.initialize(at:path+"/host",identity:identity(core),keys:keys(material),clock:clock);host.close()
            let environment=try ClientEnvironment(rootID:core.clientID,clock:clientClock,quota:core.policy.clientQuota)
            let client=try material.key(.clientMetadata).use { try DurableClientReceipts(path:path+"/client",create:true,environment:environment,metadataKey:$0,clock:clientClock) };client.close()
        })
    }
    guard let acquired=try DurableStoreBootstrap.acquire(optIn:true,at:path,role:.host,policy:policy,provider:{try metrics.provider($0)}) else { throw BootstrapError.disabled }
    let core=acquired.descriptor.core
    let owner=try DurableSessionLifecycle.reopen(at:acquired.journal,identity:identity(core),keys:keys(acquired.keys),clock:clock)
    defer { owner.close() }
    let native=WireNativeFixture()
    let adapter=try DurableHostWireAdapter(configuration:configuration,owner:owner,authorization:authorization,expectedClientRoot:core.clientID,allowNew:config.action=="setup",
        prepare:{try native.binding($0,reference:$1,configuration:$2)},runtime:{try native.runtime($0,configuration:$1)})
    func result(_ action:String) throws -> WireControl {
        var r=WireControl(action);r.bootstrapID=core.identifier;r.hostID=core.hostID;r.clientID=core.clientID;r.boot=core.policy.boot
        r.keyCreates=metrics.creates;r.keyLoads=metrics.loads;r.calls=native.calls;r.factories=native.factories;r.prefills=native.prefills
        r.issues=adapter.issues;r.begins=adapter.begins;r.recoveries=adapter.recoveries;r.peerReports=adapter.peerReports
        r.peak=Memory.peakMemory;r.high=adapter.status?.high;r.terminal=adapter.status?.providerEnding != nil;r.phase=adapter.status?.phase.rawValue;r.disposition=adapter.status?.disposition
        try AdapterContract.require(Memory.peakMemory<=128<<20);return r
    }
    var ready=try result("ready");ready.seedFieldsAbsent=true;ready.origin="S85-bootstrap-only-host-entry";try WireLane.write(ready)
    while true {
        let incoming=try WireLane.read()
        do {
            switch incoming {
            case .bytes(let bytes):
                for start in stride(from:0,to:bytes.count,by:65_536) {
                    for output in try adapter.receive(Data(bytes[start..<min(bytes.count,start+65_536)])) { try WireLane.writeFrame(output) }
                }
                try WireLane.write(result("handled"))
            case .control(let request):
                switch request.action {
                case "close":owner.close();try WireLane.write(.init("closed"));exit(0)
                case "capabilities":try WireLane.writeFrame(adapter.capabilities())
                case "step":_=try Device.withDefaultDevice(Device(.cpu)) { try adapter.step() }
                case "replay":for frame in try adapter.replay() { try WireLane.writeFrame(frame) }
                case "authorization":
                    if let allowed=request.allowed { authorization.allowed=allowed }
                    if let c=request.caller { authorization.caller = .init(principal:c.principal,device:c.device,app:c.app) }
                case "inspect":break
                default:throw AdapterError.invalid
                }
                try WireLane.write(result("ok"))
            }
        } catch { try WireLane.write(.failure(error)) }
    }
} catch { var r=WireControl.failure(error);r.action="unavailable";try? WireLane.write(r);exit(1) }
