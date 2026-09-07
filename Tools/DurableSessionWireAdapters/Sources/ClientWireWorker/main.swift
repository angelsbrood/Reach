import Foundation
import Darwin
import DurableClientReceipts
import DurableRootKeys
import DurableStoreBootstrap
import WireAdapterContract
import DurableClientWireAdapter

do {
    let config=try WireLane.control()
    guard ["setup","recover"].contains(config.action) else { throw AdapterError.invalid }
    let configuration=AdapterConfiguration(dialect:config.dialect ?? 0,model:config.model ?? "s88-tiny-native",profile:config.profile ?? "reach-durable-session-v1",optIn:config.optIn ?? false,ready:true)
    if !configuration.optIn { var off=WireControl("disabled");off.keyCreates=0;off.keyLoads=0;try WireLane.write(off);exit(0) }
    try configuration.validate()
    guard let path=config.root,let caller=config.caller,config.password==nil,config.workers==nil,config.container==nil,config.allowed != false,
          config.action != "recover" || (config.fresh==false && config.route==nil && config.result==nil) else { throw AdapterError.invalid }
    try WireFixture.pair(path)
    let auth=ClientAuthorization(caller:caller),clock:any ClientClock=try config.time.map {try FixtureClientClock(id:"s88-client",time:$0)} ?? SystemClientClock()
    let policy=try BootstrapPolicy(boot:RootKeyCodec.boot(),hostClock:config.time==nil ? "system-monotonic-raw-ns-v1" : "fixture-ns-v1:s88-host",clientClock:clock.policy)
    let metrics=WireKeyMetrics()
    guard let acquired=try DurableStoreBootstrap.acquire(optIn:true,at:path,role:.client,policy:policy,provider:{try metrics.provider($0)}) else { throw BootstrapError.disabled }
    let core=acquired.descriptor.core,environment=try ClientEnvironment(rootID:core.clientID,clock:clock,quota:core.policy.clientQuota)
    let owner=try acquired.keys.key(.clientMetadata).use {try DurableClientReceipts(path:acquired.journal,create:false,environment:environment,metadataKey:$0,clock:clock)}
    defer { owner.close() }
    let adapter=try DurableClientWireAdapter(configuration:configuration,owner:owner,authorization:auth,core:core,parent:WireFixture.base(),allowNew:config.action=="setup")
    var receiptID=0
    func result(_ action:String) -> WireControl {
        var r=WireControl(action);r.bootstrapID=core.identifier;r.hostID=core.hostID;r.clientID=core.clientID;r.boot=core.policy.boot
        r.keyCreates=metrics.creates;r.keyLoads=metrics.loads
        r.recoveries=adapter.recoveryEntries;r.peerReports=adapter.peerReports
        if let w=try? adapter.witness() { r.high=w.high;r.terminal=w.terminal }
        r.phase=String(describing:adapter.negotiation.phase);return r
    }
    var ready=result("ready");ready.seedFieldsAbsent=true;ready.origin=config.action=="recover" ? "S85-selected-client-bootstrap" : "S85-initial-client-bootstrap";try WireLane.write(ready)
    while true {
        let incoming=try WireLane.read()
        do {
            switch incoming {
            case .bytes(let bytes):
                for start in stride(from:0,to:bytes.count,by:65_536) { try adapter.receive(Data(bytes[start..<min(bytes.count,start+65_536)])) }
                try WireLane.write(result("handled"))
            case .control(let request):
                var response=result("ok")
                switch request.action {
                case "close":owner.close();try WireLane.write(.init("closed"));exit(0)
                case "open":try WireLane.writeFrame(adapter.open(requestID:"open-1"))
                case "begin":guard let route=request.route else {throw AdapterError.invalid};try WireLane.writeFrame(adapter.begin(requestID:"begin-1",generation:"g-1",operation:"s88-operation",request:AdapterContract.request(route)))
                case "recover":try WireLane.writeFrame(adapter.recover(requestID:"recover-1"));response.origin="selected-client-record-and-ticket-envelope"
                case "receipt":receiptID+=1;try WireLane.writeFrame(adapter.receipt(requestID:"receipt-"+String(receiptID)))
                case "retry-receipt":try WireLane.writeFrame(adapter.receipt(requestID:"receipt-"+String(receiptID)))
                case "knowledge":try WireLane.writeFrame(adapter.knowledge())
                case "local-state":
                    switch try adapter.localKnowledge() {case .unbegun:response.state="unbegun";case .unknown:response.state="unknown";case .known(let o):response.state="known";response.result=o.result}
                case "effect":
                    switch try adapter.beginLocalEffect() {case .fresh:response.action="fake-effect";case .unknown:response.state="unknown";case .known(let o):response.state="known";response.result=o.result}
                case "record-local":guard let bytes=request.result else {throw AdapterError.invalid};try adapter.recordLocalOutcome(bytes)
                case "authorization":if let allowed=request.allowed {auth.allowed=allowed};if let caller=request.caller {auth.caller=caller}
                case "inspect":break
                default:throw AdapterError.invalid
                }
                let fresh=result(response.action);response.high=fresh.high;response.terminal=fresh.terminal;response.phase=fresh.phase
                try WireLane.write(response)
            }
        } catch {try WireLane.write(.failure(error))}
    }
} catch {var r=WireControl.failure(error);r.action="unavailable";try? WireLane.write(r);exit(1)}
