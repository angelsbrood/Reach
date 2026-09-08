import Foundation
import Darwin
import MLX
import ReachWire
import RequestPreparationFixtures
import RequestPreparationContract
import SchemaToolPreparationFixtures
import ResumableMLXProvider

struct Snapshot:Encodable {
    let binding:ProviderBinding,accepted:DurableGenerationAcceptedPayload,batches:[DurableBatchPayload]
    let family:String,descriptor:RequestPreparationContract.ModelDescriptor,traces:[SchemaToolNativeTrace]
    let calls:Int,modelPrepares:Int,requestPreparations:Int,templateCalls:Int,requestTokenizations:Int,repairEncodes:Int,nativeEncodes:Int,entryRequestTokenizations:Int,entryRepairEncodes:Int,entryNativeEncodes:Int,factories:Int,issues:Int,begins:Int,recoveries:Int,peak:Int
    let terminal:Bool
}
do {
    let args=CommandLine.arguments
    guard args.count==5 || args.count==6 else { throw PreparationError.unsupported }
    let mode=args[1],root=args[2],output=args[3],family=args[4]
    guard ["reference","checkpoint-schema","checkpoint-guided","recover"].contains(mode),["llama","state"].contains(family),
        (mode=="recover" && args.count==5) || (mode != "recover" && args.count==6) else { throw PreparationError.unsupported }
    guard output.hasPrefix(try PreparationFixtures.base()+"/"),!output.dropFirst((try PreparationFixtures.base()).count+1).contains("/") else { throw PreparationError.identity }
    try Device.withDefaultDevice(Device(.cpu)) {
        let fixture=try SchemaToolNativeFixture(family:family),pair=try fixture.pair(root:root,fresh:mode != "recover");defer { pair.close() }
        if mode=="recover" { try pair.recover() }
        else { try pair.start(SchemaToolPreparationFixtures.request(args[5])) }
        let n=fixture.native,t=n.tokenizer,entryRequest=t.requestTokenizations,entryRepair=t.repairEncodes,entryNative=t.encodes-t.requestTokenizations-t.repairEncodes
        for _ in 0..<2000 {
            if pair.terminal { break };try pair.step()
            if mode.hasPrefix("checkpoint"),let (pass,model)=fixture.models.last,model.calls>(pass.tokens.count+63)/64+2 {
                if mode=="checkpoint-schema" && pass.kind == .schema,try SchemaToolPreparationFixtures.events(pair.batches).contains(where:{ if case .responseAppend(_,let text,_,_)=$0 { return !text.isEmpty };return false }) { break }
                if mode=="checkpoint-guided" && pass.kind == .tool && pass.index==0 { break }
            }
        }
        guard fixture.prepares==0,Memory.peakMemory<=128<<20,mode.hasPrefix("checkpoint") ? !pair.terminal : pair.terminal else { throw PreparationError.identity }
        if mode.hasPrefix("checkpoint") { _=try pair.exchange(pair.client.receipt(requestID:"checkpoint-receipt")) }
        if mode=="recover" {
            guard n.preparer.preparations==0,t.renders==0,t.requestTokenizations==0,entryRequest==0,pair.host.issues==0,pair.host.begins==0,pair.host.recoveries==1,
                  let first=fixture.models.first,first.1.calls>0,first.1.priorOffsets.first.map({$0>0})==true else { throw PreparationError.identity }
        } else if args[5] != "zero" { guard fixture.calls>0 else { throw PreparationError.identity } }
        let value=try Snapshot(binding:pair.stored(),accepted:pair.accepted!,batches:pair.batches,family:family,descriptor:n.preparer.policy.descriptor,traces:fixture.traces(),calls:fixture.calls,
            modelPrepares:fixture.prepares,requestPreparations:n.preparer.preparations,templateCalls:t.renders,requestTokenizations:t.requestTokenizations,repairEncodes:t.repairEncodes,nativeEncodes:t.encodes-t.requestTokenizations-t.repairEncodes,
            entryRequestTokenizations:entryRequest,entryRepairEncodes:entryRepair,entryNativeEncodes:entryNative,factories:fixture.models.count,issues:pair.host.issues,begins:pair.host.begins,recoveries:pair.host.recoveries,peak:Memory.peakMemory,terminal:pair.terminal)
        let bytes=try PreparationEncoding.encode(value);guard bytes.count<=192<<20 else { throw PreparationError.oversized }
        try bytes.write(to:URL(fileURLWithPath:output),options:.withoutOverwriting)
    }
    print("S92 worker settled")
} catch { fputs("S92 worker refused: \(error)\n",stderr);exit(1) }
