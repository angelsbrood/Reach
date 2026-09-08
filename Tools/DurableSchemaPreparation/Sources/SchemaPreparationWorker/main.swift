import Foundation
import Darwin
import MLX
import ReachWire
import RequestPreparationFixtures
import SchemaPreparationFixtures
import RequestPreparationContract
import ResumableMLXProvider

struct Snapshot:Encodable {
    let binding:ProviderBinding,accepted:DurableGenerationAcceptedPayload,batches:[DurableBatchPayload]
    let calls:Int,modelPrepares:Int,requestPreparations:Int,templateCalls:Int,requestTokenizations:Int,entryEncodes:Int,nativeEncodes:Int,factories:Int,issues:Int,begins:Int,recoveries:Int,peak:Int
    let inputs:[[Int]],offsets:[Int],logits:[[Float]],weights:String,terminal:Bool
}
do {
    let args=CommandLine.arguments
    guard (args.count==4 || args.count==5),["reference","checkpoint","recover"].contains(args[1]) else { throw PreparationError.unsupported }
    let mode=args[1],root=args[2],output=args[3]
    guard output.hasPrefix(try PreparationFixtures.base()+"/"),!output.dropFirst((try PreparationFixtures.base()).count+1).contains("/") else { throw PreparationError.identity }
    guard (mode=="recover" && args.count==4) || (mode != "recover" && args.count==5 && ["seven","eight","scalar","zero","short"].contains(args[4])) else { throw PreparationError.unsupported }
    try Device.withDefaultDevice(Device(.cpu)) {
        let pair=try SchemaPreparationFixtures.pair(root:root,fresh:mode != "recover");defer { pair.close() }
        if mode=="recover" {
            try pair.recover()
            guard pair.native.preparer.preparations==0,pair.native.tokenizer.renders==0,pair.native.tokenizer.encodes==0 else { throw PreparationError.identity }
        }
        else { try pair.start(SchemaPreparationFixtures.request(args[4])) }
        let entryEncodes=pair.native.tokenizer.encodes
        for _ in 0..<600 {
            if pair.terminal { break }
            try pair.step()
            if mode=="checkpoint" && pair.native.model.calls>0 {
                if try !SchemaPreparationFixtures.text(pair.batches).isEmpty { break }
            }
        }
        guard (mode != "recover" && args[4]=="zero") || pair.native.model.calls>0 else { throw PreparationError.identity }
        guard pair.native.model.prepares==0,Memory.peakMemory<=128<<20,
              mode=="checkpoint" ? !pair.terminal : pair.terminal else { throw PreparationError.identity }
        if mode=="checkpoint" { _=try pair.exchange(pair.client.receipt(requestID:"checkpoint-receipt")) }
        if mode=="recover" {
            guard pair.native.preparer.preparations==0,pair.native.tokenizer.renders==0,pair.native.tokenizer.requestTokenizations==0,pair.host.issues==0,pair.host.begins==0,pair.host.recoveries==1 else { throw PreparationError.identity }
        }
        let model=pair.native.model
        let snapshot=try Snapshot(binding:pair.stored(),accepted:pair.accepted!,batches:pair.batches,calls:model.calls,modelPrepares:model.prepares,
            requestPreparations:pair.native.preparer.preparations,templateCalls:pair.native.tokenizer.renders,requestTokenizations:pair.native.tokenizer.requestTokenizations,entryEncodes:entryEncodes,nativeEncodes:pair.native.tokenizer.encodes-pair.native.tokenizer.requestTokenizations,factories:pair.native.factories,
            issues:pair.host.issues,begins:pair.host.begins,recoveries:pair.host.recoveries,peak:Memory.peakMemory,
            inputs:model.inputs,offsets:model.priorOffsets,logits:model.outputs,weights:model.weightsIdentity,terminal:pair.terminal)
        let bytes=try PreparationEncoding.encode(snapshot);guard bytes.count<=192<<20 else { throw PreparationError.oversized }
        try bytes.write(to:URL(fileURLWithPath:output),options:.withoutOverwriting)
    }
    print("S90 worker settled")
} catch { fputs("S90 worker refused: \(error)\n",stderr);exit(1) }
