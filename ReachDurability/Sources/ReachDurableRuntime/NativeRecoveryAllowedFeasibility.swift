import Foundation
import Dispatch
import MLX
import ReachWire
import ResumableMLXProvider
import WireAdapterContract
import RecoveryAuthorityContract

extension NativeRecoveryRuntime {
    /// Executes the complete selected lane before any witness, role or admission.
    /// Grouped advances mirror the opened unit; each native step is retained.
    public static func probeAllowedFixture(model:String,prepared:String,report:String,
        fixture:AllowedRecoveryQualificationFactory? = nil) throws {
        try LocalDurableRuntime.withCPU {
            let began=DispatchTime.now().uptimeNanoseconds
            let p=try selectedProfile(at:model,fixture:fixture)
            let execution=try AuthorityCodec.decode(AuthorityExecution.self,LocalFiles.read(prepared,maximum:64<<10))
            let binding=try AuthorityCodec.decode(ProviderBinding.self,execution.provider)
            try validateFixture(binding)
            guard case .allowed(let allowed)=binding.lane else { throw AuthorityError.scope }
            let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
            let live=try ResumableMLXProvider.prepare(binding:binding,runtime:p.runtime(binding,configuration:config),owner:"allowed-feasibility",credit:ResumableMLXProvider.reservationBytes)
            defer { live.close() }
            guard var selected=try live.pendingCandidate() else { throw AuthorityError.state }
            try live.acceptCommit(selected.commit,owner:"allowed-feasibility")
            let directory=report+".steps";try LocalFiles.createDirectory(directory)
            struct Step:Encodable {
                let index:Int,action:Int,operation:String,nanoseconds:UInt64,nativeCalls:Int,checkpointBytes:Int,eventBytes:Data
                let progress:ProviderAllowedProgress
            }
            struct Reference:Encodable { let file:String,sha256:String,bytes:Int }
            var files:[Reference]=[],actions=1,maximumNs:UInt64=0,maximumFrame=0,events:[WireEvent]=[]
            var cutProbe:ProviderAllowedProgress?,cutGuided:ProviderAllowedProgress?,routeReady:ProviderAllowedProgress?
            func calls(_ profile:any NativeRecoverySelectedProfile)->Int { profile.observations.reduce(0){$0+$1.calls} }
            func observe(_ operation:String,_ started:UInt64,_ priorCalls:Int,_ profile:any NativeRecoverySelectedProfile,
                         _ provider:ResumableMLXProvider,_ candidate:ProviderCandidate) throws -> ProviderAllowedProgress {
                let progress=try provider.committedAllowedProgress(candidate),elapsed=DispatchTime.now().uptimeNanoseconds-started
                let forwards=calls(profile)-priorCalls
                guard elapsed<10_000_000_000,forwards>=0,forwards<=(operation == "prepare" || operation == "next-pass" ? 2 : operation.contains("restore") || operation == "ready-deliver" ? 0 : 1),
                      Memory.peakMemory<=128<<20,progress.proposals.count<=1,progress.deliveredCalls<=1 else { throw AuthorityError.state }
                let step=Step(index:files.count,action:actions,operation:operation,nanoseconds:elapsed,nativeCalls:forwards,checkpointBytes:candidate.data.count,eventBytes:candidate.eventBytes,progress:progress)
                let data=try AuthorityCodec.encode(step),name=String(format:"%03d",files.count)+"-"+operation+".json"
                maximumNs=max(maximumNs,elapsed);maximumFrame=max(maximumFrame,data.count)
                try LocalFiles.writeNew(data,to:directory+"/"+name);files.append(.init(file:name,sha256:AuthorityCodec.hash(data),bytes:data.count))
                if progress.phase=="probe",progress.probe.rawTokens>0,cutProbe==nil { cutProbe=progress }
                if progress.phase=="routeReady" { routeReady=progress }
                if progress.phase=="guided",let g=progress.guided,g.consumedTokens>0,g.pendingTokens>0,!progress.whole.isEmpty,cutGuided==nil { cutGuided=progress }
                return progress
            }
            var progress=try observe("prepare",began,0,p,live,selected)
            let preparationCalls=calls(p)
            guard preparationCalls==(allowed.originalTokens.count+255)/256 else { throw AuthorityError.state }
            while progress.phase != "finalReady" && progress.phase != "finalEmitted" {
                guard actions<120,progress.proposals.count<=1 else { throw AuthorityError.state }
                actions+=1;let actionStart=DispatchTime.now().uptimeNanoseconds,actionCalls=calls(p),phase=progress.phase
                let unit=(phase=="probe" || phase=="guided") ? 2 : 1
                for _ in 0..<unit {
                    let priorCalls=calls(p),operation=progress.phase=="routeReady" ? "next-pass" : "advance"
                    guard let next=try live.advance(owner:"allowed-feasibility",current:selected.commit,credit:ResumableMLXProvider.reservationBytes) else { throw AuthorityError.state }
                    try live.acceptCommit(next.commit,owner:"allowed-feasibility");selected=next
                    events+=try JSONDecoder().decode([WireEvent].self,from:next.eventBytes)
                    progress=try observe(operation,actionStart,priorCalls,p,live,selected)
                    if progress.phase != phase { break }
                }
                guard calls(p)-actionCalls<=2,DispatchTime.now().uptimeNanoseconds-actionStart<10_000_000_000 else { throw AuthorityError.state }
            }
            guard let cutProbe else { throw AuthorityError.state }
            let ready=selected,readyProgress=progress
            let successful=progress.phase=="finalReady"
            if successful,fixture != nil {
                guard progress.route=="calls",progress.completedCalls.count==1,progress.proposals.count==1,
                      progress.guided?.interceptedEndings==1,cutGuided != nil else { throw AuthorityError.state }
            }
            if fixture == nil { guard successful,progress.route=="prose",progress.proseDelivered>0,progress.proposals.isEmpty else { throw AuthorityError.state } }
            live.close()
            var readyCalls=0,restoreCalls=0,restoredRepairs=0
            if successful {
                actions+=1;let started=DispatchTime.now().uptimeNanoseconds
                let second=try selectedProfile(at:model,fixture:fixture)
                let restored=try ResumableMLXProvider.restore(committed:ready,expected:binding,runtime:second.runtime(binding,configuration:config),owner:"fresh-allowed-ready")
                defer { restored.close() }
                guard try restored.committedAllowedProgress(ready)==readyProgress,calls(second)==0 else { throw AuthorityError.state }
                _=try observe("ready-restore",started,0,second,restored,ready);restoreCalls=calls(second)
                actions+=1;let delivery=DispatchTime.now().uptimeNanoseconds
                guard let emitted=try restored.advance(owner:"fresh-allowed-ready",current:ready.commit,credit:ResumableMLXProvider.reservationBytes) else { throw AuthorityError.state }
                try restored.acceptCommit(emitted.commit,owner:"fresh-allowed-ready")
                progress=try observe("ready-deliver",delivery,0,second,restored,emitted)
                events+=try JSONDecoder().decode([WireEvent].self,from:emitted.eventBytes);readyCalls=calls(second)
                restoredRepairs=second.tokenizer.repairEncodes
                guard progress.phase=="finalEmitted",restored.isTerminal,readyCalls==0,
                      second.tokenizer.renders==0,second.tokenizer.requestTokenizations==0 else { throw AuthorityError.state }
            }
            guard p.tokenizer.renders==0,p.tokenizer.requestTokenizations==0 else { throw AuthorityError.state }
            struct Report:Encodable {
                let stage="allowed-feasibility",beforeOriginals=true,successful:Bool,model:String,artifact:String,provider:ProviderBinding
                let cutProbe:ProviderAllowedProgress,cutGuided:ProviderAllowedProgress?,routeReady:ProviderAllowedProgress?,ready:ProviderAllowedProgress,final:ProviderAllowedProgress
                let steps:[Reference],events:[WireEvent],traces:[NativeObservation],nativeCalls:Int,nativePeak:Int,prepareCalls:Int
                let actionUnits:Int,maximumActionNanoseconds:UInt64,maximumStepFrameBytes:Int,providerBytes:Int
                let readyRestoreCalls:Int,readyDeliveryCalls:Int,originalRequestEncodes:Int,repairEncodes:Int,restoredRepairEncodes:Int
                let scope="Normal artifact no-call recovery and separately prescribed state-fixture call integration are distinct. No originals exist in this probe."
            }
            let result=Report(successful:successful,model:p.preparer.policy.descriptor.model,artifact:p.manifestDigest,provider:binding,
                cutProbe:cutProbe,cutGuided:cutGuided,routeReady:routeReady,ready:readyProgress,final:progress,steps:files,events:events,traces:p.observations,
                nativeCalls:calls(p),nativePeak:Memory.peakMemory,prepareCalls:preparationCalls,actionUnits:actions,maximumActionNanoseconds:maximumNs,
                maximumStepFrameBytes:maximumFrame,providerBytes:execution.provider.count,readyRestoreCalls:restoreCalls,readyDeliveryCalls:readyCalls,
                originalRequestEncodes:p.tokenizer.requestTokenizations,repairEncodes:p.tokenizer.repairEncodes,restoredRepairEncodes:restoredRepairs)
            let data=try AuthorityCodec.encode(result);try LocalFiles.writeNew(data,to:report)
            try FileHandle.standardOutput.write(contentsOf:data+Data([10]))
        }
    }
}
