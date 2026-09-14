import Foundation
import Dispatch
import MLX
import ReachWire
import ResumableMLXProvider
import WireAdapterContract
import RecoveryAuthorityContract

extension NativeRecoveryRuntime {
    /// Pre-original empirical model work. No witness, role, admission or durable
    /// generation is created. Each observation is one bounded canonical frame.
    public static func probeRequiredFixture(model:String,prepared:String,report:String) throws {
        try LocalDurableRuntime.withCPU {
            let start=DispatchTime.now().uptimeNanoseconds
            let p=try SelectedArtifactProfile(at:model,nativeRecovery:true)
            let execution=try AuthorityCodec.decode(AuthorityExecution.self,LocalFiles.read(prepared,maximum:64<<10))
            let binding=try AuthorityCodec.decode(ProviderBinding.self,execution.provider)
            try validateFixture(binding)
            guard case .required(let required,let tokens)=binding.lane else { throw AuthorityError.scope }
            let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
            let owner="required-feasibility"
            let live=try ResumableMLXProvider.prepare(binding:binding,runtime:p.runtime(binding,configuration:config),owner:owner,credit:ResumableMLXProvider.reservationBytes)
            defer { live.close() }
            guard var selected=try live.pendingCandidate() else { throw AuthorityError.state }
            try live.acceptCommit(selected.commit,owner:owner)
            let directory=report+".steps";try LocalFiles.createDirectory(directory)
            struct Step:Encodable {
                let index:Int, operation:String, nanoseconds:UInt64, nativeCalls:Int
                let nativeOffsets:[Int], nativeInputs:[String], checkpointBytes:Int, eventBytes:Data
                let progress:ProviderRequiredProgress
            }
            var files:[String]=[],largest=0,initialCalls=0,initialNs:UInt64=0,maximumStepNs:UInt64=0,cut:ProviderRequiredProgress?
            func observe(_ operation:String,_ began:UInt64,_ priorCalls:Int,_ profile:SelectedArtifactProfile,_ provider:ResumableMLXProvider,_ current:ProviderCandidate) throws -> ProviderRequiredProgress {
                let progress=try provider.committedRequiredProgress(current)
                let traces=profile.observations, calls=traces.reduce(0){$0+$1.calls}-priorCalls
                let elapsed=DispatchTime.now().uptimeNanoseconds-began
                let offsets=Array(traces.flatMap(\.offsets).dropFirst(priorCalls)), inputs=Array(traces.flatMap(\.inputDigests).dropFirst(priorCalls))
                let events=current.eventBytes
                let step=Step(index:files.count,operation:operation,nanoseconds:elapsed,nativeCalls:calls,nativeOffsets:offsets,nativeInputs:inputs,checkpointBytes:current.data.count,eventBytes:events,progress:progress)
                let data=try AuthorityCodec.encode(step),name=String(format:"%03d",files.count)+"-"+operation+".json"
                guard data.count<=64<<10,elapsed<10_000_000_000,calls<=((operation == "prepare") ? 2 : 1),Memory.peakMemory<=128<<20 else { throw AuthorityError.state }
                if operation == "prepare" { initialCalls=calls;initialNs=elapsed }
                maximumStepNs=max(maximumStepNs,elapsed);largest=max(largest,data.count);files.append(name)
                try LocalFiles.writeNew(data,to:directory+"/"+name)
                if cut == nil,progress.phase == "generating",progress.guided.consumedTokens>0,!progress.whole.isEmpty,progress.guided.modelOffsets.allSatisfy({$0>0}) { cut=progress }
                return progress
            }
            _=try observe("prepare",start,0,p,live,selected)
            var progress=try live.committedRequiredProgress(selected)
            for _ in 0..<48 where progress.phase == "generating" {
                let began=DispatchTime.now().uptimeNanoseconds,calls=p.observations.reduce(0){$0+$1.calls}
                guard let next=try live.advance(owner:owner,current:selected.commit,credit:ResumableMLXProvider.reservationBytes) else { throw AuthorityError.state }
                try live.acceptCommit(next.commit,owner:owner);selected=next
                progress=try observe("advance",began,calls,p,live,selected)
            }
            guard let cut,progress.phase == "ready",progress.call?.name == required.tools[0].name,
                  progress.guided.terminalReason == "complete",progress.guided.interceptedEndings == 1,
                  progress.guided.consumedTokens<=48,selected.eventBytes==Data("[]".utf8),
                  initialCalls == (tokens.count+255)/256 else { throw AuthorityError.state }
            let ready=selected,readyProgress=progress;live.close()
            let restoreStart=DispatchTime.now().uptimeNanoseconds
            let second=try SelectedArtifactProfile(at:model,nativeRecovery:true)
            let restored=try ResumableMLXProvider.restore(committed:ready,expected:binding,runtime:second.runtime(binding,configuration:config),owner:"fresh-ready")
            defer { restored.close() }
            guard try restored.committedRequiredProgress(ready)==readyProgress,second.observations.reduce(0,{$0+$1.calls})==0 else { throw AuthorityError.state }
            _=try observe("ready-restore",restoreStart,0,second,restored,ready)
            let deliveryStart=DispatchTime.now().uptimeNanoseconds
            guard let emitted=try restored.advance(owner:"fresh-ready",current:ready.commit,credit:ResumableMLXProvider.reservationBytes) else { throw AuthorityError.state }
            try restored.acceptCommit(emitted.commit,owner:"fresh-ready")
            let emittedProgress=try observe("ready-deliver",deliveryStart,0,second,restored,emitted)
            let eventBytes=emitted.eventBytes,events=try JSONDecoder().decode([WireEvent].self,from:eventBytes)
            guard restored.isTerminal,emittedProgress.phase == "emitted",emittedProgress.call == readyProgress.call,
                  second.observations.reduce(0,{$0+$1.calls})==0,events.count==3,
                  case .toolCallAppendArguments(let entry,let id,let name,let args,let count)=events[0],
                  entry==required.entryID,id==required.callID,name==readyProgress.call?.name,args==readyProgress.call?.argumentsJSON,count==1,
                  case .usage(let prompt,let output)=events[1],prompt==tokens.count,output==progress.guided.sampledTokens+progress.guided.forcedTokens,
                  case .finished(.complete)=events[2] else { throw AuthorityError.state }
            struct Report:Encodable {
                let stage="required-fixture",beforeOriginals=true,cut:ProviderRequiredProgress,ready:ProviderRequiredProgress
                let provider:ProviderBinding,steps:[String],emittedEvents:Data,preparedTokens:Int,consumedTokens:Int
                let nativeCalls:Int,initialPrepareCalls:Int,initialPrepareNanoseconds:UInt64,maximumStepNanoseconds:UInt64
                let restoredReadyCalls=0,readyDeliveryCalls=0,nativePeak:Int,providerBytes:Int,maximumStepFrameBytes:Int
                let prepareObservation="Profile loading, full stored-binding validation, both prefill forwards, provider freeze/ack and validated progress; durable role IO and witness exchange are absent before originals."
            }
            let result=Report(cut:cut,ready:readyProgress,provider:binding,steps:files,emittedEvents:eventBytes,preparedTokens:tokens.count,consumedTokens:progress.guided.consumedTokens,nativeCalls:p.observations.reduce(0){$0+$1.calls},initialPrepareCalls:initialCalls,initialPrepareNanoseconds:initialNs,maximumStepNanoseconds:maximumStepNs,nativePeak:Memory.peakMemory,providerBytes:execution.provider.count,maximumStepFrameBytes:largest)
            let data=try AuthorityCodec.encode(result);try LocalFiles.writeNew(data,to:report)
            try FileHandle.standardOutput.write(contentsOf:data+Data([10]))
        }
    }
}

import ClockPolicy

struct NativeRequiredStepReference:Encodable {
    let file:String,sha256:String,bytes:Int
}
/// One acknowledged step per bounded file. The report retains only the initial
/// and latest progress, so a growing token history never accumulates in a frame.
struct NativeRequiredStepObservation:Encodable {
    let index:Int,operation:String,actionNanoseconds:UInt64,nativeCalls:Int
    let nativeOffsets:[Int],nativeInputs:[String],checkpointBytes:Int,eventBytes:Data
    let progress:ProviderRequiredProgress,evaluation:Evaluation
    init(index:Int,operation:String,began:UInt64,priorCalls:Int,traces:[NativeObservation],
         prior:ProviderRequiredProgress?,progress:ProviderRequiredProgress,candidate:ProviderCandidate,evaluation:Evaluation) throws {
        self.index=index;self.operation=operation;self.progress=progress;self.evaluation=evaluation
        actionNanoseconds=DispatchTime.now().uptimeNanoseconds-began
        nativeCalls=traces.reduce(0){$0+$1.calls}-priorCalls
        nativeOffsets=Array(traces.flatMap(\.offsets).dropFirst(priorCalls))
        nativeInputs=Array(traces.flatMap(\.inputDigests).dropFirst(priorCalls))
        checkpointBytes=candidate.data.count;eventBytes=candidate.eventBytes
        guard actionNanoseconds<10_000_000_000,Memory.peakMemory<=128<<20,
              nativeCalls>=0,nativeCalls<=(operation == "prepare" ? 2 : operation == "restore" ? 0 : 1),
              nativeOffsets.count==nativeCalls,nativeInputs.count==nativeCalls else { throw AuthorityError.state }
        if operation == "prepare" {
            guard nativeCalls==(progress.guided.promptTokens+255)/256 else { throw AuthorityError.state }
        }
        if prior?.phase == "ready" || progress.guided.interceptedEndings>(prior?.guided.interceptedEndings ?? 0) && operation == "advance" {
            guard nativeCalls==0 else { throw AuthorityError.state }
        }
        if progress.phase != "emitted" { guard eventBytes==Data("[]".utf8) else { throw AuthorityError.state } }
    }
    func write(to directory:String) throws -> NativeRequiredStepReference {
        let bytes=try AuthorityCodec.encode(self),file=String(format:"%03d",index)+"-"+operation+".json"
        try LocalFiles.writeNew(bytes,to:directory+"/"+file)
        return .init(file:file,sha256:AuthorityCodec.hash(bytes),bytes:bytes.count)
    }
}
