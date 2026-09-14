import Foundation
import Dispatch
import MLX
import ClockPolicy
import ResumableMLXProvider
import RecoveryAuthorityContract

struct NativeAllowedStepObservation:Encodable {
    let index:Int,action:Int,operation:String,actionNanoseconds:UInt64,nativeCalls:Int
    let traces:[NativeAllowedTraceDelta],checkpointBytes:Int,eventBytes:Data,progress:ProviderAllowedProgress,evaluation:Evaluation
    init(index:Int,action:Int,operation:String,began:UInt64,priorCalls:Int,traces:[NativeObservation],
         prior:ProviderAllowedProgress?,progress:ProviderAllowedProgress,candidate:ProviderCandidate,evaluation:Evaluation) throws {
        self.index=index;self.action=action;self.operation=operation;self.progress=progress;self.evaluation=evaluation
        actionNanoseconds=DispatchTime.now().uptimeNanoseconds-began
        nativeCalls=traces.reduce(0){$0+$1.calls}-priorCalls
        var remaining=priorCalls,deltas:[NativeAllowedTraceDelta]=[]
        for trace in traces {
            let skip=min(remaining,trace.calls);remaining-=skip
            if skip<trace.calls { deltas.append(.init(kind:trace.kind,index:trace.index,preparedTokens:trace.preparedTokens,
                offsets:Array(trace.offsets.dropFirst(skip)),inputDigests:Array(trace.inputDigests.dropFirst(skip)))) }
        }
        self.traces=deltas;checkpointBytes=candidate.data.count;eventBytes=candidate.eventBytes
        let maximum=operation=="prepare" || operation=="next-pass" ? 2 : operation=="restore" || operation=="ready-deliver" ? 0 : 1
        guard actionNanoseconds<10_000_000_000,nativeCalls>=0,nativeCalls<=maximum,Memory.peakMemory<=128<<20 else { throw AuthorityError.state }
        if operation=="prepare" { guard nativeCalls==(progress.probe.promptTokens+255)/256 else { throw AuthorityError.state } }
        if operation=="next-pass" {
            guard prior?.phase=="routeReady",progress.phase=="guided",let current=progress.current,
                  nativeCalls==(current.tokens.count+255)/256 else { throw AuthorityError.state }
        }
        if prior?.phase=="finalReady" { guard nativeCalls==0 else { throw AuthorityError.state } }
        if (progress.guided?.interceptedEndings ?? 0) > (prior?.guided?.interceptedEndings ?? 0),operation=="advance" {
            guard nativeCalls==0 else { throw AuthorityError.state }
        }
    }
    func write(to directory:String) throws -> NativeRequiredStepReference {
        let bytes=try AuthorityCodec.encode(self),name=String(format:"%03d",index)+"-"+operation+".json"
        try LocalFiles.writeNew(bytes,to:directory+"/"+name)
        return .init(file:name,sha256:AuthorityCodec.hash(bytes),bytes:bytes.count)
    }
}
struct NativeAllowedTraceDelta:Encodable {
    let kind:String,index:Int,preparedTokens:[Int],offsets:[Int],inputDigests:[String]
}

import AllowedToolCoordinator
import MLXLMCommon

/// Check the exact immutable pass before construction/preparation. Repair
/// re-encoding is legitimate history work and is counted separately by tokenizer.
func validateAllowedRecoveryPass(_ pass:AllowedPreparedPass,binding:AllowedToolBinding,tokenizer:ArtifactTokenizer) throws {
    guard (1...512).contains(pass.tokens.count),pass.index==0,
          pass.inputDigest == (try ResumableTokenIdentity.inputDigest(pass.tokens)) else { throw AuthorityError.scope }
    if pass.kind == .probe {
        guard pass.tokens==binding.originalTokens,pass.messages.isEmpty,pass.proposalID==nil else { throw AuthorityError.scope }
    } else {
        guard pass.kind == .tool,let id=pass.proposalID,!id.isEmpty,id.utf8.count<=256,!pass.messages.isEmpty,
              pass.tokens==tokenizer.encode(text:AllowedToolReplayInput.policy+"\n"+String(decoding:pass.messages,as:UTF8.self)) else { throw AuthorityError.scope }
    }
}
