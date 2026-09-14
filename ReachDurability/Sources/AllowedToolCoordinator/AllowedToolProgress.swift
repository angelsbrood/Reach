import Foundation
import MLXLMCommon
import MLXGuidedGeneration
import RequiredToolCoordinator

/// Observation of the exact retained history and fully validated live child.
/// Only the coordinator can construct this value; it cannot authorize work.
public struct AllowedToolProgress {
    public struct Completed {
        public let kind:AllowedPassKind,index:Int,inputDigest:String,prompt:Int,output:Int
    }
    public let completed:[Completed],schemaReturnedBytes:Int
    public let phase:AllowedPhase, route:AllowedRoute?, outcome:String?
    public let proposals:[ToolCall], current:AllowedPreparedPass?, whole:Data
    public let completedCalls:[RequiredToolCall], deliveredCalls:Int, proseDelivered:Int
    public let inputTokens:Int, outputTokens:Int
    public let probe:ResumableToolGenerationCheckpointView
    public let child:Data, guided:ResumableGuidedCheckpointView?
    init(phase:AllowedPhase,route:AllowedRoute?,outcome:String?,proposals:[ToolCall],current:AllowedPreparedPass?,whole:Data,
         completed:[Completed],schemaReturnedBytes:Int,completedCalls:[RequiredToolCall],deliveredCalls:Int,proseDelivered:Int,inputTokens:Int,outputTokens:Int,
         probe:ResumableToolGenerationCheckpointView,child:Data,guided:ResumableGuidedCheckpointView?) {
        self.phase=phase;self.route=route;self.outcome=outcome;self.proposals=proposals;self.current=current;self.whole=whole
        self.completed=completed;self.schemaReturnedBytes=schemaReturnedBytes
        self.completedCalls=completedCalls;self.deliveredCalls=deliveredCalls;self.proseDelivered=proseDelivered
        self.inputTokens=inputTokens;self.outputTokens=outputTokens;self.probe=probe;self.child=child;self.guided=guided
    }
}
