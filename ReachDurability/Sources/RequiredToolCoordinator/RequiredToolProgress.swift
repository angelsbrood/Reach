import Foundation
import MLXGuidedGeneration

/// Values from the live validated child. This type cannot prepare, advance or
/// choose a checkpoint; only RequiredToolCoordinator can construct it.
public struct RequiredToolProgress {
    public let phase:RequiredToolPhase, whole:Data, call:RequiredToolCall?
    public let child:ResumableGuidedCheckpoint, view:ResumableGuidedCheckpointView
    init(phase:RequiredToolPhase,whole:Data,call:RequiredToolCall?,child:ResumableGuidedCheckpoint,view:ResumableGuidedCheckpointView) {
        self.phase=phase;self.whole=whole;self.call=call;self.child=child;self.view=view
    }
}
