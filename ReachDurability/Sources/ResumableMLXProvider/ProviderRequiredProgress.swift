import Foundation
import RequiredToolCoordinator

public struct ProviderRequiredProgress:Codable,Equatable,Sendable {
    public let coordinator:String, phase:String, whole:Data, call:RequiredToolCall?
    public let guided:ProviderGuidedProgress
    init(selected:ProviderCandidate,coordinator:Data,progress:RequiredToolProgress) throws {
        self.coordinator=providerHash(coordinator);phase=progress.phase.rawValue;whole=progress.whole;call=progress.call
        guided=try ProviderGuidedProgress(selected:selected,child:progress.child.data,view:progress.view)
    }
}
