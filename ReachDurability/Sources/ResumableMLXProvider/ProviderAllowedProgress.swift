import Foundation
import MLXLMCommon
import AllowedToolCoordinator
import RequiredToolCoordinator

public struct ProviderAllowedProgress:Codable,Equatable,Sendable {
    public struct Proposal:Codable,Equatable,Sendable { public let id:String,name:String,arguments:String }
    public struct Pass:Codable,Equatable,Sendable {
        public let kind:String,index:Int,proposalID:String?,inputDigest:String,messagesDigest:String,tokens:[Int]
    }
    public let coordinator:String,child:String,phase:String,route:String?,outcome:String?
    public let proposals:[Proposal],current:Pass?,whole:Data,completedCalls:[RequiredToolCall]
    public let deliveredCalls:Int,proseDelivered:Int,inputTokens:Int,outputTokens:Int
    public let probe:ResumableToolGenerationCheckpointView,guided:ProviderGuidedProgress?
    init(selected:ProviderCandidate,coordinator:Data,progress p:AllowedToolProgress) throws {
        self.coordinator=providerHash(coordinator);child=providerHash(p.child);phase=p.phase.rawValue;route=p.route?.rawValue;outcome=p.outcome
        proposals=try p.proposals.map { value in
            guard let id=value.id else { throw ProviderError.invalid("allowed proposal identity") }
            return .init(id:id,name:value.function.name,arguments:String(decoding:try providerEncode(value.function.arguments),as:UTF8.self))
        }
        current=p.current.map { .init(kind:$0.kind.rawValue,index:$0.index,proposalID:$0.proposalID,inputDigest:$0.inputDigest,messagesDigest:providerHash($0.messages),tokens:$0.tokens) }
        whole=p.whole;completedCalls=p.completedCalls;deliveredCalls=p.deliveredCalls;proseDelivered=p.proseDelivered
        inputTokens=p.inputTokens;outputTokens=p.outputTokens;probe=p.probe
        guided=try p.guided.map { try .init(selected:selected,child:p.child,view:$0) }
    }
}
