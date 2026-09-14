import Foundation
import MLXGuidedGeneration

/// Read-only evidence from the already validated selected child. These values do
/// not authorize execution, choose a candidate, sample, or reconstruct a request.
public struct ProviderGuidedProgress: Codable, Equatable, Sendable {
    public struct Acceptance: Codable, Equatable, Sendable { public let token: Int, origin: String }
    public let commit: String, checkpoint: String, grammar: String, text: String, model: String
    public let ordinal: UInt64, promptTokens: Int, sampledTokens: Int, forcedTokens: Int, interceptedEndings: Int
    public let consumedTokens: Int, acceptedTokens: Int, pendingTokens: Int
    public let terminalReason: String?, cumulativeEmittedBytes: Data, modelOffsets: [Int], accepts: [Acceptance]
    init(selected: ProviderCandidate, child: Data, view: ResumableGuidedCheckpointView) throws {
        // Only called after exact live-child capture and native view validation.
        struct Envelope: Decodable { let payload: Data }
        struct Guided: Decodable {
            struct Grammar: Decodable { let accepts: [Acceptance] }
            let grammar: Grammar
        }
        struct Document: Decodable { let model: Data, guided: Guided }
        struct Cache: Decodable { let offset: Int }
        struct Model: Decodable { let caches: [Cache] }
        let decoder=JSONDecoder(), payload=try decoder.decode(Envelope.self,from:child).payload
        let d=try decoder.decode(Document.self,from:payload)
        let projection=try decoder.decode(Model.self,from:decoder.decode(Envelope.self,from:d.model).payload)
        let object=try JSONSerialization.jsonObject(with:payload) as? [String:Any]
        guard let guided=object?["guided"] as? [String:Any], let grammarValue=guided["grammar"], let textValue=guided["text"] else { throw ProviderError.invalid("guided diagnostic") }
        commit=selected.commit.identity; ordinal=try selected.commit.descriptor().ordinal
        checkpoint=providerHash(child); model=providerHash(d.model)
        grammar=providerHash(try JSONSerialization.data(withJSONObject:grammarValue,options:[.sortedKeys,.withoutEscapingSlashes]))
        text=providerHash(try JSONSerialization.data(withJSONObject:textValue,options:[.sortedKeys,.withoutEscapingSlashes]))
        promptTokens=view.promptTokens; sampledTokens=view.sampledTokens; forcedTokens=view.forcedTokens; interceptedEndings=view.interceptedEndings
        consumedTokens=view.consumedTokens; acceptedTokens=view.acceptedTokens; pendingTokens=view.pendingTokens
        terminalReason=view.terminalReason?.rawValue; cumulativeEmittedBytes=view.cumulativeEmittedBytes
        modelOffsets=projection.caches.map(\.offset); accepts=d.guided.grammar.accepts
    }
}
