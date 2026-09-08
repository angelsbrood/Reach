import Foundation
import MLXLMCommon

public enum ResumableGuidedEnd: String, Codable, Sendable { case complete, incomplete, cancelled }
public struct ResumableGuidedCompletion: Codable, Equatable, Sendable {
    public let reason: ResumableGuidedEnd
    public let promptTokens: Int
    public let sampledTokens: Int
    public let forcedTokens: Int
    public let interceptedEndings: Int
    public let acceptedTokens: Int
    public let pendingTokens: Int
    public let grammarTerminated: Bool
}
public enum ResumableGuidedRecord: Codable, Equatable, Sendable {
    case text(Data)
    case terminal(ResumableGuidedCompletion)
}

struct ResumableGuidedTextState: Codable {
    var value=ResumableGuidedTextValue()
    mutating func append(_ token: Int, tokenizer: any Tokenizer) throws -> [ResumableGuidedRecord] {
        if let bytes=try value.append(token,tokenizer:tokenizer), !bytes.isEmpty { return [.text(bytes)] }
        return []
    }
}
