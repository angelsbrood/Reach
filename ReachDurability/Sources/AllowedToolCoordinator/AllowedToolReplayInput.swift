import Foundation
import MLXLMCommon

public enum AllowedPassKind: String, Codable, Sendable { case probe, tool, schema }
public struct AllowedPreparedPass: Codable, Sendable {
    public var kind: AllowedPassKind
    public var index: Int
    public var proposalID: String?
    public var messages: Data
    public var tokens: [Int]
    public var inputDigest: String
    public var identity: ResumableTokenIdentity
}

public enum AllowedToolReplayInput {
    public static let policy = "S79-json-messages-tokenizer-v1"
    public struct Message: Codable, Equatable, Sendable { public let role: String; public let content: String }
    public static func repairMessages(_ call: ToolCall) throws -> [Message] {
        let prompt = """
        Correct the proposed tool call while preserving every value its schema permits. Return only the required JSON envelope.
        Tool name: \(call.function.name)
        Proposed arguments: \(try allowedArguments(call))
        """
        return [.init(role: "system", content: "You repair proposed JSON tool arguments without inventing a different tool."),
                .init(role: "user", content: prompt)]
    }
    public static func prepare(binding: AllowedToolBinding, kind: AllowedPassKind, index: Int = 0,
                               proposal: ToolCall? = nil, tokenizer: any Tokenizer) throws -> AllowedPreparedPass {
        let width = kind == .probe ? binding.probeOptions.vocabularySize : binding.guidedOptions.model.logitWidth
        guard width > 0 else { throw AllowedToolError.invalid("prepared token width") }
        var messages = Data(), tokens = binding.originalTokens
        if kind == .tool {
            guard let proposal, let id = proposal.id, !id.isEmpty, id.utf8.count <= 256, (0..<32).contains(index) else {
                throw AllowedToolError.invalid("repair proposal/index")
            }
            messages = try allowedEncode(repairMessages(proposal))
            guard messages.count <= 512*1024 else { throw AllowedToolError.oversized }
            // A documented local policy, not the production processor/chat template.
            tokens = tokenizer.encode(text: policy + "\n" + String(decoding: messages, as: UTF8.self))
        } else if proposal != nil || index != 0 { throw AllowedToolError.invalid("non-tool pass input") }
        guard (1...65_536).contains(tokens.count), tokens.allSatisfy({ $0 >= 0 && $0 < width }) else { throw AllowedToolError.invalid("prepared token bound") }
        let digest = try ResumableTokenIdentity.inputDigest(tokens)
        let base = kind == .probe ? binding.probeModel.identity : binding.guidedModel.identity
        let identity = ResumableTokenIdentity(model: base.model, configuration: base.configuration, weights: base.weights,
            input: digest, backend: base.backend, dependency: base.dependency)
        return .init(kind: kind, index: index, proposalID: proposal?.id, messages: messages, tokens: tokens, inputDigest: digest, identity: identity)
    }
}
