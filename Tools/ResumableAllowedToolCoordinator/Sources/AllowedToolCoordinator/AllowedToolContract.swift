import Foundation
import MLXGuidedGeneration
import MLXLMCommon
import RequiredToolCoordinator

public enum AllowedToolError: Error, Equatable { case invalid(String), incompatible, oversized, closed }

public struct AllowedModelBinding: Codable, Sendable {
    public var identity: ResumableTokenIdentity
    public var cacheSpecs: [ResumableCacheSpec]
    public var codecIdentity: String
    public init(identity: ResumableTokenIdentity, cacheSpecs: [ResumableCacheSpec], codecIdentity: String) {
        self.identity = identity; self.cacheSpecs = cacheSpecs; self.codecIdentity = codecIdentity
    }
}

public struct AllowedToolBinding: Codable, Sendable {
    public var version = 1
    public var route = "allowed"
    public var policy = "S79-proposals-first;visible-probe-unless-schema;final-ready-wins-v1"
    public var preparationPolicy = AllowedToolReplayInput.policy
    public var requestIdentity: String
    public var entryID: String
    public var namespace: String
    public var tools: [RequiredToolDefinition]
    public var responseSchema: String?
    public var originalTokens: [Int]
    public var probeModel: AllowedModelBinding
    public var guidedModel: AllowedModelBinding
    public var probeOptions: ResumableTokenOptions
    public var textOptions: ResumableTextOptions
    public var format: ToolCallFormat
    /// Source is the fixed placeholder {}. Actual pass grammars are derived.
    public var tokenizer: ResumableGrammarSpecification
    public var guidedOptions: ResumableGuidedOptions

    public init(requestIdentity: String, entryID: String, namespace: String, tools: [RequiredToolDefinition],
                responseSchema: String?, originalTokens: [Int], probeModel: AllowedModelBinding,
                guidedModel: AllowedModelBinding, probeOptions: ResumableTokenOptions,
                textOptions: ResumableTextOptions, format: ToolCallFormat,
                tokenizer: ResumableGrammarSpecification, guidedOptions: ResumableGuidedOptions) throws {
        self.requestIdentity = requestIdentity; self.entryID = entryID; self.namespace = namespace; self.tools = tools
        self.responseSchema = responseSchema; self.originalTokens = originalTokens; self.probeModel = probeModel
        self.guidedModel = guidedModel; self.probeOptions = probeOptions; self.textOptions = textOptions
        self.format = format; self.tokenizer = tokenizer; self.guidedOptions = guidedOptions
        try validate()
    }
    public func parserConfiguration() throws -> ResumableToolCallConfiguration {
        let definitions: [[String: JSONValue]] = try tools.map { tool in
            let schema = try JSONDecoder().decode(JSONValue.self, from: Data(tool.schemaJSON.utf8))
            return ["type": .string("function"), "function": .object(["name": .string(tool.name), "parameters": schema])]
        }
        return try .init(format: format, tools: definitions)
    }
    public func specification(tool index: Int?) throws -> ResumableGrammarSpecification {
        let t = tokenizer
        if let index {
            guard tools.indices.contains(index) else { throw AllowedToolError.invalid("offered tool index") }
            return try .init(structuralTag: RequiredToolContract.structuralSource([tools[index]]), vocabulary: t.vocabulary,
                vocabularyType: t.vocabularyType, tokenizerIdentity: t.tokenizerIdentity, eosTokenID: t.eosTokenID,
                unknownTokenID: t.unknownTokenID, fastForward: t.fastForward)
        }
        guard let responseSchema else { throw AllowedToolError.invalid("missing response schema") }
        return .init(jsonSchema: responseSchema, vocabulary: t.vocabulary, vocabularyType: t.vocabularyType,
            tokenizerIdentity: t.tokenizerIdentity, eosTokenID: t.eosTokenID, unknownTokenID: t.unknownTokenID, fastForward: t.fastForward)
    }
    func validate() throws {
        // Validate scalar options before using widths to construct token ranges.
        try ResumableTokenDriver.assess(identity: probeModel.identity, options: probeOptions, cacheSpecs: probeModel.cacheSpecs)
        try ResumableGuidedModelState.assess(identity: guidedModel.identity, options: guidedOptions.model, cacheSpecs: guidedModel.cacheSpecs)
        guard version == 1, route == "allowed", policy == "S79-proposals-first;visible-probe-unless-schema;final-ready-wins-v1",
              preparationPolicy == AllowedToolReplayInput.policy,
              !entryID.isEmpty, entryID.utf8.count <= 256, !requestIdentity.isEmpty, requestIdentity.utf8.count <= 1024,
              namespace.utf8.count == 32, namespace.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              (1...65_536).contains(originalTokens.count),
              originalTokens.allSatisfy({ (0..<probeOptions.vocabularySize).contains($0) && (0..<guidedOptions.model.logitWidth).contains($0) }),
              [probeModel.codecIdentity, guidedModel.codecIdentity].allSatisfy({ !$0.isEmpty && $0.utf8.count <= 1024 }) else {
            throw AllowedToolError.invalid("allowed binding/configuration")
        }
        let digest = try ResumableTokenIdentity.inputDigest(originalTokens)
        guard probeModel.identity.input == digest, guidedModel.identity.input == digest,
              probeOptions.vocabularySize == tokenizer.vocabulary.count,
              textOptions.tokenizerIdentity == tokenizer.tokenizerIdentity,
              tokenizer.source == "{}" else { throw AllowedToolError.incompatible }
        _ = try RequiredToolContract.structuralSource(tools); _ = try parserConfiguration()
        if let responseSchema {
            guard !responseSchema.isEmpty, responseSchema.utf8.count <= 65_536 else { throw AllowedToolError.oversized }
            _ = try JSONSerialization.jsonObject(with: Data(responseSchema.utf8))
        }
        let t = tokenizer
        let exact = ResumableGrammarSpecification(jsonSchema: "{}", vocabulary: t.vocabulary, vocabularyType: t.vocabularyType,
            tokenizerIdentity: t.tokenizerIdentity, eosTokenID: t.eosTokenID, unknownTokenID: t.unknownTokenID, fastForward: t.fastForward)
        guard try allowedEncode(exact) == allowedEncode(t), (1...4096).contains(t.vocabulary.count),
              !t.tokenizerIdentity.isEmpty, t.tokenizerIdentity.utf8.count <= 1024,
              t.vocabulary.indices.contains(t.eosTokenID), t.unknownTokenID.map({ t.vocabulary.indices.contains($0) && $0 != t.eosTokenID }) ?? true,
              t.vocabulary.allSatisfy({ $0.utf8.count <= 4096 && !$0.utf8.contains(0) }),
              try allowedEncode(t.vocabulary).count <= 256*1024 else { throw AllowedToolError.invalid("tokenizer binding") }
        let o = guidedOptions
        guard o.sampling == "greedy-v1", o.completionPolicy == "accepted-stop-v1",
              [o.completionReserve, o.hardReserve, o.whitespaceThreshold].allSatisfy({ (0...65_536).contains($0) }),
              o.whitespaceTokenIDs == Set(o.whitespaceTokenIDs).sorted(), o.whitespaceTokenIDs.allSatisfy({ t.vocabulary.indices.contains($0) }) else {
            throw AllowedToolError.invalid("guided options")
        }
        for bias in [o.closingBias, o.whitespaceBias].compactMap({ $0 }) {
            guard bias.count == t.vocabulary.count, bias.allSatisfy({ $0.isFinite && abs($0) <= 10_000 }) else { throw AllowedToolError.invalid("guided bias") }
        }
        guard try allowedEncode(self).count <= AllowedToolCheckpoint.maximumControlBytes else { throw AllowedToolError.oversized }
    }
}

public struct AllowedToolRuntime {
    public let tokenizer: any Tokenizer
    public let probeCodecs: ResumableStateCodecs
    public let guidedCodecs: ResumableStateCodecs
    /// Builds the model for the exact bound pass; no forward/prefill in this factory.
    /// Owners attest matching immutable model/codec/tokenizer implementation identities.
    public let model: (AllowedPreparedPass) throws -> any LanguageModel
    public init(tokenizer: any Tokenizer, probeCodecs: ResumableStateCodecs, guidedCodecs: ResumableStateCodecs,
                model: @escaping (AllowedPreparedPass) throws -> any LanguageModel) {
        self.tokenizer = tokenizer; self.probeCodecs = probeCodecs; self.guidedCodecs = guidedCodecs; self.model = model
    }
}

func allowedEncode<T: Encodable>(_ value: T) throws -> Data {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return try e.encode(value)
}
func allowedDigest(_ data: Data) -> String { ResumableGuidedValues.digest(data) }
func allowedArguments(_ call: ToolCall) throws -> String {
    let bytes = try allowedEncode(call.function.arguments)
    guard bytes.count <= 256*1024 else { throw AllowedToolError.oversized }
    return String(decoding: bytes, as: UTF8.self)
}
