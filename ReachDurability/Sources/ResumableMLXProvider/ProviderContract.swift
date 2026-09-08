import Foundation
import MLXLMCommon
import MLXGuidedGeneration
import RequiredToolCoordinator
import AllowedToolCoordinator

public enum ProviderError: Error, Equatable { case invalid(String), unsupported(String), credit, owner, commit, pending, overflow, closed, oversized }
public enum ProviderRoute: String, Codable, Sendable { case ordinary, guided, required, allowed }
public struct ProviderTextBinding: Codable, Sendable {
    public var model: AllowedModelBinding
    public var tokens: [Int]
    public var options: ResumableTokenOptions
    public var text: ResumableTextOptions
    public var entryID: String?
    public var segmentID: String?
    public init(model: AllowedModelBinding, tokens: [Int], options: ResumableTokenOptions, text: ResumableTextOptions,
                entryID: String? = nil, segmentID: String? = nil) {
        self.model = model; self.tokens = tokens; self.options = options; self.text = text; self.entryID = entryID; self.segmentID = segmentID
    }
}
public struct ProviderGuidedBinding: Codable, Sendable {
    public var model: AllowedModelBinding
    public var tokens: [Int]
    public var specification: ResumableGrammarSpecification
    public var options: ResumableGuidedOptions
    public var entryID: String?
    public var segmentID: String?
    public init(model: AllowedModelBinding, tokens: [Int], specification: ResumableGrammarSpecification, options: ResumableGuidedOptions,
                entryID: String? = nil, segmentID: String? = nil) {
        self.model = model; self.tokens = tokens; self.specification = specification; self.options = options
        self.entryID = entryID; self.segmentID = segmentID
    }
}
public enum ProviderRouteBinding: Codable, Sendable {
    case ordinary(ProviderTextBinding)
    case guided(ProviderGuidedBinding)
    case required(RequiredToolBinding, tokens: [Int])
    case allowed(AllowedToolBinding)
    public var route: ProviderRoute {
        switch self { case .ordinary: .ordinary; case .guided: .guided; case .required: .required; case .allowed: .allowed }
    }
}
public struct ProviderBinding: Codable, Sendable {
    public var version = 1
    public var policy = "S80-exact-candidate-ack;json-sorted-v1"
    public var operationID: String
    public var requestID: String
    public var lane: ProviderRouteBinding
    public init(operationID: String, requestID: String, lane: ProviderRouteBinding) {
        self.operationID = operationID; self.requestID = requestID; self.lane = lane
    }
    // This is an outer declaration/known-support check. Complete child validation
    // remains in actual prepare/restore; module-internal validators are not exposed.
    func validateDeclaration() throws {
        guard version == 1, policy == "S80-exact-candidate-ack;json-sorted-v1" else { throw ProviderError.unsupported("provider version/policy") }
        try providerID(operationID); try providerID(requestID)
        guard try providerEncode(self).count <= ProviderCandidate.maximumControlBytes else { throw ProviderError.oversized }
        switch lane {
        case .ordinary(let b):
            try ResumableTokenDriver.assess(identity: b.model.identity, options: b.options, cacheSpecs: b.model.cacheSpecs)
            try providerTokens(b.tokens, width: b.options.vocabularySize, identity: b.model.identity)
            try providerCodec(b.model.codecIdentity); try providerOptionalID(b.entryID); try providerOptionalID(b.segmentID)
            let t = b.text
            guard !t.tokenizerIdentity.isEmpty, t.tokenizerIdentity.utf8.count <= 1024,
                  t.stopTokenIDs.count <= 256, t.stopTokenIDs == Set(t.stopTokenIDs).sorted(),
                  t.stopTokenIDs.allSatisfy({ $0 >= 0 && $0 < b.options.vocabularySize }),
                  t.unknownTokenID.map({ $0 >= 0 && $0 < b.options.vocabularySize }) ?? true,
                  t.stopStrings.count <= 32, t.stopStrings.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 4096 }) else { throw ProviderError.unsupported("text declaration") }
        case .guided(let b):
            try providerGuided(b.model, b.tokens, b.specification, b.options)
            try providerOptionalID(b.entryID); try providerOptionalID(b.segmentID)
        case .required(let b, let tokens):
            guard b.version == 1, b.route == "required", b.policy == "stable-ids;accepted-eos;whole-batch;ready-wins-v1" else { throw ProviderError.unsupported("required policy") }
            try providerID(b.entryID); try providerID(b.callID); try providerCodec(b.requestIdentity)
            let exact = try RequiredToolContract.structuralSource(b.tools)
            guard b.specification.source == exact else { throw ProviderError.unsupported("required structural source") }
            try providerGuided(.init(identity: b.identity, cacheSpecs: b.cacheSpecs, codecIdentity: b.codecIdentity), tokens, b.specification, b.options)
        case .allowed(let b):
            guard b.version == 1, b.route == "allowed", b.policy == "S79-proposals-first;visible-probe-unless-schema;final-ready-wins-v1",
                  b.preparationPolicy == AllowedToolReplayInput.policy else { throw ProviderError.unsupported("allowed policy") }
            try providerID(b.entryID); try providerCodec(b.requestIdentity)
            guard b.namespace.utf8.count == 32, b.namespace.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw ProviderError.unsupported("parser namespace") }
            try ResumableTokenDriver.assess(identity: b.probeModel.identity, options: b.probeOptions, cacheSpecs: b.probeModel.cacheSpecs)
            try providerTokens(b.originalTokens, width: b.probeOptions.vocabularySize, identity: b.probeModel.identity)
            try providerCodec(b.probeModel.codecIdentity)
            _ = try RequiredToolContract.structuralSource(b.tools); _ = try b.parserConfiguration()
            if let schema = b.responseSchema {
                guard !schema.isEmpty, schema.utf8.count <= 65_536 else { throw ProviderError.oversized }
                _ = try JSONSerialization.jsonObject(with: Data(schema.utf8))
            }
            guard b.tokenizer.source == "{}", b.textOptions.tokenizerIdentity == b.tokenizer.tokenizerIdentity,
                  b.probeOptions.vocabularySize == b.tokenizer.vocabulary.count else { throw ProviderError.unsupported("allowed tokenizer declaration") }
            try providerGuided(b.guidedModel, b.originalTokens, b.tokenizer, b.guidedOptions)
        }
    }
}
public struct ProviderNativeRuntime {
    public let tokenizer: any Tokenizer
    public let codecs: ResumableStateCodecs
    /// Owner attests model/tokenizer/codec implementations match the binding.
    public let model: () throws -> any LanguageModel
    public init(tokenizer: any Tokenizer, codecs: ResumableStateCodecs, model: @escaping () throws -> any LanguageModel) {
        self.tokenizer = tokenizer; self.codecs = codecs; self.model = model
    }
}
public enum ProviderRuntime {
    case ordinary(ProviderNativeRuntime), guided(ProviderNativeRuntime), required(ProviderNativeRuntime), allowed(AllowedToolRuntime)
    var route: ProviderRoute {
        switch self { case .ordinary: .ordinary; case .guided: .guided; case .required: .required; case .allowed: .allowed }
    }
}
public enum ProviderAssessment: Equatable { case supported(reservationBytes: Int), unsupported(String) }
func providerID(_ value: String) throws {
    guard !value.isEmpty, value.utf8.count <= 256 else { throw ProviderError.invalid("provider identifier") }
}
func providerOptionalID(_ value: String?) throws { if let value { try providerID(value) } }
func providerCodec(_ value: String) throws {
    guard !value.isEmpty, value.utf8.count <= 1024 else { throw ProviderError.invalid("child implementation identity") }
}
func providerTokens(_ tokens: [Int], width: Int, identity: ResumableTokenIdentity) throws {
    guard width > 0, (1...65_536).contains(tokens.count), tokens.allSatisfy({ $0 >= 0 && $0 < width }),
          try ResumableTokenIdentity.inputDigest(tokens) == identity.input else { throw ProviderError.invalid("prepared input") }
}
func providerGuided(_ model: AllowedModelBinding, _ tokens: [Int], _ s: ResumableGrammarSpecification, _ o: ResumableGuidedOptions) throws {
    try ResumableGuidedModelState.assess(identity: model.identity, options: o.model, cacheSpecs: model.cacheSpecs)
    try providerTokens(tokens, width: o.model.logitWidth, identity: model.identity); try providerCodec(model.codecIdentity)
    guard !s.source.isEmpty, s.source.utf8.count <= 65_536, (1...4096).contains(s.vocabulary.count),
          s.vocabulary.count == o.model.logitWidth, s.vocabulary.indices.contains(s.eosTokenID),
          s.unknownTokenID.map({ s.vocabulary.indices.contains($0) && $0 != s.eosTokenID }) ?? true,
          !s.tokenizerIdentity.isEmpty, s.tokenizerIdentity.utf8.count <= 1024,
          s.vocabulary.allSatisfy({ $0.utf8.count <= 4096 && !$0.utf8.contains(0) }),
          try providerEncode(s.vocabulary).count <= 256*1024,
          o.sampling == "greedy-v1", o.completionPolicy == "accepted-stop-v1",
          [o.completionReserve, o.hardReserve, o.whitespaceThreshold].allSatisfy({ (0...65_536).contains($0) }),
          o.whitespaceTokenIDs == Set(o.whitespaceTokenIDs).sorted(), o.whitespaceTokenIDs.allSatisfy({ s.vocabulary.indices.contains($0) }) else { throw ProviderError.unsupported("guided declaration") }
    for bias in [o.closingBias, o.whitespaceBias].compactMap({ $0 }) {
        guard bias.count == s.vocabulary.count, bias.allSatisfy({ $0.isFinite && abs($0) <= 10_000 }) else { throw ProviderError.unsupported("guided bias") }
    }
}
func providerEncode<T: Encodable>(_ value: T) throws -> Data {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return try e.encode(value)
}
func providerHash(_ bytes: Data) -> String { ResumableGuidedValues.digest(bytes) }
func providerHashValid(_ value: String) -> Bool { value.utf8.count == 64 && value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) }
