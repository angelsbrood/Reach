import Foundation
import MLXLMCommon

public enum ResumableGrammarVocabulary: String, Codable, Sendable {
    case raw, byteFallback, byteLevel
    var type: VocabType { switch self { case .raw: .raw; case .byteFallback: .byteFallback; case .byteLevel: .byteLevel } }
}

/// Exact immutable tokenizer/vocabulary and compiler inputs. The tokenizer owner
/// attests bounded deterministic encode/decode, and encode IDs within this vocabulary.
public struct ResumableGrammarSpecification: Codable, Sendable {
    var kind: String = "json-schema"
    public var source: String
    public var vocabulary: [String]
    public var vocabularyType: ResumableGrammarVocabulary
    public var tokenizerIdentity: String
    public var eosTokenID: Int
    public var unknownTokenID: Int?
    public var fastForward: Bool
    var compiler: String = "xgrammar-v0.1.30-d476a48dcd8fa3b5afeddbe850e73bb3b1dcf505;single-accept-replay-v1"
    public init(jsonSchema: String, vocabulary: [String], vocabularyType: ResumableGrammarVocabulary,
                tokenizerIdentity: String, eosTokenID: Int, unknownTokenID: Int? = nil, fastForward: Bool = true) {
        source=jsonSchema; self.vocabulary=vocabulary; self.vocabularyType=vocabularyType
        self.tokenizerIdentity=tokenizerIdentity; self.eosTokenID=eosTokenID
        self.unknownTokenID=unknownTokenID; self.fastForward=fastForward
    }
    /// Exact native structural-tag source, including each tag's root-local schema.
    /// This adds a specification kind; matcher replay and generation remain unchanged.
    public init(structuralTag: String, vocabulary: [String], vocabularyType: ResumableGrammarVocabulary,
                tokenizerIdentity: String, eosTokenID: Int, unknownTokenID: Int? = nil, fastForward: Bool = true) {
        self.init(jsonSchema:structuralTag,vocabulary:vocabulary,vocabularyType:vocabularyType,
            tokenizerIdentity:tokenizerIdentity,eosTokenID:eosTokenID,unknownTokenID:unknownTokenID,fastForward:fastForward)
        kind="structural-tag"
    }
    @_spi(ResumableGuidedFixtures)
    public static func literalFixture(_ grammar: String, vocabulary: [String], vocabularyType: ResumableGrammarVocabulary,
                                      tokenizerIdentity: String, eosTokenID: Int, unknownTokenID: Int? = nil) -> Self {
        var result=Self(jsonSchema:grammar,vocabulary:vocabulary,vocabularyType:vocabularyType,
            tokenizerIdentity:tokenizerIdentity,eosTokenID:eosTokenID,unknownTokenID:unknownTokenID)
        result.kind="literal-fixture"; return result
    }
    func validate() throws {
        guard ["json-schema","literal-fixture","structural-tag"].contains(kind), !source.isEmpty, source.utf8.count<=65_536,
            !source.utf8.contains(0), (1...4096).contains(vocabulary.count),
            vocabulary.allSatisfy({ $0.utf8.count<=4096 && !$0.utf8.contains(0) }),
            vocabulary.indices.contains(eosTokenID),
            unknownTokenID.map({ vocabulary.indices.contains($0) && $0 != eosTokenID }) ?? true,
            !tokenizerIdentity.isEmpty, tokenizerIdentity.utf8.count<=1024,
            compiler=="xgrammar-v0.1.30-d476a48dcd8fa3b5afeddbe850e73bb3b1dcf505;single-accept-replay-v1" else {
            throw ResumableTokenError.unsupported("guided grammar/tokenizer declaration")
        }
        guard try ResumableGuidedValues.encoder().encode(vocabulary).count<=256*1024 else { throw ResumableTokenError.oversized }
    }
    func makeConstraint(tokenizer: any Tokenizer) throws -> GrammarConstraint {
        try validate()
        let grammarTokenizer=try GrammarTokenizer(vocab:vocabulary,vocabType:vocabularyType.type,eosTokenId:Int32(eosTokenID))
        if kind=="json-schema" {
            return try .init(tokenizer:grammarTokenizer,jsonSchema:source,fastForward:fastForward,hostTokenizer:tokenizer)
        }
        if kind=="structural-tag" {
            return try .init(tokenizer:grammarTokenizer,structuralTag:source,fastForward:fastForward,hostTokenizer:tokenizer)
        }
        return try .init(tokenizer:grammarTokenizer,grammar:source,fastForward:fastForward,hostTokenizer:tokenizer)
    }
}

public enum ResumableGuidedOrigin: String, Codable, Sendable { case sampled, forced, ending }
struct GuidedAcceptance: Codable, Equatable {
    var token: Int
    var origin: ResumableGuidedOrigin
}
struct GuidedMask: Codable, Equatable {
    var words: [Int32]
    var needsApply: Bool
    var terminated: Bool
    init(_ mask: MaskResult) { words=mask.mask; needsApply=mask.needsApply; terminated=mask.isTerminated }
    var result: MaskResult { .init(mask:words,isTerminated:terminated,needsApply:needsApply) }
    func allows(_ token: Int) -> Bool {
        token>=0 && token/32<words.count && ((UInt32(bitPattern:words[token/32]) >> UInt32(token%32)) & 1)==1
    }
}
struct ResumableGrammarRecord: Codable {
    var accepts: [GuidedAcceptance] = []
    var mask: GuidedMask
}

final class ResumableGrammarState {
    let specification: ResumableGrammarSpecification
    let constraint: GrammarConstraint
    var record: ResumableGrammarRecord
    init(specification: ResumableGrammarSpecification, tokenizer: any Tokenizer) throws {
        self.specification=specification
        constraint=try specification.makeConstraint(tokenizer:tokenizer)
        record=try .init(mask:GuidedMask(constraint.computeMask()))
    }
    static func restore(_ record: ResumableGrammarRecord, specification: ResumableGrammarSpecification,
                        tokenizer: any Tokenizer) throws -> ResumableGrammarState {
        guard record.accepts.count<=65_536, record.mask.words.count==(specification.vocabulary.count+31)/32 else {
            throw ResumableTokenError.oversized
        }
        let owner=try ResumableGrammarState(specification:specification,tokenizer:tokenizer)
        var terminated=false
        for (index,accept) in record.accepts.enumerated() {
            guard !terminated, specification.vocabulary.indices.contains(accept.token),
                accept.token != specification.unknownTokenID,
                (accept.origin == .ending) == (accept.token == specification.eosTokenID),
                accept.origin != .forced || (index>0 && specification.fastForward) else {
                throw ResumableTokenError.invalid("guided acceptance history")
            }
            terminated=try owner.constraint.replayAcceptedToken(Int32(accept.token))
        }
        let mask=try owner.currentMask(terminated:terminated)
        guard mask==record.mask else { throw ResumableTokenError.invalid("replayed grammar mask/termination") }
        owner.record=record
        return owner
    }
    // A terminated matcher has no next accept. Avoid asking xgrammar for a next mask.
    private func currentMask(terminated: Bool) throws -> GuidedMask {
        if terminated { return GuidedMask(.init(mask:[Int32](repeating:0,count:(specification.vocabulary.count+31)/32),isTerminated:true,needsApply:true)) }
        return try GuidedMask(constraint.computeMask())
    }
    func accept(_ token: Int) throws {
        guard specification.vocabulary.indices.contains(token), token != specification.unknownTokenID,
            record.accepts.count<65_536, !record.mask.terminated, record.mask.allows(token) || !record.mask.needsApply else {
            throw ResumableTokenError.invalid("guided selected token")
        }
        if token==specification.eosTokenID {
            guard record.mask.allows(token) else { throw ResumableTokenError.invalid("premature guided stop") }
            let terminated=try constraint.replayAcceptedToken(Int32(token))
            guard terminated else { throw ResumableTokenError.invalid("stop did not terminate grammar") }
            record.accepts.append(.init(token:token,origin:.ending))
            record.mask=try currentMask(terminated:true)
            return
        }
        let committed=try constraint.commitToken(Int32(token))
        guard committed.tokens.count<=4096, record.accepts.count+1+committed.tokens.count<=65_536,
            committed.tokens.allSatisfy({ specification.vocabulary.indices.contains(Int($0)) && Int($0) != specification.eosTokenID && Int($0) != specification.unknownTokenID }),
            !committed.isTerminated else { throw ResumableTokenError.unsupported("forced suffix length/ending") }
        record.accepts.append(.init(token:token,origin:.sampled))
        record.accepts += committed.tokens.map { .init(token:Int($0),origin:.forced) }
        record.mask=try currentMask(terminated:false)
    }
}
