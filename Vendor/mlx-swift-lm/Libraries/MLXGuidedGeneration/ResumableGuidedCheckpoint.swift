import Foundation
import MLXLMCommon

struct ResumableGuidedState: Codable {
    var specification: ResumableGrammarSpecification
    var options: ResumableGuidedOptions
    var modelDigest: String
    var promptCount: Int
    var grammar: ResumableGrammarRecord
    // Prefix of accepted IDs consumed by output (and, except EOS, by the model).
    // The remaining accepted suffix consists exclusively of pending forced IDs.
    var consumed: Int = 0
    var sampled: Int = 0
    var forced: Int = 0
    var intercepted: Int = 0
    var whitespaceCount: Int = 0
    var whitespaceLatched: Bool = false
    var text=ResumableGuidedTextState()
    var terminal: ResumableGuidedEnd?

    func validate(tokenizer: any Tokenizer) throws -> WhitespaceRunTracker {
        try specification.validate(); try options.validate(vocabulary:specification.vocabulary.count)
        let accepts=grammar.accepts
        guard accepts.count<=65_536, (0...accepts.count).contains(consumed), consumed<=options.model.maximumTokens,
            accepts.count-consumed<=4096, (1...65_536).contains(promptCount),
            accepts.dropFirst(consumed).allSatisfy({ $0.origin == .forced }),
            accepts.allSatisfy({ specification.vocabulary.indices.contains($0.token) }),
            sampled>=0, forced>=0, (0...1).contains(intercepted) else {
            throw ResumableTokenError.invalid("guided frontier/counters")
        }
        let prefix=accepts.prefix(consumed)
        guard sampled==prefix.filter({ $0.origin == .sampled }).count,
            forced==prefix.filter({ $0.origin == .forced }).count,
            intercepted==prefix.filter({ $0.origin == .ending }).count,
            sampled+forced+intercepted==consumed,
            (intercepted==1)==grammar.mask.terminated else { throw ResumableTokenError.invalid("guided origin accounting") }
        var tracker=WhitespaceRunTracker(threshold:options.whitespaceThreshold,whitespaceTokenIDs:Set(options.whitespaceTokenIDs))
        if options.whitespaceBias != nil {
            for entry in prefix where entry.origin != .forced { _=tracker.record(tokenID:entry.token) }
        }
        guard tracker.resumableState.count==whitespaceCount, tracker.resumableState.latched==whitespaceLatched else {
            throw ResumableTokenError.invalid("guided whitespace latch")
        }
        switch terminal {
        case nil:
            guard !grammar.mask.terminated, consumed<options.model.maximumTokens || options.model.maximumTokens==0 else {
                throw ResumableTokenError.invalid("active guided lifecycle")
            }
        case .complete:
            guard grammar.mask.terminated, intercepted==1, consumed==accepts.count else { throw ResumableTokenError.invalid("guided completion") }
        case .incomplete:
            guard !grammar.mask.terminated, consumed==options.model.maximumTokens else { throw ResumableTokenError.invalid("guided incomplete ending") }
        case .cancelled:
            guard !grammar.mask.terminated else { throw ResumableTokenError.invalid("guided cancellation") }
        }
        try text.value.validate(tokenizer:tokenizer,generated:sampled+forced,vocabulary:specification.vocabulary.count)
        // Derive the complete reachable value, including newline resets and
        // nonlinear decode, from bounded consumed history. Discard private
        // text; this does not publish records, increment usage or call a model.
        var reachableText=ResumableGuidedTextValue()
        for entry in prefix where entry.origin != .ending {
            _=try reachableText.append(entry.token,tokenizer:tokenizer)
        }
        guard reachableText==text.value else {
            throw ResumableTokenError.invalid("guided output history")
        }
        return tracker
    }
}

struct ResumableGuidedDocument: Codable {
    var version: Int = 1
    var prerequisiteIdentity: String = ResumableGuidedCheckpoint.prerequisiteIdentity
    var model: Data
    var guided: ResumableGuidedState
}

public struct ResumableGuidedCheckpoint: Equatable, Sendable {
    public static let maximumBytes=16*1024*1024
    public static let maximumGuidanceBytes=1024*1024
    public static let prerequisiteIdentity="S72:35a3be79e989c39ae568f97a70baf8bdb5b75f3161919803cc8a1530a0db63ab;S73:bd3fb02e7fab42887593512599de64ecb4d7c7c242d91359d37158d2a8227113"
    public let data: Data
    struct Envelope: Codable { let payload: Data; let sha256: String }
    init(document: ResumableGuidedDocument) throws {
        guard document.model.count<=ResumableGuidedModelCheckpoint.maximumBytes,
            try ResumableGuidedValues.encoder().encode(document.guided).count<=Self.maximumGuidanceBytes else { throw ResumableTokenError.oversized }
        let payload=try ResumableGuidedValues.encoder().encode(document)
        guard payload.count<=Self.maximumBytes else { throw ResumableTokenError.oversized }
        let encoded=try ResumableGuidedValues.encoder().encode(Envelope(payload:payload,sha256:ResumableGuidedValues.digest(payload)))
        guard encoded.count<=Self.maximumBytes else { throw ResumableTokenError.oversized }
        data=encoded
    }
    public init(data: Data) throws {
        guard data.count<=Self.maximumBytes else { throw ResumableTokenError.oversized }
        self.data=data; _=try document()
    }
    func document() throws -> ResumableGuidedDocument {
        do {
            let envelope=try JSONDecoder().decode(Envelope.self,from:data)
            guard ResumableGuidedValues.digest(envelope.payload)==envelope.sha256 else { throw ResumableTokenError.invalid("guided checksum") }
            struct Header: Decodable { let version: Int; let prerequisiteIdentity: String }
            let header=try JSONDecoder().decode(Header.self,from:envelope.payload)
            guard header.version==1, header.prerequisiteIdentity==Self.prerequisiteIdentity else { throw ResumableTokenError.incompatible }
            let d=try JSONDecoder().decode(ResumableGuidedDocument.self,from:envelope.payload)
            guard d.model.count<=ResumableGuidedModelCheckpoint.maximumBytes,
                try ResumableGuidedValues.encoder().encode(d.guided).count<=Self.maximumGuidanceBytes else { throw ResumableTokenError.oversized }
            return d
        } catch let error as ResumableTokenError { throw error }
        catch { throw ResumableTokenError.invalid("guided encoding") }
    }
}
