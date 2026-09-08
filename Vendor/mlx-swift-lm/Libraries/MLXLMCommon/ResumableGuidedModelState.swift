// Local guided candidate: additive access to the accepted supported-state codecs.
import Foundation
import MLX

public enum ResumableGuidedValues {
    public static func encoder() -> JSONEncoder { ResumableTokenCheckpoint.encoder() }
    public static func digest(_ data: Data) -> String { ResumableTokenCheckpoint.digest(data) }
}

public struct ResumableGuidedModelOptions: Codable, Equatable, Sendable {
    public var logitWidth: Int
    public var maximumTokens: Int
    public var prefillStepSize: Int
    public init(logitWidth: Int, maximumTokens: Int, prefillStepSize: Int = 512) {
        self.logitWidth = logitWidth; self.maximumTokens = maximumTokens; self.prefillStepSize = prefillStepSize
    }
    public func validate() throws {
        guard (1...4096).contains(logitWidth), (0...65_536).contains(maximumTokens),
            (1...4096).contains(prefillStepSize) else { throw ResumableTokenError.unsupported("guided model options") }
    }
}

struct GuidedModelDocument: Codable {
    var version: Int = 1
    var identity: ResumableTokenIdentity
    var options: ResumableGuidedModelOptions
    var specs: [ResumableCacheSpec]
    var codecs: [ResumableCodecDescriptor]
    var promptCount: Int
    var generatedInputs: Int
    var caches: [ResumableCacheRecord]
    var state: [ResumableStateEntry]?
    var logits: ResumableTensor?
}

public struct ResumableGuidedModelCheckpoint: Equatable, Sendable {
    public static let maximumBytes = 8 * 1024 * 1024
    public let data: Data
    init(document: GuidedModelDocument) throws {
        let payload = try ResumableGuidedValues.encoder().encode(document)
        guard payload.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        let bytes = try ResumableGuidedValues.encoder().encode(ResumableTokenCheckpoint.Envelope(
            payload: payload, sha256: ResumableGuidedValues.digest(payload)))
        guard bytes.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        data = bytes
    }
    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        self.data = data; _ = try document()
    }
    func document() throws -> GuidedModelDocument {
        do {
            let envelope = try JSONDecoder().decode(ResumableTokenCheckpoint.Envelope.self, from: data)
            guard ResumableGuidedValues.digest(envelope.payload) == envelope.sha256 else {
                throw ResumableTokenError.invalid("guided model checksum")
            }
            struct Header: Decodable { let version: Int }
            guard try JSONDecoder().decode(Header.self, from: envelope.payload).version == 1 else {
                throw ResumableTokenError.incompatible
            }
            return try JSONDecoder().decode(GuidedModelDocument.self, from: envelope.payload)
        } catch let error as ResumableTokenError { throw error }
        catch { throw ResumableTokenError.invalid("guided model encoding") }
    }
}

/// Serially confined model owner for a separate settled-logits schedule. It does not
/// sample, mutate S72's driver, or accept guidance callbacks. Only the guided lane may
/// consume its borrowed logits; the owner must not mutate or retain caches/tensors.
public final class ResumableGuidedModelState {
    private let model: any LanguageModel
    private let identity: ResumableTokenIdentity
    private let options: ResumableGuidedModelOptions
    private let specs: [ResumableCacheSpec]
    private let codecs: ResumableStateCodecs
    private var caches: [KVCache]
    private var state: LMOutput.State?
    private var logits: MLXArray?
    public let promptCount: Int
    public private(set) var generatedInputs: Int
    public private(set) var isClosed = false

    private init(model: any LanguageModel, identity: ResumableTokenIdentity, options: ResumableGuidedModelOptions,
                 specs: [ResumableCacheSpec], codecs: ResumableStateCodecs, promptCount: Int,
                 generatedInputs: Int = 0, caches: [KVCache], state: LMOutput.State? = nil, logits: MLXArray? = nil) {
        self.model = model; self.identity = identity; self.options = options; self.specs = specs; self.codecs = codecs
        self.promptCount = promptCount; self.generatedInputs = generatedInputs; self.caches = caches
        self.state = state; self.logits = logits
    }
    public static func assess(identity: ResumableTokenIdentity, options: ResumableGuidedModelOptions,
                              cacheSpecs: [ResumableCacheSpec]) throws {
        try identity.validate(); try options.validate()
        guard cacheSpecs.count <= 128 else { throw ResumableTokenError.oversized }
        for spec in cacheSpecs { try spec.validate() }
    }
    public static func prepare(model: any LanguageModel, tokens: [Int], identity: ResumableTokenIdentity,
                               options: ResumableGuidedModelOptions, cacheSpecs: [ResumableCacheSpec],
                               codecs: ResumableStateCodecs = .init()) throws -> ResumableGuidedModelState {
        try assess(identity: identity, options: options, cacheSpecs: cacheSpecs)
        guard !tokens.isEmpty, tokens.count <= 65_536, tokens.allSatisfy({ (0..<options.logitWidth).contains($0) }),
            try ResumableTokenIdentity.inputDigest(tokens) == identity.input else {
            throw ResumableTokenError.invalid("guided prompt binding")
        }
        let owner = ResumableGuidedModelState(model: model, identity: identity, options: options,
            specs: cacheSpecs, codecs: codecs, promptCount: tokens.count, caches: cacheSpecs.map { $0.makeCache() })
        do {
            if options.maximumTokens > 0 {
                for start in stride(from: 0, to: tokens.count, by: options.prefillStepSize) {
                    try owner.forward(Array(tokens[start..<min(start + options.prefillStepSize, tokens.count)]))
                }
            }
            _ = try owner.capture(); return owner
        } catch { owner.close(); throw error }
    }
    public static func restore(_ checkpoint: ResumableGuidedModelCheckpoint, model: any LanguageModel,
                               identity: ResumableTokenIdentity, options: ResumableGuidedModelOptions,
                               cacheSpecs: [ResumableCacheSpec], codecs: ResumableStateCodecs = .init()) throws -> ResumableGuidedModelState {
        try assess(identity: identity, options: options, cacheSpecs: cacheSpecs)
        let d = try checkpoint.document()
        guard d.identity == identity, d.options == options, d.specs == cacheSpecs, d.codecs == codecs.descriptors else {
            throw ResumableTokenError.incompatible
        }
        guard (1...65_536).contains(d.promptCount), (0...options.maximumTokens).contains(d.generatedInputs),
            d.caches.count == cacheSpecs.count, (options.maximumTokens == 0) == (d.logits == nil) else {
            throw ResumableTokenError.invalid("guided model counters/logits")
        }
        if let logits = d.logits {
            try logits.validate()
            guard logits.shape == [1,1,options.logitWidth], ["float16","bfloat16","float32"].contains(logits.dtype) else {
                throw ResumableTokenError.invalid("guided settled logits")
            }
        }
        let consumed = options.maximumTokens == 0 ? 0 : d.promptCount + d.generatedInputs
        for (record, spec) in zip(d.caches, cacheSpecs) {
            try record.validate(spec: spec, consumed: consumed, window: options.prefillStepSize)
        }
        for entry in d.state ?? [] { try entry.payload.validate() }
        let state = try codecs.restore(d.state)
        let caches = try zip(d.caches, cacheSpecs).map { try $0.restore(spec: $1) }
        let logits = try d.logits?.restored()
        let owner = ResumableGuidedModelState(model: model, identity: identity, options: options,
            specs: cacheSpecs, codecs: codecs, promptCount: d.promptCount, generatedInputs: d.generatedInputs,
            caches: caches, state: state, logits: logits)
        do { _ = try owner.capture(); return owner }
        catch { owner.close(); throw error }
    }
    private func forward(_ tokens: [Int]) throws {
        let input = MLXArray(tokens.map(Int32.init)).reshaped(1,-1)
        let output = withPreparedCache(caches, lengths: [tokens.count]) {
            model(.init(tokens: input), cache: caches.isEmpty ? nil : caches, state: state)
        }
        guard output.logits.shape == [1,tokens.count,options.logitWidth],
            [.float16,.bfloat16,.float32].contains(output.logits.dtype),
            output.logits.nbytes <= ResumableGuidedModelCheckpoint.maximumBytes else {
            throw ResumableTokenError.unsupported("guided model logits")
        }
        for (cache,spec) in zip(caches,specs) { try spec.validateLive(cache) }
        logits = output.logits[0..., (-1)..., 0...]
        state = output.state
        eval([logits!] + caches.flatMap { $0.innerState() })
        _ = try codecs.capture(state)
    }
    public func settledLogits() throws -> MLXArray {
        guard !isClosed else { throw ResumableTokenError.closed }
        guard let logits else { throw ResumableTokenError.invalid("no logits at zero budget") }
        return logits
    }
    /// Every ordinary sampled or forced ID is forwarded once, including the last
    /// generated token. EOS/unknown are intercepted by the guided caller, not forwarded.
    public func consume(_ token: Int) throws {
        guard !isClosed else { throw ResumableTokenError.closed }
        do {
            guard (0..<options.logitWidth).contains(token), generatedInputs < options.maximumTokens else {
                throw ResumableTokenError.invalid("guided model input/budget")
            }
            try forward([token]); generatedInputs += 1
            _ = try capture()
        } catch { close(); throw error }
    }
    public func capture() throws -> ResumableGuidedModelCheckpoint {
        guard !isClosed else { throw ResumableTokenError.closed }
        let consumed = options.maximumTokens == 0 ? 0 : promptCount + generatedInputs
        let records = try zip(caches,specs).map {
            try ResumableCacheRecord(capturing: $0, spec: $1, consumed: consumed, window: options.prefillStepSize)
        }
        return try .init(document: .init(identity: identity, options: options, specs: specs, codecs: codecs.descriptors,
            promptCount: promptCount, generatedInputs: generatedInputs, caches: records, state: codecs.capture(state),
            logits: logits.map { try .init(capturing: $0) }))
    }
    public func close() { isClosed = true; caches = []; state = nil; logits = nil }
}

/// Additive common-module access to the pinned detokenizer's actual internal values.
public struct ResumableGuidedTextValue: Codable, Equatable, Sendable {
    public var tokens: [Int] = []
    public var emitted: Data = Data()
    public var emittedTokenCount: Int = 0
    public init() {}
    public mutating func append(_ token: Int, tokenizer: any Tokenizer) throws -> Data? {
        guard tokens.count < 65_536 else { throw ResumableTokenError.oversized }
        tokens.append(token)
        try ResumableTextState.checkDecode(tokenizer, tokens: tokens)
        try ResumableTextState.checkDecode(tokenizer, tokens: [token])
        var detokenizer = NaiveStreamingDetokenizer(tokenizer: tokenizer)
        detokenizer.segmentTokens = tokens; detokenizer.segment = try ResumableTextState.string(emitted)
        let text = detokenizer.next()
        tokens = detokenizer.segmentTokens; emitted = Data(detokenizer.segment.utf8)
        if text != nil { emittedTokenCount = tokens.count }
        return text.map { Data($0.utf8) }
    }
    public func validate(tokenizer: any Tokenizer, generated: Int, vocabulary: Int) throws {
        guard (0...65_536).contains(generated), tokens.count <= generated,
            (0...tokens.count).contains(emittedTokenCount), tokens.allSatisfy({ (0..<vocabulary).contains($0) }),
            (generated == 0) == tokens.isEmpty else { throw ResumableTokenError.invalid("guided text counts") }
        let segment = try ResumableTextState.string(emitted)
        let expected = emittedTokenCount == 0 ? "" : try ResumableTextState.checkDecode(tokenizer, tokens: Array(tokens.prefix(emittedTokenCount)))
        guard Data(expected.utf8) == emitted else { throw ResumableTokenError.invalid("guided emitted segment") }
        if emittedTokenCount < tokens.count {
            try ResumableTextState.checkDecode(tokenizer,tokens:tokens)
            try ResumableTextState.checkDecode(tokenizer,tokens:[tokens.last!])
            var detokenizer = NaiveStreamingDetokenizer(tokenizer:tokenizer)
            detokenizer.segmentTokens=tokens; detokenizer.segment=segment
            guard detokenizer.next() == nil else { throw ResumableTokenError.invalid("guided unsettled text") }
        }
    }
}
