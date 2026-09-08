import Foundation
import MLX
import MLXLMCommon

public struct ResumableGuidedOptions: Codable, Sendable {
    public var model: ResumableGuidedModelOptions
    public var sampling: String = "greedy-v1"
    public var completionPolicy: String = "accepted-stop-v1"
    public var completionReserve: Int
    public var hardReserve: Int
    public var closingBias: [Float]?
    public var whitespaceBias: [Float]?
    public var whitespaceTokenIDs: [Int]
    public var whitespaceThreshold: Int
    public init(model: ResumableGuidedModelOptions, completionReserve: Int = 64, hardReserve: Int = 0,
                closingBias: [Float]? = nil, whitespaceBias: [Float]? = nil,
                whitespaceTokenIDs: Set<Int> = [], whitespaceThreshold: Int = 3) {
        self.model=model; self.completionReserve=completionReserve; self.hardReserve=hardReserve
        self.closingBias=closingBias; self.whitespaceBias=whitespaceBias
        self.whitespaceTokenIDs=whitespaceTokenIDs.sorted(); self.whitespaceThreshold=whitespaceThreshold
    }
    func validate(vocabulary: Int) throws {
        try model.validate()
        guard sampling=="greedy-v1", completionPolicy=="accepted-stop-v1",
            (0...65_536).contains(completionReserve), (0...65_536).contains(hardReserve),
            (0...65_536).contains(whitespaceThreshold), whitespaceTokenIDs.count<=vocabulary,
            whitespaceTokenIDs==Set(whitespaceTokenIDs).sorted(),
            whitespaceTokenIDs.allSatisfy({ (0..<vocabulary).contains($0) }) else { throw ResumableTokenError.unsupported("guided policy") }
        for values in [closingBias,whitespaceBias].compactMap({ $0 }) {
            guard values.count==vocabulary, values.allSatisfy({ $0.isFinite && abs($0)<=10_000 }) else {
                throw ResumableTokenError.unsupported("guided bias bounds")
            }
        }
    }
    enum Zone: String { case normal, soft, hard }
    func zone(at count: Int) -> Zone {
        if hardReserve>0 && count>=model.maximumTokens-hardReserve { return .hard }
        if count>=model.maximumTokens-completionReserve { return .soft }
        return .normal
    }
    // Same mask-gated normal/soft/hard/latched-whitespace policy as the pinned loop.
    func bias(at count: Int, mask: GuidedMask, whitespaceActive: Bool, eos: Int) -> MLXArray? {
        guard mask.needsApply else { return nil }
        var active: MLXArray?
        if let values=closingBias {
            switch zone(at:count) {
            case .normal: break
            case .soft: active=MLXArray(values)
            case .hard:
                var hard=values.map { $0>0 ? Float(0) : Float(-10_000) }
                hard[eos] -= 10_000
                active=MLXArray(hard)
            }
        }
        if let values=whitespaceBias, whitespaceActive { active=active.map { $0+MLXArray(values) } ?? MLXArray(values) }
        return active
    }
}

/// Paused guided lane with a complete single-token recurrence. Each ordinary
/// sampled token is forwarded before draining its accepted forced suffix; each
/// forced token gets its own forward call. This deliberately does not reproduce
/// the legacy callback loop's omitted sampled-token forward in its FF branch.
/// No tools, stochastic sampling, generic processors, queues or host storage.
public final class ResumableGuidedGeneration {
    public struct Batch {
        public let token: Int?
        public let origin: ResumableGuidedOrigin?
        public let records: [ResumableGuidedRecord]
        public let checkpoint: ResumableGuidedCheckpoint
    }
    private let tokenizer: any Tokenizer
    private var model: ResumableGuidedModelState?
    private var modelCheckpoint: ResumableGuidedModelCheckpoint
    private var grammar: ResumableGrammarState?
    private var state: ResumableGuidedState
    private var tracker: WhitespaceRunTracker
    public private(set) var isClosed=false
    public var terminalReason: ResumableGuidedEnd? { state.terminal }
    public var pendingForcedTokens: [Int] { state.grammar.accepts.dropFirst(state.consumed).map(\.token) }
    public var consumedTokens: Int { state.consumed }

    private init(model: ResumableGuidedModelState, modelCheckpoint: ResumableGuidedModelCheckpoint,
                 grammar: ResumableGrammarState, state: ResumableGuidedState,
                 tracker: WhitespaceRunTracker, tokenizer: any Tokenizer) {
        self.model=model; self.modelCheckpoint=modelCheckpoint; self.grammar=grammar; self.state=state
        self.tracker=tracker; self.tokenizer=tokenizer
        if state.terminal != nil { model.close(); self.model=nil; self.grammar=nil }
    }
    public static func prepare(model: any LanguageModel, tokens: [Int], identity: ResumableTokenIdentity,
                               cacheSpecs: [ResumableCacheSpec], codecs: ResumableStateCodecs = .init(),
                               tokenizer: any Tokenizer, specification: ResumableGrammarSpecification,
                               options: ResumableGuidedOptions) throws -> ResumableGuidedGeneration {
        try specification.validate(); try options.validate(vocabulary:specification.vocabulary.count)
        try ResumableGuidedModelState.assess(identity:identity,options:options.model,cacheSpecs:cacheSpecs)
        let grammar=try ResumableGrammarState(specification:specification,tokenizer:tokenizer)
        let owner=try ResumableGuidedModelState.prepare(model:model,tokens:tokens,identity:identity,
            options:options.model,cacheSpecs:cacheSpecs,codecs:codecs)
        do {
            let snapshot=try owner.capture()
            let state=ResumableGuidedState(specification:specification,options:options,
                modelDigest:ResumableGuidedValues.digest(snapshot.data),promptCount:tokens.count,grammar:grammar.record)
            let result=ResumableGuidedGeneration(model:owner,modelCheckpoint:snapshot,grammar:grammar,state:state,
                tracker:WhitespaceRunTracker(threshold:options.whitespaceThreshold,whitespaceTokenIDs:Set(options.whitespaceTokenIDs)),tokenizer:tokenizer)
            _=try result.capture(); return result
        } catch { owner.close(); throw error }
    }
    public static func restore(_ checkpoint: ResumableGuidedCheckpoint, model: any LanguageModel,
                               identity: ResumableTokenIdentity, cacheSpecs: [ResumableCacheSpec],
                               codecs: ResumableStateCodecs = .init(), tokenizer: any Tokenizer,
                               specification: ResumableGrammarSpecification, options: ResumableGuidedOptions) throws -> ResumableGuidedGeneration {
        try specification.validate(); try options.validate(vocabulary:specification.vocabulary.count)
        let d=try checkpoint.document()
        guard try ResumableGuidedValues.encoder().encode(specification)==ResumableGuidedValues.encoder().encode(d.guided.specification),
            try ResumableGuidedValues.encoder().encode(options)==ResumableGuidedValues.encoder().encode(d.guided.options),
            d.guided.modelDigest==ResumableGuidedValues.digest(d.model) else { throw ResumableTokenError.incompatible }
        let tracker=try d.guided.validate(tokenizer:tokenizer)
        guard d.guided.grammar.accepts.filter({ $0.origin != .ending }).allSatisfy({ $0.token<options.model.logitWidth }) else {
            throw ResumableTokenError.invalid("guided accepted/model width")
        }
        let grammar=try ResumableGrammarState.restore(d.guided.grammar,specification:specification,tokenizer:tokenizer)
        let child=try ResumableGuidedModelCheckpoint(data:d.model)
        let owner=try ResumableGuidedModelState.restore(child,model:model,identity:identity,options:options.model,cacheSpecs:cacheSpecs,codecs:codecs)
        guard owner.generatedInputs==d.guided.sampled+d.guided.forced, owner.promptCount==d.guided.promptCount else {
            owner.close(); throw ResumableTokenError.invalid("guided model/output frontier")
        }
        return .init(model:owner,modelCheckpoint:child,grammar:grammar,state:d.guided,tracker:tracker,tokenizer:tokenizer)
    }
    public func capture() throws -> ResumableGuidedCheckpoint {
        guard !isClosed else { throw ResumableTokenError.closed }
        return try .init(document:.init(model:modelCheckpoint.data,guided:state))
    }
    public func advance() throws -> Batch? {
        guard !isClosed else { throw ResumableTokenError.closed }
        guard state.terminal==nil else { return nil }
        do {
            guard state.consumed<state.options.model.maximumTokens else { return try finish(.incomplete,token:nil,origin:nil,records:[]) }
            guard let model, let grammar else { throw ResumableTokenError.invalid("missing guided owners") }
            if state.consumed==state.grammar.accepts.count {
                let token=try sample(model.settledLogits())
                // Unknown alone cannot be a successful schema ending.
                guard token != state.specification.unknownTokenID else { throw ResumableTokenError.unsupported("unknown guided ending") }
                if state.options.whitespaceBias != nil { _=tracker.record(tokenID:token) }
                try grammar.accept(token)
                state.grammar=grammar.record
                guard state.grammar.accepts.dropFirst(state.consumed).allSatisfy({ $0.origin == .ending || $0.token<state.options.model.logitWidth }) else {
                    throw ResumableTokenError.unsupported("forced token outside model input range")
                }
            }
            let entry=state.grammar.accepts[state.consumed]
            state.consumed+=1
            state.whitespaceCount=tracker.resumableState.count; state.whitespaceLatched=tracker.resumableState.latched
            if entry.origin == .ending {
                state.intercepted+=1
                return try finish(.complete,token:entry.token,origin:.ending,records:[])
            }
            if entry.origin == .sampled { state.sampled+=1 } else { state.forced+=1 }
            try model.consume(entry.token)
            modelCheckpoint=try model.capture(); state.modelDigest=ResumableGuidedValues.digest(modelCheckpoint.data)
            let records=try state.text.append(entry.token,tokenizer:tokenizer)
            if state.consumed==state.options.model.maximumTokens {
                return try finish(.incomplete,token:entry.token,origin:entry.origin,records:records)
            }
            return try batch(token:entry.token,origin:entry.origin,records:records)
        } catch { close(); throw error }
    }
    private func sample(_ logits: MLXArray) throws -> Int {
        let mask=state.grammar.mask, width=state.options.model.logitWidth, vocabulary=state.specification.vocabulary.count
        guard !mask.terminated, mask.words.count==(vocabulary+31)/32 else { throw ResumableTokenError.invalid("guided sampling mask") }
        var array=GuidedGenerationLoop.buildMaskArray(for:mask.result,vocabSize:vocabulary,logitDim:width)
        if !mask.needsApply && width>vocabulary {
            array=MLXArray((0..<width).map { $0<vocabulary ? Float(0) : -Float.infinity })
        }
        let values=logits.asArray(Float.self)
        guard values.allSatisfy({ !$0.isNaN && $0 != .infinity }),
            values.enumerated().contains(where:{ $0.element.isFinite && $0.offset<vocabulary && (!mask.needsApply || mask.allows($0.offset)) }) else {
            throw ResumableTokenError.invalid("no finite grammar-allowed logits")
        }
        let bias=state.options.bias(at:state.consumed,mask:mask,whitespaceActive:tracker.isActive,eos:state.specification.eosTokenID)
        let token=Int(GuidedGenerationLoop.applyMaskAndSample(logits:logits,maskArray:array,closingBias:bias))
        guard token<vocabulary, !mask.needsApply || mask.allows(token) else { throw ResumableTokenError.invalid("guided mask exclusion") }
        return token
    }
    public func cancel() throws -> Batch? {
        guard !isClosed else { throw ResumableTokenError.closed }
        guard state.terminal==nil else { return nil }
        do { return try finish(.cancelled,token:nil,origin:nil,records:[]) }
        catch { close(); throw error }
    }
    private func finish(_ reason: ResumableGuidedEnd, token: Int?, origin: ResumableGuidedOrigin?, records: [ResumableGuidedRecord]) throws -> Batch {
        state.terminal=reason; model?.close(); model=nil; grammar=nil
        var records=records
        records.append(.terminal(.init(reason:reason,promptTokens:state.promptCount,sampledTokens:state.sampled,
            forcedTokens:state.forced,interceptedEndings:state.intercepted,acceptedTokens:state.grammar.accepts.count,
            pendingTokens:state.grammar.accepts.count-state.consumed,grammarTerminated:state.grammar.mask.terminated)))
        return try batch(token:token,origin:origin,records:records)
    }
    private func batch(token: Int?, origin: ResumableGuidedOrigin?, records: [ResumableGuidedRecord]) throws -> Batch {
        let checkpoint=try capture()
        guard records.count<=2,
            try ResumableGuidedValues.encoder().encode(state).count + ResumableGuidedValues.encoder().encode(records).count<=ResumableGuidedCheckpoint.maximumGuidanceBytes else {
            throw ResumableTokenError.oversized
        }
        return .init(token:token,origin:origin,records:records,checkpoint:checkpoint)
    }
    /// Silent discard. Use cancel for a semantic terminal record; no model work here.
    public func close() { isClosed=true; model?.close(); model=nil; grammar=nil }
}
