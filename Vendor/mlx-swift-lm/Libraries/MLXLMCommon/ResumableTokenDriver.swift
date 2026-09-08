// Local candidate: opt-in paused raw-token execution.

import Foundation
import MLX
import MLXNN

/// Model owners attest that all mutable forward state is in the declared caches and
/// LMOutput.State, with no hidden RNG, background producer, mutable weights or side effects.
/// The backend identity must name the compatible device/OS/MLX build and native byte order.
public struct ResumableTokenIdentity: Codable, Equatable, Sendable {
    public let model: String
    public let configuration: String
    public let weights: String
    public let input: String
    public let backend: String
    public let dependency: String

    public init(model: String, configuration: String, weights: String, input: String,
                backend: String, dependency: String) {
        self.model = model; self.configuration = configuration; self.weights = weights
        self.input = input; self.backend = backend; self.dependency = dependency
    }

    public static func inputDigest(_ tokens: [Int]) throws -> String {
        ResumableTokenCheckpoint.digest(try ResumableTokenCheckpoint.encoder().encode(tokens))
    }

    func validate() throws {
        guard [model, configuration, weights, input, backend, dependency].allSatisfy({
            !$0.isEmpty && $0.utf8.count <= 1024
        }) else { throw ResumableTokenError.invalid("compatibility identity") }
    }
}

/// Deliberately excludes arbitrary samplers/processors, quantization, masks, batching,
/// speculative/MTP and multimodal preparation. It does not change GenerateParameters.
public struct ResumableTokenOptions: Codable, Equatable, Sendable {
    public var vocabularySize: Int
    public var maximumTokens: Int
    public var prefillStepSize: Int
    public var temperature: Float
    public var topP: Float
    public var topK: Int
    public var minP: Float
    public var seed: UInt64
    public var sampler: String
    public var repetitionPenalty: Float?
    public var repetitionContextSize: Int
    public var presencePenalty: Float?
    public var presenceContextSize: Int
    public var frequencyPenalty: Float?
    public var frequencyContextSize: Int

    public init(vocabularySize: Int, maximumTokens: Int, prefillStepSize: Int = 512,
                temperature: Float = 0, topP: Float = 1, topK: Int = 0, minP: Float = 0,
                seed: UInt64 = 0, repetitionPenalty: Float? = nil,
                repetitionContextSize: Int = 20, presencePenalty: Float? = nil,
                presenceContextSize: Int = 20, frequencyPenalty: Float? = nil,
                frequencyContextSize: Int = 20) {
        self.vocabularySize = vocabularySize; self.maximumTokens = maximumTokens
        self.prefillStepSize = prefillStepSize; self.temperature = temperature
        self.topP = topP; self.topK = topK; self.minP = minP; self.seed = seed
        self.sampler = temperature == 0 ? "argmax-v1" : "explicit-key-v1"
        self.repetitionPenalty = repetitionPenalty; self.repetitionContextSize = repetitionContextSize
        self.presencePenalty = presencePenalty; self.presenceContextSize = presenceContextSize
        self.frequencyPenalty = frequencyPenalty; self.frequencyContextSize = frequencyContextSize
    }

    func validate() throws {
        guard (1...65_536).contains(vocabularySize), (0...65_536).contains(maximumTokens),
            (1...4096).contains(prefillStepSize), temperature.isFinite, temperature >= 0,
            temperature == 0 || (1 / temperature).isFinite,
            topP.isFinite, (0...1).contains(topP), topK >= 0, topK <= vocabularySize,
            minP.isFinite, (0...1).contains(minP),
            sampler == (temperature == 0 ? "argmax-v1" : "explicit-key-v1")
        else { throw ResumableTokenError.unsupported("sampling/options") }
        for size in [repetitionContextSize, presenceContextSize, frequencyContextSize] {
            guard (1...4096).contains(size) else { throw ResumableTokenError.unsupported("history size") }
        }
        for penalty in [repetitionPenalty, presencePenalty, frequencyPenalty].compactMap({ $0 }) {
            guard penalty.isFinite else { throw ResumableTokenError.invalid("penalty") }
        }
        if let repetitionPenalty, repetitionPenalty < 0 {
            throw ResumableTokenError.unsupported("negative repetition penalty")
        }
    }

    var parameters: GenerateParameters {
        GenerateParameters(maxTokens: maximumTokens, temperature: temperature, topP: topP,
            topK: topK, minP: minP, repetitionPenalty: repetitionPenalty,
            repetitionContextSize: repetitionContextSize, presencePenalty: presencePenalty,
            presenceContextSize: presenceContextSize, frequencyPenalty: frequencyPenalty,
            frequencyContextSize: frequencyContextSize, prefillStepSize: prefillStepSize, seed: seed)
    }
}

/// Serially confined, opt-in raw-token driver. No work runs between calls. Each call
/// returns a settled checkpoint; consumers decide when/how to commit or publish it.
/// This driver owns fresh caches; callers must not retain or mutate them through the model.
/// Existing TokenIterator and its pipelined sampling remain untouched.
public final class ResumableTokenDriver {
    public struct Step {
        public let token: Int
        public let checkpoint: ResumableTokenCheckpoint
    }

    private let model: any LanguageModel
    private let identity: ResumableTokenIdentity
    private let options: ResumableTokenOptions
    private let specs: [ResumableCacheSpec]
    private let codecs: ResumableStateCodecs
    private let promptCount: Int
    private var caches: [KVCache]
    private var state: LMOutput.State?
    private var processor: PenaltyProcessor
    private var randomKey: MLXArray?
    private var randomDraws: Int
    private var pending: Int?
    public private(set) var tokenCount: Int
    public private(set) var exhausted: Bool
    public private(set) var isClosed = false

    /// Checks declarations without any model call, cache creation or sampling.
    public static func assess(identity: ResumableTokenIdentity, options: ResumableTokenOptions,
                              cacheSpecs: [ResumableCacheSpec]) throws {
        try identity.validate(); try options.validate()
        guard cacheSpecs.count <= 128 else { throw ResumableTokenError.oversized }
        for spec in cacheSpecs { try spec.validate() }
    }

    private init(model: any LanguageModel, identity: ResumableTokenIdentity,
                 options: ResumableTokenOptions, specs: [ResumableCacheSpec],
                 codecs: ResumableStateCodecs, promptCount: Int, caches: [KVCache],
                 state: LMOutput.State?, processor: PenaltyProcessor, randomKey: MLXArray?,
                 randomDraws: Int, pending: Int?, tokenCount: Int, exhausted: Bool) {
        self.model = model; self.identity = identity; self.options = options; self.specs = specs
        self.codecs = codecs; self.promptCount = promptCount; self.caches = caches
        self.state = state; self.processor = processor; self.randomKey = randomKey
        self.randomDraws = randomDraws; self.pending = pending; self.tokenCount = tokenCount
        self.exhausted = exhausted
    }

    /// Prepare batch-one text directly through forward calls, carrying typed state across
    /// every prefill chunk. Generic model.prepare may preprocess media or lose intermediate
    /// state; it is intentionally outside this explicitly declared text-only contract.
    /// C0 contains the first sampled but not returned token (unless maximumTokens is zero).
    public static func prepare(model: any LanguageModel, tokens: [Int],
                               identity: ResumableTokenIdentity, options: ResumableTokenOptions,
                               cacheSpecs: [ResumableCacheSpec],
                               codecs: ResumableStateCodecs = .init()) throws -> ResumableTokenDriver {
        try assess(identity: identity, options: options, cacheSpecs: cacheSpecs)
        guard !tokens.isEmpty, tokens.count <= 65_536,
            tokens.allSatisfy({ $0 >= 0 && $0 < options.vocabularySize }),
            try ResumableTokenIdentity.inputDigest(tokens) == identity.input
        else { throw ResumableTokenError.invalid("input tokens/binding") }
        var processor = PenaltyProcessor.resumable(options)
        processor.prompt(MLXArray(tokens.map(Int32.init)))
        let driver = ResumableTokenDriver(model: model, identity: identity, options: options,
            specs: cacheSpecs, codecs: codecs, promptCount: tokens.count,
            caches: cacheSpecs.map { $0.makeCache() }, state: nil, processor: processor,
            randomKey: options.temperature == 0 ? nil : MLXRandom.key(options.seed),
            randomDraws: 0, pending: nil, tokenCount: 0, exhausted: options.maximumTokens == 0)
        do {
            if !driver.exhausted {
                var start = 0
                while start < tokens.count {
                    let end = min(start + options.prefillStepSize, tokens.count)
                    let input = MLXArray(tokens[start..<end].map(Int32.init)).reshaped(1, -1)
                    let logits = try driver.forward(input)
                    if end == tokens.count { driver.pending = try driver.sample(logits) }
                    start = end
                }
            }
            _ = try driver.capture()
            return driver
        } catch { driver.close(); throw error }
    }

    /// All metadata is checked before creating tensors/caches. No model entry point,
    /// prompt prefill, RNG initialization, sampling or existing-driver mutation occurs.
    public static func restore(_ checkpoint: ResumableTokenCheckpoint, model: any LanguageModel,
                               identity: ResumableTokenIdentity, options: ResumableTokenOptions,
                               cacheSpecs: [ResumableCacheSpec],
                               codecs: ResumableStateCodecs = .init()) throws -> ResumableTokenDriver {
        try assess(identity: identity, options: options, cacheSpecs: cacheSpecs)
        let d = try checkpoint.document()
        guard d.identity == identity, d.options == options, d.cacheSpecs == cacheSpecs,
            d.codecs == codecs.descriptors else { throw ResumableTokenError.incompatible }
        guard (1...65_536).contains(d.promptCount), d.tokenCount >= 0,
            d.tokenCount <= options.maximumTokens,
            d.exhausted == (d.tokenCount == options.maximumTokens),
            (d.exhausted ? d.pending == nil : d.pending.map({ $0 >= 0 && $0 < options.vocabularySize }) == true),
            d.caches.count == cacheSpecs.count
        else { throw ResumableTokenError.invalid("pending token/count/exhaustion") }
        let sampled = options.maximumTokens == 0 ? 0 : min(d.tokenCount + 1, options.maximumTokens)
        guard d.randomDraws == (options.temperature == 0 ? 0 : sampled),
            (options.temperature == 0) == (d.randomKey == nil)
        else { throw ResumableTokenError.invalid("RNG accounting") }
        if let key = d.randomKey {
            try key.validate()
            guard key.shape == [2], key.dtype == "uint32" else {
                throw ResumableTokenError.invalid("RNG key")
            }
        }
        let consumed = options.maximumTokens == 0 ? 0 : d.promptCount + sampled - 1
        for (record, spec) in zip(d.caches, cacheSpecs) {
            try record.validate(spec: spec, consumed: consumed, window: options.prefillStepSize)
        }
        try PenaltyProcessor.validateResumable(d.rings, options: options)
        for ring in d.rings.compactMap({ $0 }) {
            let capacity = ring.buffer.count
            let expectedCount = min(d.promptCount + sampled, capacity)
            let initialIndex = d.promptCount > capacity ? 0 : d.promptCount % capacity
            guard ring.count == expectedCount,
                ring.writeIndex == (initialIndex + sampled) % capacity
            else { throw ResumableTokenError.invalid("processor history accounting") }
        }
        for entry in d.state ?? [] { try entry.payload.validate() }
        let state = try codecs.restore(d.state)
        let caches = try zip(d.caches, cacheSpecs).map { try $0.restore(spec: $1) }
        let driver = ResumableTokenDriver(model: model, identity: identity, options: options,
            specs: cacheSpecs, codecs: codecs, promptCount: d.promptCount, caches: caches,
            state: state, processor: try PenaltyProcessor.restoredResumable(d.rings, options: options),
            randomKey: try d.randomKey?.restored(), randomDraws: d.randomDraws,
            pending: d.pending, tokenCount: d.tokenCount, exhausted: d.exhausted)
        // Force restored supported arrays before returning a paused driver.
        _ = try driver.capture()
        return driver
    }

    public func advance() throws -> Step? {
        guard !isClosed else { throw ResumableTokenError.closed }
        guard !exhausted else { return nil }
        do {
            guard let token = pending else { throw ResumableTokenError.invalid("missing pending token") }
            tokenCount += 1
            exhausted = tokenCount == options.maximumTokens
            if exhausted { pending = nil }
            else { pending = try sample(forward(MLXArray([Int32(token)]).reshaped(1, 1))) }
            // No usable token/checkpoint pair escapes when a new unsupported state appears.
            return try Step(token: token, checkpoint: capture())
        } catch { close(); throw error }
    }

    private func forward(_ tokens: MLXArray) throws -> MLXArray {
        let output = withPreparedCache(caches, lengths: [tokens.dim(1)]) {
            model(.init(tokens: tokens), cache: caches.isEmpty ? nil : caches, state: state)
        }
        guard output.logits.shape == [1, tokens.dim(1), options.vocabularySize],
            [DType.float16, .bfloat16, .float32].contains(output.logits.dtype)
        else { throw ResumableTokenError.unsupported("model logits shape/dtype") }
        for (cache, spec) in zip(caches, specs) { try spec.validateLive(cache) }
        state = output.state
        eval([output.logits] + caches.flatMap { $0.innerState() })
        _ = try codecs.capture(state)
        return output.logits[0..., -1, 0...]
    }

    private func sample(_ logits: MLXArray) throws -> Int {
        var logits = processor.process(logits: logits)
        let values = logits.asArray(Float.self)
        guard values.contains(where: { $0.isFinite }),
            values.allSatisfy({ !$0.isNaN && $0 != .infinity })
        else { throw ResumableTokenError.invalid("non-finite logits") }
        let token: MLXArray
        if options.temperature == 0 { token = argMax(logits, axis: -1) }
        else {
            if logits.dtype == .bfloat16 { logits = logits.asType(.float32) }
            // Same full-vocabulary filter order and thresholds as the pinned TopPSampler.
            if (options.topP > 0 && options.topP < 1) || options.minP > 0 || options.topK > 0 {
                logits = logSoftmax(logits)
                if options.topP > 0 && options.topP < 1 {
                    let indices = argSort(logits, axis: -1)
                    let sorted = takeAlong(logits, indices, axis: -1)
                    let keep = cumsum(exp(sorted), axis: -1) .> (1 - options.topP)
                    logits = putAlong(logits, indices,
                        values: MLX.where(keep, sorted, MLXArray(-Float.infinity)), axis: -1)
                }
                if options.minP > 0 {
                    let threshold = logits.max(axis: -1, keepDims: true) + log(MLXArray(options.minP))
                    logits = MLX.where(logits .>= threshold, logits, MLXArray(-Float.infinity))
                }
                if options.topK > 0 && options.topK < options.vocabularySize {
                    let indices = argPartition(-logits, kth: options.topK - 1, axis: -1)[0..., options.topK...]
                    logits = putAlong(logits, indices, values: MLXArray(-Float.infinity), axis: -1)
                }
            }
            guard let key = randomKey else { throw ResumableTokenError.invalid("missing random key") }
            let (next, draw) = MLXRandom.split(key: key)
            token = MLXRandom.categorical(logits * (1 / options.temperature), key: draw)
            randomKey = next
            randomDraws += 1
        }
        eval([token] + [randomKey].compactMap { $0 })
        let value = token.item(Int.self)
        guard value >= 0 && value < options.vocabularySize else {
            throw ResumableTokenError.invalid("sampled token")
        }
        processor.didSample(token: token)
        return value
    }

    public func capture() throws -> ResumableTokenCheckpoint {
        guard !isClosed else { throw ResumableTokenError.closed }
        let consumed = options.maximumTokens == 0 ? 0 : promptCount + min(tokenCount, options.maximumTokens - 1)
        let records = try zip(caches, specs).map {
            try ResumableCacheRecord(capturing: $0, spec: $1, consumed: consumed,
                window: options.prefillStepSize)
        }
        let frozenState = try codecs.capture(state)
        let frozenKey = try randomKey.map { try ResumableTensor(capturing: $0) }
        let bytes = records.flatMap(\.tensors).reduce(0) { $0 + $1.bytes.count }
            + (frozenState ?? []).reduce(0) { $0 + $1.payload.metadata.count
                + $1.payload.tensors.reduce(0) { $0 + $1.bytes.count } }
            + (frozenKey?.bytes.count ?? 0)
        guard bytes <= ResumableTokenCheckpoint.maximumBytes else { throw ResumableTokenError.oversized }
        return try ResumableTokenCheckpoint(document: .init(identity: identity, options: options,
            cacheSpecs: specs, codecs: codecs.descriptors, promptCount: promptCount,
            tokenCount: tokenCount, pending: pending, exhausted: exhausted,
            randomKey: frozenKey, randomDraws: randomDraws,
            rings: processor.captureResumable(), caches: records, state: frozenState))
    }

    /// Every submitted evaluation is synchronous and settled before returning. Discard
    /// unused lazy values on refusal/close without submitting unsupported graphs. The
    /// declared model contract prohibits independent background work. No model/sampler call.
    public func close() {
        guard !isClosed else { return }
        isClosed = true
        pending = nil
        caches = []
        state = nil
        randomKey = nil
    }
}
