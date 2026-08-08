import Foundation
import HuggingFace
import MLX
import MLXGuidedGeneration
import MLXHuggingFace
import MLXLLM
import MLXLMCommon
import ReachWire
import Tokenizers

/// Open weights on the host GPU behind the slot — single-node MLX only for
/// this package (the exo adapter is funded scope, and deliberately absent).
public final class MLXFilling: SlotFilling {
    public let modelID: String
    public let displayName: String
    public let capabilities: [String] = []

    private let configuration: ModelConfiguration
    private let container = ContainerBox()

    /// Known registry ids map through `LLMRegistry`; anything else is
    /// treated as a Hugging Face repo id.
    public init(modelID: String) {
        self.modelID = modelID
        switch modelID {
        // The model sets the demo's pacing, and it is the ONLY thing that
        // does — measured 2026-07-31 across seven runs. The prompt's stated
        // word count moves nothing (3000/5000/8000 all landed in the same
        // band) and neither does the paragraph count. What changes is the
        // model, and it moves both terms of the same fraction: a larger one
        // writes more tokens AND emits them more slowly, so wall-clock swings
        // far more than the parameter count suggests.
        //
        //   e2b-qat-4bit  ~2,500 tok  ~110 tok/s  19–27 s   (too tight)
        //   e4b-it-4bit   ~2,700 tok   ~90 tok/s  ~30 s     ← the demo
        //   26b-a4b-8bit  ~4,100 tok   ~54 tok/s  76 s      (dominates the film)
        //
        // 26B is the better sentence about the rig and the worse film: at 76 s
        // the stream *is* the piece, and the one span that must run 1:1 — the
        // hop — ends up buried in fast-forward. E4B is the compromise that is
        // not a compromise.
        case "gemma-4-e4b", "default":
            // Straight off the registry: upstream names this one, so it
            // carries its own `extraEOSTokens` and there is no hand-built
            // configuration to drift.
            configuration = LLMRegistry.gemma4_e4b_it_4bit
            displayName = "Gemma 4 E4B (4-bit)"
        case "gemma-4-26b":
            // Kept because it is the strongest claim available if a take ever
            // wants it: 26B is self-evidently not running on the handset.
            // Hand-built — the MoE build is in no registry.
            configuration = ModelConfiguration(
                id: "mlx-community/gemma-4-26b-a4b-it-8bit",
                extraEOSTokens: ["<turn|>"]
            )
            displayName = "Gemma 4 26B A4B (8-bit)"
        case "gemma-4-e2b":
            // The fast path, kept as the shoot-day fallback.
            // ⚠️ Hand-built because the QAT weights are in no registry, and
            // `extraEOSTokens` is not decoration: without it the stream does
            // not stop at the turn boundary, and what that looks like is the
            // essay followed by chatbot text — the one thing the closing
            // frame cannot have.
            configuration = ModelConfiguration(
                id: "mlx-community/gemma-4-E2B-it-qat-4bit",
                extraEOSTokens: ["<turn|>"]
            )
            displayName = "Gemma 4 E2B (QAT 4-bit)"
        default:
            configuration = ModelConfiguration(id: modelID)
            displayName = modelID
        }
    }

    public func prewarm() async throws {
        let loaded = try await container.get(configuration: configuration)
        let tokenizer = await loaded.tokenizer
        try await container.prewarmGuidance(tokenizer: tokenizer)
    }

    public func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, Error> {
        let (stream, continuation) = AsyncThrowingStream<WireEvent, Error>.makeStream()
        let configuration = self.configuration
        let box = container
        let task = Task {
            do {
                let container = try await box.get(configuration: configuration)
                let messages = TranscriptChat.messages(from: request.transcript)
                let maxTokens = request.options.maximumResponseTokens ?? 512
                let temperature = request.options.temperature
                let schemaJSON = try request.schema.map(ResponseGuidance.schemaJSON)
                // Outside `perform`, because a tool whose schema will not
                // render is a refusal to answer rather than an empty answer,
                // and this is where the throw is still legible.
                let tools = try ToolRendering.specs(for: request)
                // One entry id for the whole turn's calls: the framework groups
                // them under a single `toolCalls` transcript entry, and minting
                // a fresh id per call would scatter one turn across several.
                let toolCallsEntryID = UUID().uuidString

                if let schemaJSON {
                    try await container.perform { context in
                        let xgTokenizer: GrammarTokenizer
                        let constraint: GrammarConstraint
                        do {
                            xgTokenizer = try await box.grammarTokenizer(
                                tokenizer: context.tokenizer)
                            constraint = try await box.constraint(
                                schemaJSON: schemaJSON,
                                tokenizer: xgTokenizer,
                                hostTokenizer: context.tokenizer)
                        } catch {
                            throw ResponseGuidance.unsupported(error)
                        }
                        let bias = await box.tokenizerBias(tokenizer: context.tokenizer)

                        // Deliberately identical to the established prompt
                        // preparation below: schemas constrain the response,
                        // not the input or the model's chat template.
                        let chat: [Chat.Message] = try messages.map { message in
                            switch message.role {
                            case .system: return .system(message.text)
                            case .user: return .user(message.text)
                            case .tool:
                                if case .output(let callID) = message.tool {
                                    return .tool(message.text, id: callID)
                                }
                                return .tool(message.text)
                            case .assistant:
                                if case .calls(let calls) = message.tool {
                                    return .assistant(
                                        message.text,
                                        toolCalls: try calls.map(Self.toolCall(from:))
                                    )
                                }
                                return .assistant(message.text)
                            }
                        }
                        let input = try await context.processor.prepare(
                            input: UserInput(
                                chat: chat,
                                tools: tools,
                                additionalContext: ["enable_thinking": false]
                            )
                        )

                        // Tool arguments remain on the existing unconstrained
                        // detector path. Prose is held back until the probe has
                        // either produced a call or definitively has not: a
                        // failed probe must not leak unconstrained response text
                        // before the grammar-owned answer begins.
                        if let tools {
                            var parameters = GenerateParameters(maxTokens: maxTokens)
                            if let temperature {
                                parameters.temperature = Float(temperature)
                            }
                            var buffered = SchemaToolProbeBuffer()
                            let probe = try MLXLMCommon.generate(
                                input: input,
                                parameters: parameters,
                                context: context,
                                tools: tools
                            )
                            for await event in probe {
                                try Task.checkCancellation()
                                switch event {
                                case .chunk:
                                    break
                                case .info(let info):
                                    buffered.appendUsage(.usage(
                                        inputTokens: info.promptTokenCount,
                                        outputTokens: info.generationTokenCount
                                    ))
                                case .toolCall(let call):
                                    guard let arguments = Self.argumentsJSON(of: call) else {
                                        continue
                                    }
                                    buffered.appendToolCall(.toolCallAppendArguments(
                                        entryID: toolCallsEntryID,
                                        id: call.id ?? UUID().uuidString,
                                        name: call.function.name,
                                        content: arguments,
                                        tokenCount: 1
                                    ))
                                }
                            }
                            if let toolEvents = buffered.selectedToolEvents {
                                for event in toolEvents { continuation.yield(event) }
                                return
                            }
                        }

                        let structuralReserve = CompletionReserve.estimate(
                            schemaJSON: schemaJSON,
                            tokenizer: context.tokenizer)
                        let completionReserve = Swift.max(structuralReserve * 3, maxTokens / 4)
                        let hardReserve = structuralReserve * 8
                        let generatedTokenCount: Int
                        do {
                            generatedTokenCount = try GuidedGenerationLoop.run(
                                input: input,
                                context: context,
                                constraint: constraint,
                                maxTokens: maxTokens,
                                vocabSize: xgTokenizer.vocabSize,
                                completionReserve: completionReserve,
                                hardReserve: hardReserve,
                                closingBias: bias.closing,
                                whitespaceBias: bias.whitespace,
                                whitespaceTokenIDs: bias.whitespaceTokenIDs
                            ) { text in
                                continuation.yield(.responseAppend(
                                    entryID: nil,
                                    text: text,
                                    segmentID: nil,
                                    tokenCount: 1
                                ))
                                return !Task.isCancelled
                            }
                        } catch {
                            throw ResponseGuidance.generationError(error, maxTokens: maxTokens)
                        }
                        try Task.checkCancellation()
                        continuation.yield(.usage(
                            inputTokens: input.text.tokens.size,
                            outputTokens: generatedTokenCount
                        ))
                    }
                    continuation.yield(.finished(.complete))
                    continuation.finish()
                    return
                }

                // No-schema requests remain on the established sampler and
                // tool-call detector path. Keep this branch mechanically
                // unchanged: response guidance must not alter ordinary asks.
                let events = try await container.perform { context in
                    let chat: [Chat.Message] = try messages.map { message in
                        switch message.role {
                        case .system: return .system(message.text)
                        case .user: return .user(message.text)
                        case .tool:
                            if case .output(let callID) = message.tool {
                                return .tool(message.text, id: callID)
                            }
                            return .tool(message.text)
                        case .assistant:
                            if case .calls(let calls) = message.tool {
                                return .assistant(
                                    message.text,
                                    toolCalls: try calls.map(Self.toolCall(from:))
                                )
                            }
                            return .assistant(message.text)
                        }
                    }
                    // Gemma 4's thinking is configurable, and a thought block
                    // rendered on camera is a killed take. The template kwarg
                    // is the belt; the rehearsal is what proves the template
                    // honours it, because nothing here can.
                    let input = try await context.processor.prepare(
                        input: UserInput(
                            chat: chat,
                            tools: tools,
                            additionalContext: ["enable_thinking": false]
                        )
                    )
                    var parameters = GenerateParameters(maxTokens: maxTokens)
                    if let temperature {
                        parameters.temperature = Float(temperature)
                    }
                    // `tools` again, and not redundantly: the first copy is
                    // rendered into the prompt, this one configures the
                    // detector that reads the model's answer back.
                    return try MLXLMCommon.generate(
                        input: input,
                        parameters: parameters,
                        context: context,
                        tools: tools
                    )
                }

                for await event in events {
                    if Task.isCancelled { break }
                    switch event {
                    case .chunk(let chunk):
                        continuation.yield(.responseAppend(entryID: nil, text: chunk, segmentID: nil, tokenCount: 1))
                    case .info(let info):
                        continuation.yield(.usage(
                            inputTokens: info.promptTokenCount,
                            outputTokens: info.generationTokenCount
                        ))
                    case .toolCall(let call):
                        // The call arrives already parsed: MLX's own
                        // `ToolCallProcessor`, configured from the model's
                        // `model_type`, swallows the `<|tool_call>…<tool_call|>`
                        // span out of the chunk stream and hands it over whole.
                        // So the arguments cross in one piece — which is also
                        // what Apple's MLXLanguageModel.Executor does, and what
                        // the grammar forces: Gemma's syntax has no escape
                        // mechanism, so a fragment emitted early can turn out
                        // to be wrong once the closing token lands, and this
                        // wire has no way to take one back.
                        guard let arguments = Self.argumentsJSON(of: call) else { break }
                        continuation.yield(.toolCallAppendArguments(
                            entryID: toolCallsEntryID,
                            id: call.id ?? UUID().uuidString,
                            name: call.function.name,
                            content: arguments,
                            tokenCount: 1
                        ))
                    }
                }
                continuation.yield(.finished(Task.isCancelled ? .cancelled : .complete))
                continuation.finish()
            } catch is CancellationError {
                continuation.yield(.finished(.cancelled))
                continuation.finish()
            } catch {
                continuation.yield(.finished(.error("\(error)")))
                continuation.finish()
            }
        }
        continuation.onTermination = { _ in task.cancel() }
        return stream
    }

    /// A call the model already made, on its way back into the prompt for the
    /// next turn. The arguments were a JSON string on the wire because that is
    /// what the framework's `GeneratedContent` renders losslessly; MLX wants
    /// them as a dictionary, and a blob that will not parse becomes an empty
    /// argument set rather than a dropped call — the model needs to see that it
    /// asked, or it asks again.
    private static func toolCall(from call: TranscriptChat.Message.Call) throws -> MLXLMCommon.ToolCall {
        let arguments = (try? JSONSerialization.jsonObject(with: Data(call.argumentsJSON.utf8)))
            .flatMap { $0 as? [String: any Sendable] } ?? [:]
        return MLXLMCommon.ToolCall(
            function: .init(name: call.name, arguments: arguments),
            id: call.id
        )
    }

    /// The arguments of a parsed call as JSON, which is what the framework's
    /// channel accumulates into `Transcript.ToolCall.arguments`. Nil when they
    /// will not encode, which drops the call rather than sending a fragment no
    /// `GeneratedContent(json:)` can read.
    private static func argumentsJSON(of call: MLXLMCommon.ToolCall) -> String? {
        guard let data = try? JSONEncoder().encode(call.function.arguments) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }
}

/// One loaded model container shared across generations.
actor ContainerBox {
    private var container: ModelContainer?
    private var cachedGrammarTokenizer: GrammarTokenizer?
    private var constraintTemplates: [String: GrammarConstraint] = [:]
    private var guidanceBias: GuidanceBias?
    private var guidanceStatistics = GuidanceCacheStatistics()

    func get(configuration: ModelConfiguration) async throws -> ModelContainer {
        if let container { return container }
        let loaded = try await #huggingFaceLoadModelContainer(configuration: configuration)
        container = loaded
        return loaded
    }

    /// Prewarm only model-wide grammar state. Request schemas remain lazy, so
    /// prewarm never guesses a cache key no real generation will use.
    func prewarmGuidance(tokenizer: any MLXLMCommon.Tokenizer) throws {
        _ = try makeGrammarTokenizer(tokenizer: tokenizer)
    }

    func grammarTokenizer(tokenizer: any MLXLMCommon.Tokenizer) throws -> GrammarTokenizer {
        try makeGrammarTokenizer(tokenizer: tokenizer)
    }

    func constraint(
        schemaJSON: String,
        tokenizer: GrammarTokenizer,
        hostTokenizer: any MLXLMCommon.Tokenizer
    ) throws -> GrammarConstraint {
        if let template = constraintTemplates[schemaJSON] {
            do {
                return try template.clone()
            } catch {
                // The pinned xgrammar exposes Fork through the Swift surface
                // but can report it unavailable at runtime. A failed clone is
                // never reused: discard it and compile a fresh matcher.
                guidanceStatistics.constraintCloneFailures += 1
                constraintTemplates.removeValue(forKey: schemaJSON)
            }
        }

        guidanceStatistics.constraintCompiles += 1
        let constraint = try GrammarConstraint(
            tokenizer: tokenizer,
            jsonSchema: schemaJSON,
            fastForward: true,
            hostTokenizer: hostTokenizer
        )
        do {
            let clone = try constraint.clone()
            constraintTemplates[schemaJSON] = constraint
            return clone
        } catch {
            guidanceStatistics.constraintCloneFailures += 1
        }
        return constraint
    }

    func tokenizerBias(tokenizer: any MLXLMCommon.Tokenizer) -> GuidanceBias {
        makeTokenizerBias(tokenizer: tokenizer)
    }

    func guidanceCacheStatistics() -> GuidanceCacheStatistics {
        guidanceStatistics
    }

    private func makeGrammarTokenizer(
        tokenizer: any MLXLMCommon.Tokenizer
    ) throws -> GrammarTokenizer {
        if let cachedGrammarTokenizer { return cachedGrammarTokenizer }
        guidanceStatistics.tokenizerBuilds += 1
        let vocab = TokenizerVocabExtractor.extractForGrammar(from: tokenizer)
        let made = try GrammarTokenizer(
            vocab: vocab.vocab,
            vocabType: vocab.vocabType,
            eosTokenId: Int32(tokenizer.eosTokenId ?? 0)
        )
        cachedGrammarTokenizer = made
        return made
    }

    private func makeTokenizerBias(tokenizer: any MLXLMCommon.Tokenizer) -> GuidanceBias {
        if let guidanceBias { return guidanceBias }
        guidanceStatistics.biasBuilds += 1
        let closing = ClosingTokenBias.compute(
            tokenizer: tokenizer,
            eosTokenId: tokenizer.eosTokenId)
        let whitespace = WhitespaceTokenBias.compute(tokenizer: tokenizer)
        let made = GuidanceBias(
            closing: closing,
            whitespace: whitespace.bias,
            whitespaceTokenIDs: whitespace.tokenIDs)
        guidanceBias = made
        return made
    }
}

struct GuidanceCacheStatistics: Sendable, Equatable {
    var tokenizerBuilds = 0
    var biasBuilds = 0
    var constraintCompiles = 0
    var constraintCloneFailures = 0
}

/// Tokenizer-derived arrays are immutable after construction and are only
/// added to logits by the generation loop. The unchecked conformance matches
/// the engine's own GrammarTokenizer/GrammarConstraint cache boundary.
final class GuidanceBias: @unchecked Sendable {
    let closing: MLXArray
    let whitespace: MLXArray
    let whitespaceTokenIDs: Set<Int>

    init(closing: MLXArray, whitespace: MLXArray, whitespaceTokenIDs: Set<Int>) {
        self.closing = closing
        self.whitespace = whitespace
        self.whitespaceTokenIDs = whitespaceTokenIDs
    }
}
