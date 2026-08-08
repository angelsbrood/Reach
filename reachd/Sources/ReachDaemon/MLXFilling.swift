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
                let schemaJSON = try request.schema.map(ResponseGuidance.schemaJSON)
                let tools = try ToolRendering.specs(for: request)
                let toolMode = request.options.toolCalling ?? .allowed
                let toolPlan: ToolGuidancePlan?
                if tools != nil {
                    toolPlan = try ToolGuidance.plan(for: request.tools)
                } else {
                    toolPlan = nil
                }
                if toolMode == .required, toolPlan == nil {
                    throw ToolGuidanceError.requiredWithoutTools
                }
                let toolCallsEntryID = UUID().uuidString

                // Keep the no-schema/no-tools path outside the model actor
                // exactly as before this pass. Tool guidance must not alter
                // ordinary prompt preparation, sampling, event order, usage,
                // or the lifetime for which the container is borrowed.
                if schemaJSON == nil, toolPlan == nil {
                    let events = try await container.perform { context in
                        let chat = try Self.chat(from: messages)
                        let input = try await context.processor.prepare(
                            input: UserInput(
                                chat: chat,
                                tools: tools,
                                additionalContext: ["enable_thinking": false]
                            )
                        )
                        let parameters = UnconstrainedSampling.parameters(
                            options: request.options,
                            maxTokens: maxTokens
                        )
                        return try MLXLMCommon.generate(
                            input: input,
                            parameters: parameters,
                            context: context,
                            tools: tools
                        )
                    }
                    for await event in events {
                        try Task.checkCancellation()
                        switch event {
                        case .chunk(let chunk):
                            continuation.yield(.responseAppend(
                                entryID: nil,
                                text: chunk,
                                segmentID: nil,
                                tokenCount: 1
                            ))
                        case .info(let info):
                            continuation.yield(.usage(
                                inputTokens: info.promptTokenCount,
                                outputTokens: info.generationTokenCount
                            ))
                        case .toolCall:
                            throw ToolGuidanceError.incompleteOutput(
                                "an unconstrained call escaped a request with no offered tools")
                        }
                    }
                    continuation.yield(.finished(.complete))
                    continuation.finish()
                    return
                }

                try await container.perform { context in
                    let chat = try Self.chat(from: messages)
                    let input = try await context.processor.prepare(
                        input: UserInput(
                            chat: chat,
                            tools: tools,
                            additionalContext: ["enable_thinking": false]
                        )
                    )

                    var xgTokenizer: GrammarTokenizer?
                    var bias: GuidanceBias?
                    var toolConstraints: [String: GrammarConstraint] = [:]
                    var requiredConstraint: GrammarConstraint?

                    if schemaJSON != nil || toolPlan != nil {
                        xgTokenizer = try await box.grammarTokenizer(tokenizer: context.tokenizer)
                        bias = await box.tokenizerBias(tokenizer: context.tokenizer)
                    }

                    // Refuse unsupported argument schemas before the model can
                    // emit prose, select a call, or cause any adopting-app work.
                    if let toolPlan, let xgTokenizer {
                        for tool in toolPlan.tools {
                            do {
                                toolConstraints[tool.name] = try await box.structuralConstraint(
                                    structuralTag: tool.structuralTag,
                                    tokenizer: xgTokenizer,
                                    hostTokenizer: context.tokenizer
                                )
                            } catch {
                                throw ToolGuidance.unsupported(tool: tool.name, error: error)
                            }
                        }
                        if toolMode == .required {
                            if toolPlan.tools.count == 1 {
                                requiredConstraint = toolConstraints[toolPlan.tools[0].name]
                            } else {
                                do {
                                    requiredConstraint = try await box.structuralConstraint(
                                        structuralTag: toolPlan.combinedStructuralTag,
                                        tokenizer: xgTokenizer,
                                        hostTokenizer: context.tokenizer
                                    )
                                } catch {
                                    throw ToolGuidance.unsupported(
                                        tool: toolPlan.tools.map(\.name).joined(separator: ", "),
                                        error: error
                                    )
                                }
                            }
                        }
                    }

                    var usage = AccumulatedUsage()

                    if toolMode == .required,
                       let toolPlan,
                       let constraint = requiredConstraint,
                       let xgTokenizer,
                       let bias
                    {
                        let generated = try Self.runToolGuidance(
                            input: input,
                            context: context,
                            constraint: constraint,
                            grammarTokenizer: xgTokenizer,
                            bias: bias,
                            tools: toolPlan.tools,
                            maxTokens: maxTokens,
                            label: toolPlan.tools.map(\.name).joined(separator: ", ")
                        )
                        usage.add(input: input.text.tokens.size, output: generated.tokenCount)
                        let accepted = try ToolGuidance.parseEnvelope(
                            generated.text,
                            offeredNames: Set(toolPlan.tools.map(\.name))
                        )
                        continuation.yield(.toolCallAppendArguments(
                            entryID: toolCallsEntryID,
                            id: UUID().uuidString,
                            name: accepted.name,
                            content: accepted.argumentsJSON,
                            tokenCount: 1
                        ))
                        continuation.yield(usage.event)
                        return
                    }

                    if let toolPlan, let tools {
                        guard let xgTokenizer, let bias else {
                            throw ToolGuidanceError.incompleteOutput(
                                "the grammar tokenizer was not prepared for offered tools")
                        }
                        let parameters = UnconstrainedSampling.parameters(
                            options: request.options,
                            maxTokens: maxTokens
                        )
                        var proposals: [ProposedToolCall] = []
                        let probe = try MLXLMCommon.generate(
                            input: input,
                            parameters: parameters,
                            context: context,
                            tools: tools
                        )
                        for await event in probe {
                            try Task.checkCancellation()
                            switch event {
                            case .chunk(let chunk):
                                // Schema probes remain private; ordinary prose
                                // retains its established streaming behavior.
                                if ToolRouting.streamsProbeProse(
                                    hasResponseSchema: schemaJSON != nil)
                                {
                                    continuation.yield(.responseAppend(
                                        entryID: nil,
                                        text: chunk,
                                        segmentID: nil,
                                        tokenCount: 1
                                    ))
                                }
                            case .info(let info):
                                usage.add(
                                    input: info.promptTokenCount,
                                    output: info.generationTokenCount
                                )
                            case .toolCall(let call):
                                proposals.append(try ToolGuidance.proposedCall(call))
                            }
                        }

                        let selection = ToolRouting.selection(
                            proposals: proposals,
                            hasResponseSchema: schemaJSON != nil
                        )
                        if case .calls = selection {
                            for (proposal, tool) in try ToolRouting.replayPairs(
                                proposals: proposals,
                                plan: toolPlan
                            ) {
                                let constraint: GrammarConstraint
                                if let precompiled = toolConstraints.removeValue(forKey: tool.name) {
                                    constraint = precompiled
                                } else {
                                    do {
                                        constraint = try await box.structuralConstraint(
                                            structuralTag: tool.structuralTag,
                                            tokenizer: xgTokenizer,
                                            hostTokenizer: context.tokenizer
                                        )
                                    } catch {
                                        throw ToolGuidance.unsupported(tool: tool.name, error: error)
                                    }
                                }
                                let replayInput = try await Self.replayInput(
                                    proposal: proposal,
                                    context: context
                                )
                                let generated = try Self.runToolGuidance(
                                    input: replayInput,
                                    context: context,
                                    constraint: constraint,
                                    grammarTokenizer: xgTokenizer,
                                    bias: bias,
                                    tools: [tool],
                                    maxTokens: maxTokens,
                                    label: tool.name
                                )
                                usage.add(
                                    input: replayInput.text.tokens.size,
                                    output: generated.tokenCount
                                )
                                let accepted = try ToolGuidance.parseEnvelope(
                                    generated.text,
                                    offeredNames: Set([tool.name])
                                )
                                continuation.yield(.toolCallAppendArguments(
                                    entryID: toolCallsEntryID,
                                    id: proposal.id,
                                    name: accepted.name,
                                    content: accepted.argumentsJSON,
                                    tokenCount: 1
                                ))
                            }
                            continuation.yield(usage.event)
                            return
                        }

                        if case .prose = selection {
                            continuation.yield(usage.event)
                            return
                        }
                    }

                    if let schemaJSON, let xgTokenizer, let bias {
                        let constraint: GrammarConstraint
                        do {
                            constraint = try await box.constraint(
                                schemaJSON: schemaJSON,
                                tokenizer: xgTokenizer,
                                hostTokenizer: context.tokenizer
                            )
                        } catch {
                            throw ResponseGuidance.unsupported(error)
                        }
                        let structuralReserve = CompletionReserve.estimate(
                            schemaJSON: schemaJSON,
                            tokenizer: context.tokenizer
                        )
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
                        usage.add(input: input.text.tokens.size, output: generatedTokenCount)
                        continuation.yield(usage.event)
                        return
                    }

                    throw ToolGuidanceError.incompleteOutput(
                        "tool guidance did not select a call, response, or prose result")
                }
                continuation.yield(.finished(.complete))
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

    private static func chat(from messages: [TranscriptChat.Message]) throws -> [Chat.Message] {
        try messages.map { message in
            switch message.role {
            case .system:
                return .system(message.text)
            case .user:
                return .user(message.text)
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
    }

    private static func replayInput(
        proposal: ProposedToolCall,
        context: ModelContext
    ) async throws -> LMInput {
        let prompt = """
        Correct the proposed tool call while preserving every value its schema permits. Return only the required JSON envelope.
        Tool name: \(proposal.name)
        Proposed arguments: \(proposal.argumentsJSON)
        """
        return try await context.processor.prepare(
            input: UserInput(
                chat: [
                    .system("You repair proposed JSON tool arguments without inventing a different tool."),
                    .user(prompt),
                ],
                tools: nil,
                additionalContext: ["enable_thinking": false]
            )
        )
    }

    private static func runToolGuidance(
        input: LMInput,
        context: ModelContext,
        constraint: GrammarConstraint,
        grammarTokenizer: GrammarTokenizer,
        bias: GuidanceBias,
        tools: [GuidedTool],
        maxTokens: Int,
        label: String
    ) throws -> GuidedToolOutput {
        let structuralReserve = tools.map { tool in
            CompletionReserve.estimate(
                schemaJSON: tool.schemaJSON,
                tokenizer: context.tokenizer
            ) + context.tokenizer.encode(text: tool.beginLiteral + "}").count
        }.max() ?? 64
        let completionReserve = Swift.max(structuralReserve * 3, maxTokens / 4)
        let hardReserve = structuralReserve * 8
        var output = ""
        do {
            let count = try GuidedGenerationLoop.run(
                input: input,
                context: context,
                constraint: constraint,
                maxTokens: maxTokens,
                vocabSize: grammarTokenizer.vocabSize,
                completionReserve: completionReserve,
                hardReserve: hardReserve,
                closingBias: bias.closing,
                whitespaceBias: bias.whitespace,
                whitespaceTokenIDs: bias.whitespaceTokenIDs
            ) { delta in
                output += delta
                return !Task.isCancelled
            }
            return GuidedToolOutput(text: output, tokenCount: count)
        } catch {
            throw ToolGuidance.generationError(error, tool: label, maxTokens: maxTokens)
        }
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

}

private struct GuidedToolOutput: Sendable {
    var text: String
    var tokenCount: Int
}

private struct AccumulatedUsage: Sendable {
    private(set) var inputTokens = 0
    private(set) var outputTokens = 0

    mutating func add(input: Int, output: Int) {
        inputTokens += input
        outputTokens += output
    }

    var event: WireEvent {
        .usage(inputTokens: inputTokens, outputTokens: outputTokens)
    }
}

/// One loaded model container shared across generations.
actor ContainerBox {
    private var container: ModelContainer?
    private var cachedGrammarTokenizer: GrammarTokenizer?
    private var constraintTemplates: [GuidanceConstraintKey: GrammarConstraint] = [:]
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
        try constraint(
            key: GuidanceConstraintKey(kind: .responseJSON, source: schemaJSON),
            tokenizer: tokenizer,
            hostTokenizer: hostTokenizer
        )
    }

    func structuralConstraint(
        structuralTag: String,
        tokenizer: GrammarTokenizer,
        hostTokenizer: any MLXLMCommon.Tokenizer
    ) throws -> GrammarConstraint {
        try constraint(
            key: GuidanceConstraintKey(kind: .toolStructural, source: structuralTag),
            tokenizer: tokenizer,
            hostTokenizer: hostTokenizer
        )
    }

    private func constraint(
        key: GuidanceConstraintKey,
        tokenizer: GrammarTokenizer,
        hostTokenizer: any MLXLMCommon.Tokenizer
    ) throws -> GrammarConstraint {
        if let template = constraintTemplates[key] {
            do {
                return try template.clone()
            } catch {
                // The pinned xgrammar exposes Fork through the Swift surface
                // but can report it unavailable at runtime. A failed clone is
                // never reused: discard it and compile a fresh matcher.
                guidanceStatistics.constraintCloneFailures += 1
                constraintTemplates.removeValue(forKey: key)
            }
        }

        guidanceStatistics.constraintCompiles += 1
        switch key.kind {
        case .responseJSON: guidanceStatistics.responseConstraintCompiles += 1
        case .toolStructural: guidanceStatistics.toolConstraintCompiles += 1
        }
        let constraint: GrammarConstraint
        switch key.kind {
        case .responseJSON:
            constraint = try GrammarConstraint(
                tokenizer: tokenizer,
                jsonSchema: key.source,
                fastForward: true,
                hostTokenizer: hostTokenizer
            )
        case .toolStructural:
            constraint = try GrammarConstraint(
                tokenizer: tokenizer,
                structuralTag: key.source,
                fastForward: true,
                hostTokenizer: hostTokenizer
            )
        }
        do {
            let clone = try constraint.clone()
            constraintTemplates[key] = constraint
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
        let closing = CompletionGuidance.closingBias(
            tokenizer: tokenizer,
            eosTokenID: tokenizer.eosTokenId)
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
    var responseConstraintCompiles = 0
    var toolConstraintCompiles = 0
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
