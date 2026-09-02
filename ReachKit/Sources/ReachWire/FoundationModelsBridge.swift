#if canImport(FoundationModels)
import Foundation
import FoundationModels

public extension WireGenerationSchema {
    init(_ native: GenerationSchema) {
        do {
            let data = try JSONEncoder().encode(native)
            do {
                self = try JSONDecoder().decode(WireGenerationSchema.self, from: data)
            } catch {
                self.init(deferredEncodingError: String(describing: error), nativeJSON: data)
            }
        } catch {
            self.init(deferredEncodingError: String(describing: error))
        }
    }

    func native() throws -> GenerationSchema {
        if let deferredNativeJSON {
            return try JSONDecoder().decode(GenerationSchema.self, from: deferredNativeJSON)
        }
        let data = try JSONEncoder().encode(self)
        return try JSONDecoder().decode(GenerationSchema.self, from: data)
    }

    /// Re-establish the pre-portability trust boundary: on Apple, a schema is
    /// admitted only if Foundation Models itself accepts the canonical value.
    internal func validateNativeFoundationModelsValue() throws {
        _ = try native()
    }
}

public extension WireTranscript {
    init(_ native: Transcript) {
        do {
            let data = try JSONEncoder().encode(native)
            do {
                self = try JSONDecoder().decode(WireTranscript.self, from: data)
            } catch {
                self.init(deferredEncodingError: String(describing: error), nativeJSON: data)
            }
        } catch {
            self.init(deferredEncodingError: String(describing: error))
        }
    }

    func native() throws -> Transcript {
        if let deferredNativeJSON {
            return try JSONDecoder().decode(Transcript.self, from: deferredNativeJSON)
        }
        let data = try JSONEncoder().encode(self)
        return try JSONDecoder().decode(Transcript.self, from: data)
    }

    internal func validateNativeFoundationModelsValue() throws {
        _ = try native()
    }
}

public extension WireToolDefinition {
    var parameters: GenerationSchema {
        get { try! portableParameters.native() }
        set { portableParameters = WireGenerationSchema(newValue) }
    }

    init(name: String, description: String, parameters: GenerationSchema) {
        self.init(
            name: name,
            description: description,
            portableParameters: WireGenerationSchema(parameters)
        )
    }

    init(_ native: Transcript.ToolDefinition) {
        self.init(name: native.name, description: native.description, parameters: native.parameters)
    }

    func native() -> Transcript.ToolDefinition {
        Transcript.ToolDefinition(name: name, description: description, parameters: parameters)
    }
}

public extension WireGenerationOptions {
    init(_ native: GenerationOptions) {
        temperature = native.temperature
        maximumResponseTokens = native.maximumResponseTokens
        if let mode = native.samplingMode, mode == .greedy {
            sampling = .greedy
        }
        if let mode = native.toolCallingMode {
            switch mode {
            case .allowed: toolCalling = .allowed
            case .required: toolCalling = .required
            case .disallowed: toolCalling = .disallowed
            default: toolCalling = nil
            }
        }
    }

    func native() -> GenerationOptions {
        let mode: GenerationOptions.SamplingMode? = switch sampling {
        case .greedy: .greedy
        case .topK(let k, let seed): .random(top: k, seed: seed)
        case .topP(let p, let seed): .random(probabilityThreshold: p, seed: seed)
        case nil: nil
        }
        let toolMode: GenerationOptions.ToolCallingMode? = switch toolCalling {
        case .allowed: .allowed
        case .required: .required
        case .disallowed: .disallowed
        case nil: nil
        }
        return GenerationOptions(
            samplingMode: mode,
            temperature: temperature,
            maximumResponseTokens: maximumResponseTokens,
            toolCallingMode: toolMode
        )
    }
}

public extension WireContextOptions {
    init(_ native: ContextOptions) {
        includeSchemaInPrompt = native.includeSchemaInPrompt
        switch native.reasoningLevel {
        case .light: reasoning = .light
        case .moderate: reasoning = .moderate
        case .deep: reasoning = .deep
        case .custom(let value): reasoning = .custom(value)
        case nil: reasoning = nil
        default: reasoning = nil
        }
    }

    func native() -> ContextOptions {
        let level: ContextOptions.ReasoningLevel? = switch reasoning {
        case .light: .light
        case .moderate: .moderate
        case .deep: .deep
        case .custom(let value): .custom(value)
        case nil: nil
        }
        return ContextOptions(includeSchemaInPrompt: includeSchemaInPrompt, reasoningLevel: level)
    }
}

public extension WireGenerationRequest {
    var transcript: Transcript {
        get { try! portableTranscript.native() }
        set { portableTranscript = WireTranscript(newValue) }
    }

    var schema: GenerationSchema? {
        get { try! portableSchema?.native() }
        set { portableSchema = newValue.map(WireGenerationSchema.init) }
    }

    init(
        id: UUID,
        transcript: Transcript,
        tools: [WireToolDefinition] = [],
        schema: GenerationSchema? = nil,
        options: WireGenerationOptions = WireGenerationOptions(),
        context: WireContextOptions = WireContextOptions()
    ) {
        self.init(
            id: id,
            portableTranscript: WireTranscript(transcript),
            tools: tools,
            portableSchema: schema.map(WireGenerationSchema.init),
            options: options,
            context: context
        )
    }

    init(_ native: LanguageModelExecutorGenerationRequest) {
        self.init(
            id: native.id,
            transcript: native.transcript,
            tools: native.enabledToolDefinitions.map(WireToolDefinition.init),
            schema: native.schema,
            options: WireGenerationOptions(native.generationOptions),
            context: WireContextOptions(native.contextOptions)
        )
    }
}
#endif
