import Foundation
import FoundationModels

// The wire codec bridges the framework's transcript and generation types by
// hand — the named stub from the plan. `Transcript` and `GenerationSchema`
// are natively Codable and ride as themselves; only the options types and
// tool definitions need mirrors. Native conformances are adopted when the
// framework core open-sourcing lands; this file is the seam that rebase
// replaces.

public struct WireToolDefinition: Codable, Sendable {
    public var name: String
    public var description: String
    public var parameters: GenerationSchema

    public init(name: String, description: String, parameters: GenerationSchema) {
        self.name = name
        self.description = description
        self.parameters = parameters
    }

    public init(_ native: Transcript.ToolDefinition) {
        self.init(name: native.name, description: native.description, parameters: native.parameters)
    }

    public func native() -> Transcript.ToolDefinition {
        Transcript.ToolDefinition(name: name, description: description, parameters: parameters)
    }
}

public enum WireSampling: Codable, Sendable, Equatable {
    case greedy
    case topK(Int, seed: UInt64?)
    case topP(Double, seed: UInt64?)
}

public enum WireToolCalling: String, Codable, Sendable, Equatable {
    case allowed
    case required
    case disallowed
}

public struct WireGenerationOptions: Codable, Sendable, Equatable {
    public var temperature: Double?
    public var maximumResponseTokens: Int?
    public var sampling: WireSampling?
    public var toolCalling: WireToolCalling?

    public init(
        temperature: Double? = nil,
        maximumResponseTokens: Int? = nil,
        sampling: WireSampling? = nil,
        toolCalling: WireToolCalling? = nil
    ) {
        self.temperature = temperature
        self.maximumResponseTokens = maximumResponseTokens
        self.sampling = sampling
        self.toolCalling = toolCalling
    }

    public init(_ native: GenerationOptions) {
        temperature = native.temperature
        maximumResponseTokens = native.maximumResponseTokens
        // SamplingMode exposes no public read accessor (its `Kind` enum
        // exists but nothing returns it — feedback-worthy). Greedy is
        // detectable via Equatable; custom sampling rides as nil and the
        // host applies its defaults. Documented v0 limitation, resolved by
        // the framework-core rebase.
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

    public func native() -> GenerationOptions {
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

public enum WireReasoningLevel: Codable, Sendable, Equatable {
    case light
    case moderate
    case deep
    case custom(String)
}

public struct WireContextOptions: Codable, Sendable, Equatable {
    public var includeSchemaInPrompt: Bool?
    public var reasoning: WireReasoningLevel?

    public init(includeSchemaInPrompt: Bool? = nil, reasoning: WireReasoningLevel? = nil) {
        self.includeSchemaInPrompt = includeSchemaInPrompt
        self.reasoning = reasoning
    }

    public init(_ native: ContextOptions) {
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

    public func native() -> ContextOptions {
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

/// The generation request as it crosses the trust boundary. `metadata` from
/// the framework request is deliberately dropped in v0: its values are
/// existential `Sendable & Codable & Equatable`, which JSON coding cannot
/// carry generically. Documented limitation.
public struct WireGenerationRequest: Codable, Sendable {
    public var id: UUID
    public var transcript: Transcript
    public var tools: [WireToolDefinition]
    public var schema: GenerationSchema?
    public var options: WireGenerationOptions
    public var context: WireContextOptions

    public init(
        id: UUID,
        transcript: Transcript,
        tools: [WireToolDefinition] = [],
        schema: GenerationSchema? = nil,
        options: WireGenerationOptions = WireGenerationOptions(),
        context: WireContextOptions = WireContextOptions()
    ) {
        self.id = id
        self.transcript = transcript
        self.tools = tools
        self.schema = schema
        self.options = options
        self.context = context
    }

    public init(_ native: LanguageModelExecutorGenerationRequest) {
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
