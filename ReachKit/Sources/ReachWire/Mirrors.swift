import Foundation

// Portable values are the wire source of truth. The native Foundation Models
// spellings remain an Apple-edge adapter in FoundationModelsBridge.swift.

public struct WireToolDefinition: Codable, Sendable {
    public var name: String
    public var description: String
    public var portableParameters: WireGenerationSchema

    public init(name: String, description: String, portableParameters: WireGenerationSchema) {
        self.name = name
        self.description = description
        self.portableParameters = portableParameters
    }

    private enum CodingKeys: String, CodingKey { case name, description, parameters }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        description = try container.decode(String.self, forKey: .description)
        portableParameters = try container.decode(WireGenerationSchema.self, forKey: .parameters)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(description, forKey: .description)
        try container.encode(portableParameters, forKey: .parameters)
    }
}

#if !canImport(FoundationModels)
public extension WireToolDefinition {
    var parameters: WireGenerationSchema {
        get { portableParameters }
        set { portableParameters = newValue }
    }

    init(name: String, description: String, parameters: WireGenerationSchema) {
        self.init(name: name, description: description, portableParameters: parameters)
    }
}
#endif

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

}

/// The generation request as it crosses the trust boundary. `metadata` from
/// the framework request is deliberately dropped in v0: its values are
/// existential `Sendable & Codable & Equatable`, which JSON coding cannot
/// carry generically. Documented limitation.
public struct WireGenerationRequest: Codable, Sendable {
    public var id: UUID
    public var portableTranscript: WireTranscript
    public var tools: [WireToolDefinition]
    public var portableSchema: WireGenerationSchema?
    public var options: WireGenerationOptions
    public var context: WireContextOptions

    public init(
        id: UUID,
        portableTranscript: WireTranscript,
        tools: [WireToolDefinition] = [],
        portableSchema: WireGenerationSchema? = nil,
        options: WireGenerationOptions = WireGenerationOptions(),
        context: WireContextOptions = WireContextOptions()
    ) {
        self.id = id
        self.portableTranscript = portableTranscript
        self.tools = tools
        self.portableSchema = portableSchema
        self.options = options
        self.context = context
    }

    private enum CodingKeys: String, CodingKey { case id, transcript, tools, schema, options, context }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        portableTranscript = try container.decode(WireTranscript.self, forKey: .transcript)
        tools = try container.decode([WireToolDefinition].self, forKey: .tools)
        portableSchema = try container.decodeIfPresent(WireGenerationSchema.self, forKey: .schema)
        options = try container.decode(WireGenerationOptions.self, forKey: .options)
        context = try container.decode(WireContextOptions.self, forKey: .context)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(portableTranscript, forKey: .transcript)
        try container.encode(tools, forKey: .tools)
        try container.encodeIfPresent(portableSchema, forKey: .schema)
        try container.encode(options, forKey: .options)
        try container.encode(context, forKey: .context)
    }
}

#if !canImport(FoundationModels)
public extension WireGenerationRequest {
    var transcript: WireTranscript {
        get { portableTranscript }
        set { portableTranscript = newValue }
    }

    var schema: WireGenerationSchema? {
        get { portableSchema }
        set { portableSchema = newValue }
    }

    init(
        id: UUID,
        transcript: WireTranscript,
        tools: [WireToolDefinition] = [],
        schema: WireGenerationSchema? = nil,
        options: WireGenerationOptions = WireGenerationOptions(),
        context: WireContextOptions = WireContextOptions()
    ) {
        self.init(
            id: id,
            portableTranscript: transcript,
            tools: tools,
            portableSchema: schema,
            options: options,
            context: context
        )
    }
}
#endif
