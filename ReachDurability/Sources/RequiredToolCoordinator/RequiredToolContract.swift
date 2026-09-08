import Foundation
import MLXGuidedGeneration
import MLXLMCommon

public enum RequiredToolError: Error, Equatable {
    case invalid(String), oversized, incompatible, closed
}

public struct RequiredToolDefinition: Codable, Equatable, Sendable {
    public var name: String
    public var schemaJSON: String
    public init(name: String, schemaJSON: String) { self.name = name; self.schemaJSON = schemaJSON }
}

public struct RequiredToolCall: Codable, Equatable, Sendable {
    public let name: String
    public let argumentsJSON: String
}

public enum RequiredToolContract {
    public static let maximumEnvelopeBytes = 256 * 1024
    public static let maximumArgumentsBytes = 256 * 1024
    public static func structuralSource(_ tools: [RequiredToolDefinition]) throws -> String {
        guard (1...32).contains(tools.count) else { throw RequiredToolError.invalid("required tools count") }
        var names = Set<String>()
        let elements: [[String: Any]] = try tools.map { tool in
            guard !tool.name.isEmpty, tool.name.utf8.count <= 1024,
                  names.insert(tool.name).inserted, tool.schemaJSON.utf8.count <= 65_536 else {
                throw RequiredToolError.invalid("tool name/schema bounds or duplicate name")
            }
            let schema = try JSONSerialization.jsonObject(with: Data(tool.schemaJSON.utf8))
            let name = String(decoding: try requiredEncoder().encode(tool.name), as: UTF8.self)
            return ["type": "tag", "begin": "{\"name\":\(name),\"arguments\":",
                    "content": ["type": "json_schema", "json_schema": schema], "end": ["}"]]
        }
        let data = try JSONSerialization.data(withJSONObject:
            ["type": "structural_tag", "format": ["type": "or", "elements": elements]],
            options: [.sortedKeys, .withoutEscapingSlashes])
        guard data.count <= 65_536 else { throw RequiredToolError.oversized }
        return String(decoding: data, as: UTF8.self)
    }

    /// Whole-envelope shape/name parsing follows ToolGuidance. Native structural
    /// acceptance enforces the selected argument schema before this helper runs.
    public static func parseEnvelope(_ bytes: Data, tools: [RequiredToolDefinition]) throws -> RequiredToolCall {
        guard bytes.count <= maximumEnvelopeBytes else { throw RequiredToolError.oversized }
        guard let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let name = object["name"] as? String,
              let arguments = object["arguments"] as? [String: Any],
              tools.contains(where: { $0.name == name }) else {
            throw RequiredToolError.invalid("complete envelope needs an offered name and object arguments")
        }
        let normalized = try JSONSerialization.data(withJSONObject: arguments, options: [.sortedKeys, .withoutEscapingSlashes])
        guard normalized.count <= maximumArgumentsBytes else { throw RequiredToolError.oversized }
        return .init(name: name, argumentsJSON: String(decoding: normalized, as: UTF8.self))
    }
}

public struct RequiredToolBinding: Codable, Sendable {
    public var version = 1
    public var route = "required"
    public var policy = "stable-ids;accepted-eos;whole-batch;ready-wins-v1"
    public var requestIdentity: String
    public var entryID: String
    public var callID: String
    public var tools: [RequiredToolDefinition]
    public var identity: ResumableTokenIdentity
    public var cacheSpecs: [ResumableCacheSpec]
    /// Caller-owned codec implementation identity. The child additionally binds
    /// and validates every actual registered descriptor, including at C0.
    public var codecIdentity: String
    public var specification: ResumableGrammarSpecification
    public var options: ResumableGuidedOptions

    public init(requestIdentity: String, entryID: String, callID: String,
                tools: [RequiredToolDefinition], identity: ResumableTokenIdentity,
                cacheSpecs: [ResumableCacheSpec], codecIdentity: String,
                vocabulary: [String], vocabularyType: ResumableGrammarVocabulary,
                tokenizerIdentity: String, eosTokenID: Int, unknownTokenID: Int?,
                fastForward: Bool, options: ResumableGuidedOptions) throws {
        self.requestIdentity = requestIdentity; self.entryID = entryID; self.callID = callID
        self.tools = tools; self.identity = identity; self.cacheSpecs = cacheSpecs
        self.codecIdentity = codecIdentity; self.options = options
        specification = .init(structuralTag: try RequiredToolContract.structuralSource(tools),
            vocabulary: vocabulary, vocabularyType: vocabularyType, tokenizerIdentity: tokenizerIdentity,
            eosTokenID: eosTokenID, unknownTokenID: unknownTokenID, fastForward: fastForward)
        try validate()
    }

    func validate() throws {
        guard version == 1, route == "required", policy == "stable-ids;accepted-eos;whole-batch;ready-wins-v1",
              [entryID, callID].allSatisfy({ !$0.isEmpty && $0.utf8.count <= 256 }),
              [requestIdentity, codecIdentity].allSatisfy({ !$0.isEmpty && $0.utf8.count <= 1024 }) else {
            throw RequiredToolError.invalid("required route/identity/policy")
        }
        let exact = ResumableGrammarSpecification(structuralTag: try RequiredToolContract.structuralSource(tools),
            vocabulary: specification.vocabulary, vocabularyType: specification.vocabularyType,
            tokenizerIdentity: specification.tokenizerIdentity, eosTokenID: specification.eosTokenID,
            unknownTokenID: specification.unknownTokenID, fastForward: specification.fastForward)
        guard try requiredEncoder().encode(specification) == requiredEncoder().encode(exact) else {
            throw RequiredToolError.incompatible
        }
        guard try requiredEncoder().encode(self).count <= RequiredToolCheckpoint.maximumControlBytes else {
            throw RequiredToolError.oversized
        }
        try ResumableGuidedModelState.assess(identity: identity, options: options.model, cacheSpecs: cacheSpecs)
    }
}

func requiredEncoder() -> JSONEncoder {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return e
}
