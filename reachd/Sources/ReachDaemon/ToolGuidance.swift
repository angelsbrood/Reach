import Foundation
import MLXGuidedGeneration
import MLXLMCommon
import ReachWire

enum GuidanceGrammarKind: String, Hashable, Sendable {
    case responseJSON
    case toolStructural
}

struct GuidanceConstraintKey: Hashable, Sendable {
    var kind: GuidanceGrammarKind
    var source: String
}

struct GuidedTool: Sendable {
    var definition: WireToolDefinition
    var schemaJSON: String
    var structuralTag: String
    var beginLiteral: String

    var name: String { definition.name }
}

struct ToolGuidancePlan: Sendable {
    var tools: [GuidedTool]
    var combinedStructuralTag: String

    func tool(named name: String) -> GuidedTool? {
        tools.first { $0.name == name }
    }
}

struct ProposedToolCall: Sendable, Equatable {
    var id: String
    var name: String
    var argumentsJSON: String
}

struct ConstrainedToolCall: Sendable, Equatable {
    var name: String
    var argumentsJSON: String
}

enum ToolProbeSelection: Sendable, Equatable {
    case calls([ProposedToolCall])
    case constrainedResponse
    case prose
}

enum ToolRouting {
    static func streamsProbeProse(hasResponseSchema: Bool) -> Bool {
        !hasResponseSchema
    }

    static func selection(
        proposals: [ProposedToolCall],
        hasResponseSchema: Bool
    ) -> ToolProbeSelection {
        if !proposals.isEmpty { return .calls(proposals) }
        return hasResponseSchema ? .constrainedResponse : .prose
    }

    static func replayPairs(
        proposals: [ProposedToolCall],
        plan: ToolGuidancePlan
    ) throws -> [(ProposedToolCall, GuidedTool)] {
        try proposals.map { proposal in
            guard let tool = plan.tool(named: proposal.name) else {
                throw ToolGuidanceError.unknownTool(proposal.name)
            }
            return (proposal, tool)
        }
    }
}

enum ToolGuidance {
    static func plan(for definitions: [WireToolDefinition]) throws -> ToolGuidancePlan {
        guard !definitions.isEmpty else { throw ToolGuidanceError.requiredWithoutTools }

        var seen = Set<String>()
        for definition in definitions where !seen.insert(definition.name).inserted {
            throw ToolGuidanceError.duplicateName(definition.name)
        }

        let tools = try definitions.map { definition in
            let schemaJSON: String
            do {
                schemaJSON = try ResponseGuidance.schemaJSON(definition.parameters)
            } catch {
                throw unsupported(tool: definition.name, error: error)
            }
            let begin = try beginLiteral(for: definition.name)
            let provisional = GuidedTool(
                definition: definition,
                schemaJSON: schemaJSON,
                structuralTag: "",
                beginLiteral: begin
            )
            var tool = provisional
            do {
                tool.structuralTag = try structuralTag(for: [provisional])
            } catch {
                throw unsupported(tool: definition.name, error: error)
            }
            return tool
        }
        let combined: String
        do {
            combined = try structuralTag(for: tools)
        } catch {
            throw unsupported(
                tool: tools.map(\.name).joined(separator: ", "),
                error: error
            )
        }
        return ToolGuidancePlan(
            tools: tools,
            combinedStructuralTag: combined
        )
    }

    /// A model-format-neutral strict JSON envelope. Each alternative fixes
    /// the offered name before xgrammar opens that tool's own argument schema.
    /// Keeping the schema as the tag content also preserves its root-local
    /// `$defs` and `$ref` relationship without rewriting pointers in Swift.
    static func structuralTag(for tools: [GuidedTool]) throws -> String {
        guard !tools.isEmpty else { throw ToolGuidanceError.requiredWithoutTools }
        let alternatives: [[String: Any]] = try tools.map { tool in
            let schema = try JSONSerialization.jsonObject(with: Data(tool.schemaJSON.utf8))
            return [
                "type": "tag",
                "begin": tool.beginLiteral,
                "content": [
                    "type": "json_schema",
                    "json_schema": schema,
                ],
                "end": ["}"],
            ]
        }
        let source: [String: Any] = [
            "type": "structural_tag",
            "format": [
                "type": "or",
                "elements": alternatives,
            ],
        ]
        do {
            let data = try JSONSerialization.data(
                withJSONObject: source,
                options: [.sortedKeys, .withoutEscapingSlashes]
            )
            guard let result = String(data: data, encoding: .utf8), !result.isEmpty else {
                throw ToolGuidanceError.encodingFailed("the structural grammar was not UTF-8")
            }
            return result
        } catch let error as ToolGuidanceError {
            throw error
        } catch {
            throw ToolGuidanceError.encodingFailed(String(describing: error))
        }
    }

    static func proposedCall(_ call: MLXLMCommon.ToolCall) throws -> ProposedToolCall {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        do {
            let data = try encoder.encode(call.function.arguments)
            guard let json = String(data: data, encoding: .utf8) else {
                throw ToolGuidanceError.candidateUnencodable(call.function.name)
            }
            return ProposedToolCall(
                id: call.id ?? UUID().uuidString,
                name: call.function.name,
                argumentsJSON: json
            )
        } catch let error as ToolGuidanceError {
            throw error
        } catch {
            throw ToolGuidanceError.candidateUnencodable(
                "\(call.function.name): \(String(describing: error))")
        }
    }

    static func parseEnvelope(_ source: String, offeredNames: Set<String>) throws -> ConstrainedToolCall {
        let value: Any
        do {
            value = try JSONSerialization.jsonObject(with: Data(source.utf8))
        } catch {
            throw ToolGuidanceError.incompleteOutput(String(describing: error))
        }
        guard let object = value as? [String: Any],
              let name = object["name"] as? String,
              let arguments = object["arguments"] as? [String: Any]
        else {
            throw ToolGuidanceError.incompleteOutput(
                "the accepted envelope did not contain an object name and object arguments")
        }
        guard offeredNames.contains(name) else { throw ToolGuidanceError.unknownTool(name) }
        let data = try JSONSerialization.data(
            withJSONObject: arguments,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard let argumentsJSON = String(data: data, encoding: .utf8) else {
            throw ToolGuidanceError.incompleteOutput("the accepted arguments were not UTF-8 JSON")
        }
        return ConstrainedToolCall(name: name, argumentsJSON: argumentsJSON)
    }

    static func unsupported(tool: String, error: any Error) -> ToolGuidanceError {
        if let existing = error as? ToolGuidanceError,
           case .schemaUnsupported = existing
        {
            return existing
        }
        let rendered = String(describing: error)
        return .schemaUnsupported(
            tool: tool,
            reason: rendered.isEmpty ? "the grammar engine gave no reason" : rendered
        )
    }

    static func generationError(_ error: any Error, tool: String, maxTokens: Int) -> any Error {
        if error is CancellationError { return CancellationError() }
        if case GuidedGenerationError.incompleteOutput = error {
            return ToolGuidanceError.budgetExhausted(tool: tool, maxTokens: maxTokens)
        }
        if case GuidedGenerationError.prematureEOS = error {
            return ToolGuidanceError.incompleteOutput(
                "tool `\(tool)` ended before its argument grammar accepted")
        }
        return error
    }

    private static func beginLiteral(for name: String) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        let data = try encoder.encode(name)
        guard let encodedName = String(data: data, encoding: .utf8) else {
            throw ToolGuidanceError.encodingFailed("tool name was not UTF-8")
        }
        return "{\"name\":\(encodedName),\"arguments\":"
    }
}

enum ToolGuidanceError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    case schemaUnsupported(tool: String, reason: String)
    case duplicateName(String)
    case requiredWithoutTools
    case encodingFailed(String)
    case candidateUnencodable(String)
    case unknownTool(String)
    case incompleteOutput(String)
    case budgetExhausted(tool: String, maxTokens: Int)

    var description: String {
        switch self {
        case .schemaUnsupported(let tool, let reason):
            "the cluster could not constrain the arguments for tool `\(tool)` to its schema: \(reason)"
        case .duplicateName(let name):
            "the cluster cannot offer duplicate tool name `\(name)`"
        case .requiredWithoutTools:
            "the cluster was required to call a tool, but no tools were offered"
        case .encodingFailed(let reason):
            "the cluster could not encode its tool-call grammar: \(reason)"
        case .candidateUnencodable(let name):
            "the cluster could not encode the proposed arguments for tool `\(name)`"
        case .unknownTool(let name):
            "the cluster selected unoffered tool `\(name)`"
        case .incompleteOutput(let reason):
            "the cluster could not finish constrained tool arguments: \(reason)"
        case .budgetExhausted(let tool, let maxTokens):
            "the cluster could not finish the constrained arguments for tool `\(tool)` within its \(maxTokens)-token limit"
        }
    }

    var errorDescription: String? { description }
}
