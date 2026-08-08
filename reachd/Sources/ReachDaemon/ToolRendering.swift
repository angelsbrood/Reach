import Foundation
import FoundationModels
import ReachWire

/// Tool definitions as a chat template wants to read them.
///
/// The shape is the OpenAI-style function envelope every tuned open-weights
/// template is trained against, and Gemma 4's own
/// `format_function_declaration` reads exactly it: `tool_data['function']`
/// with `name`, `description`, and a `parameters` object it walks as JSON
/// Schema. Nothing here hand-translates a schema — `GenerationSchema` already
/// encodes to JSON Schema (spike S6c: `type`, `properties`, `required`, and a
/// byte-identical Codable round trip), so the parameters field is one
/// `JSONEncoder` away. Apple's own MLX adapter converts it the same way.
enum ToolRendering {
    /// What to render for a request, or nil when nothing should be.
    ///
    /// `.disallowed` renders nothing, which is the whole of how the mode is
    /// honored: a model that was never told the tools exist cannot call them.
    /// `.allowed` uses this prompt shape only for the private proposal pass;
    /// `.required` uses it as context while a structural grammar forces one
    /// of the offered calls.
    static func specs(for request: WireGenerationRequest) throws -> [[String: any Sendable]]? {
        guard request.options.toolCalling != .disallowed, !request.tools.isEmpty else {
            return nil
        }
        return try request.tools.map(spec(for:))
    }

    static func spec(for tool: WireToolDefinition) throws -> [String: any Sendable] {
        let encoded: Data
        do {
            encoded = try JSONEncoder().encode(tool.parameters)
        } catch {
            throw ToolRenderingError.schemaUnrenderable(tool: tool.name, reason: "\(error)")
        }
        guard let parameters = try? JSONSerialization.jsonObject(with: encoded),
              let object = parameters as? [String: any Sendable]
        else {
            throw ToolRenderingError.schemaUnrenderable(
                tool: tool.name,
                reason: "its parameters did not encode as a JSON object"
            )
        }
        return [
            "type": "function",
            "function": [
                "name": tool.name,
                "description": tool.description,
                "parameters": object,
            ] as [String: any Sendable],
        ]
    }
}

/// A tool the model could not be told about. This travels: the filling turns a
/// throw into `.finished(.error(…))`, which crosses the wire and lands on the
/// asking app's screen, so it is written to be read there.
enum ToolRenderingError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    case schemaUnrenderable(tool: String, reason: String)

    var description: String {
        switch self {
        case .schemaUnrenderable(let tool, let reason):
            "the cluster could not describe the tool \(tool) to the model: \(reason)"
        }
    }

    var errorDescription: String? { description }
}
