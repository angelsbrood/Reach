import Foundation
import FoundationModels
import MLXGuidedGeneration
import ReachWire

/// The stable rendering boundary between FoundationModels' response schema
/// and xgrammar's JSON-schema compiler.
enum ResponseGuidance {
    static let refusalPrefix =
        "the cluster could not constrain this response to the requested schema: "

    /// FoundationModels' schema is already JSON Schema. Sorting object keys
    /// makes the bytes stable across equivalent requests, which in turn makes
    /// the compiled-template cache key stable. Semantic property order remains
    /// explicit in the schema's `x-order` member.
    static func schemaJSON(_ schema: GenerationSchema) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        do {
            let data = try encoder.encode(schema)
            guard let json = String(data: data, encoding: .utf8), !json.isEmpty else {
                throw ResponseGuidanceError.schemaUnsupported(
                    reason: "the schema encoder did not produce UTF-8 JSON")
            }
            return json
        } catch let error as ResponseGuidanceError {
            throw error
        } catch {
            throw ResponseGuidanceError.schemaUnsupported(reason: String(describing: error))
        }
    }

    static func unsupported(_ error: any Error) -> ResponseGuidanceError {
        if let error = error as? ResponseGuidanceError { return error }
        let reason = String(describing: error)
        return .schemaUnsupported(reason: reason.isEmpty ? "the grammar engine gave no reason" : reason)
    }

    /// Preserve cancellation as cancellation and turn an exhausted grammar
    /// budget into the product-level sentence that crosses the wire.
    static func generationError(_ error: any Error, maxTokens: Int) -> any Error {
        if error is CancellationError { return CancellationError() }
        if case GuidedGenerationError.incompleteOutput = error {
            return ResponseGuidanceError.incompleteOutput(maxTokens: maxTokens)
        }
        if case GuidedGenerationError.prematureEOS = error {
            return ResponseGuidanceError.generationFailed(
                reason: "the model ended before the grammar accepted the response")
        }
        return error
    }
}

/// Errors here cross the wire as generation failures and are intentionally
/// written for the person holding the app, not for an engine log.
enum ResponseGuidanceError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    case schemaUnsupported(reason: String)
    case incompleteOutput(maxTokens: Int)
    case generationFailed(reason: String)

    var description: String {
        switch self {
        case .schemaUnsupported(let reason):
            ResponseGuidance.refusalPrefix + reason
        case .incompleteOutput(let maxTokens):
            "the cluster could not finish the constrained response within its \(maxTokens)-token limit"
        case .generationFailed(let reason):
            "the cluster could not finish the constrained response: \(reason)"
        }
    }

    var errorDescription: String? { description }
}
