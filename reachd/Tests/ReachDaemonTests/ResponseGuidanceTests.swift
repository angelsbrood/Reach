import Foundation
import FoundationModels
import MLXGuidedGeneration
import MLXLMCommon
import ReachWire
import Testing
@testable import ReachDaemon

@Suite(.serialized)
struct ResponseGuidanceTests {
    @Generable
    struct TwoField {
        var name: String
        var count: Int
    }

    @Generable
    struct Nested {
        var value: TwoField
    }

    @Generable
    enum Color {
        case red
        case green
        case blue
    }

    @Generable
    struct EnumValue {
        var color: Color
    }

    @Generable
    struct FixedArray {
        @Guide(.count(3))
        var values: [Int]
    }

    @Generable
    struct OptionalValue {
        var required: String
        var optional: String?
    }

    @Test func schemasRenderDeterministicallyAndKeepFoundationModelsShapes() throws {
        let first = try ResponseGuidance.schemaJSON(TwoField.generationSchema)
        #expect(first == (try ResponseGuidance.schemaJSON(TwoField.generationSchema)))
        #expect(first == String(data: Data(first.utf8), encoding: .utf8))

        let two = try Self.object(first)
        #expect(two["type"] as? String == "object")
        let twoProperties = try #require(two["properties"] as? [String: Any])
        #expect((twoProperties["name"] as? [String: Any])?["type"] as? String == "string")
        #expect((twoProperties["count"] as? [String: Any])?["type"] as? String == "integer")

        let nestedJSON = try ResponseGuidance.schemaJSON(Nested.generationSchema)
        let nested = try Self.properties(of: Nested.generationSchema)
        let nestedValue = try #require(nested["value"] as? [String: Any])
        #expect(nestedValue["$ref"] != nil)
        #expect(nestedJSON.contains("TwoField"))

        let enumerated = try Self.properties(of: EnumValue.generationSchema)
        let color = try #require(enumerated["color"] as? [String: Any])
        #expect(color["enum"] as? [String] == ["red", "green", "blue"])

        let fixed = try Self.properties(of: FixedArray.generationSchema)
        let values = try #require(fixed["values"] as? [String: Any])
        #expect(values["type"] as? String == "array")
        #expect(values["minItems"] as? Int == 3)
        #expect(values["maxItems"] as? Int == 3)

        let optionalRoot = try Self.object(
            ResponseGuidance.schemaJSON(OptionalValue.generationSchema))
        let optional = try #require(optionalRoot["properties"] as? [String: Any])
        let optionalValue = try #require(optional["optional"] as? [String: Any])
        #expect(optionalValue["type"] as? String == "string")
        #expect((optionalRoot["required"] as? [String])?.contains("optional") == false)
    }

    @Test func unsupportedGrammarCarriesTheExactRefusalPrefixAndEngineReason() async throws {
        let tokenizer = ByteTokenizer()
        let box = ContainerBox()
        let grammarTokenizer = try await box.grammarTokenizer(tokenizer: tokenizer)
        do {
            _ = try await box.constraint(
                schemaJSON: #"{"type":"not-a-json-schema-type"}"#,
                tokenizer: grammarTokenizer,
                hostTokenizer: tokenizer)
            Issue.record("invalid schema unexpectedly compiled")
        } catch {
            let refusal = ResponseGuidance.unsupported(error)
            #expect(refusal.description.hasPrefix(ResponseGuidance.refusalPrefix))
            #expect(refusal.description.count > ResponseGuidance.refusalPrefix.count)
        }
    }

    @Test func tokenizerAndBiasReuseWhileConstraintsRemainIndependent() async throws {
        let tokenizer = ByteTokenizer()
        let box = ContainerBox()

        try await box.prewarmGuidance(tokenizer: tokenizer)
        try await box.prewarmGuidance(tokenizer: tokenizer)

        let xg = try await box.grammarTokenizer(tokenizer: tokenizer)
        let schema = #"{"additionalProperties":false,"properties":{"x":{"type":"integer"}},"required":["x"],"type":"object"}"#
        let first = try await box.constraint(
            schemaJSON: schema,
            tokenizer: xg,
            hostTokenizer: tokenizer)
        let second = try await box.constraint(
            schemaJSON: schema,
            tokenizer: xg,
            hostTokenizer: tokenizer)

        let secondBefore = try second.computeMask()
        _ = try first.commitToken(Int32(Character("{").asciiValue!))
        let secondAfter = try second.computeMask()
        #expect(secondBefore.mask == secondAfter.mask)

        let statistics = await box.guidanceCacheStatistics()
        #expect(statistics.tokenizerBuilds == 1)
        // Bias arrays are exercised by S12 and the real-weight loopback: a
        // bare `swift test` executable has no MLX default.metallib to create
        // those arrays safely.
        #expect(statistics.biasBuilds == 0)
        // Newer xgrammar clones one compiled template. The pinned 0.1.30
        // reports Fork unavailable, so the required fallback recompiles.
        if statistics.constraintCloneFailures == 0 {
            #expect(statistics.constraintCompiles == 1)
        } else {
            #expect(statistics.constraintCompiles == 2)
        }
    }

    @Test func cancellationAndBudgetExhaustionStayDistinct() {
        let cancelled = ResponseGuidance.generationError(CancellationError(), maxTokens: 8)
        #expect(cancelled is CancellationError)

        let incomplete = ResponseGuidance.generationError(
            GuidedGenerationError.incompleteOutput,
            maxTokens: 8)
        #expect(incomplete as? ResponseGuidanceError == .incompleteOutput(maxTokens: 8))
        #expect(String(describing: incomplete).contains("8-token limit"))

        let premature = ResponseGuidance.generationError(
            GuidedGenerationError.prematureEOS,
            maxTokens: 8)
        #expect(premature as? ResponseGuidanceError == .generationFailed(
            reason: "the model ended before the grammar accepted the response"))
    }

    @Test func schemaToolProbeSelectsCallsAndNeverItsProse() {
        var noCall = SchemaToolProbeBuffer()
        noCall.appendUsage(.usage(inputTokens: 10, outputTokens: 4))
        #expect(noCall.selectedToolEvents == nil)

        let call = WireEvent.toolCallAppendArguments(
            entryID: "tools",
            id: "call-1",
            name: "clock",
            content: #"{"zone":"UTC"}"#,
            tokenCount: 1)
        var withCall = SchemaToolProbeBuffer()
        withCall.appendToolCall(call)
        withCall.appendUsage(.usage(inputTokens: 10, outputTokens: 7))
        #expect(withCall.selectedToolEvents == [
            call,
            .usage(inputTokens: 10, outputTokens: 7),
        ])
    }

    private static func object(_ json: String) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
    }

    private static func properties(of schema: GenerationSchema) throws -> [String: Any] {
        let root = try object(ResponseGuidance.schemaJSON(schema))
        return try #require(root["properties"] as? [String: Any])
    }
}

private struct ByteTokenizer: MLXLMCommon.Tokenizer {
    func encode(text: String, addSpecialTokens: Bool) -> [Int] {
        Array(text.utf8).map(Int.init)
    }

    func decode(tokenIds: [Int], skipSpecialTokens: Bool) -> String {
        String(bytes: tokenIds.map { UInt8($0 & 0xff) }, encoding: .utf8) ?? ""
    }

    func convertTokenToId(_ token: String) -> Int? {
        guard token.utf8.count == 1, let byte = token.utf8.first else { return nil }
        return Int(byte)
    }

    func convertIdToToken(_ id: Int) -> String? {
        guard (0 ..< 256).contains(id) else { return nil }
        return String(UnicodeScalar(UInt8(id)))
    }

    var bosToken: String? { nil }
    var eosToken: String? { String(UnicodeScalar(UInt8(255))) }
    var unknownToken: String? { nil }

    func applyChatTemplate(
        messages: [[String: any Sendable]],
        tools: [[String: any Sendable]]?,
        additionalContext: [String: any Sendable]?
    ) throws -> [Int] { [] }
}
