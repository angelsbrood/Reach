import Foundation
import FoundationModels
import MLXGuidedGeneration
import MLXLMCommon
import ReachWire
import Testing
@testable import ReachDaemon

@Suite(.serialized)
struct ToolGuidanceTests {
    @Generable
    struct Leaf {
        var code: String
        var count: Int
    }

    @Generable
    enum Mode {
        case fast
        case safe
    }

    @Generable
    struct Arguments {
        var leaf: Leaf
        var mode: Mode

        @Guide(.count(2))
        var values: [Int]

        var note: String?
    }

    @Test func envelopeIsDeterministicStrictEscapedAndOrdered() throws {
        let definitions = [
            Self.tool(name: "quote\"and\\slash"),
            Self.tool(name: "second"),
        ]
        let first = try ToolGuidance.plan(for: definitions)
        let second = try ToolGuidance.plan(for: definitions)
        #expect(first.combinedStructuralTag == second.combinedStructuralTag)
        #expect(first.tools.map(\.name) == definitions.map(\.name))

        let root = try Self.object(first.combinedStructuralTag)
        #expect(root["type"] as? String == "structural_tag")
        let format = try #require(root["format"] as? [String: Any])
        let alternatives = try #require(format["elements"] as? [[String: Any]])
        #expect(alternatives.count == 2)
        #expect(alternatives[0]["begin"] as? String
            == "{\"name\":\"quote\\\"and\\\\slash\",\"arguments\":")
        #expect(alternatives[0]["end"] as? [String] == ["}"])
        #expect((alternatives[0]["content"] as? [String: Any])?["type"] as? String
            == "json_schema")
        #expect(!first.combinedStructuralTag.contains("<tool_call>"))
    }

    @Test func duplicateAndEmptyToolSetsRefuseBeforeSampling() {
        #expect(throws: ToolGuidanceError.duplicateName("same")) {
            _ = try ToolGuidance.plan(for: [Self.tool(name: "same"), Self.tool(name: "same")])
        }
        #expect(throws: ToolGuidanceError.requiredWithoutTools) {
            _ = try ToolGuidance.plan(for: [])
        }
    }

    @Test func nestedDefsEnumsArraysAndOptionalsCompileAsOneStructuralTool() async throws {
        let plan = try ToolGuidance.plan(for: [Self.tool(name: "record")])
        let source = plan.tools[0].structuralTag
        #expect(source.contains("$defs"))
        #expect(source.contains("enum"))
        #expect(source.contains("minItems"))

        let tokenizer = GuidanceByteTokenizer()
        let box = ContainerBox()
        let xg = try await box.grammarTokenizer(tokenizer: tokenizer)
        _ = try await box.structuralConstraint(
            structuralTag: source,
            tokenizer: xg,
            hostTokenizer: tokenizer
        )
    }

    @Test func responseAndStructuralGrammarCachesCannotCollide() async throws {
        let tokenizer = GuidanceByteTokenizer()
        let box = ContainerBox()
        let xg = try await box.grammarTokenizer(tokenizer: tokenizer)
        let schema = try ResponseGuidance.schemaJSON(Arguments.generationSchema)
        let structural = try ToolGuidance.plan(for: [Self.tool(name: "record")])
            .tools[0].structuralTag

        _ = try await box.constraint(
            schemaJSON: schema,
            tokenizer: xg,
            hostTokenizer: tokenizer
        )
        _ = try await box.structuralConstraint(
            structuralTag: structural,
            tokenizer: xg,
            hostTokenizer: tokenizer
        )
        let statistics = await box.guidanceCacheStatistics()
        #expect(statistics.responseConstraintCompiles >= 1)
        #expect(statistics.toolConstraintCompiles >= 1)
    }

    @Test func proposedAndAcceptedCallsPreserveIdentityButNotRawFormatting() throws {
        let native = MLXLMCommon.ToolCall(
            function: .init(
                name: "record",
                arguments: ["z": .int(2), "a": .string("candidate")]
            ),
            id: "call-7"
        )
        let proposed = try ToolGuidance.proposedCall(native)
        #expect(proposed.id == "call-7")
        #expect(proposed.name == "record")
        #expect(proposed.argumentsJSON == #"{"a":"candidate","z":2}"#)

        let accepted = try ToolGuidance.parseEnvelope(
            #"{"name":"record","arguments":{"z":2,"a":"accepted"}}"#,
            offeredNames: ["record"]
        )
        #expect(accepted.name == "record")
        #expect(accepted.argumentsJSON == #"{"a":"accepted","z":2}"#)
    }

    @Test func refusalErrorsAreExactLegibleAndNeverEmpty() {
        let refusal = ToolGuidance.unsupported(
            tool: "record",
            error: GuidanceFailure.broken
        )
        #expect(refusal.description.hasPrefix(
            "the cluster could not constrain the arguments for tool `record` to its schema: "))
        #expect(refusal.description.count
            > "the cluster could not constrain the arguments for tool `record` to its schema: ".count)

        #expect(throws: ToolGuidanceError.unknownTool("other")) {
            _ = try ToolGuidance.parseEnvelope(
                #"{"name":"other","arguments":{}}"#,
                offeredNames: ["record"]
            )
        }
        #expect(throws: ToolGuidanceError.self) {
            _ = try ToolGuidance.parseEnvelope("{", offeredNames: ["record"])
        }
    }

    @Test func cancellationAndIncompleteBudgetsRemainErrors() {
        #expect(ToolGuidance.generationError(
            CancellationError(), tool: "record", maxTokens: 8) is CancellationError)
        let exhausted = ToolGuidance.generationError(
            GuidedGenerationError.incompleteOutput,
            tool: "record",
            maxTokens: 8
        )
        #expect(exhausted as? ToolGuidanceError == .budgetExhausted(
            tool: "record", maxTokens: 8))
    }

    @Test func routingPreservesProseAndSelectsCallsOrConstrainedResponsesExactly() throws {
        #expect(ToolRouting.streamsProbeProse(hasResponseSchema: false))
        #expect(!ToolRouting.streamsProbeProse(hasResponseSchema: true))
        #expect(ToolRouting.selection(proposals: [], hasResponseSchema: false) == .prose)
        #expect(ToolRouting.selection(
            proposals: [], hasResponseSchema: true) == .constrainedResponse)

        let proposals = [
            ProposedToolCall(id: "1", name: "first", argumentsJSON: #"{"x":1}"#),
            ProposedToolCall(id: "2", name: "first", argumentsJSON: #"{"x":2}"#),
            ProposedToolCall(id: "3", name: "second", argumentsJSON: #"{"x":3}"#),
        ]
        #expect(ToolRouting.selection(
            proposals: proposals,
            hasResponseSchema: true) == .calls(proposals))
        let plan = try ToolGuidance.plan(for: [
            Self.tool(name: "first"),
            Self.tool(name: "second"),
        ])
        let pairs = try ToolRouting.replayPairs(proposals: proposals, plan: plan)
        #expect(pairs.map { $0.0.id } == ["1", "2", "3"])
        #expect(pairs.map { $0.1.name } == ["first", "first", "second"])
        #expect(pairs.map { $0.0.argumentsJSON }
            == [#"{"x":1}"#, #"{"x":2}"#, #"{"x":3}"#])

        #expect(throws: ToolGuidanceError.unknownTool("missing")) {
            _ = try ToolRouting.replayPairs(
                proposals: [ProposedToolCall(
                    id: "4", name: "missing", argumentsJSON: "{}")],
                plan: plan
            )
        }
    }

    private static func tool(name: String) -> WireToolDefinition {
        WireToolDefinition(
            name: name,
            description: "Records a nested value.",
            parameters: Arguments.generationSchema
        )
    }

    private static func object(_ json: String) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
    }
}

private enum GuidanceFailure: Error { case broken }

private struct GuidanceByteTokenizer: MLXLMCommon.Tokenizer {
    func encode(text: String, addSpecialTokens: Bool) -> [Int] { Array(text.utf8).map(Int.init) }
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
