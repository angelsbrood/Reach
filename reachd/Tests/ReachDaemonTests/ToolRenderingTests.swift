import Foundation
import FoundationModels
import ReachWire
import Testing
@testable import ReachDaemon

/// The daemon's two tool-facing translations: what an app's tools look like on
/// the way into the prompt, and what a tool round trip already in the
/// transcript looks like on the way back in.
///
/// Neither needs weights. The first is a JSON shape a chat template reads; the
/// second is the mapping that decides whether a second turn sees the question
/// it already asked and the answer it already got.
@Suite struct ToolRenderingTests {
    private static func clock(named name: String = "current_time") throws -> WireToolDefinition {
        WireToolDefinition(
            name: name,
            description: "The current time on this device.",
            parameters: try GenerationSchema(
                type: GeneratedContent.self,
                properties: []
            )
        )
    }

    private static func request(
        tools: [WireToolDefinition],
        calling: WireToolCalling? = nil
    ) -> WireGenerationRequest {
        WireGenerationRequest(
            id: UUID(),
            transcript: Transcript(entries: []),
            tools: tools,
            options: WireGenerationOptions(toolCalling: calling)
        )
    }

    @Test func aToolBecomesTheEnvelopeAChatTemplateReads() throws {
        let specs = try ToolRendering.specs(for: Self.request(tools: [Self.clock()]))
        let spec = try #require(specs?.first)

        #expect(spec["type"] as? String == "function")
        let function = try #require(spec["function"] as? [String: any Sendable])
        #expect(function["name"] as? String == "current_time")
        #expect(function["description"] as? String == "The current time on this device.")

        // Gemma's `format_function_declaration` walks `parameters` as JSON
        // Schema and reads `type` off it; anything else renders an empty
        // declaration the model cannot call.
        let parameters = try #require(function["parameters"] as? [String: any Sendable])
        #expect(parameters["type"] as? String == "object")
    }

    @Test func everyToolTheAppEnabledIsOffered() throws {
        let specs = try ToolRendering.specs(for: Self.request(
            tools: [try Self.clock(named: "current_time"), try Self.clock(named: "battery")]
        ))
        let names = (specs ?? []).compactMap { spec in
            (spec["function"] as? [String: any Sendable])?["name"] as? String
        }
        #expect(names == ["current_time", "battery"])
    }

    /// `.disallowed` is honored by never telling the model the tools exist.
    /// That is the whole enforcement, and it is exact — there is no constrained
    /// decoding here to refuse a call with, so the only reliable way to not get
    /// one is to not offer it.
    @Test func disallowedOffersNothingAtAll() throws {
        let specs = try ToolRendering.specs(for: Self.request(
            tools: [try Self.clock()],
            calling: .disallowed
        ))
        #expect(specs == nil)
    }

    @Test func allowedAndRequiredBothOffer() throws {
        for mode in [WireToolCalling.allowed, .required] {
            let specs = try ToolRendering.specs(for: Self.request(tools: [try Self.clock()], calling: mode))
            #expect(specs?.count == 1, "\(mode) should still offer the tool")
        }
    }

    /// A session with no tools must render exactly as it did before this pass —
    /// nil rather than an empty array, because the template branches on
    /// `tools` being truthy and an empty list is a different prompt.
    @Test func aSessionWithNoToolsRendersNoToolBlock() throws {
        #expect(try ToolRendering.specs(for: Self.request(tools: [])) == nil)
    }

    // MARK: - The transcript on the way back in

    @Test func aCallAndItsAnswerSurviveIntoTheNextTurn() throws {
        let call = Transcript.ToolCall(
            id: "call-1",
            toolName: "current_time",
            arguments: try GeneratedContent(json: #"{"timezone":"Europe/Vienna"}"#)
        )
        let transcript = Transcript(entries: [
            .prompt(Transcript.Prompt(segments: [.text(Transcript.TextSegment(content: "what time is it?"))])),
            .toolCalls(Transcript.ToolCalls([call])),
            .toolOutput(Transcript.ToolOutput(
                id: "call-1",
                toolName: "current_time",
                segments: [.text(Transcript.TextSegment(content: "08:15 in Europe/Vienna"))]
            )),
        ])

        let messages = TranscriptChat.messages(from: transcript)
        #expect(messages.count == 3, "the call and its answer were dropped: \(messages.map(\.role))")

        #expect(messages[0].role == .user)

        #expect(messages[1].role == .assistant)
        guard case .calls(let calls) = messages[1].tool else {
            Issue.record("the assistant turn does not carry its calls")
            return
        }
        #expect(calls.count == 1)
        #expect(calls[0].id == "call-1")
        #expect(calls[0].name == "current_time")
        #expect(calls[0].argumentsJSON.contains("Europe/Vienna"))

        #expect(messages[2].role == .tool)
        #expect(messages[2].text == "08:15 in Europe/Vienna")
        // The id that ties the answer to the question is the CALL's, not the
        // entry's — spike S6a watched the framework hand back exactly the id
        // minted for the call.
        #expect(messages[2].tool == .output(callID: "call-1"))
    }

    @Test func aTranscriptWithoutToolsMapsExactlyAsItAlwaysDid() throws {
        let transcript = Transcript(entries: [
            .instructions(Transcript.Instructions(
                segments: [.text(Transcript.TextSegment(content: "be terse"))],
                toolDefinitions: []
            )),
            .prompt(Transcript.Prompt(segments: [.text(Transcript.TextSegment(content: "hello"))])),
            .response(Transcript.Response(segments: [.text(Transcript.TextSegment(content: "hi"))])),
        ])
        let messages = TranscriptChat.messages(from: transcript)
        #expect(messages.map(\.role) == [.system, .user, .assistant])
        #expect(messages.allSatisfy { $0.tool == nil })
        #expect(messages.map(\.text) == ["be terse", "hello", "hi"])
    }
}
