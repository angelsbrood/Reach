import Foundation
import Testing
@testable import ReachWire

@Suite struct PortableGenerationTests {
    private func expectDataCorrupted(
        _ expectedDescription: String,
        _ operation: () throws -> Void
    ) {
        do {
            try operation()
            Issue.record("invalid portable value unexpectedly decoded")
        } catch DecodingError.dataCorrupted(let context) {
            #expect(context.debugDescription == expectedDescription)
        } catch {
            Issue.record("expected DecodingError.dataCorrupted, got \(error)")
        }
    }

    private func canonicalSchemaJSON(_ source: String) throws -> String {
        let schema = try JSONDecoder().decode(WireGenerationSchema.self, from: Data(source.utf8))
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(schema), as: UTF8.self)
    }

    private func fixedSchema() throws -> WireGenerationSchema {
        try WireGenerationSchema(jsonValue: .object([
            "additionalProperties": .bool(false),
            "description": .string("Fixed object."),
            "properties": .object([
                "count": .object(["type": .string("integer")]),
                "label": .object(["type": .string("string")]),
            ]),
            "required": .array([.string("label")]),
            "title": .string("Fixed"),
            "type": .string("object"),
            "x-order": .array([.string("count"), .string("label")]),
        ]))
    }

    private func fixedTranscript() throws -> WireTranscript {
        let schema = try fixedSchema()
        return WireTranscript(entries: [
            .instructions(.init(
                id: "instructions",
                segments: [.text(.init(id: "instructions-text", content: "Fixed instructions."))],
                toolDefinitions: [.init(name: "lookup", description: "Fixed lookup.", parameters: schema)]
            )),
            .prompt(.init(
                id: "prompt",
                segments: [
                    .text(.init(id: "prompt-text", content: "Fixed prompt.")),
                    .structure(.init(
                        id: "prompt-structure",
                        source: "Fixed",
                        content: .object(["label": .string("value")])
                    )),
                ],
                options: ["temperature": .number(0.25)],
                responseFormat: .init(name: "Fixed", description: "Fixed object.", schema: schema),
                contextOptions: ["includeSchemaInPrompt": .bool(true)],
                metadata: ["turn": .integer(1)]
            )),
            .toolCalls(.init(id: "calls", calls: [
                .init(id: "call", name: "lookup", argumentsJSON: #"{"label":"value"}"#, metadata: ["fixed": .bool(true)]),
            ])),
            .toolOutput(.init(
                id: "call",
                toolCallID: "call",
                toolName: "lookup",
                segments: [.text(.init(id: "output-text", content: "Fixed output."))]
            )),
            .response(.init(
                id: "response",
                assetIDs: ["asset"],
                segments: [.text(.init(id: "response-text", content: "Fixed response."))]
            )),
            .reasoning(.init(
                id: "reasoning",
                segments: [.text(.init(id: "reasoning-text", content: "Fixed reasoning."))],
                signature: Data([0, 1, 2]),
                metadata: ["phase": .string("fixed")]
            )),
        ])
    }

    @Test func everyPortableTranscriptArmRoundTripsDeterministically() throws {
        let transcript = try fixedTranscript()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let first = try encoder.encode(transcript)
        let decoded = try JSONDecoder().decode(WireTranscript.self, from: first)
        #expect(decoded == transcript)
        #expect(try encoder.encode(decoded) == first)
        #expect(decoded.count == 6)
    }

    @Test func portableRequestRoundTripsWithoutANativeFrameworkType() throws {
        let schema = try fixedSchema()
        let request = WireGenerationRequest(
            id: try #require(UUID(uuidString: "00000000-0000-0000-0000-000000000055")),
            portableTranscript: try fixedTranscript(),
            tools: [.init(name: "lookup", description: "Fixed lookup.", portableParameters: schema)],
            portableSchema: schema,
            options: .init(
                temperature: 0.5,
                maximumResponseTokens: 32,
                sampling: .topK(8, seed: 7),
                toolCalling: .required
            ),
            context: .init(includeSchemaInPrompt: true, reasoning: .custom("fixed"))
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let first = try encoder.encode(request)
        let decoded = try JSONDecoder().decode(WireGenerationRequest.self, from: first)
        #expect(try encoder.encode(decoded) == first)
        #expect(decoded.portableTranscript == request.portableTranscript)
        #expect(decoded.portableSchema == request.portableSchema)
    }

    @Test func unknownSchemaKeywordsArePrunedAtEverySchemaBoundary() throws {
        let source = Data(#"{"additionalProperties":false,"futureRoot":true,"properties":{"keptName":{"futureNested":1,"type":"string"}},"required":[],"title":"Fixed","type":"object","x-order":["keptName"]}"#.utf8)
        let schema = try JSONDecoder().decode(WireGenerationSchema.self, from: source)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        #expect(String(data: try encoder.encode(schema), encoding: .utf8) == #"{"additionalProperties":false,"properties":{"keptName":{"type":"string"}},"required":[],"title":"Fixed","type":"object","x-order":["keptName"]}"#)
    }

    @Test func unknownTranscriptShapesStillFailClosed() {
        let unknownEntry = Data(#"{"transcript":{"entries":[{"id":"future","role":"future"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#.utf8)
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(WireTranscript.self, from: unknownEntry)
        }

        let unknownSegment = Data(#"{"transcript":{"entries":[{"contents":[{"id":"future","type":"future"}],"id":"prompt","role":"user"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#.utf8)
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(WireTranscript.self, from: unknownSegment)
        }
    }

    @Test func baselineInvalidNativeShapesFailInThePortableDecoder() {
        expectDataCorrupted("generation schema type is unsupported") {
            _ = try JSONDecoder().decode(
                WireGenerationSchema.self,
                from: Data(#"{"type":"future"}"#.utf8)
            )
        }

        let malformedNestedSchema = Data(#"{"transcript":{"entries":[{"contents":[{"id":"text","text":"Prompt.","type":"text"}],"contextOptions":{},"id":"prompt","options":{},"responseFormat":{"jsonSchema":{"name":"Bad","schema":{"type":"future"}},"type":"jsonSchema"},"role":"user"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#.utf8)
        expectDataCorrupted("generation schema type is unsupported") {
            _ = try JSONDecoder().decode(WireTranscript.self, from: malformedNestedSchema)
        }

        let malformedArguments = Data(#"{"transcript":{"entries":[{"id":"calls","role":"response","toolCalls":[{"arguments":"not-json","id":"call","name":"lookup"}]}]},"type":"FoundationModels.Transcript","version":"1.1"}"#.utf8)
        expectDataCorrupted("transcript tool-call arguments must contain valid JSON") {
            _ = try JSONDecoder().decode(WireTranscript.self, from: malformedArguments)
        }
    }

    @Test func boundedSchemaGrammarRejectsIncompleteOrContradictoryForms() {
        let invalid: [(String, String)] = [
            (#"{"type":"array"}"#, "generation schema array requires items"),
            (#"{"additionalProperties":false,"properties":{},"required":[],"type":"object","x-order":[]}"#, "generation schema requires string title"),
            (#"{"properties":{},"required":[],"title":"Object","type":"object","x-order":[]}"#, "generation schema object requires boolean additionalProperties"),
            (#"{"additionalProperties":false,"properties":{},"title":"Object","type":"object","x-order":[]}"#, "generation schema requires string array required"),
            (#"{"additionalProperties":false,"properties":{},"required":[],"title":"Object","type":"object","x-order":["missing"]}"#, "generation schema x-order names a missing property"),
            (#"{"anyOf":[{"type":"string"}]}"#, "generation schema requires string title"),
            (#"{"anyOf":[],"title":"Any"}"#, "generation schema anyOf must be a nonempty array"),
            (#"{"minimum":0.5,"type":"integer"}"#, "generation schema minimum must be an integer"),
            (#"{"items":{"type":"string"},"minItems":"1","type":"array"}"#, "generation schema minItems must be an integer"),
            (#"{"title":"Named","type":"string"}"#, "named string generation schema requires enum"),
            (#"{"enum":[],"title":"Named","type":"string"}"#, "named string generation schema requires a nonempty enum"),
            (#"{"pattern":"[","type":"string"}"#, "generation schema pattern is invalid"),
            (#"{"enum":["a"],"pattern":1,"type":"string"}"#, "generation schema pattern must be a string"),
            (##"{"additionalProperties":false,"properties":{"a":{"$ref":"#/$defs/A"}},"required":["a"],"title":"Root","type":"object","x-order":["a"]}"##, "generation schema contains an undefined $ref"),
            (##"{"$defs":{"A":{"additionalProperties":false,"properties":{},"required":[],"title":"B","type":"object","x-order":[]}},"additionalProperties":false,"properties":{"a":{"$ref":"A"}},"required":["a"],"title":"Root","type":"object","x-order":["a"]}"##, "generation schema contains an undefined $ref"),
            (##"{"$defs":{"first":{"additionalProperties":false,"properties":{},"required":[],"title":"A","type":"object","x-order":[]},"second":{"anyOf":[{"type":"string"}],"title":"A"}},"additionalProperties":false,"properties":{"a":{"$ref":"A"}},"required":["a"],"title":"Root","type":"object","x-order":["a"]}"##, "generation schema contains a duplicate type"),
        ]
        for (source, description) in invalid {
            expectDataCorrupted(description) {
                _ = try JSONDecoder().decode(WireGenerationSchema.self, from: Data(source.utf8))
            }
        }
    }

    @Test func boundedSchemaGrammarCanonicalizesTypeSpecifically() throws {
        let cases: [(String, String)] = [
            (#"{"future":true,"minItems":1,"minLength":1,"type":"string"}"#, #"{"type":"string"}"#),
            (#"{"const":"fixed","title":"Ignored","type":"string"}"#, #"{"const":"fixed"}"#),
            (#"{"enum":["a","b"],"title":"Choice","type":"string"}"#, #"{"enum":["a","b"],"title":"Choice","type":"string"}"#),
            (#"{"enum":["a","a"],"type":"string"}"#, #"{"enum":["a","a"],"type":"string"}"#),
            (#"{"enum":[],"type":"string"}"#, #"{"enum":[],"type":"string"}"#),
            (#"{"enum":["a"],"pattern":"x","type":"string"}"#, #"{"enum":["a"],"pattern":"x","type":"string"}"#),
            (#"{"pattern":"^[a-z]+$","type":"string"}"#, #"{"pattern":"^[a-z]+$","type":"string"}"#),
            (#"{"minimum":1,"pattern":"ignored","title":"Ignored","type":"integer"}"#, #"{"minimum":1,"type":"integer"}"#),
            (#"{"maximum":3.5,"minimum":1,"type":"number"}"#, #"{"maximum":3.5,"minimum":1,"type":"number"}"#),
            (#"{"maximum":18446744073709551615,"type":"number"}"#, #"{"maximum":1.8446744073709552e+19,"type":"number"}"#),
            (#"{"minimum":-18446744073709551615,"type":"number"}"#, #"{"minimum":-1.8446744073709552e+19,"type":"number"}"#),
            (#"{"items":{"type":"string"},"maxItems":3,"minItems":1,"title":"Ignored","type":"array"}"#, #"{"items":{"type":"string"},"maxItems":3,"minItems":1,"type":"array"}"#),
            (#"{"additionalProperties":true,"properties":{"dropped":{"type":"integer"},"kept":{"type":"string"}},"required":["dropped","kept","missing"],"title":"Object","type":"object","x-order":["kept"]}"#, #"{"additionalProperties":false,"properties":{"kept":{"type":"string"}},"required":["kept"],"title":"Object","type":"object","x-order":["kept"]}"#),
            (#"{"additionalProperties":false,"properties":{"a":{"type":"string"},"b":{"type":"integer"}},"required":["b","a"],"title":"Object","type":"object","x-order":["a","b"]}"#, #"{"additionalProperties":false,"properties":{"a":{"type":"string"},"b":{"type":"integer"}},"required":["a","b"],"title":"Object","type":"object","x-order":["a","b"]}"#),
            (#"{"anyOf":[{"type":"string"},{"type":"integer"}],"description":"D","title":"Any","type":"boolean"}"#, #"{"anyOf":[{"type":"string"},{"type":"integer"}],"description":"D","title":"Any"}"#),
            (#"{"anyOf":[{"type":"string"},{"type":"string"}],"title":"Any"}"#, #"{"anyOf":[{"type":"string"},{"type":"string"}],"title":"Any"}"#),
            (#"{"description":"Root D","items":{"description":"Array D","items":{"description":"Item D","enum":["a"],"title":"Item","type":"string"},"type":"array"},"type":"array"}"#, #"{"items":{"items":{"enum":["a"],"type":"string"},"type":"array"},"type":"array"}"#),
            (#"{"anyOf":[{"description":"D","enum":["x"],"title":"Choice","type":"string"}],"title":"Root"}"#, #"{"anyOf":[{"enum":["x"],"type":"string"}],"title":"Root"}"#),
            (#"{"additionalProperties":false,"properties":{"x":{"description":"D","enum":["x"],"title":"Choice","type":"string"}},"required":["x"],"title":"Root","type":"object","x-order":["x"]}"#, #"{"additionalProperties":false,"properties":{"x":{"description":"D","enum":["x"],"type":"string"}},"required":["x"],"title":"Root","type":"object","x-order":["x"]}"#),
            (##"{"$defs":{"Child":{"additionalProperties":false,"properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"items":{"$ref":"Child","description":"D"},"type":"array"}"##, ##"{"$defs":{"Child":{"additionalProperties":false,"properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"items":{"$ref":"#/$defs/Child"},"type":"array"}"##),
            (##"{"$defs":{"Child":{"additionalProperties":false,"properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"anyOf":[{"$ref":"Child","description":"D"}],"title":"Root"}"##, ##"{"$defs":{"Child":{"additionalProperties":false,"properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"anyOf":[{"$ref":"#/$defs/Child"}],"title":"Root"}"##),
            (##"{"$defs":{"Child":{"additionalProperties":false,"properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"additionalProperties":false,"properties":{"x":{"$ref":"Child","description":"D"}},"required":["x"],"title":"Root","type":"object","x-order":["x"]}"##, ##"{"$defs":{"Child":{"additionalProperties":false,"properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"additionalProperties":false,"properties":{"x":{"$ref":"#/$defs/Child","description":"D"}},"required":["x"],"title":"Root","type":"object","x-order":["x"]}"##),
            (#"{"items":{"additionalProperties":false,"description":"Child D","properties":{},"required":[],"title":"Child","type":"object","x-order":[]},"type":"array"}"#, ##"{"$defs":{"Child":{"additionalProperties":false,"description":"Child D","properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"items":{"$ref":"#/$defs/Child"},"type":"array"}"##),
            (#"{"anyOf":[{"additionalProperties":false,"description":"Child D","properties":{},"required":[],"title":"Child","type":"object","x-order":[]}],"title":"Root"}"#, ##"{"$defs":{"Child":{"additionalProperties":false,"description":"Child D","properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"anyOf":[{"$ref":"#/$defs/Child"}],"title":"Root"}"##),
            (#"{"additionalProperties":false,"properties":{"object":{"additionalProperties":false,"description":"Object D","properties":{},"required":[],"title":"Nested","type":"object","x-order":[]},"string":{"description":"String D","type":"string"},"union":{"anyOf":[{"type":"string"}],"description":"Union D","title":"Union"}},"required":["object","string","union"],"title":"Root","type":"object","x-order":["object","string","union"]}"#, ##"{"$defs":{"Nested":{"additionalProperties":false,"description":"Object D","properties":{},"required":[],"title":"Nested","type":"object","x-order":[]},"Union":{"anyOf":[{"type":"string"}],"description":"Union D","title":"Union"}},"additionalProperties":false,"properties":{"object":{"$ref":"#/$defs/Nested","description":"Object D"},"string":{"description":"String D","type":"string"},"union":{"$ref":"#/$defs/Union","description":"Union D"}},"required":["object","string","union"],"title":"Root","type":"object","x-order":["object","string","union"]}"##),
            (#"{"$defs":{"A":{"type":"string"}},"type":"string"}"#, #"{"type":"string"}"#),
            (#"{"$defs":{"A":{"type":"future"}},"type":"string"}"#, #"{"type":"string"}"#),
            (#"{"$defs":1,"type":"string"}"#, #"{"type":"string"}"#),
            (##"{"additionalProperties":false,"properties":{"dropped":{"$ref":"#/$defs/A"},"kept":{"type":"string"}},"required":["dropped","kept"],"title":"Root","type":"object","x-order":["kept"]}"##, #"{"additionalProperties":false,"properties":{"kept":{"type":"string"}},"required":["kept"],"title":"Root","type":"object","x-order":["kept"]}"#),
            (#"{"additionalProperties":false,"properties":{"dropped":{"$ref":"external"},"kept":{"type":"string"}},"required":["dropped","kept"],"title":"Root","type":"object","x-order":["kept"]}"#, #"{"additionalProperties":false,"properties":{"kept":{"type":"string"}},"required":["kept"],"title":"Root","type":"object","x-order":["kept"]}"#),
            (##"{"$defs":{"raw-key":{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"title":"A","type":"object","x-order":["value"]}},"additionalProperties":false,"properties":{"a":{"$ref":"A"}},"required":["a"],"title":"Root","type":"object","x-order":["a"]}"##, ##"{"$defs":{"A":{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"title":"A","type":"object","x-order":["value"]}},"additionalProperties":false,"properties":{"a":{"$ref":"#/$defs/A"}},"required":["a"],"title":"Root","type":"object","x-order":["a"]}"##),
            (##"{"$defs":{"raw-key":{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"title":"B","type":"object","x-order":["value"]}},"additionalProperties":false,"properties":{"b":{"$ref":"B"}},"required":["b"],"title":"Root","type":"object","x-order":["b"]}"##, ##"{"$defs":{"B":{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"title":"B","type":"object","x-order":["value"]}},"additionalProperties":false,"properties":{"b":{"$ref":"#/$defs/B"}},"required":["b"],"title":"Root","type":"object","x-order":["b"]}"##),
            (##"{"$defs":{"A":{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"title":"A","type":"object","x-order":["value"]},"Unused":{"additionalProperties":false,"properties":{},"required":[],"title":"Unused","type":"object","x-order":[]}},"additionalProperties":false,"properties":{"a":{"$ref":"#/$defs/A"}},"required":["a"],"title":"Root","type":"object","x-order":["a"]}"##, ##"{"$defs":{"A":{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"title":"A","type":"object","x-order":["value"]}},"additionalProperties":false,"properties":{"a":{"$ref":"#/$defs/A"}},"required":["a"],"title":"Root","type":"object","x-order":["a"]}"##),
        ]
        for (source, expected) in cases {
            #expect(try canonicalSchemaJSON(source) == expected, Comment(rawValue: source))
        }
    }

    @Test func manyReachableDefinitionsResolveThroughTheIndexedBoundedPath() throws {
        let count = 512
        var definitions: [String: Any] = [:]
        for index in 0..<count {
            let name = "D\(index)"
            let property: [String: Any] = index + 1 == count
                ? ["type": "string"]
                : ["$ref": "D\(index + 1)"]
            definitions[name] = [
                "additionalProperties": false,
                "properties": ["next": property],
                "required": ["next"],
                "title": name,
                "type": "object",
                "x-order": ["next"],
            ]
        }
        let source: [String: Any] = [
            "$defs": definitions,
            "additionalProperties": false,
            "properties": ["root": ["$ref": "D0"]],
            "required": ["root"],
            "title": "Root",
            "type": "object",
            "x-order": ["root"],
        ]
        let data = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
        let schema = try JSONDecoder().decode(WireGenerationSchema.self, from: data)
        guard case .object(let object) = schema.jsonValue,
              case .object(let canonicalDefinitions)? = object["$defs"]
        else {
            Issue.record("expected the reachable definition table")
            return
        }
        #expect(canonicalDefinitions.count == count)
    }

    @Test func toolOutputIdentityCanonicalizesToTheToolCallID() throws {
        let source = Data(#"{"transcript":{"entries":[{"contents":[],"id":"entry-id","role":"tool","toolCallID":"call-id","toolName":"lookup"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#.utf8)
        let transcript = try JSONDecoder().decode(WireTranscript.self, from: source)
        guard case .toolOutput(let output) = transcript.entries.first else {
            Issue.record("expected a tool-output entry")
            return
        }
        #expect(output.id == "call-id")
        #expect(output.toolCallID == "call-id")

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        #expect(String(decoding: try encoder.encode(transcript), as: UTF8.self) == #"{"transcript":{"entries":[{"contents":[],"id":"call-id","role":"tool","toolCallID":"call-id","toolName":"lookup"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#)
    }

    @Test func responseMetadataDerivesAssetIDsAndOmitsEmptyMetadata() throws {
        let cases: [(String, String)] = [
            (#"{"transcript":{"entries":[{"assets":["a"],"contents":[],"id":"response","role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#, #"{"transcript":{"entries":[{"assets":["a"],"contents":[],"id":"response","metadata":{"assetIDs":["a"]},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#),
            (#"{"transcript":{"entries":[{"assets":["a"],"contents":[],"id":"response","metadata":{"assetIDs":["stale"],"foo":true},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#, #"{"transcript":{"entries":[{"assets":["a"],"contents":[],"id":"response","metadata":{"assetIDs":["a"],"foo":true},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#),
            (#"{"transcript":{"entries":[{"assets":[],"contents":[],"id":"response","role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#, #"{"transcript":{"entries":[{"contents":[],"id":"response","role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#),
            (#"{"transcript":{"entries":[{"assets":[],"contents":[],"id":"response","metadata":{"assetIDs":["stale"]},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#, #"{"transcript":{"entries":[{"assets":["stale"],"contents":[],"id":"response","metadata":{"assetIDs":["stale"]},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#),
            (#"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":["stale"]},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#, #"{"transcript":{"entries":[{"assets":["stale"],"contents":[],"id":"response","metadata":{"assetIDs":["stale"]},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#),
            (#"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":[],"foo":true},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#, #"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":[],"foo":true},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#),
            (#"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":"raw"},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#, #"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":"raw"},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#),
            (#"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":[1]},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#, #"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":[1]},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#),
            (#"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":null},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#, #"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":null},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#),
        ]
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        for (source, expected) in cases {
            let transcript = try JSONDecoder().decode(WireTranscript.self, from: Data(source.utf8))
            #expect(String(decoding: try encoder.encode(transcript), as: UTF8.self) == expected)
        }
    }

    @Test func responseFormatIdentityDerivesFromTheNormalizedSchema() throws {
        let cases: [(String, String, String?)] = [
            (#"{"description":"Inner D","enum":["x"],"title":"Inner","type":"string"}"#, "Inner", "Inner D"),
            (#"{"enum":["x"],"type":"string"}"#, "String", nil),
            (#"{"type":"integer"}"#, "Int", nil),
            (#"{"type":"number"}"#, "Double", nil),
            (#"{"type":"boolean"}"#, "Bool", nil),
            (#"{"type":"null"}"#, "Null", nil),
            (#"{"items":{"type":"string"},"type":"array"}"#, "Array<String>", nil),
            (#"{"items":{"enum":["x"],"title":"Choice","type":"string"},"type":"array"}"#, "Array<Choice>", nil),
            (#"{"const":"x"}"#, "x", nil),
        ]
        for (schemaSource, expectedName, expectedDescription) in cases {
            let schema = try JSONSerialization.jsonObject(with: Data(schemaSource.utf8))
            let source: [String: Any] = [
                "transcript": ["entries": [[
                    "contents": [],
                    "contextOptions": [:],
                    "id": "prompt",
                    "options": [:],
                    "responseFormat": [
                        "jsonSchema": [
                            "description": "Outer D",
                            "name": "Outer",
                            "schema": schema,
                        ],
                        "type": "jsonSchema",
                    ],
                    "role": "user",
                ]]],
                "type": "FoundationModels.Transcript",
                "version": "1.1",
            ]
            let data = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
            let transcript = try JSONDecoder().decode(WireTranscript.self, from: data)
            guard case .prompt(let prompt) = transcript.entries.first,
                  let responseFormat = prompt.responseFormat
            else {
                Issue.record("expected a prompt response format")
                continue
            }
            #expect(responseFormat.name == expectedName)
            #expect(responseFormat.description == expectedDescription)
        }
    }

    @Test func publicPortableMutationStillEncodesCanonicalSafeBytes() throws {
        let schema = try fixedSchema()
        var responseFormat = WireTranscript.ResponseFormat(
            name: "Outer",
            description: "Outer D",
            schema: schema
        )
        #expect(responseFormat.name == "Fixed")
        #expect(responseFormat.description == "Fixed object.")
        responseFormat.name = "Mutated"
        responseFormat.description = "Mutated D"

        var toolOutput = WireTranscript.ToolOutput(
            id: "entry-id",
            toolCallID: "call-id",
            toolName: "lookup",
            segments: []
        )
        #expect(toolOutput.id == "call-id")
        toolOutput.id = "mutated-id"

        var response = WireTranscript.Response(
            id: "response",
            assetIDs: ["a"],
            segments: [],
            metadata: ["assetIDs": .array([.string("stale")])]
        )
        response.metadata["assetIDs"] = .array([.string("mutated")])
        let transcript = WireTranscript(entries: [
            .prompt(.init(segments: [], responseFormat: responseFormat)),
            .toolOutput(toolOutput),
            .response(response),
        ])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = String(decoding: try encoder.encode(transcript), as: UTF8.self)
        #expect(encoded.contains(#""name":"Fixed""#))
        #expect(encoded.contains(#""description":"Fixed object.""#))
        #expect(encoded.contains(#""id":"call-id","role":"tool","toolCallID":"call-id""#))
        #expect(encoded.contains(#""assets":["a"]"#))
        #expect(encoded.contains(#""assetIDs":["a"]"#))

        let malformedArguments = WireTranscript(entries: [
            .toolCalls(.init(calls: [
                .init(id: "call", name: "lookup", argumentsJSON: "not-json"),
            ])),
        ])
        #expect(throws: EncodingError.self) {
            _ = try encoder.encode(malformedArguments)
        }
    }

    @Test func toolCallArgumentsAdmitEveryConfirmedGeneratedContentJSONShape() throws {
        for arguments in ["{}", "[]", "1", "1.25", "null", "true", #""text""#] {
            let source: [String: Any] = [
                "transcript": ["entries": [[
                    "id": "calls",
                    "role": "response",
                    "toolCalls": [[
                        "arguments": arguments,
                        "id": "call",
                        "name": "lookup",
                    ]],
                ]]],
                "type": "FoundationModels.Transcript",
                "version": "1.1",
            ]
            _ = try JSONDecoder().decode(
                WireTranscript.self,
                from: JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
            )
        }
    }
}
