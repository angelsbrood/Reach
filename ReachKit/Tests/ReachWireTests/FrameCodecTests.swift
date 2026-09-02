import Foundation
#if canImport(FoundationModels)
import FoundationModels
#endif
import Testing
@testable import ReachWire

private func roundTrip<F: WireFrame>(_ frame: F) throws -> F {
    let encoded = try FrameCodec.encode(frame)
    var reassembler = FrameReassembler()
    let frames = try reassembler.feed(encoded)
    #expect(frames.count == 1)
    return try frames[0].decode(F.self)
}

@Suite struct EnvelopeTests {
    @Test func reassemblerHandlesByteDribble() throws {
        let encoded = try FrameCodec.encode(Ping(nonce: 7))
        var reassembler = FrameReassembler()
        var collected: [RawFrame] = []
        for byte in encoded {
            collected.append(contentsOf: try reassembler.feed(Data([byte])))
        }
        #expect(collected.count == 1)
        #expect(try collected[0].decode(Ping.self).nonce == 7)
    }

    @Test func reassemblerHandlesCoalescedFrames() throws {
        var blob = try FrameCodec.encode(Ping(nonce: 1))
        blob.append(try FrameCodec.encode(Pong(nonce: 2)))
        blob.append(try FrameCodec.encode(ErrorFrame(code: "x", message: "y")))
        var reassembler = FrameReassembler()
        let frames = try reassembler.feed(blob)
        #expect(frames.map(\.type) == [.ping, .pong, .errorFrame])
    }

    @Test func oversizeFrameRejected() {
        var reassembler = FrameReassembler()
        var header = Data()
        var length = UInt32(FrameCodec.maxFrameLength + 1).bigEndian
        withUnsafeBytes(of: &length) { header.append(contentsOf: $0) }
        header.append(FrameType.ping.rawValue)
        #expect(throws: WireError.self) { _ = try reassembler.feed(header) }
    }

    @Test func oversizeFrameRefusedBeforeSending() {
        let oversized = ErrorFrame(
            code: "oversized",
            message: String(repeating: "x", count: Int(FrameCodec.maxFrameLength))
        )
        do {
            _ = try FrameCodec.encode(oversized)
            Issue.record("an over-limit outgoing frame was encoded")
        } catch let WireError.frameTooLarge(length) {
            #expect(length > FrameCodec.maxFrameLength)
        } catch {
            Issue.record("unexpected outgoing-frame error: \(error)")
        }
    }

    @Test func unknownFrameTypeRejected() {
        var reassembler = FrameReassembler()
        var blob = Data()
        var length = UInt32(2).bigEndian
        withUnsafeBytes(of: &length) { blob.append(contentsOf: $0) }
        blob.append(255)
        blob.append(0x7B)
        do {
            _ = try reassembler.feed(blob)
            Issue.record("an unknown frame type was accepted")
        } catch {
            #expect("\(error)" == "frame type 255 is not in this protocol version's vocabulary")
        }
    }

    @Test func unknownOptionalJSONFieldIsIgnored() throws {
        let body = Data(#"{"client":"future-client","futureHint":true,"versions":[0]}"#.utf8)
        let raw = RawFrame(type: .hello, body: body)
        let decoded = try raw.decode(Hello.self)
        #expect(decoded.client == "future-client")
        #expect(decoded.versions == [0])
    }

    @Test func malformedBodyRejected() throws {
        var blob = Data()
        let body = Data("not json".utf8)
        var length = UInt32(1 + body.count).bigEndian
        withUnsafeBytes(of: &length) { blob.append(contentsOf: $0) }
        blob.append(FrameType.ping.rawValue)
        blob.append(body)
        var reassembler = FrameReassembler()
        let frames = try reassembler.feed(blob)
        #expect(frames.count == 1)
        #expect(throws: WireError.self) { _ = try frames[0].decode(Ping.self) }
    }

    @Test func mismatchedFrameTypeRejected() throws {
        let encoded = try FrameCodec.encode(Ping(nonce: 3))
        var reassembler = FrameReassembler()
        let frames = try reassembler.feed(encoded)
        #expect(throws: WireError.self) { _ = try frames[0].decode(Pong.self) }
    }
}

@Suite struct ControlFrameTests {
    @Test func helloRoundTrip() throws {
        let back = try roundTrip(Hello(client: "reachkit-test"))
        #expect(back.versions == Wire.supportedVersions)
        #expect(back.client == "reachkit-test")
    }

    @Test func helloAckRoundTrip() throws {
        let ack = HelloAck(
            cluster: "studio",
            models: [ModelDescriptor(id: "gemma-3-1b", displayName: "Gemma 3 1B", capabilities: [])]
        )
        let back = try roundTrip(ack)
        #expect(back == ack)
    }

    @Test func helloAckCarriesDialCandidates() throws {
        let full = HelloAck(
            cluster: "studio",
            models: [ModelDescriptor(id: "gemma-3-1b", displayName: "Gemma 3 1B", capabilities: [])],
            addrs: ["192.168.8.104", "10.86.0.1"],
            port: 47337,
            roads: [
                RoadEndpoint(host: "192.168.8.104", port: 47337),
                RoadEndpoint(host: "198.51.100.8", port: 55001),
            ]
        )
        #expect(try roundTrip(full) == full)

        // Older daemons omit the fields entirely; absent keys decode nil.
        let legacy = HelloAck(cluster: "studio", models: [])
        let decoded = try roundTrip(legacy)
        #expect(decoded == legacy)
        #expect(decoded.addrs == nil)
        #expect(decoded.port == nil)
        #expect(decoded.roads == nil)
        #expect(decoded.relayRoads == nil)
    }

    @Test func helloAckV0BytesStayCompatible() throws {
        let frame = HelloAck(
            version: 0,
            cluster: "studio",
            models: [],
            addrs: ["192.168.8.104"],
            port: 47_337,
            roads: [RoadEndpoint(host: "192.168.8.104", port: 47_337)],
            // A selected-v0 encoder has no relay vocabulary, even when a new
            // caller accidentally supplies the additive property.
            relayRoads: [RoadEndpoint(host: "10.87.0.1", port: 47_337)]
        )
        let encoded = try FrameCodec.encode(frame, for: 0)
        let body = try #require(String(data: encoded.dropFirst(5), encoding: .utf8))
        #expect(body == #"{"addrs":["192.168.8.104"],"cluster":"studio","models":[],"port":47337,"roads":[{"host":"192.168.8.104","port":47337}],"version":0}"#)

        // Likewise, a newly built v0 decoder treats the key as unknown rather
        // than letting its spelling alter or invalidate a v0 session.
        let ignored = try RawFrame(
            type: .helloAck,
            body: Data(#"{"cluster":"studio","models":[],"relayRoads":null,"version":0}"#.utf8)
        ).decode(HelloAck.self)
        #expect(ignored.relayRoads == nil)
    }

    @Test func helloAckRelayRoadsHaveThreeAuthorityStates() throws {
        let omitted = try RawFrame(
            type: .helloAck,
            body: Data(#"{"cluster":"studio","models":[],"version":1}"#.utf8)
        ).decode(HelloAck.self)
        #expect(omitted.relayRoads == nil)

        let cleared = try RawFrame(
            type: .helloAck,
            body: Data(#"{"cluster":"studio","models":[],"relayRoads":[],"version":1}"#.utf8)
        ).decode(HelloAck.self)
        #expect(cleared.relayRoads == [])

        let replaced = HelloAck(
            version: 1,
            cluster: "studio",
            models: [],
            relayRoads: [RoadEndpoint(host: "10.87.0.1", port: 47_337)]
        )
        #expect(try roundTrip(replaced) == replaced)
    }

    @Test func helloAckRelayRoadsRejectNullDuplicatesAndUnsafeEndpoints() throws {
        let invalidBodies = [
            #"{"cluster":"studio","models":[],"relayRoads":null,"version":1}"#,
            #"{"cluster":"studio","models":[],"relayRoads":[{"host":"10.87.0.1","port":47337},{"host":"10.87.0.1","port":47337}],"version":1}"#,
            #"{"cluster":"studio","models":[],"relayRoads":[{"host":"203.0.113.1","port":47337}],"version":1}"#,
            #"{"cluster":"studio","models":[],"relayRoads":[{"host":"010.87.0.1","port":47337}],"version":1}"#,
            #"{"cluster":"studio","models":[],"relayRoads":[{"host":"10.87.0.0","port":47337}],"version":1}"#,
            #"{"cluster":"studio","models":[],"relayRoads":[{"host":"10.87.0.255","port":47337}],"version":1}"#,
            #"{"cluster":"studio","models":[],"relayRoads":[{"host":"10.87.0.1","port":0}],"version":1}"#,
        ]
        for body in invalidBodies {
            #expect(throws: WireError.self) {
                _ = try RawFrame(type: .helloAck, body: Data(body.utf8)).decode(HelloAck.self)
            }
        }

        let future = try RawFrame(
            type: .helloAck,
            body: Data(#"{"cluster":"studio","futureRelayPolicy":"hedged","models":[],"version":1}"#.utf8)
        ).decode(HelloAck.self)
        #expect(future.cluster == "studio")
        #expect(future.relayRoads == nil)
    }

    /// `SessionResume`/`SessionResumed` were round-tripped here and nowhere
    /// else — this was their only exercise in the whole tree, and a codec test
    /// is not a client. They are deleted; their type bytes stay reserved.
    @Test func sessionFramesRoundTrip() throws {
        let opened = SessionOpened(sessionID: UUID(), token: "tok", capabilities: ["text"])
        #expect(try roundTrip(opened) == opened)
    }

    /// 5 and 6 belonged to the deleted resume frames and must not be handed to
    /// anything else: a v0 daemon still reads those bytes as a resume, so a
    /// reuse would be decoded as the wrong frame rather than refused as an
    /// unknown one. `FrameType` throws on unrecognized bytes, which is what
    /// makes reserving them safe and reusing them silent.
    @Test func theRetiredResumeTypeBytesStayRetired() {
        #expect(FrameType(rawValue: 5) == nil)
        #expect(FrameType(rawValue: 6) == nil)
    }

    @Test func grantFramesRoundTrip() throws {
        let event = GrantEvent(requestID: UUID(), deviceID: "d", bundleID: "b", displayName: "App", appKeyFingerprint: "f")
        #expect(try roundTrip(event) == event)
        let rule = GrantRule(requestID: UUID(), allow: true)
        #expect(try roundTrip(rule) == rule)
    }

    @Test func enrollFramesRoundTrip() throws {
        let begin = EnrollBegin(token: "token", deviceName: "phone")
        #expect(try roundTrip(begin) == begin)
        let challenge = EnrollChallenge(nonce: Data([0, 1]), version: 0)
        #expect(try roundTrip(challenge) == challenge)

        let legacyBegin = try RawFrame(
            type: .enrollBegin,
            body: Data(#"{"deviceName":"old phone","token":"old"}"#.utf8)
        ).decode(EnrollBegin.self)
        #expect(legacyBegin.versions == nil)
        #expect(Wire.offeredOrLegacy(legacyBegin.versions) == [0])

        let legacyChallenge = try RawFrame(
            type: .enrollChallenge,
            body: Data(#"{"nonce":"AA=="}"#.utf8)
        ).decode(EnrollChallenge.self)
        #expect(legacyChallenge.version == nil)
        #expect(Wire.selectedOrLegacy(legacyChallenge.version) == 0)

        let request = EnrollCertRequest(
            devicePubDER: Data([1, 2, 3]),
            wgPubKey: Data(repeating: 9, count: 32),
            popSig: Data([4, 5])
        )
        #expect(try roundTrip(request) == request)

        let grant = EnrollGrant(
            deviceCertDER: Data([6]),
            caCertDER: Data([7]),
            wg: WGProvision(
                assignedIP: "10.64.0.2",
                serverPublicKey: Data(repeating: 1, count: 32),
                endpoint: "203.0.113.7:51820",
                allowedIPs: ["10.64.0.1/32"],
                keepaliveSeconds: 25
            )
        )
        #expect(try roundTrip(grant) == grant)

        // The frame that ends the ceremony, and the one the keeper waits for
        // before it believes anything. Both values matter on the wire: false is
        // the ordinary re-pair, where the conf already named this key.
        for applyPending in [true, false] {
            let confirmed = EnrollConfirmed(applyPending: applyPending)
            #expect(try roundTrip(confirmed) == confirmed)
        }
    }

    @Test func appEnrollFramesRoundTrip() throws {
        let begin = AppEnrollBegin(bundleID: "systems.reach.example", displayName: "Example")
        #expect(try roundTrip(begin) == begin)

        let request = AppEnrollCertRequest(
            appPubX963: Data([4, 1, 2, 3]),
            popSig: Data([9, 9])
        )
        #expect(try roundTrip(request) == request)

        let grant = AppEnrollGrant(appCertDER: Data([6, 6]), caCertDER: Data([7]))
        #expect(try roundTrip(grant) == grant)
    }
}

@Suite struct EventFrameTests {
    @Test func allEventShapesRoundTrip() throws {
        let events: [WireEvent] = [
            .responseAppend(entryID: "e", text: "hi", segmentID: "s", tokenCount: 2),
            .responseReplace(entryID: nil, text: "swap", segmentID: nil, tokenCount: 1),
            .reasoningAppend(entryID: "r", text: "think", segmentID: nil, tokenCount: 3),
            .toolCallAppendArguments(entryID: "t", id: "call1", name: "search", content: "{", tokenCount: 1),
            .usage(inputTokens: 12, outputTokens: 34),
            .finished(.complete),
            .finished(.cancelled),
            .finished(.error("boom")),
        ]
        for (index, event) in events.enumerated() {
            let back = try roundTrip(Ev(seq: UInt64(index), event: event))
            #expect(back.event == event)
            #expect(back.seq == UInt64(index))
        }
    }
}

#if canImport(FoundationModels)
@Suite struct GenerationRequestTests {
    private func sampleTranscript() -> Transcript {
        let tool = Transcript.ToolDefinition(
            name: "lookup",
            description: "Looks a thing up.",
            parameters: GenerationSchema(
                type: GeneratedContent.self,
                properties: []
            )
        )
        let instructions = Transcript.Entry.instructions(
            Transcript.Instructions(
                id: "i1",
                segments: [.text(.init(id: "i1s1", content: "Be terse."))],
                toolDefinitions: [tool]
            )
        )
        let prompt = Transcript.Entry.prompt(
            Transcript.Prompt(
                id: "p1",
                segments: [.text(.init(id: "p1s1", content: "Name a river."))],
                options: GenerationOptions(temperature: 0.5)
            )
        )
        return Transcript(entries: [instructions, prompt])
    }

    private func validRequestObject() throws -> [String: Any] {
        let request = WireGenerationRequest(
            id: try #require(UUID(uuidString: "00000000-0000-0000-0000-000000000057")),
            transcript: sampleTranscript(),
            tools: [WireToolDefinition(
                name: "lookup",
                description: "Looks a thing up.",
                parameters: GenerationSchema(type: GeneratedContent.self, properties: [])
            )],
            schema: GenerationSchema(type: GeneratedContent.self, properties: [])
        )
        return try #require(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any]
        )
    }

    private func requestData(
        mutating mutation: (inout [String: Any]) throws -> Void
    ) throws -> Data {
        var object = try validRequestObject()
        try mutation(&object)
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private func expectRequestDataCorrupted(_ data: Data, _ label: String) {
        do {
            _ = try JSONDecoder().decode(WireGenerationRequest.self, from: data)
            Issue.record("\(label) unexpectedly crossed the Apple wire boundary")
        } catch DecodingError.dataCorrupted {
            // The corresponding Foundation Models native value rejected it.
        } catch {
            Issue.record("\(label) produced \(error), expected DecodingError.dataCorrupted")
        }
    }

    @Test func malformedNativeValuesFailDuringWholeRequestDecode() throws {
        let malformedSchema: [String: Any] = ["type": "future"]

        expectRequestDataCorrupted(try requestData { request in
            request["schema"] = malformedSchema
        }, "top-level response schema")

        expectRequestDataCorrupted(try requestData { request in
            request["tools"] = [[
                "description": "Looks a thing up.",
                "name": "lookup",
                "parameters": malformedSchema,
            ]]
        }, "enabled tool schema")

        expectRequestDataCorrupted(try requestData { request in
            request["transcript"] = [
                "transcript": ["entries": [[
                    "contents": [["id": "prompt-text", "text": "Prompt.", "type": "text"]],
                    "contextOptions": [:],
                    "id": "prompt",
                    "options": [:],
                    "responseFormat": [
                        "jsonSchema": ["name": "Bad", "schema": malformedSchema],
                        "type": "jsonSchema",
                    ],
                    "role": "user",
                ]]],
                "type": "FoundationModels.Transcript",
                "version": "1.1",
            ]
        }, "transcript response-format schema")

        expectRequestDataCorrupted(try requestData { request in
            request["transcript"] = [
                "transcript": ["entries": [[
                    "id": "tool-calls",
                    "role": "response",
                    "toolCalls": [[
                        "arguments": "not-json",
                        "id": "call",
                        "name": "lookup",
                    ]],
                ]]],
                "type": "FoundationModels.Transcript",
                "version": "1.1",
            ]
        }, "transcript tool-call arguments")
    }

    @Test func portableSchemaCanonicalizationMatchesTheCurrentNativeDecoder() throws {
        let sources = [
            #"{"future":true,"minItems":1,"minLength":1,"type":"string"}"#,
            #"{"const":"fixed","title":"Ignored","type":"string"}"#,
            #"{"enum":["a","b"],"title":"Choice","type":"string"}"#,
            #"{"enum":[],"type":"string"}"#,
            #"{"enum":["a"],"pattern":"x","type":"string"}"#,
            #"{"pattern":"^[a-z]+$","type":"string"}"#,
            #"{"minimum":1,"pattern":"ignored","title":"Ignored","type":"integer"}"#,
            #"{"maximum":3.5,"minimum":1,"type":"number"}"#,
            #"{"maximum":18446744073709551615,"type":"number"}"#,
            #"{"minimum":-18446744073709551615,"type":"number"}"#,
            #"{"items":{"type":"string"},"maxItems":3,"minItems":1,"title":"Ignored","type":"array"}"#,
            #"{"additionalProperties":true,"properties":{"dropped":{"type":"integer"},"kept":{"type":"string"}},"required":["dropped","kept","missing"],"title":"Object","type":"object","x-order":["kept"]}"#,
            #"{"additionalProperties":false,"properties":{"a":{"type":"string"},"b":{"type":"integer"}},"required":["b","a"],"title":"Object","type":"object","x-order":["a","b"]}"#,
            #"{"anyOf":[{"type":"string"},{"type":"integer"}],"description":"D","title":"Any","type":"boolean"}"#,
            #"{"description":"Root D","items":{"description":"Array D","items":{"description":"Item D","enum":["a"],"title":"Item","type":"string"},"type":"array"},"type":"array"}"#,
            #"{"anyOf":[{"description":"D","enum":["x"],"title":"Choice","type":"string"}],"title":"Root"}"#,
            #"{"additionalProperties":false,"properties":{"x":{"description":"D","enum":["x"],"title":"Choice","type":"string"}},"required":["x"],"title":"Root","type":"object","x-order":["x"]}"#,
            ##"{"$defs":{"Child":{"additionalProperties":false,"properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"items":{"$ref":"Child","description":"D"},"type":"array"}"##,
            ##"{"$defs":{"Child":{"additionalProperties":false,"properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"anyOf":[{"$ref":"Child","description":"D"}],"title":"Root"}"##,
            ##"{"$defs":{"Child":{"additionalProperties":false,"properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"additionalProperties":false,"properties":{"x":{"$ref":"Child","description":"D"}},"required":["x"],"title":"Root","type":"object","x-order":["x"]}"##,
            #"{"items":{"additionalProperties":false,"description":"Child D","properties":{},"required":[],"title":"Child","type":"object","x-order":[]},"type":"array"}"#,
            #"{"anyOf":[{"additionalProperties":false,"description":"Child D","properties":{},"required":[],"title":"Child","type":"object","x-order":[]}],"title":"Root"}"#,
            #"{"additionalProperties":false,"properties":{"object":{"additionalProperties":false,"description":"Object D","properties":{},"required":[],"title":"Nested","type":"object","x-order":[]},"string":{"description":"String D","type":"string"},"union":{"anyOf":[{"type":"string"}],"description":"Union D","title":"Union"}},"required":["object","string","union"],"title":"Root","type":"object","x-order":["object","string","union"]}"#,
            #"{"$defs":{"A":{"type":"string"}},"type":"string"}"#,
            #"{"$defs":{"A":{"type":"future"}},"type":"string"}"#,
            #"{"$defs":1,"type":"string"}"#,
            ##"{"additionalProperties":false,"properties":{"dropped":{"$ref":"#/$defs/A"},"kept":{"type":"string"}},"required":["dropped","kept"],"title":"Root","type":"object","x-order":["kept"]}"##,
            #"{"additionalProperties":false,"properties":{"dropped":{"$ref":"external"},"kept":{"type":"string"}},"required":["dropped","kept"],"title":"Root","type":"object","x-order":["kept"]}"#,
            ##"{"$defs":{"raw-key":{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"title":"A","type":"object","x-order":["value"]}},"additionalProperties":false,"properties":{"a":{"$ref":"A"}},"required":["a"],"title":"Root","type":"object","x-order":["a"]}"##,
            ##"{"$defs":{"raw-key":{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"title":"B","type":"object","x-order":["value"]}},"additionalProperties":false,"properties":{"b":{"$ref":"B"}},"required":["b"],"title":"Root","type":"object","x-order":["b"]}"##,
            ##"{"$defs":{"A":{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"title":"A","type":"object","x-order":["value"]},"Unused":{"additionalProperties":false,"properties":{},"required":[],"title":"Unused","type":"object","x-order":[]}},"additionalProperties":false,"properties":{"a":{"$ref":"#/$defs/A"}},"required":["a"],"title":"Root","type":"object","x-order":["a"]}"##,
        ]
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        for source in sources {
            let data = Data(source.utf8)
            let portable = try JSONDecoder().decode(WireGenerationSchema.self, from: data)
            let native = try JSONDecoder().decode(GenerationSchema.self, from: data)
            #expect(try encoder.encode(portable) == encoder.encode(native), Comment(rawValue: source))
        }
    }

    @Test func portableToolOutputIdentityMatchesTheCurrentNativeDecoder() throws {
        let source = Data(#"{"transcript":{"entries":[{"contents":[],"id":"entry-id","role":"tool","toolCallID":"call-id","toolName":"lookup"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#.utf8)
        let portable = try JSONDecoder().decode(WireTranscript.self, from: source)
        let native = try JSONDecoder().decode(Transcript.self, from: source)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        #expect(try encoder.encode(portable) == encoder.encode(native))
    }

    @Test func portableResponseMetadataMatchesTheCurrentNativeDecoder() throws {
        let sources = [
            #"{"transcript":{"entries":[{"assets":["a"],"contents":[],"id":"response","role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
            #"{"transcript":{"entries":[{"assets":["a"],"contents":[],"id":"response","metadata":{"assetIDs":["stale"],"foo":true},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
            #"{"transcript":{"entries":[{"assets":[],"contents":[],"id":"response","role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
            #"{"transcript":{"entries":[{"assets":[],"contents":[],"id":"response","metadata":{"assetIDs":["stale"]},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
            #"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":["stale"]},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
            #"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":[],"foo":true},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
            #"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":"raw"},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
            #"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":[1]},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
            #"{"transcript":{"entries":[{"contents":[],"id":"response","metadata":{"assetIDs":null},"role":"response"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
        ]
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        for source in sources {
            let data = Data(source.utf8)
            let portable = try JSONDecoder().decode(WireTranscript.self, from: data)
            let native = try JSONDecoder().decode(Transcript.self, from: data)
            #expect(try encoder.encode(portable) == encoder.encode(native), Comment(rawValue: source))
        }
    }

    @Test func portableResponseFormatIdentityMatchesTheCurrentNativeDecoder() throws {
        let sources = [
            #"{"transcript":{"entries":[{"contents":[],"contextOptions":{},"id":"prompt","options":{},"responseFormat":{"jsonSchema":{"description":"Outer D","name":"Outer","schema":{"description":"Inner D","enum":["x"],"title":"Inner","type":"string"}},"type":"jsonSchema"},"role":"user"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
            #"{"transcript":{"entries":[{"contents":[],"contextOptions":{},"id":"prompt","options":{},"responseFormat":{"jsonSchema":{"description":"Outer D","name":"Outer","schema":{"enum":["x"],"type":"string"}},"type":"jsonSchema"},"role":"user"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
            #"{"transcript":{"entries":[{"contents":[],"contextOptions":{},"id":"prompt","options":{},"responseFormat":{"jsonSchema":{"description":"Outer D","name":"Outer","schema":{"items":{"enum":["x"],"title":"Choice","type":"string"},"type":"array"}},"type":"jsonSchema"},"role":"user"}]},"type":"FoundationModels.Transcript","version":"1.1"}"#,
        ]
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        for source in sources {
            let data = Data(source.utf8)
            let portable = try JSONDecoder().decode(WireTranscript.self, from: data)
            let native = try JSONDecoder().decode(Transcript.self, from: data)
            #expect(try encoder.encode(portable) == encoder.encode(native), Comment(rawValue: source))
        }
    }

    @Test func deferredNativeConstructionRetainsASafeNativeReadPath() throws {
        let nativeSchema = GenerationSchema(type: GeneratedContent.self, properties: [])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let schemaJSON = try encoder.encode(nativeSchema)
        let deferredSchema = WireGenerationSchema(
            deferredEncodingError: "forced portable conversion failure",
            nativeJSON: schemaJSON
        )
        let tool = WireToolDefinition(
            name: "lookup",
            description: "Looks a thing up.",
            portableParameters: deferredSchema
        )
        #expect(try encoder.encode(tool.parameters) == schemaJSON)
        #expect(throws: WirePortableValueError.self) {
            _ = try JSONEncoder().encode(tool)
        }

        let nativeTranscript = sampleTranscript()
        let transcriptJSON = try JSONEncoder().encode(nativeTranscript)
        let deferredTranscript = WireTranscript(
            deferredEncodingError: "forced portable conversion failure",
            nativeJSON: transcriptJSON
        )
        let request = WireGenerationRequest(
            id: UUID(),
            portableTranscript: deferredTranscript
        )
        #expect(request.transcript == nativeTranscript)
        #expect(throws: WirePortableValueError.self) {
            _ = try JSONEncoder().encode(request)
        }
    }

    @Test func transcriptSurvivesTheWireByteIdentically() throws {
        let transcript = sampleTranscript()
        let request = WireGenerationRequest(
            id: UUID(),
            transcript: transcript,
            tools: [WireToolDefinition(name: "lookup", description: "d", parameters: GenerationSchema(type: GeneratedContent.self, properties: []))],
            options: WireGenerationOptions(temperature: 0.5, maximumResponseTokens: 80, sampling: .greedy),
            context: WireContextOptions(includeSchemaInPrompt: true, reasoning: .moderate)
        )
        let begin = GenerateBegin(sessionID: UUID(), genID: UUID(), request: request)

        let firstEncode = try FrameCodec.encode(begin)
        var reassembler = FrameReassembler()
        let decoded = try reassembler.feed(firstEncode)[0].decode(GenerateBegin.self)

        #expect(decoded.request.transcript == transcript)

        // Determinism: sorted-keys JSON means re-encoding the decoded frame
        // reproduces the bytes exactly.
        let secondEncode = try FrameCodec.encode(decoded)
        #expect(firstEncode == secondEncode)
    }

    @Test func optionsMirrorRoundTripsThroughNative() throws {
        let wire = WireGenerationOptions(
            temperature: 0.7,
            maximumResponseTokens: 42,
            sampling: .topK(40, seed: 7),
            toolCalling: .allowed
        )
        let native = wire.native()
        #expect(native.temperature == 0.7)
        #expect(native.maximumResponseTokens == 42)
        #expect(native.toolCallingMode == .allowed)

        let back = WireGenerationOptions(native)
        #expect(back.temperature == 0.7)
        #expect(back.maximumResponseTokens == 42)
        #expect(back.toolCalling == .allowed)
        // Documented v0 limitation: non-greedy sampling has no public read
        // path off GenerationOptions, so it does not survive the return trip.
        #expect(back.sampling == nil)
    }

    @Test func greedySamplingSurvivesTheReadPath() {
        let native = GenerationOptions(samplingMode: .greedy)
        #expect(WireGenerationOptions(native).sampling == .greedy)
    }

    @Test func contextMirrorRoundTrips() {
        let native = ContextOptions(includeSchemaInPrompt: false, reasoningLevel: .custom("careful"))
        let wire = WireContextOptions(native)
        #expect(wire.includeSchemaInPrompt == false)
        #expect(wire.reasoning == .custom("careful"))
        let nativeAgain = wire.native()
        #expect(nativeAgain == native)
    }
}
#endif
