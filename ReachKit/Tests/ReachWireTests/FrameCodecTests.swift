import Foundation
import FoundationModels
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

    @Test func unknownFrameTypeRejected() {
        var reassembler = FrameReassembler()
        var blob = Data()
        var length = UInt32(2).bigEndian
        withUnsafeBytes(of: &length) { blob.append(contentsOf: $0) }
        blob.append(255)
        blob.append(0x7B)
        #expect(throws: WireError.self) { _ = try reassembler.feed(blob) }
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
        #expect(back.versions == [Wire.version])
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
            port: 47337
        )
        #expect(try roundTrip(full) == full)

        // Older daemons omit the fields entirely; absent keys decode nil.
        let legacy = HelloAck(cluster: "studio", models: [])
        let decoded = try roundTrip(legacy)
        #expect(decoded == legacy)
        #expect(decoded.addrs == nil)
        #expect(decoded.port == nil)
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
