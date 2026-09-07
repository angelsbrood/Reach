import Foundation
import Testing
@testable import ReachWire

/// Exactly this source runs against committed S86 and the candidate. No new-band
/// types are referenced. Artifacts are deterministic synthetic codec fixtures.
@Suite struct LegacyWireCompatibilityTests {
    @Test func committedBaselineComparisonCorpus() throws {
        var rows: [String: String] = [:]
        let uuid = UUID(uuidString: "00000000-0000-0000-0000-000000000087")!
        let bytes = Data([0, 255, 254, 127, 47])
        let schema = try WireGenerationSchema(jsonValue: .object([
            "title": .string("Synthetic"), "type": .string("object"),
            "properties": .object(["text": .object(["type": .string("string")])]),
            "required": .array([.string("text")]), "x-order": .array([.string("text")]), "additionalProperties": .bool(false)
        ]))
        let request = WireGenerationRequest(id: uuid, portableTranscript: .init(entries: [
            .prompt(.init(id: "prompt", segments: [.text(.init(id: "text", content: "synthetic / é e\u{301}"))]))
        ]), tools: [.init(name: "lookup", description: "synthetic", portableParameters: schema)], portableSchema: schema)

        func raw(_ type: UInt8, _ body: Data) throws -> RawFrame {
            var wire = Data(); var length = UInt32(body.count + 1).bigEndian
            withUnsafeBytes(of: &length) { wire.append(contentsOf: $0) }
            wire.append(type); wire.append(body)
            var reassembler = FrameReassembler()
            return try #require(reassembler.feed(wire).first)
        }
        func add<F: WireFrame>(_ name: String, _ frame: F) throws {
            for version: UInt8 in [0, 1] {
                let encoded = try FrameCodec.encode(frame, for: version)
                let decoded = try raw(F.frameType.rawValue, Data(encoded.dropFirst(5)))
                try decoded.requireSupported(by: version)
                #expect(try FrameCodec.encode(decoded.decode(F.self), for: version) == encoded)
                rows["valid/\(name)/v\(version)"] = encoded.base64EncodedString()
                var object = try #require(JSONSerialization.jsonObject(with: decoded.body) as? [String: Any])
                object["futureOptional"] = ["synthetic": true]
                let additive = try raw(F.frameType.rawValue, JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
                let reencoded = try FrameCodec.encode(additive.decode(F.self), for: version)
                #expect(reencoded == encoded)
                rows["additive/\(name)/v\(version)"] = reencoded.base64EncodedString()
            }
        }
        func invalid(_ name: String, expecting expected: String? = nil, _ operation: () throws -> Void) {
            do { try operation(); Issue.record("invalid fixture accepted: \(name)"); rows["invalid/\(name)"] = "ACCEPTED" }
            catch WireError.unknownFrameType { rows["invalid/\(name)"] = "unknown-frame-type" }
            catch WireError.malformedFrame { rows["invalid/\(name)"] = "malformed-frame" }
            catch WireError.frameTooLarge { rows["invalid/\(name)"] = "frame-too-large" }
            catch { rows["invalid/\(name)"] = String(reflecting: type(of: error)) }
            if let expected { #expect(rows["invalid/\(name)"] == expected) }
        }
        try add("hello", Hello(versions: [1,0], client: "synthetic/fixture"))
        try add("helloAck", HelloAck(version: 1, cluster: "synthetic", models: [.init(id: "fixture", displayName: "Fixture", capabilities: [])]))
        try add("sessionOpen", SessionOpen(modelID: "fixture"))
        try add("sessionOpened", SessionOpened(sessionID: uuid, token: "synthetic/token", capabilities: ["portable"]))
        try add("ping", Ping(nonce: .max)); try add("pong", Pong(nonce: 0))
        try add("error", ErrorFrame(code: "synthetic", message: "message / ü"))
        try add("grantSubscribe", GrantSubscribe())
        try add("grantEvent", GrantEvent(requestID: uuid, deviceID: "synthetic", bundleID: "fixture", displayName: "Fixture", appKeyFingerprint: "not-a-key"))
        try add("grantRule", GrantRule(requestID: uuid, allow: false))
        try add("generateBegin", GenerateBegin(sessionID: uuid, genID: uuid, request: request))
        try add("generateReattach", GenerateReattach(sessionID: uuid, token: "synthetic", genID: uuid, fromSeq: 0))
        try add("generateCancel", GenerateCancel(genID: uuid))
        try add("evAck", EvAck(seq: 0))
        try add("ev", Ev(seq: 0, event: .responseAppend(entryID: "e", text: "a/b", segmentID: "s", tokenCount: 1)))
        try add("enrollBegin", EnrollBegin(token: "synthetic", deviceName: "fixture"))
        try add("enrollChallenge", EnrollChallenge(nonce: bytes, version: 1))
        try add("enrollCertRequest", EnrollCertRequest(devicePubDER: bytes, wgPubKey: bytes, popSig: bytes))
        try add("enrollGrant", EnrollGrant(deviceCertDER: bytes, caCertDER: bytes, wg: .init(assignedIP: "10.0.0.1", serverPublicKey: bytes, endpoint: "fixture.invalid:123", allowedIPs: ["10.0.0.0/24"], keepaliveSeconds: 25)))
        try add("enrollComplete", EnrollComplete(ok: false))
        try add("enrollConfirmed", EnrollConfirmed(applyPending: true))
        try add("appEnrollBegin", AppEnrollBegin(bundleID: "fixture", displayName: "Fixture"))
        try add("appEnrollCertRequest", AppEnrollCertRequest(appPubX963: bytes, popSig: bytes))
        try add("appEnrollGrant", AppEnrollGrant(appCertDER: bytes, caCertDER: bytes))
        #expect(rows.keys.filter { $0.hasPrefix("valid/") }.count == 48)

        let events: [WireEvent] = [
            .responseReplace(entryID: nil, text: "text", segmentID: nil, tokenCount: 1),
            .reasoningAppend(entryID: nil, text: "reason", segmentID: nil, tokenCount: 0),
            .toolCallAppendArguments(entryID: "entry", id: "call", name: "lookup", content: "{\"path\":\"/a\"}", tokenCount: 2),
            .usage(inputTokens: 1, outputTokens: 2), .finished(.complete), .finished(.cancelled), .finished(.error("synthetic"))
        ]
        for (i, event) in events.enumerated() { try add("event-\(i)", Ev(seq: UInt64(i), event: event)) }
        let roads = [RoadEndpoint(host: "10.1.2.3", port: 1234)]
        for version: UInt8 in [0, 1] {
            for (label, relay) in [("omitted", Optional<[RoadEndpoint]>.none), ("empty", []), ("replace", roads)] {
                try add("relay-selected-\(version)-\(label)", HelloAck(version: version, cluster: "fixture", models: [], relayRoads: relay))
            }
        }
        for (name, field) in [
            ("null", "null"), ("wrong-type", "true"),
            ("duplicate", "[{\"host\":\"10.1.2.3\",\"port\":1234},{\"host\":\"10.1.2.3\",\"port\":1234}]"),
            ("public", "[{\"host\":\"8.8.8.8\",\"port\":1234}]"),
            ("zero-port", "[{\"host\":\"10.1.2.3\",\"port\":0}]"),
            ("noncanonical", "[{\"host\":\"010.1.2.3\",\"port\":1234}]"),
            ("broadcast", "[{\"host\":\"10.1.2.255\",\"port\":1234}]")
        ] {
            let body = "{\"version\":1,\"cluster\":\"fixture\",\"models\":[],\"relayRoads\":\(field)}"
            invalid("relay-\(name)") { _ = try raw(2, Data(body.utf8)).decode(HelloAck.self) }
            let legacy = body.replacingOccurrences(of: "\"version\":1", with: "\"version\":0")
            let decoded: HelloAck = try raw(2, Data(legacy.utf8)).decode()
            #expect(decoded.relayRoads == nil)
            rows["ignored-v0/relay-\(name)"] = try FrameCodec.encode(decoded).base64EncodedString()
        }
        for type: UInt8 in [5, 6, 49, 255] { invalid("type-\(type)") { _ = try raw(type, Data("{}".utf8)) } }
        for (name, body) in [("missing", "{}"), ("null", "{\"nonce\":null}"), ("overflow", "{\"nonce\":18446744073709551616}"), ("negative", "{\"nonce\":-1}"), ("malformed", "{")] {
            invalid("ping-\(name)", expecting: "malformed-frame") {
                _ = try raw(Ping.frameType.rawValue, Data(body.utf8)).decode(Ping.self)
            }
        }
        for version: UInt8 in [0,1] {
            invalid("encode-invalid-relay-v\(version)") {
                _ = try FrameCodec.encode(HelloAck(version: 1, cluster: "fixture", models: [], relayRoads: [RoadEndpoint(host: "8.8.8.8", port: 123)]), for: version)
            }
        }
        #expect(Wire.supportedVersions == [1,0])
        #expect(Wire.offeredOrLegacy(nil) == [0])
        #expect(Wire.selectedOrLegacy(nil) == 0)
        if let path = ProcessInfo.processInfo.environment["S87_LEGACY_OUTPUT"] {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            try encoder.encode(rows).write(to: URL(fileURLWithPath: path), options: .atomic)
        }
    }
}
