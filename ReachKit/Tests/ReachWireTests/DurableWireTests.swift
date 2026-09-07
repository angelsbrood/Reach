import Foundation
import Testing
@testable import ReachWire

/// All acceptances, tickets and contexts below are SYNTHETIC. No store, caller,
/// MAC, remote clock or actual tool outcome is authenticated by these fixtures.
@Suite(.serialized) struct DurableWireTests {
    private let model = "synthetic/model"
    private let root = "00000000-0000-0000-0000-000000000084"
    private let digest = String(repeating: "a", count: 64)
    private var session: DurableSessionReference { .init(modelID: model, profile: DurableWire.profile, sessionID: "00000000-0000-0000-0000-000000000087") }
    private var reference: DurableGenerationReference { .init(session: session, generationID: "generation", operationID: "original-operation") }
    private var ticket: Data { Data((0..<41).map(UInt8.init)) }
    // Deliberately not JSON: interiors must never be decoded/re-encoded by wire.
    private var context: Data { Data([255, 0, 47, 254, 32, 10]) }
    // Predetermined synthetic spelling, intentionally not a hash of `context`.
    private var contextDigest: String { String(repeating: "b", count: 64) }
    private var witness: DurableWitness { .init(context: contextDigest, clientRoot: root, revision: 0, high: 0, terminal: false, prefix: digest, registrations: 0, calls: digest) }
    private var request: WireGenerationRequest { .init(id: UUID(uuidString: "00000000-0000-0000-0000-000000000087")!, portableTranscript: .init(entries: [])) }
    private var caps: DurableMessage { .capabilities(.init(.init(modelID: model, profiles: [DurableWire.profile]))) }
    private var open: DurableMessage { .open(.init(.init(requestID: "open", modelID: model, profile: DurableWire.profile, durable: true))) }
    private var opened: DurableMessage { .opened(.init(.init(requestID: "open", session: session, ticket: ticket))) }
    private var begin: DurableMessage { .begin(.init(.init(requestID: "begin", reference: reference, ticket: ticket, request: request))) }
    private var accepted: DurableMessage { .accepted(.init(.init(requestID: "begin", reference: reference, kind: .begin, context: context, contextDigest: contextDigest))) }
    private var recover: DurableMessage { .recover(.init(.init(requestID: "recover", reference: reference, ticket: ticket, context: context, contextDigest: contextDigest, clientRoot: root, witness: witness))) }
    private var recovered: DurableMessage { .accepted(.init(.init(requestID: "recover", reference: reference, kind: .recover, context: context, contextDigest: contextDigest))) }
    private var batch: DurableMessage { .batch(.init(.init(reference: reference, contextDigest: contextDigest, first: 1, count: 2, commit: digest, skip: 1, bytes: Data([255,0,1,2])))) }
    private var receipt: DurableMessage { .receipt(.init(.init(requestID: "receipt", reference: reference, witness: witness))) }
    private var receiptAccepted: DurableMessage { .receiptAccepted(.init(.init(requestID: "receipt", reference: reference, witness: witness))) }
    private var knowledge: DurableMessage { .knowledge(.init(.init(reference: reference, contextDigest: contextDigest, callID: Data("é".utf8), name: Data("lookup".utf8), arguments: Data("{ \"a\" : 1 }".utf8), state: .unknown, outcome: nil))) }
    private var refused: DurableMessage { .refused(.init(.init(correlation: .init(requestID: "open", operation: .open), reason: .unavailable))) }
    private var all: [DurableMessage] { [caps, open, opened, begin, accepted, recover, batch, receipt, receiptAccepted, knowledge, refused] }

    private func raw(_ message: DurableMessage) throws -> RawFrame {
        var reassembler = FrameReassembler()
        return try #require(reassembler.feed(message.encode(version: 2)).first)
    }
    private func expectRefusal(_ operation: () throws -> Void) {
        #expect(throws: (any Error).self, performing: operation)
    }
    private func selected() throws -> DurableNegotiation {
        var state = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: true)
        _ = try state.receive(raw(caps)); _ = try state.send(open); _ = try state.receive(raw(opened))
        #expect(state.phase == .selected)
        return state
    }
    private func active() throws -> DurableNegotiation {
        var state = try selected()
        _ = try state.send(begin); _ = try state.receive(raw(accepted))
        #expect(state.phase == .accepted)
        return state
    }
    private func altered(_ message: DurableMessage, _ change: (inout [String: Any]) -> Void) throws -> RawFrame {
        let original = try raw(message)
        var object = try #require(JSONSerialization.jsonObject(with: original.body) as? [String: Any])
        change(&object)
        return RawFrame(type: original.type, body: try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]))
    }
    private func checkInvalid<P: DurablePayload>(_ value: DurablePacket<P>) throws {
        expectRefusal { _ = try FrameCodec.encode(value, for: 2) }
        // Components are plain Codable data; only complete frame packets are
        // validated. This deliberately bypasses packet encoding to feed hostile
        // bytes to the actual receive decoder, without a second wire codec.
        let body = try DurableWire.canonical(value.payload)
        expectRefusal { _ = try DurableMessage.decode(RawFrame(type: P.frameType, body: body), version: 2) }
    }

    @Test func freshDeclaredRecoveryRemainsPendingUntilExactReply() throws {
        var state = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: true)
        _ = try state.receive(raw(caps))
        _ = try state.send(recover)
        #expect(state.phase == .recovering)
        expectRefusal { _ = try state.receive(raw(caps)) }
        expectRefusal { _ = try state.send(open) }
        expectRefusal { _ = try state.send(recover) }
        expectRefusal { _ = try state.receive(raw(opened)) }
        expectRefusal { _ = try state.receive(raw(accepted)) }
        expectRefusal { _ = try state.receive(altered(recovered) { $0["contextDigest"] = digest }) }
        expectRefusal { _ = try state.receive(altered(recovered) { $0["context"] = Data("changed".utf8).base64EncodedString() }) }
        #expect(state.phase == .recovering)
        _ = try state.receive(raw(recovered))
        #expect(state.phase == .accepted)
        var changed = try raw(recover).decode(DurableGenerateRecover.self)
        changed.payload.ticket[0] ^= 1
        expectRefusal { _ = try state.send(.recover(changed)) }
        changed = try raw(recover).decode(); changed.payload.reference.session.sessionID = root
        expectRefusal { _ = try state.send(.recover(changed)) }
        _ = try state.send(recover); _ = try state.receive(raw(recovered))
        _ = try state.receive(raw(batch))
    }

    @Test func freshRecoveryRequiresLocalDeclarationAndExactSelection() throws {
        for optIn in [false, true] {
            for declared in [false, true] {
                var state = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: optIn)
                if declared { _ = try state.receive(raw(caps)) }
                if optIn && declared { _ = try state.send(recover) }
                else { expectRefusal { _ = try state.send(recover) } }
            }
        }
        for profiles in [[], ["other-profile"]] {
            var state = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: true)
            _ = try state.receive(raw(.capabilities(.init(.init(modelID: model, profiles: profiles)))))
            expectRefusal { _ = try state.send(recover) }
        }
        for field in ["modelID", "profile"] {
            var state = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: true)
            _ = try state.receive(raw(caps))
            var request = try raw(recover).decode(DurableGenerateRecover.self)
            if field == "modelID" { request.payload.reference.session.modelID = "other" }
            else { request.payload.reference.session.profile = "other" }
            expectRefusal { _ = try state.send(.recover(request)) }
        }
    }

    @Test func defaultsAndExplicitSyntheticOffer() throws {
        #expect(Wire.version == 1 && Wire.supportedVersions == [1,0])
        #expect(Wire.baselineVersion == 0)
        #expect(Wire.negotiate(offered: [2,1,0]) == 1)
        #expect(Wire.negotiate(offered: [2,1,0], supported: [2,1,0]) == 2)
        #expect(Wire.negotiate(offered: [2]) == nil)
        #expect(Wire.offeredOrLegacy(nil) == [0])
        #expect(Wire.selectedOrLegacy(nil) == 0)
        #expect(Hello(client: "fixture").versions == [1,0])
        #expect(EnrollBegin(token: "synthetic", deviceName: "fixture").versions == [1,0])
        #expect(AppEnrollBegin(bundleID: "fixture", displayName: "fixture").versions == [1,0])
    }

    @Test func allElevenDefaultOldVersionAndMalformedReceiveGates() throws {
        #expect(all.map(\.frameType.rawValue) == Array(UInt8(50)...UInt8(60)))
        for message in all {
            expectRefusal { _ = try message.encode() }
            expectRefusal { _ = try DurableMessage.decode(raw(message)) }
            for version: UInt8 in [0,1] {
                expectRefusal { _ = try message.encode(version: version) }
                var state = try DurableNegotiation(selectedDialect: version, modelID: model, localOptIn: true)
                for body in [Data("{".utf8), Data(repeating: 0, count: DurableWire.controlLimit+1)] {
                    do {
                        _ = try state.receive(RawFrame(type: message.frameType, body: body))
                        Issue.record("old dialect dispatched a durable body")
                    } catch WireError.frameRequiresVersion(let type, let introduced, let negotiated) {
                        #expect(type == message.frameType && introduced == 2 && negotiated == version)
                    } catch { Issue.record("body decoded before gate: \(error)") }
                }
                #expect(state.phase == .volatile)
            }
        }
    }

    @Test func allElevenCodecDribbleCoalescedAndAdditiveKeys() throws {
        let blob = try all.reduce(into: Data()) { $0.append(try $1.encode(version: 2)) }
        var dribble = FrameReassembler(), coalesced = FrameReassembler()
        var pieces: [RawFrame] = []
        for byte in blob { pieces += try dribble.feed(Data([byte])) }
        let together = try coalesced.feed(blob)
        #expect(pieces.map(\.type) == all.map(\.frameType))
        #expect(together.map(\.body) == pieces.map(\.body))
        for (i, message) in all.enumerated() {
            #expect(try DurableMessage.decode(pieces[i], version: 2).encode(version: 2) == message.encode(version: 2))
            let extended = try altered(message) { $0["futureOptional"] = ["ignored": true] }
            #expect(try DurableMessage.decode(extended, version: 2).encode(version: 2) == message.encode(version: 2))
        }
    }

    @Test func syntheticPhasesPreserveOriginalBytesAndWitness() throws {
        var state = try active()
        guard case .batch(let b) = try state.receive(raw(batch)) else { Issue.record("wrong frame"); return }
        #expect(b.payload.skip == 1 && b.payload.bytes == Data([255,0,1,2]))
        _ = try state.send(receipt)
        _ = try state.receive(raw(receiptAccepted))
        _ = try state.send(knowledge); _ = try state.receive(raw(knowledge))
        _ = try state.send(recover)
        #expect(state.phase == .recovering)
        guard case .accepted(let result) = try state.receive(raw(recovered)) else { Issue.record("wrong frame"); return }
        #expect(result.payload.context == context)
        #expect(try raw(opened).decode(DurableSessionOpened.self).payload.ticket == ticket)
        #expect(state.phase == .accepted)
        // Fresh explicit recovery starts from a correlated selected session, never begin.
        var fresh = try selected()
        _ = try fresh.send(recover); _ = try fresh.receive(raw(recovered))
        #expect(fresh.phase == .accepted)
    }

    @Test func unavailableDisabledUnknownModelAndVolatileRemainUnaccepted() throws {
        for optIn in [false,true] {
            for profiles in [[], ["future-unknown-profile"], [DurableWire.profile]] {
                var state = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: optIn)
                let declaration = DurableMessage.capabilities(.init(.init(modelID: model, profiles: profiles)))
                _ = try state.receive(raw(declaration))
                expectRefusal { _ = try state.send(begin) }
                if optIn && profiles == [DurableWire.profile] { _ = try state.send(open) }
                else { expectRefusal { _ = try state.send(open) }; #expect(state.phase == .declared) }
                expectRefusal { _ = try state.receive(raw(accepted)) }
            }
        }
        var missing = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: true)
        expectRefusal { _ = try missing.send(open) }
        expectRefusal { _ = try missing.receive(altered(caps) { $0["modelID"] = "other" }) }
        _ = try missing.receive(raw(caps))
        expectRefusal { _ = try missing.send(.open(.init(.init(requestID: "open", modelID: model, profile: "other", durable: true)))) }
        expectRefusal { _ = try missing.send(.open(.init(.init(requestID: "open", modelID: "other", profile: DurableWire.profile, durable: true)))) }
        var state = try active()
        state.observeVolatileOpen(SessionOpen(modelID: model))
        #expect(state.phase == .volatile)
        expectRefusal { _ = try state.send(begin) }; expectRefusal { _ = try state.send(recover) }
        expectRefusal { _ = try state.receive(raw(batch)) }
    }

    @Test func staleMismatchedAcceptanceAndDirectionNeverSelect() throws {
        var state = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: true)
        expectRefusal { _ = try state.receive(raw(opened)) }
        expectRefusal { _ = try state.send(caps) }
        _ = try state.receive(raw(caps)); _ = try state.send(open)
        expectRefusal { _ = try state.send(opened) }
        expectRefusal { _ = try state.receive(altered(opened) { $0["requestID"] = "stale" }) }
        for field in ["modelID", "profile"] {
            expectRefusal { _ = try state.receive(altered(opened) { var s = $0["session"] as! [String: Any]; s[field] = "other"; $0["session"] = s }) }
        }
        #expect(state.phase == .opening)
        _ = try state.receive(raw(opened)); _ = try state.send(begin)
        expectRefusal { _ = try state.receive(raw(batch)) }
        for field in ["requestID", "kind"] {
            expectRefusal { _ = try state.receive(altered(accepted) { $0[field] = field == "kind" ? "recover" : "stale" }) }
        }
        for field in ["generationID", "operationID"] {
            expectRefusal { _ = try state.receive(altered(accepted) { var r = $0["reference"] as! [String: Any]; r[field] = "other"; $0["reference"] = r }) }
        }
        #expect(state.phase == .beginning)
        _ = try state.receive(raw(accepted))
        expectRefusal { _ = try state.receive(raw(accepted)) }
        expectRefusal { _ = try state.send(begin) }
        _ = try state.send(recover)
        expectRefusal { _ = try state.receive(raw(accepted)) }
        let changed = Data("changed opaque context".utf8)
        expectRefusal { _ = try state.receive(altered(recovered) { $0["context"] = changed.base64EncodedString() }) }
        expectRefusal { _ = try state.receive(altered(recovered) { $0["contextDigest"] = digest }) }
        #expect(state.phase == .recovering)
        _ = try state.receive(raw(recovered))
    }

    @Test func recoveryAndReceiptBindingsFailWithoutMutationOrFallback() throws {
        var state = try active()
        var r = try raw(recover).decode(DurableGenerateRecover.self)
        r.payload.ticket[0] ^= 1
        expectRefusal { _ = try state.send(.recover(r)) }
        r = try raw(recover).decode(); r.payload.reference.operationID = "different"
        expectRefusal { _ = try state.send(.recover(r)) }
        _ = try state.send(receipt)
        expectRefusal { _ = try state.send(recover) }
        expectRefusal { _ = try state.receive(altered(receiptAccepted) { var w = $0["witness"] as! [String: Any]; w["prefix"] = String(repeating: "b", count: 64); $0["witness"] = w }) }
        expectRefusal { _ = try state.receive(altered(receiptAccepted) { $0["requestID"] = "stale" }) }
        #expect(state.phase == .accepted)
        _ = try state.receive(raw(receiptAccepted))
        expectRefusal { _ = try state.receive(raw(receiptAccepted)) }
        r = try raw(recover).decode(); r.payload.clientRoot = session.sessionID; r.payload.witness.clientRoot = session.sessionID
        expectRefusal { _ = try state.send(.recover(r)) }
        expectRefusal { _ = try state.receive(altered(batch) { $0["contextDigest"] = digest }) }
        expectRefusal { _ = try state.receive(altered(knowledge) { $0["contextDigest"] = digest }) }
    }

    @Test func allRefusalReasonsAndOperationsAreExplicitAndTerminal() throws {
        let reasons: [DurableRefusalReason] = [.unavailable,.incompatible,.unauthorized,.expired,.unknownOrLost,.invalid,.busyOrFull]
        for operation: DurableRefusalOperation in [.open,.begin,.recover,.receipt] {
            for reason in reasons {
                var state = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: true)
                _ = try state.receive(raw(caps)); _ = try state.send(open)
                if operation != .open { _ = try state.receive(raw(opened)) }
                if operation == .begin { _ = try state.send(begin) }
                if operation == .recover { _ = try state.send(recover) }
                if operation == .receipt { _ = try state.send(begin); _ = try state.receive(raw(accepted)); _ = try state.send(receipt) }
                let c = DurableCorrelation(requestID: operation.rawValue, operation: operation,
                                           sessionID: operation == .open ? nil : session.sessionID,
                                           generationID: operation == .open ? nil : reference.generationID)
                let failure = DurableMessage.refused(.init(.init(correlation: c, reason: reason)))
                expectRefusal { _ = try state.receive(altered(failure) { var c = $0["correlation"] as! [String: Any]; c["requestID"] = "stale"; $0["correlation"] = c }) }
                guard case .refused(let result) = try state.receive(raw(failure)) else { Issue.record("missing explicit refusal"); return }
                #expect(result.payload.reason == reason && state.refusal == reason && state.phase == .refused)
                expectRefusal { _ = try state.send(begin) }; expectRefusal { _ = try state.send(recover) }
                expectRefusal { _ = try state.receive(raw(opened)) }
            }
        }
    }

    @Test func profileIdentifierAndTicketBoundaries() throws {
        for profiles in [[], (0..<8).map { String(repeating: "p", count: 63) + String($0) }] {
            _ = try raw(.capabilities(.init(.init(modelID: String(repeating: "m", count: 256), profiles: profiles))))
        }
        for profiles in [[""], ["é"], [String(repeating: "p", count: 65)], ["same", "same"], (0..<9).map(String.init)] {
            try checkInvalid(DurableCapabilities(.init(modelID: model, profiles: profiles)))
        }
        for id in ["", String(repeating: "é", count: 129)] { try checkInvalid(DurableCapabilities(.init(modelID: id, profiles: []))) }
        for count in [41,4096] { _ = try raw(.opened(.init(.init(requestID: "open", session: session, ticket: Data(repeating: 255, count: count))))) }
        for count in [0,40,4097] { try checkInvalid(DurableSessionOpened(.init(requestID: "open", session: session, ticket: Data(repeating: 0, count: count)))) }
        var invalidSession = session; invalidSession.sessionID = "00000000-0000-0000-0000-0000000000AB"
        try checkInvalid(DurableSessionOpened(.init(requestID: "open", session: invalidSession, ticket: ticket)))
        // Unicode-equivalent free IDs remain different byte identities during correlation.
        var state = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: true)
        _ = try state.receive(raw(caps))
        _ = try state.send(.open(.init(.init(requestID: "é", modelID: model, profile: DurableWire.profile, durable: true))))
        expectRefusal { _ = try state.receive(altered(opened) { $0["requestID"] = "e\u{301}" }) }
    }

    @Test func contextBoundsAndDigestSyntaxDoNotAuthenticateBytes() throws {
        for count in [1, DurableWire.contextLimit] {
            let bytes = Data(repeating: 255, count: count)
            let message = DurableMessage.accepted(.init(.init(requestID: "begin", reference: reference, kind: .begin, context: bytes, contextDigest: contextDigest)))
            let decoded = try raw(message).decode(DurableGenerationAccepted.self)
            #expect(decoded.payload.context == bytes)
            #expect(try message.encode(version: 2).count < DurableWire.controlLimit)
        }
        for count in [0, DurableWire.contextLimit+1] {
            let bytes = Data(repeating: 0, count: count)
            try checkInvalid(DurableGenerationAccepted(.init(requestID: "begin", reference: reference, kind: .begin, context: bytes, contextDigest: contextDigest)))
        }
        for invalidDigest in ["short", String(repeating: "G", count: 64), String(repeating: "A", count: 64)] {
            try checkInvalid(DurableGenerationAccepted(.init(requestID: "begin", reference: reference, kind: .begin, context: context, contextDigest: invalidDigest)))
        }
        // Arbitrary context and a syntactically valid declared digest are valid
        // wire data, even without a hash relation. Trusted adapter verification
        // remains separate from codec shape and requester-side correlation.
        let decoded = try altered(accepted) { $0["contextDigest"] = digest }.decode(DurableGenerationAccepted.self)
        #expect(decoded.payload.context == context && decoded.payload.contextDigest == digest)
        var unselected = try DurableNegotiation(selectedDialect: 2, modelID: model, localOptIn: true)
        expectRefusal { _ = try unselected.receive(raw(accepted)) }
    }

    @Test func completeWitnessShapesAndOneOver() throws {
        for w in [witness, DurableWitness(context: contextDigest, clientRoot: root, revision: .max, high: 65_536, terminal: true, prefix: digest, registrations: 32, calls: digest)] {
            let frame = DurableReceipt(.init(requestID: "receipt", reference: reference, witness: w))
            #expect(try raw(.receipt(frame)).decode(DurableReceipt.self).payload.witness == w)
        }
        let mutations: [(inout DurableWitness) -> Void] = [
            { $0.version = 2 }, { $0.policy = "other" }, { $0.high = 65_537; $0.revision = 1 },
            { $0.high = 1 }, { $0.revision = 1 }, { $0.terminal = true }, { $0.registrations = 1 },
            { $0.high = 1; $0.revision = 1; $0.registrations = 33 }, { $0.registrations = -1 },
            { $0.prefix = String(repeating: "A", count: 64) }, { $0.calls = "short" }, { $0.clientRoot = "invalid" }
        ]
        for mutate in mutations { var w = witness; mutate(&w); try checkInvalid(DurableReceipt(.init(requestID: "receipt", reference: reference, witness: w))) }
        var rec = try raw(recover).decode(DurableGenerateRecover.self); rec.payload.witness.context = digest
        try checkInvalid(rec)
    }

    @Test func exactBatchMaximumSkipAndOverflow() throws {
        var b = try raw(batch).decode(DurableBatch.self)
        b.payload.first = 61_441; b.payload.count = 4096; b.payload.skip = 4095
        b.payload.bytes = Data(repeating: 255, count: 8<<20)
        let encoded = try FrameCodec.encode(b, for: 2)
        #expect(encoded.count < DurableWire.bulkLimit)
        #expect(!String(decoding: encoded.dropFirst(5), as: UTF8.self).contains("\\/"))
        #expect(try raw(.batch(b)).decode(DurableBatch.self).payload.bytes == b.payload.bytes)
        let mutations: [(inout DurableBatchPayload) -> Void] = [
            { $0.first = 0 }, { $0.first = .max }, { $0.first = 65_536 },
            { $0.count = 0 }, { $0.count = 4097 }, { $0.count = -1 },
            { $0.skip = -1 }, { $0.skip = $0.count },
            { $0.bytes = Data() }, { $0.bytes = Data(repeating: 0, count: (8<<20)+1) }, { $0.commit = "invalid" }
        ]
        for mutate in mutations { var value = try raw(batch).decode(DurableBatch.self); mutate(&value.payload); try checkInvalid(value) }
    }

    @Test func knowledgeExactUTF8UnknownAndKnownCanonicalOutcome() throws {
        var frame = try raw(knowledge).decode(DurableToolKnowledge.self)
        #expect(frame.payload.callID == Data("é".utf8) && frame.payload.arguments == Data("{ \"a\" : 1 }".utf8))
        for kind: DurableOutcomeKind in [.success,.failure] {
            frame.payload.state = .known
            frame.payload.outcome = .init(kind: kind, result: Data([255,0,47]), digest: digest)
            #expect(try raw(.knowledge(frame)).decode(DurableToolKnowledge.self).payload.outcome == frame.payload.outcome)
        }
        frame.payload.state = .unknown; try checkInvalid(frame)
        frame.payload.state = .known; frame.payload.outcome = nil; try checkInvalid(frame)
        frame = try raw(knowledge).decode()
        frame.payload.callID = Data(repeating: 97, count: 256); frame.payload.name = Data(repeating: 98, count: 1024)
        frame.payload.arguments = Data(repeating: 47, count: 8<<20)
        #expect(try FrameCodec.encode(frame, for: 2).count < DurableWire.bulkLimit)
        for field in ["callID","name","arguments"] {
            for invalidUTF8 in [Data([255]), Data([0xc0,0xaf]), Data([0xed,0xa0,0x80])] {
                expectRefusal { _ = try DurableMessage.decode(altered(knowledge) { $0[field] = invalidUTF8.base64EncodedString() }, version: 2) }
            }
            let maximum = field == "callID" ? 256 : field == "name" ? 1024 : 8<<20
            expectRefusal { _ = try DurableMessage.decode(altered(knowledge) { $0[field] = Data(repeating: 97, count: maximum+1).base64EncodedString() }, version: 2) }
        }
        for field in ["callID","name"] { expectRefusal { _ = try DurableMessage.decode(altered(knowledge) { $0[field] = "" }, version: 2) } }
        var outcome = DurableOutcome(kind: .success, result: Data(), digest: digest)
        let overhead = try DurableWire.canonical(outcome).count
        let largestResult = (((1<<20)-overhead)/4)*3
        outcome.result = Data(repeating: 255, count: largestResult)
        try outcome.validate()
        #expect(try DurableWire.canonical(outcome).count == (1<<20)-(((1<<20)-overhead)%4))
        outcome.result.append(255)
        expectRefusal { try outcome.validate() } // base64 + JSON exceeds canonical 1 MiB.
        frame.payload.state = .known; frame.payload.outcome = outcome
        try checkInvalid(frame)
        for mutate: (inout DurableOutcome) -> Void in [{ $0.version = 2 }, { $0.digest = "invalid" }] {
            var bad = DurableOutcome(kind: .success, result: Data(), digest: digest); mutate(&bad)
            frame.payload.state = .known; frame.payload.outcome = bad; try checkInvalid(frame)
        }
    }

    @Test func requiredNullMissingEnumsConflictsAndIntegerOverflowDecode() throws {
        for message in all {
            let object = try #require(JSONSerialization.jsonObject(with: raw(message).body) as? [String: Any])
            for key in object.keys {
                expectRefusal { _ = try DurableMessage.decode(altered(message) { $0.removeValue(forKey: key) }, version: 2) }
                expectRefusal { _ = try DurableMessage.decode(altered(message) { $0[key] = NSNull() }, version: 2) }
            }
        }
        for (message, key) in [(accepted,"kind"),(knowledge,"state"),(refused,"reason")] {
            expectRefusal { _ = try DurableMessage.decode(altered(message) { $0[key] = "unknown-enum" }, version: 2) }
        }
        expectRefusal { _ = try DurableMessage.decode(altered(knowledge) { $0["outcome"] = NSNull() }, version: 2) }
        expectRefusal { _ = try DurableMessage.decode(altered(refused) { var c = $0["correlation"] as! [String: Any]; c["sessionID"] = session.sessionID; $0["correlation"] = c }, version: 2) }
        expectRefusal { _ = try DurableMessage.decode(altered(open) { $0["durable"] = false }, version: 2) }
        for (key, numeric) in [("first","18446744073709551616"),("count","9223372036854775808"),("skip","-9223372036854775809")] {
            var body = String(decoding: try raw(batch).body, as: UTF8.self)
            let value = key == "count" ? "2" : "1"
            body = body.replacingOccurrences(of: "\"\(key)\":\(value)", with: "\"\(key)\":\(numeric)")
            expectRefusal { _ = try DurableMessage.decode(RawFrame(type: .durableBatch, body: Data(body.utf8)), version: 2) }
        }
    }

    @Test func actualEncodedBodyCeilingsIncludeUnknownJSONOverhead() throws {
        for message in [caps,batch,knowledge] {
            let original = try raw(message)
            let limit = DurableWire.bodyLimit(original.type)
            // Add an optional ASCII field sized to make the actual incoming body
            // exactly the limit. Unknown keys are additive but still consume bytes.
            var object = try #require(JSONSerialization.jsonObject(with: original.body) as? [String: Any])
            object["padding"] = ""
            let empty = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys,.withoutEscapingSlashes])
            object["padding"] = String(repeating: "p", count: limit-empty.count)
            let exact = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys,.withoutEscapingSlashes])
            #expect(exact.count == limit)
            _ = try DurableMessage.decode(RawFrame(type: original.type, body: exact), version: 2)
            expectRefusal { _ = try DurableMessage.decode(RawFrame(type: original.type, body: exact + Data([32])), version: 2) }
        }
        func sizedRequest(_ count: Int) -> DurableGenerateBegin {
            var r = request
            r.portableTranscript = .init(entries: [.prompt(.init(id: "prompt", segments: [.text(.init(id: "text", content: String(repeating: "x", count: count)))]))])
            return .init(.init(requestID: "begin", reference: reference, ticket: ticket, request: r))
        }
        let overhead = try FrameCodec.encode(sizedRequest(0), for: 2).count-5
        let exact = try FrameCodec.encode(sizedRequest(DurableWire.controlLimit-overhead), for: 2)
        #expect(exact.count-5 == DurableWire.controlLimit)
        _ = try RawFrame(type: .durableGenerateBegin, body: Data(exact.dropFirst(5))).decode(DurableGenerateBegin.self)
        try checkInvalid(sizedRequest(DurableWire.controlLimit-overhead+1))
    }

    @Test func explicitV2RelayInheritsV1TriStateAndRefusals() throws {
        for relay in [Optional<[RoadEndpoint]>.none, [], [.init(host: "10.2.3.4", port: 123)]] {
            let frame = HelloAck(version: 2, cluster: "synthetic", models: [], relayRoads: relay)
            var reassembler = FrameReassembler()
            let decoded = try #require(reassembler.feed(FrameCodec.encode(frame, for: 2)).first).decode(HelloAck.self)
            #expect(decoded.relayRoads == relay)
        }
        for json in ["null", "true", "[{\"host\":\"8.8.8.8\",\"port\":1}]", "[{\"host\":\"10.2.3.4\",\"port\":0}]"] {
            let body = Data("{\"version\":2,\"cluster\":\"synthetic\",\"models\":[],\"relayRoads\":\(json)}".utf8)
            expectRefusal { _ = try RawFrame(type: .helloAck, body: body).decode(HelloAck.self) }
        }
        expectRefusal { _ = try FrameCodec.encode(HelloAck(version: 2, cluster: "synthetic", models: [], relayRoads: [.init(host: "8.8.8.8", port: 1)]), for: 2) }
    }
}
