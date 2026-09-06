import XCTest
import Foundation
import MLX
@testable import MLXGuidedGeneration
@testable import MLXLMCommon
import RequiredToolFixtures
@testable import RequiredToolCoordinator

final class RequiredToolCheckpointTests: XCTestCase {
    func testUnexpectedAdvanceErrorClosesWithoutBatchAndPreservesOldSnapshot() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try RTSetup(rtFixture("single")), tokenizer = FaultTokenizer()
            let live = try RequiredToolCoordinator.prepare(binding: setup.binding, model: setup.model, tokens: setup.prompt,
                tokenizer: tokenizer, codecs: setup.registry)
            let saved = try live.capture()
            tokenizer.fail = true
            XCTAssertThrowsError(try live.advance()); XCTAssertTrue(live.isClosed)
            XCTAssertThrowsError(try live.capture()); XCTAssertThrowsError(try live.cancel())
            let fresh = try RTSetup(setup.item), restored = try fresh.restore(saved); defer { restored.close() }
            XCTAssertEqual(fresh.model.calls, 0)
            let rows = try rtDrain(restored, item: setup.item)
            XCTAssertEqual(rows.flatMap(\.events).last, .finished(.complete))
            let readySetup = try RTSetup(setup.item), ready = try readySetup.prepare()
            _ = try rtPrefix(ready, item: setup.item, boundary: "ready")
            let oldReady = try ready.capture(), calls = readySetup.model.calls
            ready.close(); XCTAssertEqual(readySetup.model.calls, calls); XCTAssertThrowsError(try ready.advance())
            let back = try fresh.restore(oldReady); defer { back.close() }
            XCTAssertEqual(try back.advance()?.events.count, 3)
        }
    }

    func testChangedExpectedBindingsAndPrepareValidation() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try RTSetup(rtFixture("multi-text")), live = try setup.prepare(); defer { live.close() }
            _ = try rtPrefix(live, item: setup.item, boundary: "arguments")
            let saved = try live.capture(), independent = try live.capture(), calls = setup.model.calls
            let changes: [(inout RequiredToolBinding) -> Void] = [
                { $0.entryID += "x" }, { $0.callID += "x" }, { $0.requestIdentity += "x" }, { $0.route = "allowed" },
                { $0.tools.reverse() }, { $0.tools[0].name += "x" }, { $0.tools[0].schemaJSON = "{}" },
                { $0.specification.fastForward.toggle() }, { $0.specification.tokenizerIdentity += "x" },
                { $0.specification.vocabulary[1] += "x" }, { $0.options.model.maximumTokens += 1 },
                { $0.codecIdentity += "x" }, { $0.cacheSpecs = [] }, { $0.policy += "x" },
                { b in let i = b.identity; b.identity = .init(model: i.model + "x", configuration: i.configuration, weights: i.weights, input: i.input, backend: i.backend, dependency: i.dependency) },
                { b in let i = b.identity; b.identity = .init(model: i.model, configuration: i.configuration, weights: i.weights, input: i.input + "x", backend: i.backend, dependency: i.dependency) }]
            for mutate in changes {
                var b = setup.binding; mutate(&b)
                let fresh = try RTSetup(setup.item)
                XCTAssertThrowsError(try RequiredToolCoordinator.restore(saved, expected: b, model: fresh.model, tokenizer: S74ByteTokenizer(), codecs: fresh.registry))
                XCTAssertEqual(fresh.model.calls, 0); XCTAssertEqual(try live.capture(), independent); XCTAssertEqual(setup.model.calls, calls)
            }
            XCTAssertThrowsError(try RequiredToolCoordinator.restore(saved, expected: setup.binding, model: setup.model, tokenizer: S74ByteTokenizer(), codecs: .init()))
            for mutate in [
                { (b: inout RequiredToolBinding) in b.entryID = "" }, { $0.callID = String(repeating: "a", count: 257) },
                { $0.tools = [] }, { $0.tools[0].name = "" }, { $0.tools.append($0.tools[0]) },
                { $0.tools[0].schemaJSON = "{" }, { $0.specification.source = "{}" }] {
                var b = setup.binding; mutate(&b); let fresh = try RTSetup(setup.item)
                XCTAssertThrowsError(try RequiredToolCoordinator.prepare(binding: b, model: fresh.model, tokens: fresh.prompt, tokenizer: S74ByteTokenizer(), codecs: fresh.registry))
                XCTAssertEqual(fresh.model.calls, 0)
            }
            let fresh = try RTSetup(setup.item)
            XCTAssertThrowsError(try RequiredToolCoordinator.prepare(binding: setup.binding, model: fresh.model, tokens: [9], tokenizer: S74ByteTokenizer(), codecs: fresh.registry))
            XCTAssertEqual(fresh.model.calls, 0)
        }
    }

    func testRecomputedOuterChildJoinsAndEarlierNewlineOutput() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try RTSetup(rtFixture("newline")), live = try setup.prepare(); defer { live.close() }
            let c0 = try live.capture()
            _ = try rtPrefix(live, item: setup.item, boundary: "newline")
            let newline = try live.capture()
            XCTAssertTrue(try rtSnapshot(newline).newlineReset)
            _ = try rtPrefix(live, item: setup.item, boundary: "ready")
            let ready = try live.capture(), guardSaved = try live.capture(), guardCalls = setup.model.calls
            let cases: [(RequiredToolCheckpoint, (inout RequiredToolDocument) throws -> Void)] = [
                (newline, { $0.control.whole[0] = 91 }),
                (newline, { $0.control.counts.sampled += 1 }),
                (newline, { $0.control.counts.accepted += 1 }),
                (newline, { $0.control.phase = .ready }),
                (newline, { $0.control.phase = .emitted; $0.control.outcome = .complete }),
                (ready, { $0.control.phase = .generating }),
                (ready, { $0.control.outcome = .cancelled }),
                (ready, { $0.control.call = nil }),
                (ready, { $0.control.call = .init(name: "other", argumentsJSON: "{}") }),
                (ready, { $0.control.call = .init(name: setup.item.expectedName, argumentsJSON: "{}") }),
                (ready, { d in d.child = try c0.document().child; d.control.childDigest = sgHash(d.child) }),
                (ready, { d in
                    var child = try ResumableGuidedCheckpoint(data: d.child).document()
                    child.guided.sampled += 1
                    d.child = try ResumableGuidedCheckpoint(document: child).data
                    d.control.childDigest = sgHash(d.child)
                })]
            for (base, mutate) in cases {
                var d = try base.document(); try mutate(&d)
                let bad = try RequiredToolCheckpoint(document: d), fresh = try RTSetup(setup.item)
                XCTAssertThrowsError(try fresh.restore(bad))
                XCTAssertEqual(fresh.model.calls, 0); XCTAssertEqual(try live.capture(), guardSaved); XCTAssertEqual(setup.model.calls, guardCalls)
            }
            // Ready/emitted children still undergo full native validation.
            var emitted = try XCTUnwrap(live.advance()).checkpoint.document()
            var child = try ResumableGuidedCheckpoint(data: emitted.child).document()
            child.guided.grammar.mask.words = []
            emitted.child = try ResumableGuidedCheckpoint(document: child).data; emitted.control.childDigest = sgHash(emitted.child)
            XCTAssertThrowsError(try setup.restore(RequiredToolCheckpoint(document: emitted)))
        }
    }

    func testEncodedBoundsVersionsCorruptionAndProjectionPairing() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try RTSetup(rtFixture("single")), live = try setup.prepare(); defer { live.close() }
            let saved = try live.capture()
            var unknown = try saved.document(); unknown.version = 2
            XCTAssertThrowsError(try RequiredToolCheckpoint(data: RequiredToolCheckpoint(document: unknown).data))
            for bytes in [Data(), Data(saved.data.dropLast()), Data("not JSON".utf8), Data(repeating: 0, count: RequiredToolCheckpoint.maximumBytes + 1)] {
                XCTAssertThrowsError(try RequiredToolCheckpoint(data: bytes))
            }
            var envelope = try JSONDecoder().decode(RequiredToolCheckpoint.Envelope.self, from: saved.data); envelope.sha256 = "wrong"
            XCTAssertThrowsError(try RequiredToolCheckpoint(data: encoder().encode(envelope)))
            let changes: [(inout RequiredToolDocument) -> Void] = [
                { $0.child = Data(repeating: 0, count: ResumableGuidedCheckpoint.maximumBytes + 1) },
                { $0.control.whole = Data(repeating: 65, count: RequiredToolContract.maximumEnvelopeBytes + 1) },
                { $0.control.call = .init(name: "x", argumentsJSON: String(repeating: "x", count: RequiredToolContract.maximumArgumentsBytes + 1)) },
                { $0.control.binding.requestIdentity = String(repeating: "x", count: RequiredToolCheckpoint.maximumControlBytes) }]
            for mutate in changes { var d = try saved.document(); mutate(&d); XCTAssertThrowsError(try RequiredToolCheckpoint(document: d)) }
            XCTAssertThrowsError(try RequiredToolCheckpoint(document: saved.document(), records: Array(repeating: .finished(.cancelled), count: 4)))
            let d = try saved.document(), child = try ResumableGuidedCheckpoint(data: d.child)
            let native = try ResumableGuidedGeneration.restore(child, model: setup.model, identity: setup.binding.identity,
                cacheSpecs: setup.binding.cacheSpecs, codecs: setup.registry, tokenizer: S74ByteTokenizer(), specification: setup.binding.specification, options: setup.binding.options)
            defer { native.close() }
            _ = try native.advance()
            XCTAssertThrowsError(try ResumableGuidedCheckpointView(checkpoint: child, validatedOperation: native, tokenizer: S74ByteTokenizer()))
        }
    }
}

// Test-only fault switch, confined to one synchronous test invocation.
private final class FaultTokenizer: Tokenizer, @unchecked Sendable {
    var fail = false
    let base = S74ByteTokenizer()
    func encode(text: String, addSpecialTokens: Bool) -> [Int] { base.encode(text: text, addSpecialTokens: addSpecialTokens) }
    func decode(tokenIds: [Int], skipSpecialTokens: Bool) -> String {
        fail ? String(repeating: "x", count: 256 * 1024 + 1) : base.decode(tokenIds: tokenIds, skipSpecialTokens: skipSpecialTokens)
    }
    func convertTokenToId(_ token: String) -> Int? { base.convertTokenToId(token) }
    func convertIdToToken(_ id: Int) -> String? { base.convertIdToToken(id) }
    var bosToken: String? { base.bosToken }
    var eosToken: String? { base.eosToken }
    var unknownToken: String? { base.unknownToken }
    func applyChatTemplate(messages: [[String: any Sendable]], tools: [[String: any Sendable]]?, additionalContext: [String: any Sendable]?) throws -> [Int] { [] }
}
