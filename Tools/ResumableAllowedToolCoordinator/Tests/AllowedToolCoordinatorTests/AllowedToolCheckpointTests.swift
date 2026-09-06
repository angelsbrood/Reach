import XCTest
import Foundation
import MLX
@testable import MLXGuidedGeneration
@testable import MLXLMCommon
import ReachWire
import AllowedToolFixtures
@testable import AllowedToolCoordinator

final class AllowedToolCheckpointTests: XCTestCase {
    func testExpectedBindingChangesAndKnownPrepareRefusals() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try ATSetup(atFixture("multi")), live = try setup.prepare(); defer { live.close() }
            _ = try atPrefix(live, boundary: "route")
            let saved = try live.capture(), calls = setup.factory.calls
            let changes: [(inout AllowedToolBinding) -> Void] = [
                { $0.entryID += "x" }, { $0.namespace = String(repeating: "a", count: 32) }, { $0.requestIdentity += "x" },
                { $0.route = "required" }, { $0.policy += "x" }, { $0.preparationPolicy += "x" }, { $0.tools.reverse() },
                { $0.tools[0].schemaJSON = "{}" }, { $0.tools[0].name += "x" }, { $0.responseSchema = "{}" },
                { $0.originalTokens[0] += 1 }, { $0.probeOptions.maximumTokens += 1 }, { $0.guidedOptions.model.maximumTokens += 1 },
                { $0.tokenizer.tokenizerIdentity += "x" }, { $0.tokenizer.vocabulary[1] += "x" }, { $0.format = .xmlFunction },
                { $0.guidedModel.codecIdentity += "x" }, { $0.probeModel.cacheSpecs = [] },
                { b in let i = b.guidedModel.identity; b.guidedModel.identity = .init(model: i.model+"x", configuration: i.configuration, weights: i.weights, input: i.input, backend: i.backend, dependency: i.dependency) }]
            for mutate in changes {
                var b = setup.binding; mutate(&b); let fresh = try ATSetup(setup.item)
                XCTAssertThrowsError(try AllowedToolCoordinator.restore(saved, expected: b, runtime: fresh.runtime))
                XCTAssertEqual(fresh.factory.calls, 0); XCTAssertEqual(try live.capture(), saved); XCTAssertEqual(setup.factory.calls, calls)
            }
            let invalid: [(inout AllowedToolBinding) -> Void] = [
                { $0.entryID = "" }, { $0.entryID = String(repeating: "x", count: 257) }, { $0.namespace = "bad" },
                { $0.tools = [] }, { $0.tools.append($0.tools[0]) }, { $0.tools[0].name = "" },
                { $0.tools[0].schemaJSON = "{" }, { $0.responseSchema = String(repeating: "x", count: 65_537) },
                { $0.guidedOptions.model.maximumTokens = -1 }, { $0.tokenizer.eosTokenID = 9999 }]
            for mutate in invalid {
                var b = setup.binding; mutate(&b); let fresh = try ATSetup(setup.item)
                XCTAssertThrowsError(try AllowedToolCoordinator.prepare(binding: b, runtime: fresh.runtime)); XCTAssertEqual(fresh.factory.calls, 0)
            }
            // RC1: invalid scalar widths must throw before factory/forward/prefill,
            // including direct public preparation for every relevant pass kind.
            let proposal = try XCTUnwrap(saved.document().control.proposals.first)
            let originalModels = setup.factory.models.count, originalPrefills = setup.factory.prepares
            for width in [-1, 0] {
                for probeWidth in [true, false] {
                    var b = setup.binding
                    if probeWidth { b.probeOptions.vocabularySize = width }
                    else { b.guidedOptions.model.logitWidth = width }
                    let refused = try ATSetup(setup.item)
                    XCTAssertThrowsError(try AllowedToolCoordinator.prepare(binding: b, runtime: refused.runtime))
                    XCTAssertThrowsError(try AllowedToolCoordinator.restore(saved, expected: b, runtime: refused.runtime))
                    let kinds: [AllowedPassKind] = probeWidth ? [.probe] : [.schema, .tool]
                    for kind in kinds {
                        XCTAssertThrowsError(try AllowedToolReplayInput.prepare(binding: b, kind: kind,
                            proposal: kind == .tool ? proposal : nil, tokenizer: refused.runtime.tokenizer))
                    }
                    XCTAssertTrue(refused.factory.models.isEmpty)
                    XCTAssertEqual(refused.factory.calls, 0); XCTAssertEqual(refused.factory.prepares, 0)
                    XCTAssertEqual(try live.capture(), saved); XCTAssertFalse(live.isClosed)
                    XCTAssertEqual(setup.factory.models.count, originalModels)
                    XCTAssertEqual(setup.factory.calls, calls); XCTAssertEqual(setup.factory.prepares, originalPrefills)
                }
            }
            let valid = try ATSetup(setup.item), restored = try valid.restore(saved); defer { restored.close() }
            XCTAssertEqual(try restored.capture(), saved); XCTAssertEqual(valid.factory.calls, 0)
        }
    }

    func testRetainedNativeAndOuterConsistencyJoins() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try ATSetup(atFixture("multi")), live = try setup.prepare(); defer { live.close() }
            let c0 = try live.capture()
            _ = try atPrefix(live, boundary: "route"); let route = try live.capture()
            _ = try atPrefix(live, boundary: "pending"); let pending = try live.capture()
            _ = try atPrefix(live, boundary: "call-ready"); let ready = try live.capture()
            _ = try atPrefix(live, boundary: "interpass"); let interpass = try live.capture()
            _ = try atPrefix(live, boundary: "newline"); let newline = try live.capture()
            _ = try atPrefix(live, boundary: "emitted"); let emitted = try live.capture(), calls = setup.factory.calls
            let changes: [(AllowedToolCheckpoint, (inout AllowedDocument) throws -> Void)] = [
                (route, { $0.control.route = .schema }),
                (route, { d in d.control.probe = try changedProbe(d.control.probe, key: "issuedIDs", value: []) }),
                (route, { d in d.control.probe = try changedProbe(d.control.probe, key: "generationTokens", value: 0) }),
                (route, { d in d.child = try c0.document().child; d.control.childDigest = sgHash(d.child) }),
                (pending, { $0.control.current!.messages = Data("different".utf8) }),
                (pending, { $0.control.current!.tokens[0] += 1 }),
                (pending, { $0.control.current!.index += 1 }),
                (pending, { $0.control.current!.proposalID = "different" }),
                (pending, { $0.control.guided!.sampled += 1 }),
                (pending, { $0.control.phase = .finalReady; $0.control.outcome = .complete }),
                (ready, { $0.control.deliveredCalls += 1 }),
                (interpass, { $0.control.completed[0].output += 1 }),
                (interpass, { $0.control.completed[0].inputDigest = "different" }),
                (newline, { $0.control.whole[0] = 91 }),
                (newline, { $0.control.records.reverse() }),
                (newline, { $0.control.schemaReturnedBytes = 1 }),
                (emitted, { $0.control.deliveredCalls -= 1 }),
                (emitted, { d in
                    var child = try ResumableGuidedCheckpoint(data: d.child).document()
                    child.guided.grammar.mask.words = []
                    d.child = try ResumableGuidedCheckpoint(document: child).data; d.control.childDigest = sgHash(d.child)
                })]
            for (base, mutate) in changes {
                var d = try base.document(); try mutate(&d); let fresh = try ATSetup(setup.item)
                XCTAssertThrowsError(try fresh.restore(AllowedToolCheckpoint(document: d)))
                XCTAssertEqual(fresh.factory.calls, 0); XCTAssertEqual(try live.capture(), emitted); XCTAssertEqual(setup.factory.calls, calls)
            }
        }
    }

    func testTaggedRecordsAndHonestOuterHistoryBoundary() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try ATSetup(atFixture("multi")), live = try setup.prepare(); defer { live.close() }
            _ = try atPrefix(live, boundary: "pending")
            let saved = try live.capture(); var d = try saved.document()
            let first = d.control.proposals[0]
            XCTAssertEqual(first.function.arguments["n"], .double(1.5)); XCTAssertEqual(first.function.arguments["count"], .int(1))
            let tagged = try encoder().encode(ResumableToolCallRecord.toolCall(first))
            let decoded = try JSONDecoder().decode(ResumableToolCallRecord.self, from: tagged)
            XCTAssertEqual(try encoder().encode(decoded), tagged)
            XCTAssertTrue(String(decoding: tagged, as: UTF8.self).contains("number"))
            XCTAssertTrue(String(decoding: tagged, as: UTF8.self).contains("integer"))
            // Recomputed-checksum historical prose is outer-owned, not available
            // from a discarded S76 snapshot. Native current-guided joins still run.
            let index = try XCTUnwrap(d.control.records.firstIndex { if case .response = $0 { return true }; return false })
            d.control.records[index] = .response(Data("Z".utf8))
            let fresh = try ATSetup(setup.item), alternate = try fresh.restore(AllowedToolCheckpoint(document: d)); defer { alternate.close() }
            XCTAssertEqual(fresh.factory.calls, 0); XCTAssertEqual(alternate.phase, .guided)
            XCTAssertEqual(try live.capture(), saved)
        }
    }

    func testActualEncodedLimitsVersionsAndCorruption() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try ATSetup(atFixture("single")), live = try setup.prepare(); defer { live.close() }
            let saved = try live.capture()
            var unknown = try saved.document(); unknown.version = 2
            XCTAssertThrowsError(try AllowedToolCheckpoint(data: AllowedToolCheckpoint(document: unknown).data))
            for bytes in [Data(), Data(saved.data.dropLast()), Data("bad".utf8), Data(repeating: 0, count: AllowedToolCheckpoint.maximumBytes + 1)] {
                XCTAssertThrowsError(try AllowedToolCheckpoint(data: bytes))
            }
            var envelope = try JSONDecoder().decode(AllowedToolCheckpoint.Envelope.self, from: saved.data); envelope.sha256 = "wrong"
            XCTAssertThrowsError(try AllowedToolCheckpoint(data: encoder().encode(envelope)))
            let changes: [(inout AllowedDocument) -> Void] = [
                { $0.child = Data(repeating: 0, count: ResumableToolGenerationCheckpoint.maximumBytes + 1) },
                { $0.control.whole = Data(repeating: 1, count: 256*1024 + 1) },
                { $0.control.records = Array(repeating: .response(Data()), count: 4097) },
                { $0.control.records = [.response(Data(repeating: 65, count: 512*1024 + 1))] },
                { $0.control.binding.requestIdentity = String(repeating: "x", count: AllowedToolCheckpoint.maximumControlBytes) }]
            for mutate in changes { var d = try saved.document(); mutate(&d); XCTAssertThrowsError(try AllowedToolCheckpoint(document: d)) }
            XCTAssertThrowsError(try AllowedToolCheckpoint(document: saved.document(), records: Array(repeating: .finished(.cancelled), count: 4097)))
            _ = try atPrefix(live, boundary: "pending")
            let guided = try live.capture()
            for mutate in [
                { (d: inout AllowedDocument) in d.child = Data(repeating: 0, count: ResumableGuidedCheckpoint.maximumBytes + 1) },
                { $0.control.current!.messages = Data(repeating: 65, count: 512*1024 + 1) },
                { $0.control.current!.tokens = Array(repeating: 1, count: 65_537) }] {
                var d = try guided.document(); mutate(&d); XCTAssertThrowsError(try AllowedToolCheckpoint(document: d))
            }
        }
    }

    func testFailureCloseAndPriorSnapshotIsolation() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try ATSetup(atFixture("single")), live = try setup.prepare()
            let prefix = try atPrefix(live, boundary: "probe-partial"), saved = try live.capture()
            let model = setup.factory.models[0].1; model.faultAt = model.calls + 1
            XCTAssertThrowsError(try live.advance()); XCTAssertTrue(live.isClosed); XCTAssertThrowsError(try live.capture())
            let fresh = try ATSetup(setup.item), restored = try fresh.restore(saved); defer { restored.close() }
            XCTAssertEqual(fresh.factory.calls, 0)
            let suffix = try atDrain(restored)
            XCTAssertEqual((prefix+suffix).flatMap(\.events).last, .finished(.complete))
            let readySetup = try ATSetup(atFixture("multi")), ready = try readySetup.prepare()
            _ = try atPrefix(ready, boundary: "call-ready")
            let old = try ready.capture(), calls = readySetup.factory.calls
            ready.close(); XCTAssertEqual(readySetup.factory.calls, calls); XCTAssertThrowsError(try ready.cancel())
            let backSetup = try ATSetup(readySetup.item), back = try backSetup.restore(old); defer { back.close() }
            XCTAssertEqual(try back.advance()?.events.count, 1); XCTAssertEqual(backSetup.factory.calls, 0)
        }
    }
}

private func changedProbe(_ view: ResumableToolGenerationCheckpointView, key: String, value: Any) throws -> ResumableToolGenerationCheckpointView {
    var object = try JSONSerialization.jsonObject(with: encoder().encode(view)) as! [String: Any]
    object[key] = value
    return try JSONDecoder().decode(ResumableToolGenerationCheckpointView.self, from: JSONSerialization.data(withJSONObject: object))
}
