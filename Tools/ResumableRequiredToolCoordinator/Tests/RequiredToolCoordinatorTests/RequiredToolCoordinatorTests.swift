import XCTest
import Foundation
import MLX
import MLXGuidedGeneration
import MLXLMCommon
import ReachWire
import RequiredToolFixtures
@testable import RequiredToolCoordinator

final class RequiredToolCoordinatorTests: XCTestCase {
    func testActualEnvelopesAndPrivateWireDelivery() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for name in ["single", "multi-int", "multi-text", "newline", "ff-off"] {
                let setup = try RTSetup(rtFixture(name)), live = try setup.prepare()
                defer { live.close() }
                let rows = try rtDrain(live, item: setup.item), final = try live.capture()
                try rtAssertResult(rows, setup: setup, final: final)
                XCTAssertTrue(rows.dropLast().allSatisfy { $0.events.isEmpty })
                if name == "single" { XCTAssertTrue(rows.contains { $0.state.pending > 0 }); XCTAssertTrue(rows.contains { $0.state.incompleteUnicode }) }
                if name == "newline" { XCTAssertTrue(rows.contains { $0.state.newlineReset }) }
                if name == "ff-off" { XCTAssertTrue(rows.allSatisfy { $0.state.pending == 0 && $0.state.forced == 0 }) }
            }
        }
    }

    func testSettledGenerationReadyAndEmittedRestore() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for name in ["c0", "pending", "name", "arguments", "unicode", "newline", "before-eos", "ready", "emitted"] {
                let selected = try rtCase(name), setup = try RTSetup(rtFixture(selected.fixture)), original = try setup.prepare()
                defer { original.close() }
                _ = try rtPrefix(original, item: setup.item, boundary: selected.boundary)
                let saved = try original.capture(), count = setup.model.calls
                let suffix = try rtDrain(original, item: setup.item), final = try original.capture()
                let fresh = try RTSetup(setup.item), restored = try fresh.restore(saved)
                defer { restored.close() }
                XCTAssertEqual(fresh.model.calls, 0); XCTAssertEqual(fresh.model.prepares, 0)
                XCTAssertEqual(try restored.capture(), saved)
                XCTAssertEqual(try rtDrain(restored, item: fresh.item), suffix)
                try rtCompare(restored.capture().data, final.data)
                XCTAssertEqual(fresh.model.inputs, Array(setup.model.inputs.dropFirst(count)))
                let restoredCalls = fresh.model.calls
                XCTAssertNil(try restored.advance()); XCTAssertNil(try restored.cancel()); XCTAssertEqual(fresh.model.calls, restoredCalls)
            }
        }
    }

    func testAcceptedEOSUsageAndReadyCancellationWins() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try RTSetup(rtFixture("single")), live = try setup.prepare()
            defer { live.close() }
            _ = try rtPrefix(live, item: setup.item, boundary: "before-eos")
            let before = try live.capture().document()
            XCTAssertNoThrow(try RequiredToolContract.parseEnvelope(before.control.whole, tools: setup.item.tools))
            XCTAssertEqual(live.phase, .generating); XCTAssertNil(before.control.outcome)
            let eos = try XCTUnwrap(live.advance()); XCTAssertTrue(eos.events.isEmpty); XCTAssertEqual(live.phase, .ready)
            let ready = eos.checkpoint, calls = setup.model.calls
            let emitted = try XCTUnwrap(live.cancel())
            let fresh = try RTSetup(setup.item), restored = try fresh.restore(ready)
            defer { restored.close() }
            XCTAssertEqual(try restored.advance()?.events, emitted.events)
            XCTAssertEqual(setup.model.calls, calls); XCTAssertEqual(fresh.model.calls, 0)
            XCTAssertEqual(emitted.events, [
                .toolCallAppendArguments(entryID: setup.binding.entryID, id: setup.binding.callID, name: setup.item.expectedName,
                    content: setup.item.expectedArguments, tokenCount: 1),
                .usage(inputTokens: 5, outputTokens: setup.item.expected.utf8.count), .finished(.complete)])
            let d = try emitted.checkpoint.document()
            XCTAssertEqual(d.control.counts.consumed, d.control.counts.sampled + d.control.counts.forced + 1)
            let post = try fresh.restore(emitted.checkpoint); defer { post.close() }
            XCTAssertNil(try post.advance()); XCTAssertNil(try post.cancel())
        }
    }

    func testZeroBudgetIncompleteCancellationAndClose() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for name in ["zero", "incomplete", "partial-budget", "cancel"] {
                let setup = try RTSetup(rtFixture(name)), live = try setup.prepare(), old = try live.capture()
                let rows = try rtDrain(live, item: setup.item), saved = try live.capture()
                try rtAssertResult(rows, setup: setup, final: saved)
                if name == "zero" { XCTAssertEqual(setup.model.calls, 0) }
                let calls = setup.model.calls
                XCTAssertNil(try live.advance()); XCTAssertNil(try live.cancel()); XCTAssertEqual(setup.model.calls, calls)
                live.close(); XCTAssertThrowsError(try live.capture())
                let independent = try RTSetup(setup.item), restored = try independent.restore(old)
                defer { restored.close() }
                XCTAssertEqual(try rtDrain(restored, item: setup.item), rows)
            }
            let setup = try RTSetup(rtFixture("single")), live = try setup.prepare()
            _ = try rtPrefix(live, item: setup.item, boundary: "unicode")
            let old = try live.capture(), calls = setup.model.calls
            XCTAssertEqual(try live.cancel()?.events, [.finished(.cancelled)]); XCTAssertEqual(setup.model.calls, calls)
            live.close()
            let fresh = try RTSetup(setup.item), resumed = try fresh.restore(old); defer { resumed.close() }
            XCTAssertTrue(try rtDrain(resumed, item: setup.item).flatMap(\.events).contains(.finished(.complete)))
        }
    }

    func testToolGuidanceGrammarAndEnvelopeSourceSemantics() throws {
        let tool = RequiredToolDefinition(name: "a\"/\\", schemaJSON: ##"{"type":"object","$defs":{"x":{"type":"integer"}},"properties":{"x":{"$ref":"#/$defs/x"}}}"##)
        let source = try RequiredToolContract.structuralSource([tool])
        let tree = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any])
        XCTAssertEqual(tree["type"] as? String, "structural_tag")
        let format = try XCTUnwrap(tree["format"] as? [String: Any]); XCTAssertEqual(format["type"] as? String, "or")
        let tags = try XCTUnwrap(format["elements"] as? [[String: Any]])
        XCTAssertEqual(tags.count, 1); XCTAssertEqual(tags[0]["type"] as? String, "tag")
        XCTAssertEqual(tags[0]["begin"] as? String, "{\"name\":\"a\\\"/\\\\\",\"arguments\":")
        XCTAssertEqual(tags[0]["end"] as? [String], ["}"])
        let content = try XCTUnwrap(tags[0]["content"] as? [String: Any]); XCTAssertEqual(content["type"] as? String, "json_schema")
        XCTAssertEqual(try rtJSON(content["json_schema"]!), try rtJSON(JSONSerialization.jsonObject(with: Data(tool.schemaJSON.utf8))))
        XCTAssertEqual(try RequiredToolContract.structuralSource([tool]), source)
        let envelope = "{\"name\":\(try rtJSON(tool.name)),\"arguments\":{\"z\":\"/中\",\"a\":[1,2]}}"
        XCTAssertEqual(try RequiredToolContract.parseEnvelope(Data(envelope.utf8), tools: [tool]).argumentsJSON, #"{"a":[1,2],"z":"/中"}"#)
        for value in [#"{"name":"unknown","arguments":{}}"#, #"{"name":"a","arguments":[]}"#, "{}", "{"] {
            XCTAssertThrowsError(try RequiredToolContract.parseEnvelope(Data(value.utf8), tools: [tool]))
        }
        XCTAssertThrowsError(try RequiredToolContract.structuralSource([])); XCTAssertThrowsError(try RequiredToolContract.structuralSource([tool, tool]))
    }

    func testTinyLibraryLlamaNativeComposition() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try RTSetup(rtFixture("llama")), live = try setup.prepare(); defer { live.close() }
            let rows = try rtDrain(live, item: setup.item)
            try rtAssertResult(rows, setup: setup, final: live.capture())
            XCTAssertEqual(setup.model.weightBytes, 35264)
        }
    }
}
