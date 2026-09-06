import XCTest
import Foundation
import MLX
import MLXLMCommon
import MLXGuidedGeneration
import ReachWire
import AllowedToolFixtures
@testable import AllowedToolCoordinator

final class AllowedToolCoordinatorTests: XCTestCase {
    func testNativeContinuationAtProposalGuidedAndDeliveryCuts() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try ATSetup(atFixture("multi")), live = try setup.prepare(); defer { live.close() }
            var rows: [ATObserved] = []
            var saved: [(AllowedToolCheckpoint, Int, [Int])] = []
            for cut in ["c0", "probe-partial", "route", "guided-c0", "pending", "call-ready", "interpass", "second-c0", "unicode", "newline", "final-ready", "emitted"] {
                rows += try atPrefix(live, boundary: cut)
                saved.append((try live.capture(), rows.count, setup.factory.models.map { $0.1.calls }))
            }
            rows += try atDrain(live)
            let final = try live.capture()
            for (snapshot, offset, calls) in saved {
                let fresh = try ATSetup(setup.item), restored = try fresh.restore(snapshot); defer { restored.close() }
                XCTAssertEqual(fresh.factory.calls, 0); XCTAssertEqual(fresh.factory.models.count, 1)
                XCTAssertEqual(try restored.capture(), snapshot)
                XCTAssertEqual(try atDrain(restored), Array(rows.dropFirst(offset)))
                try atCompare(restored.capture().data, final.data)
                try atCompareTraces(fresh.factory.traces(), setup.factory.traces(dropping: calls))
            }
        }
    }

    func testNativeRoutePrecedenceAndOrderedCalls() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for name in ["prose", "schema", "single", "multi", "precedence", "unknown"] {
                let setup = try ATSetup(atFixture(name)), live = try setup.prepare(); defer { live.close() }
                let rows = try atDrain(live)
                try atAssertOutcome(rows, setup: setup, final: live.capture())
                if name == "multi" {
                    XCTAssertEqual(rows.last?.state.proposalIDs, [atID(0), atID(1), atID(2)])
                    XCTAssertTrue(rows.contains { $0.state.phase == .callReady }); XCTAssertTrue(rows.contains { $0.state.phase == .interpass })
                }
                if name == "precedence" { XCTAssertEqual(live.route, .calls) }
            }
        }
    }

    func testDynamicInputAndDistinctDeliveryPrepareBoundaries() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try ATSetup(atFixture("multi")), live = try setup.prepare(); defer { live.close() }
            _ = try atPrefix(live, boundary: "route")
            XCTAssertEqual(setup.factory.models.count, 1)
            let route = try live.capture(), fresh = try ATSetup(setup.item), restored = try fresh.restore(route)
            defer { restored.close() }
            XCTAssertEqual(fresh.factory.calls, 0); XCTAssertEqual(fresh.factory.models.count, 1)
            let c0 = try XCTUnwrap(live.advance()); XCTAssertTrue(c0.events.isEmpty)
            let input = try XCTUnwrap(c0.checkpoint.document().control.current)
            let actual = try route.document().control.proposals[0]
            XCTAssertEqual(input.messages, try atExpectedMessages(actual))
            XCTAssertNotEqual(input.tokens, setup.binding.originalTokens)
            XCTAssertEqual(input.identity.input, try ResumableTokenIdentity.inputDigest(input.tokens))
            _ = try atPrefix(live, boundary: "call-ready")
            let before = setup.factory.calls, modelCount = setup.factory.models.count
            let delivered = try XCTUnwrap(live.advance())
            XCTAssertEqual(delivered.events.count, 1); XCTAssertEqual(live.phase, .interpass)
            XCTAssertEqual(setup.factory.calls, before); XCTAssertEqual(setup.factory.models.count, modelCount)
            let between = try live.capture(), midSetup = try ATSetup(setup.item), mid = try midSetup.restore(between)
            defer { mid.close() }
            XCTAssertEqual(midSetup.factory.calls, 0); XCTAssertEqual(midSetup.factory.models.count, 1)
            XCTAssertTrue(try XCTUnwrap(mid.advance()).events.isEmpty)
            XCTAssertEqual(midSetup.factory.models.count, 2); XCTAssertEqual(try atSnapshot(mid.capture()).index, 1)
        }
    }

    func testCancellationAtActiveAndNonfinalBoundaries() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for cut in ["c0", "probe-partial", "route", "pending", "call-ready", "interpass", "second-c0", "final-ready"] {
                let setup = try ATSetup(atFixture("multi")), live = try setup.prepare(); defer { live.close() }
                let prefix = try atPrefix(live, boundary: cut), saved = try live.capture(), before = setup.factory.calls, made = setup.factory.models.count
                let ending = try XCTUnwrap(live.cancel())
                XCTAssertEqual(setup.factory.calls, before); XCTAssertEqual(setup.factory.models.count, made)
                if cut == "final-ready" { XCTAssertEqual(ending.events.count, 3); XCTAssertEqual(ending.events.last, .finished(.complete)) }
                else { XCTAssertEqual(ending.events, [.finished(.cancelled)]) }
                let fresh = try ATSetup(setup.item), restored = try fresh.restore(saved); defer { restored.close() }
                XCTAssertEqual(fresh.factory.calls, 0)
                XCTAssertEqual(try restored.cancel()?.events, ending.events)
                XCTAssertNil(try restored.advance()); XCTAssertNil(try restored.cancel())
                try atAssertOutcome(prefix + [atObserve(ending)], setup: setup, final: live.capture())
            }
        }
    }

    func testLengthZeroAndIncompletePreservePriorEvents() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for name in ["length", "zero", "guided-incomplete", "schema-incomplete", "second-incomplete"] {
                let setup = try ATSetup(atFixture(name)), live = try setup.prepare(); defer { live.close() }
                let rows = try atDrain(live); try atAssertOutcome(rows, setup: setup, final: live.capture())
                if name == "zero" { XCTAssertEqual(setup.factory.calls, 0) }
                if name == "second-incomplete" { XCTAssertEqual(rows.last?.state.delivered, 1); XCTAssertEqual(setup.factory.models.count, 3) }
                let fresh = try ATSetup(setup.item), frozen = try fresh.restore(live.capture()); defer { frozen.close() }
                XCTAssertEqual(fresh.factory.calls, 0); XCTAssertNil(try frozen.advance()); XCTAssertNil(try frozen.cancel())
            }
        }
    }

    func testTinyLibraryLlamaSchemaComposition() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try ATSetup(atFixture("llama")), live = try setup.prepare(); defer { live.close() }
            let rows = try atDrain(live); try atAssertOutcome(rows, setup: setup, final: live.capture())
            XCTAssertEqual(setup.factory.models.count, 2); XCTAssertNotNil(setup.factory.models.last?.1.llama)
            XCTAssertEqual(setup.factory.models.last?.1.weightBytes, 35264)
        }
    }
}
