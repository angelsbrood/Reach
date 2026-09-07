import XCTest
import Foundation
import MLX
import ReachWire
import StoreFixtures
import ResumableMLXProvider
@testable import DurableHostStore

final class StoreNativeTests: XCTestCase {
    func testFourNativeRoutesReplayBarrierAndTerminalNoFactory() throws {
        for name in ["ordinary", "guided", "required", "allowed"] {
            let setup = try PFSetup(name), identity = try StoreIdentity(provider: setup.binding), keys = try skeys(), path = fixturePath()
            defer { try? FileManager.default.removeItem(atPath: path) }
            let store = try DurableHostStore.initialize(at: path, identity: identity, keys: keys)
            let generation = try DurableGeneration.start(store: store) { setup.runtime }
            var frames: [StoreReplayFrame] = [], empty = 0
            while !(try store.snapshot().terminal) {
                let oldHigh = try store.snapshot().high, oldOrdinal = try StoreCommitProjection(store.snapshot().candidate!, identity: identity).ordinal
                try generation.advance()
                let state = try store.snapshot()
                XCTAssertEqual(try StoreCommitProjection(state.candidate!, identity: identity).ordinal, oldOrdinal+1)
                if oldHigh == state.high { empty += 1 }
                if state.high > oldHigh && !state.terminal {
                    let calls = setup.calls
                    XCTAssertThrowsError(try generation.advance()) { XCTAssertEqual($0 as? StoreError, .replayRequired) }
                    XCTAssertEqual(setup.calls, calls)
                }
                frames += try drain(generation)
            }
            XCTAssertGreaterThan(empty, 0)
            try assertOutcome(frames, setup: setup)
            XCTAssertGreaterThan(setup.calls, 0); XCTAssertEqual(setup.prefills, 0)
            let all = try store.replay(after: 0), high = try store.snapshot().high
            XCTAssertThrowsError(try store.replay(after: high+1))
            let epoch = store.ownerEpoch; generation.close()
            let reopened = try DurableHostStore.reopen(at: path, identity: identity, keys: keys)
            let terminal = try DurableGeneration.recover(store: reopened) { XCTFail("terminal acquired runtime"); return setup.runtime }
            XCTAssertEqual(reopened.ownerEpoch, epoch+1)
            XCTAssertEqual(try terminal.replay(after: 0), all)
            let last = try XCTUnwrap(all.last)
            if last.count > 1 {
                let replay = try terminal.replay(after: last.firstSequence)
                XCTAssertEqual(replay.first?.eventBytes, last.eventBytes); XCTAssertEqual(replay.first?.skipPrefix, 1)
            }
            XCTAssertNil(try terminal.advance()); terminal.close()
        }
        XCTAssertLessThanOrEqual(Memory.peakMemory, 128*1024*1024)
    }
    func testCancellationAndAtomicToolTail() throws {
        for name in ["ordinary-cancel", "guided", "required", "allowed"] {
            let setup = try PFSetup(name), identity = try StoreIdentity(provider: setup.binding), path = fixturePath()
            defer { try? FileManager.default.removeItem(atPath: path) }
            let store = try DurableHostStore.initialize(at: path, identity: identity, keys: skeys())
            let generation = try DurableGeneration.start(store: store) { setup.runtime }
            defer { generation.close() }
            var frames: [StoreReplayFrame] = []
            for _ in 0..<500 {
                let candidate = try store.snapshot().candidate!
                let checkpoint = try JSONSerialization.jsonObject(with: candidate.checkpointBytes) as! [String: Any]
                let ready: Bool
                if name == "ordinary-cancel" {
                    let child = try payload(Data(base64Encoded: checkpoint["child"] as! String)!) as! [String: Any]
                    ready = (child["output"] as? [String: Any])?["generationCount"] as? Int == 7
                } else if name == "guided" {
                    let child = try payload(Data(base64Encoded: checkpoint["child"] as! String)!) as! [String: Any]
                    let guided = child["guided"] as! [String: Any], grammar = guided["grammar"] as! [String: Any]
                    ready = (grammar["accepts"] as! [Any]).count > (guided["consumed"] as! Int)
                } else if name == "required" { ready = checkpoint["phase"] as? String == "required.ready" }
                else { ready = checkpoint["phase"] as? String == "allowed.interpass" }
                if ready { break }
                try generation.advance(); frames += try drain(generation)
                XCTAssertFalse(try store.snapshot().terminal)
            }
            let calls = setup.calls
            try generation.advance(cancel: true); frames += try drain(generation)
            XCTAssertTrue(try store.snapshot().terminal); XCTAssertEqual(setup.calls, calls)
            let events = try frames.flatMap { try JSONDecoder().decode([WireEvent].self, from: $0.eventBytes) }
            if name == "required" {
                try assertOutcome(frames, setup: setup); XCTAssertEqual(frames.last?.count, 3)
            } else {
                XCTAssertEqual(events.last, .finished(.cancelled))
                if name == "ordinary-cancel" {
                    let text = events.compactMap { e -> String? in if case .responseAppend(_, let s, _, _) = e { return s }; return nil }.joined()
                    XCTAssertEqual(text, "helloST")
                }
                if name == "allowed" { XCTAssertEqual(events.filter { if case .toolCallAppendArguments = $0 { return true }; return false }.count, 1) }
            }
            XCTAssertNil(try generation.advance(cancel: true))
        }
    }
}
