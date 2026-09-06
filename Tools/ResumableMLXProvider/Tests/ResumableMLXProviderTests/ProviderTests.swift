import XCTest
import Foundation
import MLX
import ReachWire
import ProviderFixtures
@testable import ResumableMLXProvider

final class ProviderTests: XCTestCase {
    func testFourRouteProjectionAndCommitBarriers() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for name in ["ordinary", "guided", "required", "allowed"] {
                let setup = try PFSetup(name)
                XCTAssertThrowsError(try ResumableMLXProvider.prepare(binding: setup.binding, runtime: setup.runtime, owner: "owner-1", credit: 0))
                XCTAssertEqual(setup.factories, 0); XCTAssertEqual(setup.calls, 0)
                let live = try setup.prepare(); defer { live.close() }
                let c0 = try XCTUnwrap(live.pendingCandidate()), c0Calls = setup.calls
                XCTAssertEqual(c0.eventBytes, Data("[]".utf8)); XCTAssertNil(live.acceptedCommit)
                XCTAssertThrowsError(try live.advance(owner: "owner-1", current: c0.commit, credit: ResumableMLXProvider.reservationBytes))
                XCTAssertThrowsError(try live.cancel(owner: "owner-1", current: c0.commit, credit: ResumableMLXProvider.reservationBytes))
                XCTAssertThrowsError(try live.acceptCommit(c0.commit, owner: "wrong"))
                XCTAssertEqual(try live.pendingCandidate(), c0); XCTAssertEqual(setup.calls, c0Calls)
                try live.acceptCommit(c0.commit, owner: "owner-1")
                var current = c0, rows = [try pfRow(c0)], empty = 0, nonempty = 0
                for _ in 0..<2000 {
                    let before = setup.calls, factories = setup.factories
                    XCTAssertThrowsError(try live.advance(owner: "wrong", current: current.commit, credit: ResumableMLXProvider.reservationBytes))
                    XCTAssertThrowsError(try live.cancel(owner: "owner-1", current: current.commit, credit: 0))
                    XCTAssertThrowsError(try live.advance(owner: "owner-1", current: current.commit, credit: ResumableMLXProvider.reservationBytes-1))
                    XCTAssertEqual(setup.calls, before); XCTAssertEqual(setup.factories, factories)
                    let candidate = try XCTUnwrap(live.advance(owner: "owner-1", current: current.commit, credit: ResumableMLXProvider.reservationBytes))
                    let after = setup.calls, made = setup.factories
                    XCTAssertEqual(try live.pendingCandidate()?.data, candidate.data)
                    // Duplicate previous ack must leave a newer pending candidate intact.
                    try live.acceptCommit(current.commit, owner: "owner-1")
                    XCTAssertEqual(try live.pendingCandidate(), candidate); XCTAssertEqual(live.acceptedCommit, current.commit)
                    var wrong = try candidate.commit.descriptor(); wrong.eventsDigest = String(repeating: "a", count: 64)
                    XCTAssertThrowsError(try live.acceptCommit(ProviderCommit(wrong), owner: "owner-1"))
                    XCTAssertThrowsError(try live.advance(owner: "owner-1", current: current.commit, credit: ResumableMLXProvider.reservationBytes))
                    XCTAssertThrowsError(try live.cancel(owner: "owner-1", current: current.commit, credit: ResumableMLXProvider.reservationBytes))
                    XCTAssertEqual(setup.calls, after); XCTAssertEqual(setup.factories, made)
                    XCTAssertFalse(live.isTerminal)
                    let row = try pfRow(candidate); rows.append(row)
                    if candidate.eventBytes == Data("[]".utf8) { empty += 1 } else { nonempty += 1 }
                    try live.acceptCommit(candidate.commit, owner: "owner-1"); current = candidate
                    if row.terminal { break }
                }
                XCTAssertTrue(live.isTerminal); XCTAssertGreaterThan(empty, 0); XCTAssertGreaterThan(nonempty, 0)
                let before = setup.calls
                XCTAssertNil(try live.advance(owner: "owner-1", current: current.commit, credit: 0))
                XCTAssertNil(try live.cancel(owner: "owner-1", current: current.commit, credit: 0))
                try live.acceptCommit(current.commit, owner: "owner-1"); XCTAssertEqual(setup.calls, before)
                let fresh = try PFSetup(name), host = try PFHost(restoring: current, prefix: rows, setup: fresh); defer { host.live.close() }
                XCTAssertEqual(fresh.calls, 0); XCTAssertTrue(host.live.isTerminal); try pfAssert(host, setup: setup)
            }
        }
    }
    func testLengthIncompleteAndCancellationPolicies() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for name in ["ordinary-length", "ordinary-zero", "guided-incomplete", "guided-structural"] {
                let setup = try PFSetup(name), host = try PFHost(setup); defer { host.live.close() }
                try host.drain(); try pfAssert(host, setup: setup)
                if name == "guided-incomplete" { XCTAssertEqual(try pfEvents(host.rows).last, .finished(.error(ProviderEvents.incomplete))) }
            }
            for (name, cut) in [("ordinary-cancel","stop-prefix"), ("guided","pending"), ("required","ready"), ("allowed","interpass")] {
                let setup = try PFSetup(name), host = try PFHost(setup); defer { host.live.close() }
                try host.reach(cut); let prefix = host.rows, calls = setup.calls
                let value = try XCTUnwrap(host.step(cancel: true)), events = try ProviderEvents.decode(value.eventBytes)
                XCTAssertEqual(setup.calls, calls); XCTAssertEqual(Array(host.rows.prefix(prefix.count)), prefix)
                if name == "required" { XCTAssertEqual(events.count, 3); XCTAssertEqual(events.last, .finished(.complete)) }
                else { XCTAssertEqual(events.last, .finished(.cancelled)) }
                if name == "guided" || name == "allowed" { XCTAssertEqual(events, [.finished(.cancelled)]) }
                if name == "ordinary-cancel" {
                    XCTAssertEqual(events, [.responseAppend(entryID: "response-stable", text: "ST", segmentID: "segment-stable", tokenCount: 1), .finished(.cancelled)])
                }
                if name == "allowed" {
                    let published = try pfEvents(host.rows).filter { if case .toolCallAppendArguments = $0 { return true }; return false }
                    XCTAssertEqual(published.count, 1)
                }
                try pfAssert(host, setup: setup)
            }
        }
    }
    func testCommittedSelectionCloseAndNativeContinuation() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for (name, cut) in [("ordinary","visible"), ("guided","pending"), ("required","ready"), ("allowed","interpass")] {
                let setup = try PFSetup(name), reference = try PFHost(setup); defer { reference.live.close() }
                try reference.reach(cut); let saved = reference.committed, prefix = reference.rows
                try reference.drain(); try pfAssert(reference, setup: setup)
                let branchSetup = try PFSetup(name), branch = try PFHost(restoring: saved, prefix: prefix, setup: branchSetup)
                let unpublished = try XCTUnwrap(branch.live.advance(owner: branch.owner, current: saved.commit, credit: ResumableMLXProvider.reservationBytes))
                XCTAssertNotEqual(unpublished.commit, saved.commit); XCTAssertEqual(branch.live.acceptedCommit, saved.commit)
                branch.live.close(); XCTAssertTrue(branch.live.isClosed); XCTAssertEqual(saved, branch.committed)
                let fresh = try PFSetup(name), restored = try PFHost(restoring: saved, prefix: prefix, setup: fresh); defer { restored.live.close() }
                XCTAssertEqual(fresh.calls, 0); XCTAssertEqual(fresh.prefills, 0)
                XCTAssertEqual(restored.live.acceptedCommit, saved.commit)
                try restored.drain(); XCTAssertEqual(restored.rows, reference.rows)
                try pfCompare(restored.committed, reference.committed)
            }
        }
    }
    func testUTF8EncodingAndPostWorkFailureIsolation() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            XCTAssertThrowsError(try ProviderEvents.text(Data([0xff]), entryID: nil, segmentID: nil))
            let a = try ProviderEvents.text(Data("é".utf8), entryID: nil, segmentID: nil)
            let b = try ProviderEvents.text(Data("e\u{301}".utf8), entryID: nil, segmentID: nil)
            XCTAssertNotEqual(try ProviderEvents.encode([a]), try ProviderEvents.encode([b]))
            let setup = try PFSetup("ordinary"), host = try PFHost(setup), saved = host.committed
            let before = setup.calls
            host.live.encodeEvents = { _ in throw ProviderError.invalid("injected post-work encoding failure") }
            XCTAssertThrowsError(try host.live.advance(owner: host.owner, current: saved.commit, credit: ResumableMLXProvider.reservationBytes))
            XCTAssertGreaterThan(setup.calls, before); XCTAssertTrue(host.live.isClosed); XCTAssertEqual(host.committed, saved)
            XCTAssertThrowsError(try host.live.pendingCandidate())
            let fresh = try PFSetup("ordinary"), restored = try PFHost(restoring: saved, prefix: host.rows, setup: fresh); defer { restored.live.close() }
            XCTAssertEqual(fresh.calls, 0); try restored.drain(); try pfAssert(restored, setup: fresh)
        }
    }
}
