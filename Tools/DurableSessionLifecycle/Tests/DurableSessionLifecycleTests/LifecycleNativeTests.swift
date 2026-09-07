import XCTest
import Foundation
import Darwin
import MLX
import LifecycleFixtures
import DurableHostStore
import ReachWire
@testable import DurableSessionLifecycle

final class LifecycleNativeTests: XCTestCase {
    func testPublicationChecksAfterFinalCatalogPersistence() throws {
        for mode in ["active", "terminal", "replay", "authorization", "reattach"] {
            let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: mode, time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller(), setup = try PFSetup("ordinary")
            defer { try? FileManager.default.removeItem(atPath: path) }
            let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); defer { owner.close() }
            let ticket = try owner.issueTicket(authorization: auth), a = try XCTUnwrap(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: setup.binding).attachment)
            var armed = false, crossed = false, cursor: UInt64 = 0
            if mode == "replay" || mode == "reattach" { _ = try complete(owner, ticket: ticket, auth: auth, attachment: a, setup: setup, cursor: &cursor) }
            if mode == "reattach" { try owner.detach(ticket: ticket, authorization: auth, attachment: a) }
            var writes = 0
            owner.fault = { point in
                if point == .afterC0 && mode != "terminal" { armed = true }
                if point == .afterChildTerminal { armed = true }
                if point == .afterCatalogRename {
                    writes += 1
                    // Replay performs maintenance (two writes), context (one),
                    // then its final persistence. Target that final fourth write.
                    if mode == "replay" && writes == 4 { armed = true }
                    if mode == "reattach" && writes == 3 { armed = true }
                    if armed && !crossed {
                        crossed = true
                        if mode == "authorization" { auth.allowed = false }
                        else { clock.time = 100+(mode == "active" ? LifecycleLimits.inflight : mode == "reattach" ? LifecycleLimits.wait : LifecycleLimits.terminal) }
                    }
                }
            }
            if mode == "reattach" {
                XCTAssertThrowsError(try owner.attach(ticket: ticket, authorization: auth, generation: "g", cursor: cursor)) { XCTAssertEqual($0 as? LifecycleError, .expired) }
            } else if mode == "replay" {
                XCTAssertThrowsError(try owner.replay(ticket: ticket, authorization: auth, attachment: a, after: 0)) { XCTAssertEqual($0 as? LifecycleError, .expired) }
            } else if mode == "authorization" {
                XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { setup.runtime }) { XCTAssertEqual($0 as? LifecycleError, .unauthorized) }
            } else {
                var stopped: LifecycleStatus?
                for _ in 0..<100 {
                    let next = try owner.step(ticket: ticket, authorization: auth, attachment: a) { setup.runtime }
                    if crossed { stopped = next; break }
                    _ = try collect(owner, ticket: ticket, auth: auth, attachment: a, cursor: &cursor)
                }
                XCTAssertEqual(try XCTUnwrap(stopped).phase, .tombstone, mode)
            }
            XCTAssertTrue(crossed, mode); owner.fault = { _ in }
            let calls = setup.calls, factories = setup.factories
            XCTAssertThrowsError(try owner.replay(ticket: ticket, authorization: auth, attachment: a, after: 0))
            XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("post-boundary factory"); return setup.runtime })
            XCTAssertEqual(setup.calls, calls); XCTAssertEqual(setup.factories, factories)
            if mode != "authorization" { XCTAssertNil(try owner.catalog.load().records[0].work) }
        }
    }
    // Kept in the publication regression group: these paths return outer
    // retirement status, which still requires current caller/ticket authority.
    func testExpiredStatusAuthenticatesAfterRetirement() throws {
        for mode in ["post-revoked", "intent-revoked", "post-ticket-expired"] {
            let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: mode, time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller(), setup = try PFSetup("ordinary")
            defer { try? FileManager.default.removeItem(atPath: path) }
            let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); defer { owner.close() }
            let ticket = try owner.issueTicket(authorization: auth), a = try XCTUnwrap(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: setup.binding).attachment)
            var armed = false, expired = false, revokedOrExpiredTicket = false
            owner.fault = { point in
                if point == .afterC0 { armed = true }
                if point == .afterCatalogRename && !expired {
                    if mode == "intent-revoked", try owner.catalog.load(allowUncertain: true).records[0].work?.times.transitionStartedAt != nil { armed = true }
                    if armed { clock.time = 100+LifecycleLimits.inflight; expired = true }
                }
                if point == .afterRetirementIntent && mode.hasSuffix("revoked") { auth.allowed = false; revokedOrExpiredTicket = true }
                if point == .afterTombstone && mode == "post-ticket-expired" { clock.time = 100+LifecycleLimits.session; revokedOrExpiredTicket = true }
            }
            XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) {
                if mode == "intent-revoked" { XCTFail("pre-native expiry invoked provider") }
                return setup.runtime
            }) { XCTAssertEqual($0 as? LifecycleError, mode == "post-ticket-expired" ? .expired : .unauthorized, mode) }
            owner.fault = { _ in }
            XCTAssertTrue(expired); XCTAssertTrue(revokedOrExpiredTicket)
            let record = try owner.catalog.load().records[0]
            XCTAssertEqual(record.phase, .tombstone); XCTAssertTrue(record.work == nil && record.cleanup == nil)
            let calls = setup.calls, factories = setup.factories
            if mode == "intent-revoked" { XCTAssertEqual(calls, 0); XCTAssertEqual(factories, 0) }
            XCTAssertThrowsError(try owner.replay(ticket: ticket, authorization: auth, attachment: a, after: 0))
            XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("retired provider"); return setup.runtime })
            XCTAssertEqual(setup.calls, calls); XCTAssertEqual(setup.factories, factories)
        }
    }
    override func tearDownWithError() throws {
        XCTAssertLessThanOrEqual(Memory.peakMemory, 128*1024*1024)
        print("S82 native MLX peak bytes: \(Memory.peakMemory)")
    }
    func testLostTerminalPromotionOriginalRetentionAndActualTerminalQuota() throws {
        let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "terminal-quota", time: LifecycleLimits.second), keys = try lifecycleKeys(), auth = caller(), setup = try PFSetup("ordinary")
        let identity = try LifecycleIdentity(clock: clock, quota: StoreLimits.reservation+LifecycleLimits.metadataReserve+4*1024*1024)
        defer { try? FileManager.default.removeItem(atPath: path) }
        let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock)
        let ticket = try owner.issueTicket(authorization: auth), a = try XCTUnwrap(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: setup.binding).attachment)
        owner.fault = { if $0 == .afterChildTerminal { throw LifecycleError.io("lost terminal promotion", EIO) } }
        var cursor: UInt64 = 0, reached = false
        for _ in 0..<100 {
            do { try owner.step(ticket: ticket, authorization: auth, attachment: a) { setup.runtime } }
            catch { XCTAssertEqual(error as? LifecycleError, .io("lost terminal promotion", EIO)); reached = true; break }
            _ = try collect(owner, ticket: ticket, auth: auth, attachment: a, cursor: &cursor)
        }
        XCTAssertTrue(reached)
        let pending = try owner.catalog.load().records[0]
        XCTAssertNotEqual(pending.phase, .terminal); XCTAssertEqual(pending.work!.times.transitionStartedAt, LifecycleLimits.second)
        owner.close(); clock.time = 61*LifecycleLimits.second
        let recovered = try DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: clock); defer { recovered.close() }
        let record = try recovered.catalog.load().records[0]
        XCTAssertEqual(record.phase, .terminal); XCTAssertEqual(record.work!.times.terminalUntil, 601*LifecycleLimits.second)
        XCTAssertNil(try recovered.begin(ticket: ticket, authorization: auth, generation: "g", provider: setup.binding).attachment)
        let fresh = try XCTUnwrap(recovered.attach(ticket: ticket, authorization: auth, generation: "g", cursor: 0).attachment)
        let frames = try recovered.replay(ticket: ticket, authorization: auth, attachment: fresh, after: 0)
        try assertOutcome(frames, setup: setup)
        _ = try recovered.step(ticket: ticket, authorization: auth, attachment: fresh) { XCTFail("terminal factory"); return setup.runtime }
        let before = try recovered.catalog.files.usage(), child = try OwnedDirectory(path: recovered.catalog.files.childPath(record.work!.child))
        defer { child.close() }
        // Real allocated orphan bytes under a retained terminal count toward the
        // global next-set credit; no mocked counter and no replay eviction.
        let orphan = "b-"+UUID().uuidString.lowercased()+".bin"
        try child.writeNew(orphan, bytes: Data(repeating: 0xa5, count: 6*1024*1024), maximum: StoreLimits.candidate)
        let after = try recovered.catalog.files.usage()
        XCTAssertGreaterThanOrEqual(after.bytes-before.bytes, 6*1024*1024)
        let extra = try recovered.issueTicket(authorization: auth), count = try recovered.catalog.load().records.count
        XCTAssertThrowsError(try recovered.begin(ticket: extra, authorization: auth, generation: "new", provider: cpuBinding("new"))) { XCTAssertEqual($0 as? LifecycleError, .full) }
        XCTAssertEqual(try recovered.catalog.load().records.count, count)
        XCTAssertTrue(try child.exists(orphan)); XCTAssertEqual(try recovered.replay(ticket: ticket, authorization: auth, attachment: fresh, after: 0), frames)
        let calls = setup.calls, factories = setup.factories
        clock.time = 601*LifecycleLimits.second; try recovered.maintenance()
        let tombstone = try recovered.catalog.load().records[0]
        XCTAssertEqual(tombstone.phase, .tombstone); XCTAssertEqual(tombstone.disposition, "terminal-expired")
        XCTAssertNil(tombstone.work); XCTAssertEqual(tombstone.ending, .complete)
        XCTAssertEqual(setup.calls, calls); XCTAssertEqual(setup.factories, factories)
        XCTAssertTrue(try recovered.catalog.files.children.names(maximum: 64, allowed: LifecycleFileSystem.childRole).isEmpty)
    }
    func testStepCrossingExpiryAndAuthorizationRevokedBeforePublication() throws {
        for mode in ["expiry", "revoked"] {
            let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: mode, time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller(), setup = try PFSetup("ordinary")
            defer { try? FileManager.default.removeItem(atPath: path) }
            let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); defer { owner.close() }
            let ticket = try owner.issueTicket(authorization: auth), a = try XCTUnwrap(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: setup.binding).attachment)
            owner.fault = { if $0 == .afterC0 && mode == "revoked" { auth.allowed = false } }
            if mode == "expiry" {
                _ = try owner.step(ticket: ticket, authorization: auth, attachment: a) { setup.runtime }
                let store = try owner.child(owner.catalog.load().records[0]).store
                store.fault = { if $0 == .afterAckBeforePublication, try store.snapshot().high > 0 { clock.time = 100+LifecycleLimits.inflight } }
                var result: LifecycleStatus?
                for _ in 0..<10 {
                    let next = try owner.step(ticket: ticket, authorization: auth, attachment: a) { setup.runtime }
                    if next.phase == .tombstone { result = next; break }
                }
                let expired = try XCTUnwrap(result)
                XCTAssertEqual(expired.disposition, "inflight-expired"); XCTAssertNil(expired.providerEnding); XCTAssertGreaterThan(expired.high, 0)
                store.fault = { _ in } // release the fixture observer's capture
                XCTAssertThrowsError(try owner.replay(ticket: ticket, authorization: auth, attachment: a, after: 0))
                XCTAssertNil(try owner.catalog.load().records[0].work)
            } else {
                XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { setup.runtime }) { XCTAssertEqual($0 as? LifecycleError, .unauthorized) }
                XCTAssertThrowsError(try owner.replay(ticket: ticket, authorization: auth, attachment: a, after: 0))
                auth.allowed = true; owner.fault = { _ in }
                let record = try owner.catalog.load().records[0]
                XCTAssertEqual(record.phase, .active)
                // A valid C0 under allocating contradicts its pre-provider rule.
                var contradictory = try owner.catalog.load(); contradictory.records[0].phase = .allocating
                try owner.catalog.replace(contradictory); try owner.maintenance()
                XCTAssertTrue(try owner.catalog.load().records[0].nonResumable)
                let calls = setup.calls, factories = setup.factories
                XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("allocating nonempty fallback"); return setup.runtime })
                _ = try owner.cancel(ticket: ticket, authorization: auth, attachment: a)
                XCTAssertEqual(setup.calls, calls); XCTAssertEqual(setup.factories, factories)
            }
        }
    }
    func testRequiredAndAllowedTerminalRetirementJoins() throws {
        for route in ["required", "allowed"] {
            let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "native", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller(), setup = try PFSetup(route)
            defer { try? FileManager.default.removeItem(atPath: path) }
            let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); defer { owner.close() }
            let ticket = try owner.issueTicket(authorization: auth), a = try XCTUnwrap(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: setup.binding).attachment)
            var cursor: UInt64 = 0
            let frames = try complete(owner, ticket: ticket, auth: auth, attachment: a, setup: setup, cursor: &cursor)
            try assertOutcome(frames, setup: setup)
            let events = try frames.flatMap { try JSONDecoder().decode([WireEvent].self, from: $0.eventBytes) }
            XCTAssertEqual(events.last, .finished(.complete))
            XCTAssertEqual(events.filter { if case .toolCallAppendArguments = $0 { return true }; return false }.count, route == "required" ? 1 : 3)
            let calls = setup.calls, factories = setup.factories
            XCTAssertEqual(try owner.replay(ticket: ticket, authorization: auth, attachment: a, after: 0), frames)
            let retired = try owner.cancel(ticket: ticket, authorization: auth, attachment: a)
            XCTAssertEqual(retired.phase, .tombstone); XCTAssertEqual(retired.providerEnding, .complete)
            XCTAssertEqual(setup.calls, calls); XCTAssertEqual(setup.factories, factories)
            XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("retired runtime"); return setup.runtime })
            XCTAssertEqual(try owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: setup.binding).phase, .tombstone)
        }
    }
}
