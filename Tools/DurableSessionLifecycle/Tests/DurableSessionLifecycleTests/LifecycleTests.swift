import XCTest
import Foundation
import CryptoKit
import LifecycleFixtures
import DurableHostStore
@testable import DurableSessionLifecycle

final class LifecycleTests: XCTestCase {
    func testSiblingLiveReturnsCheckAfterPersistence() throws {
        for mode in ["begin", "repeat", "attach", "touch", "detach"] {
            let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: mode, time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller()
            defer { try? FileManager.default.removeItem(atPath: path) }
            let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); defer { owner.close() }
            let binding = try cpuBinding(), ticket = try owner.issueTicket(authorization: auth)
            let a = mode == "begin" ? nil : try owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: binding).attachment
            var crossed = false, writes = 0
            owner.fault = { point in
                if point == .afterCatalogRename {
                    writes += 1
                    // Fresh begin has empty maintenance+context+admission; repeat
                    // has one record's maintenance+context; mutation adds a write.
                    let last = mode == "begin" || mode == "repeat" ? 3 : 4
                    if writes == last { crossed = true; clock.time = 100+LifecycleLimits.wait }
                }
            }
            switch mode {
            case "begin", "repeat": XCTAssertThrowsError(try owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: binding)) { XCTAssertEqual($0 as? LifecycleError, .expired) }
            case "attach": XCTAssertThrowsError(try owner.attach(ticket: ticket, authorization: auth, generation: "g", cursor: 0)) { XCTAssertEqual($0 as? LifecycleError, .expired) }
            case "touch": XCTAssertThrowsError(try owner.touch(ticket: ticket, authorization: auth, attachment: XCTUnwrap(a))) { XCTAssertEqual($0 as? LifecycleError, .expired) }
            default: XCTAssertThrowsError(try owner.detach(ticket: ticket, authorization: auth, attachment: XCTUnwrap(a))) { XCTAssertEqual($0 as? LifecycleError, .expired) }
            }
            XCTAssertTrue(crossed, mode); owner.fault = { _ in }
            XCTAssertTrue(try owner.catalog.load().records[0].work == nil)
        }
    }
    func testTicketAuthorityContextCanonicalAndExpiry() throws {
        let clock = try FixtureLifecycleClock(id: "tickets", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller()
        let good = try TicketCodec.issue(identity: identity, keys: keys, auth: auth, now: 100, ttl: 100)
        let claims = try TicketCodec.verify(good, identity: identity, keys: keys, auth: auth, now: 199)
        let wrapped = Data(repeating: 0, count: 64)+good.data
        XCTAssertEqual(try TicketCodec.verify(SessionTicket(data: wrapped.dropFirst(64)), identity: identity, keys: keys, auth: auth, now: 199).namespace, claims.namespace)
        XCTAssertEqual(claims.expires, 200)
        XCTAssertThrowsError(try TicketCodec.verify(good, identity: identity, keys: keys, auth: auth, now: 200))
        XCTAssertThrowsError(try TicketCodec.verify(good, identity: identity, keys: lifecycleKeys(), auth: auth, now: 100))
        XCTAssertThrowsError(try TicketCodec.verify(good, identity: identity, keys: keys, auth: caller("different"), now: 100))
        auth.allowed = false
        XCTAssertThrowsError(try TicketCodec.verify(good, identity: identity, keys: keys, auth: auth, now: 100)) { XCTAssertEqual($0 as? LifecycleError, .unauthorized) }
        auth.allowed = true
        for bad in ["boot", "namespace", "policy", "version", "lifetime", "future", "root"] {
            var c = claims
            switch bad { case "boot": c.boot = "other"; case "namespace": c.namespace = "bad"; case "policy": c.policy = "other"; case "version": c.version = 2; case "lifetime": c.expires = LifecycleLimits.session+101; case "future": c.issued = 101; default: c.incarnation = UUID().uuidString.lowercased() }
            let body = try lcEncode(c), mac = Data(HMAC<SHA256>.authenticationCode(for: body, using: keys.ticket))
            XCTAssertThrowsError(try TicketCodec.verify(SessionTicket(data: lcUInt(UInt64(body.count))+body+mac), identity: identity, keys: keys, auth: auth, now: 100), bad)
        }
        var tampered = good.data; tampered[tampered.count-1] ^= 1
        XCTAssertThrowsError(try TicketCodec.verify(SessionTicket(data: tampered), identity: identity, keys: keys, auth: auth, now: 100))
        XCTAssertThrowsError(try SessionTicket(data: Data(count: LifecycleLimits.ticket+1)))
        XCTAssertThrowsError(try TicketCodec.issue(identity: identity, keys: keys, auth: auth, now: .max-1, ttl: 10))
        XCTAssertThrowsError(try TicketCodec.issue(identity: identity, keys: keys, auth: auth, now: 100, ttl: LifecycleLimits.session+1))
        let spaced = try Data([32])+lcEncode(claims), signed = Data(HMAC<SHA256>.authenticationCode(for: spaced, using: keys.ticket))
        XCTAssertThrowsError(try TicketCodec.verify(SessionTicket(data: lcUInt(UInt64(spaced.count))+spaced+signed), identity: identity, keys: keys, auth: auth, now: 100))
        XCTAssertThrowsError(try TicketCodec.issue(identity: identity, keys: keys, auth: caller(String(repeating: "x", count: 257)), now: 100, ttl: 100))
    }
    func testDuplicateBeginAdmissionAndStaleAttachments() throws {
        let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "admission", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock)
        defer { try? FileManager.default.removeItem(atPath: path) }
        let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); defer { owner.close() }
        let auth = caller(), tickets = try (0..<5).map { _ in try owner.issueTicket(authorization: auth) }
        let first = try owner.begin(ticket: tickets[0], authorization: auth, generation: "g", provider: cpuBinding("first"))
        XCTAssertEqual(first.phase, .allocating)
        let original = try owner.catalog.load().records[0]
        for _ in 0..<3 { _ = try owner.begin(ticket: tickets[0], authorization: auth, generation: "g", provider: cpuBinding("first")) }
        XCTAssertEqual(try owner.catalog.load().records.count, 1)
        XCTAssertEqual(try owner.catalog.load().records[0].work!.times.admitted, original.work!.times.admitted)
        for n in 1...3 { XCTAssertEqual(try owner.begin(ticket: tickets[n], authorization: auth, generation: "g", provider: cpuBinding("op-\(n)")).phase, .queued) }
        XCTAssertThrowsError(try owner.begin(ticket: tickets[4], authorization: auth, generation: "g", provider: cpuBinding("fifth")))
        XCTAssertThrowsError(try owner.begin(ticket: tickets[1], authorization: auth, generation: "second", provider: cpuBinding("same-session-second")))
        XCTAssertThrowsError(try owner.begin(ticket: tickets[0], authorization: auth, generation: "g", provider: cpuBinding("changed")))
        XCTAssertThrowsError(try owner.begin(ticket: tickets[4], authorization: auth, generation: String(repeating: "x", count: 257), provider: cpuBinding("oversized")))
        XCTAssertTrue(try owner.catalog.files.children.names(maximum: 64, allowed: LifecycleFileSystem.childRole).isEmpty)
        let old = try XCTUnwrap(first.attachment)
        let attached = try owner.attach(ticket: tickets[0], authorization: auth, generation: "g", cursor: 0), fresh = try XCTUnwrap(attached.attachment)
        XCTAssertGreaterThan(fresh.epoch, old.epoch)
        XCTAssertThrowsError(try owner.touch(ticket: tickets[0], authorization: auth, attachment: old))
        XCTAssertThrowsError(try owner.detach(ticket: tickets[0], authorization: auth, attachment: old))
        XCTAssertThrowsError(try owner.cancel(ticket: tickets[0], authorization: auth, attachment: old))
        XCTAssertThrowsError(try owner.acknowledgeDelivery(ticket: tickets[0], authorization: auth, attachment: fresh, through: 1))
        auth.allowed = false
        XCTAssertThrowsError(try owner.step(ticket: tickets[0], authorization: auth, attachment: fresh) { XCTFail("unauthorized factory"); throw LifecycleError.unauthorized })
        auth.allowed = true
        _ = try owner.cancel(ticket: tickets[0], authorization: auth, attachment: fresh)
        try owner.maintenance()
        let d = try owner.catalog.load()
        XCTAssertEqual(d.records.filter { $0.phase.reservesExecution }.count, 1)
        XCTAssertEqual(d.records.filter { $0.phase == .queued }.count, 2)
    }
    func testAll64TombstonesAndExpiredNamespaceCannotResurrect() throws {
        let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "records", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); defer { owner.close() }
        var tickets: [SessionTicket] = []
        for n in 0..<64 {
            let ticket = try owner.issueTicket(authorization: auth, lifetime: 1000); tickets.append(ticket)
            let state = try owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: cpuBinding("op-\(n)"))
            _ = try owner.cancel(ticket: ticket, authorization: auth, attachment: XCTUnwrap(state.attachment))
        }
        let d = try owner.catalog.load()
        XCTAssertEqual(d.records.count, 64); XCTAssertTrue(d.records.allSatisfy { $0.phase == .tombstone && $0.work == nil && $0.cleanup == nil })
        let extra = try owner.issueTicket(authorization: auth, lifetime: 1000)
        XCTAssertThrowsError(try owner.begin(ticket: extra, authorization: auth, generation: "g", provider: cpuBinding("extra")))
        XCTAssertEqual(try owner.begin(ticket: tickets[0], authorization: auth, generation: "g", provider: cpuBinding("op-0")).phase, .tombstone)
        clock.time = 1100; try owner.maintenance()
        XCTAssertTrue(try owner.catalog.load().records.isEmpty)
        XCTAssertThrowsError(try owner.begin(ticket: tickets[0], authorization: auth, generation: "g", provider: cpuBinding("op-0"))) { XCTAssertEqual($0 as? LifecycleError, .expired) }
        XCTAssertTrue(try owner.catalog.files.children.names(maximum: 64, allowed: LifecycleFileSystem.childRole).isEmpty)
        XCTAssertTrue(try owner.catalog.files.requests.names(maximum: 65, allowed: LifecycleFileSystem.requestRole).isEmpty)
    }
    func testOriginalDeadlineArithmeticAndMissingDetach() throws {
        let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "deadlines", time: 10*LifecycleLimits.second), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock)
        let ticket = try owner.issueTicket(authorization: auth), state = try owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: cpuBinding())
        let a = try XCTUnwrap(state.attachment), original = try owner.catalog.load().records[0]
        clock.time += 30*LifecycleLimits.second
        try owner.touch(ticket: ticket, authorization: auth, attachment: a)
        let contact = clock.time; owner.close(); clock.time += 20*LifecycleLimits.second
        let reopened = try DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: clock); defer { reopened.close() }
        let saved = try reopened.catalog.load().records[0], t = saved.work!.times
        XCTAssertEqual(t.detachedUntil, contact+LifecycleLimits.wait)
        XCTAssertEqual(t.queueUntil, original.work!.times.queueUntil)
        XCTAssertEqual(t.absoluteUntil, original.work!.times.absoluteUntil)
        XCTAssertThrowsError(try reopened.touch(ticket: ticket, authorization: auth, attachment: a))
        let fresh = try XCTUnwrap(reopened.attach(ticket: ticket, authorization: auth, generation: "g", cursor: 0).attachment)
        try reopened.detach(ticket: ticket, authorization: auth, attachment: fresh)
        let detached = try reopened.catalog.load().records[0]
        clock.time += 10*LifecycleLimits.second
        try reopened.detach(ticket: ticket, authorization: auth, attachment: fresh)
        XCTAssertEqual(try reopened.catalog.load().records[0].work!.times.detachedUntil, detached.work!.times.detachedUntil)
        // Pure deadline policy branches need no fabricated child or model.
        var active = saved; active.phase = .active
        XCTAssertEqual(reopened.expiry(active, now: t.detachedUntil!), "detached-expired")
        active.work!.times.attached = true; active.work!.times.detachedUntil = nil
        XCTAssertEqual(reopened.expiry(active, now: t.absoluteUntil), "inflight-expired")
        active.phase = .terminal; active.work!.times.terminalUntil = t.admitted+LifecycleLimits.terminal
        XCTAssertEqual(reopened.expiry(active, now: t.admitted+LifecycleLimits.terminal), "terminal-expired")
        clock.time = original.work!.times.queueUntil; try reopened.maintenance()
        XCTAssertEqual(try reopened.catalog.load().records[0].phase, .tombstone)
    }
    func testClockPolicyRollbackAndOwnerEpochRefusal() throws {
        let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "clock", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock)
        clock.time = 99
        XCTAssertThrowsError(try owner.issueTicket(authorization: auth))
        owner.close()
        XCTAssertThrowsError(try DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: clock))
        clock.time = 100
        XCTAssertThrowsError(try DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: FixtureLifecycleClock(id: "other", time: 100)))
        let reopened = try DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: clock)
        XCTAssertEqual(reopened.ownerEpoch, 2); reopened.close()
        XCTAssertThrowsError(try reopened.issueTicket(authorization: auth))
    }
}
