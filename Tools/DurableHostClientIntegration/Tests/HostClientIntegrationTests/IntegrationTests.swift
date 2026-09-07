import XCTest
import Foundation
import HostClientContract
import HostClientFixtures
import LifecycleFixtures
import MLX
@testable import DurableClientReceipts
@testable import DurableSessionLifecycle

final class IntegrationTests: XCTestCase {
    func testTerminalWitnessRefusalsAndAtomicReceiptRetirement() throws {
        let f = try JoinedFixture(route: "allowed"), w = try f.drive()
        XCTAssertTrue(w.terminal); XCTAssertGreaterThan(w.registrations, 1); XCTAssertGreaterThan(f.setup.calls, 0)
        let allocation = try JoinedFixture.allocation(f.hostPath), before = try f.host.catalog.load().records[0]
        for field in ["root", "context", "prefix", "calls", "count", "high", "terminal", "revision-policy"] {
            var bad = w
            switch field {
            case "root": bad.clientRoot = UUID().uuidString.lowercased()
            case "context": bad.context = String(repeating: "0", count: 64)
            case "prefix": bad.prefix = String(repeating: "0", count: 64)
            case "calls": bad.calls = String(repeating: "0", count: 64)
            case "count": bad.registrations -= 1
            case "high": bad.high += 1
            case "terminal": bad.terminal = false
            default: bad.policy = "changed"
            }
            XCTAssertThrowsError(try f.accept(bad))
            XCTAssertEqual(try JoinedFixture.allocation(f.hostPath), allocation)
        }
        XCTAssertEqual(try f.host.catalog.load().records[0].high, before.high)
        let native = f.setup.calls, factories = f.setup.factories
        let result = try f.accept(w)
        XCTAssertTrue(result.phase == .tombstone && result.providerEnding != nil)
        XCTAssertTrue(result.disposition == (try w.disposition()))
        let record = try f.host.catalog.load().records[0]
        XCTAssertTrue(record.work == nil && record.cleanup == nil)
        XCTAssertTrue(try f.host.catalog.files.children.names(maximum: 64, allowed: LifecycleFileSystem.childRole).isEmpty)
        XCTAssertTrue(try f.host.catalog.files.requests.names(maximum: 65, allowed: LifecycleFileSystem.requestRole).isEmpty)
        XCTAssertTrue(try f.witness() == w)
        f.attachment = nil
        XCTAssertTrue(try f.accept(w).disposition == result.disposition)
        var changed = w; changed.revision += 1; XCTAssertThrowsError(try f.accept(changed))
        XCTAssertEqual(f.setup.calls, native); XCTAssertEqual(f.setup.factories, factories)
    }
    func testStableWitnessExcludesEffectsAndOwnerEpoch() throws {
        let f = try JoinedFixture(route: "required"), w = try f.drive(), binding = try f.firstTool()
        _ = try f.accept(w)
        guard case .fresh = try f.client.beginEffect(binding, handle: f.handle, authority: f.authority, authorization: f.clientAuth) else { return XCTFail("first permission") }
        XCTAssertTrue(try f.witness() == w); try f.reopenClient(); XCTAssertTrue(try f.witness() == w)
        guard case .unknown = try f.client.beginEffect(binding, handle: f.handle, authority: f.authority, authorization: f.clientAuth) else { return XCTFail("reissued permission") }
        let outcome = try ClientOutcome.make(kind: .failure, result: Data("known-failure".utf8), binding: binding, authority: f.authority)
        _ = try f.client.recordOutcome(outcome, binding: binding, handle: f.handle, authority: f.authority, authorization: f.clientAuth)
        XCTAssertTrue(try f.witness() == w); XCTAssertTrue(try f.accept(w).phase == .tombstone)
        try f.reopenClient()
        XCTAssertTrue(try f.client.effect(binding, handle: f.handle, authority: f.authority, authorization: f.clientAuth) == .known(outcome))
    }
    func testPartialWitnessAcknowledgesWithoutRetiringAndStaleAttachRefuses() throws {
        let f = try JoinedFixture()
        while try f.witness().high == 0 {
            _ = try f.accept(f.witness())
            _ = try f.host.step(ticket: f.ticket, authorization: f.auth, attachment: f.attachment) { f.setup.runtime }
            _ = try f.drain()
        }
        let partial = try f.witness(); XCTAssertFalse(partial.terminal)
        XCTAssertTrue(try f.accept(partial).phase == .active)
        let stale = f.attachment!
        f.attachment = try f.host.attachClient(ticket: f.ticket, authorization: f.auth, generation: f.generation,
            witness: partial, expectedClientRoot: f.clientEnvironment.rootID).attachment
        XCTAssertThrowsError(try f.host.acceptClientWitness(partial, expectedClientRoot: f.clientEnvironment.rootID, ticket: f.ticket,
            authorization: f.auth, generation: f.generation, attachment: stale))
        _ = try f.drive()
        XCTAssertThrowsError(try f.accept(partial)) // A now-stale volatile delivery assertion cannot move backward.
        XCTAssertTrue(try f.host.catalog.load().records[0].work != nil)
    }
    func testCancellationTombstoneAndExpiredOriginalTicketStayDistinct() throws {
        let f = try JoinedFixture(lifetime: 10_000_000_000), w = try f.witness()
        let cancelled = try f.host.cancel(ticket: f.ticket, authorization: f.auth, attachment: f.attachment)
        XCTAssertTrue(cancelled.disposition == "cancelled")
        XCTAssertThrowsError(try f.accept(w))
        f.hostClock.time = f.authority.context.expires; try f.host.maintenance()
        XCTAssertTrue(try f.host.catalog.load().records.isEmpty)
        XCTAssertThrowsError(try f.accept(w))
        f.clientClock.time = f.authority.context.expires; try f.client.maintenance()
        XCTAssertThrowsError(try f.witness())
    }
}
