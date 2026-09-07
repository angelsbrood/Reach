import XCTest
import Foundation
import Darwin
import HostClientContract
import HostClientFixtures
import LifecycleFixtures
@testable import DurableClientReceipts
@testable import DurableSessionLifecycle

final class RecoveryTests: XCTestCase {
    func testHostPostIOContextAndReceiptAuthorization() throws {
        for expire in [false, true] {
            for context in [true, false] {
                let f = try JoinedFixture(lifetime: 10_000_000_000)
                let hook = {
                    if expire { f.hostClock.time = f.authority.context.expires } else { f.auth.allowed = false }
                }
                if context {
                    XCTAssertThrowsError(try f.host.exportClientContext(ticket: f.ticket, authorization: f.auth,
                        attachment: f.attachment, publicationHook: hook))
                } else {
                    XCTAssertThrowsError(try f.host.replayForClient(ticket: f.ticket, authorization: f.auth,
                        attachment: f.attachment, after: 0, publicationHook: hook))
                }
            }
            let g = try JoinedFixture(route: "required", lifetime: 10_000_000_000), w = try g.drive()
            XCTAssertThrowsError(try g.accept(w) {
                if expire { g.hostClock.time = g.authority.context.expires } else { g.auth.allowed = false }
            })
            XCTAssertTrue(try g.host.catalog.load().records[0].work == nil)
        }
    }
    func testClientWitnessChecksAuthorizationAndTimeAfterLastRead() throws {
        for expire in [false, true] {
            let f = try JoinedFixture()
            f.clientFault = { if $0 == .beforePublication {
                if expire { f.clientClock.time = f.authority.context.expires } else { f.clientAuth.allowed = false }
            } }
            XCTAssertThrowsError(try f.witness()); f.clientFault = { _ in }
        }
    }
    func testReceiptIntentFaultsAreDistinctFromWorkerDeaths() throws {
        for point in [LifecycleFault.beforeRetirementIntent, .afterRetirementIntent, .duringContentDeletion, .afterTombstone] {
            let f = try JoinedFixture(route: "required"), w = try f.drive()
            f.host.fault = { if $0 == point { throw LifecycleError.io("injected S84", EIO) } }
            XCTAssertThrowsError(try f.accept(w)); f.host.fault = { _ in }
            let r = try f.host.catalog.load().records[0]
            if point == .beforeRetirementIntent { XCTAssertTrue(r.work != nil && r.disposition == nil) }
            else { XCTAssertNil(r.work); XCTAssertEqual(r.disposition, try w.disposition()) }
            XCTAssertTrue(try f.accept(w).phase == .tombstone)
            XCTAssertTrue(try f.witness() == w)
        }
    }
    func testCurrentRevocationBeforeReceiptIntentPreventsSelection() throws {
        let f = try JoinedFixture(route: "required"), w = try f.drive()
        f.host.fault = { if $0 == .beforeRetirementIntent { f.auth.allowed = false } }
        XCTAssertThrowsError(try f.accept(w)); f.host.fault = { _ in }
        let r = try f.host.catalog.load().records[0]
        XCTAssertTrue(r.work != nil && r.disposition == nil)
    }
    func testCorruptEstablishedClientAuthorityDoesNotBootstrapFromReplay() throws {
        let f = try JoinedFixture(route: "required"); _ = try f.drive()
        f.client.close()
        try Data(repeating: 0, count: 200).write(to: URL(fileURLWithPath: f.clientPath).appendingPathComponent("current"))
        XCTAssertThrowsError(try f.reopenClient())
        XCTAssertTrue(try f.host.catalog.load().records[0].work != nil)
    }
}
