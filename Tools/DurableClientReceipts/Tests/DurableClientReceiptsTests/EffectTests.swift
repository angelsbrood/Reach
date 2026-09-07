import XCTest
import Foundation
import ClientReceiptFixtures
@testable import DurableClientReceipts

final class EffectTests: XCTestCase {
    func testUnknownNeverReissuesAndKnownOutcomeIsExact() throws {
        let f = try Fixture(); _ = try f.accept()
        XCTAssertTrue(try f.state() == .unbegun)
        XCTAssertThrowsError(try f.outcome())
        guard case .fresh = try f.begin() else { return XCTFail("missing first permission") }
        guard case .unknown = try f.begin() else { return XCTFail("reissued permission") }
        try f.reopen(); XCTAssertTrue(try f.state() == .unknown)
        guard case .unknown = try f.begin() else { return XCTFail("reissued after reopen") }
        let value = try f.outcome(); XCTAssertTrue(try f.outcome() == value)
        guard case .known(let stored) = try f.begin() else { return XCTFail("missing stored outcome") }
        XCTAssertTrue(stored == value); try f.reopen(); XCTAssertTrue(try f.state() == .known(value))
        XCTAssertTrue(try f.receipt().terminal)
    }
    func testExactUTF8CallAndOutcomeBindings() throws {
        let f = try Fixture(); _ = try f.accept()
        let variants = [try ReceiptFixtures.binding("other"), try ReceiptFixtures.binding(name: "other"),
                        try ReceiptFixtures.binding(arguments: "{\"word\":\"e\u{301}\"}")]
        for b in variants {
            XCTAssertThrowsError(try f.begin(b)); XCTAssertThrowsError(try f.state(b))
            XCTAssertThrowsError(try f.client.recordOutcome(ReceiptFixtures.outcome(f.a), binding: b,
                handle: f.h, authority: f.a, authorization: f.auth))
        }
        XCTAssertThrowsError(try ToolBinding(id: Data([255]), name: Data([65]), arguments: Data()))
        guard case .fresh = try f.begin() else { return XCTFail("missing permission") }
        let known = try f.outcome(ReceiptFixtures.outcome(f.a, kind: .failure))
        XCTAssertTrue(known.kind == .failure)
        XCTAssertThrowsError(try f.outcome(ReceiptFixtures.outcome(f.a, kind: .success)))
        XCTAssertThrowsError(try f.outcome(ReceiptFixtures.outcome(f.a, kind: .failure, result: Data("different".utf8))))
        XCTAssertThrowsError(try f.outcome(.init(kind: known.kind, result: known.result, digest: String(repeating: "0", count: 64))))
        XCTAssertTrue(try f.state() == .known(known))
    }
    func testToolObligationOutlivesTerminalAndHostDeadlines() throws {
        let f = try Fixture(); _ = try f.accept(); _ = try f.begin()
        f.clock.time += 1_000_000_000_000 // Beyond 120s, 15m, and host terminal retention.
        try f.client.maintenance(); try f.reopen()
        XCTAssertTrue(try f.state() == .unknown); XCTAssertTrue(try f.receipt().terminal)
        _ = try f.outcome(); XCTAssertTrue(try f.state() == .known(ReceiptFixtures.outcome(f.a)))
        let other = try Fixture()
        _ = try other.accept(ReceiptFixtures.envelope([
            .toolCallAppendArguments(entryID: nil, id: "call-1", name: "fake", content: "{\"word\":\"é\"}", tokenCount: 1),
            .finished(.cancelled)]))
        XCTAssertTrue(try other.state() == .unbegun); _ = try other.begin(); _ = try other.outcome()
        XCTAssertTrue(try other.receipt().terminal)
    }
    func testGlobalOutcomeCreditCannotBeSpentByAdmissions() throws {
        let f = try Fixture(quota: 6<<20)
        XCTAssertThrowsError(try f.accept()) // Two pending maximum outcomes cannot fit this real quota.
        XCTAssertEqual(try f.receipt().high, 0)
        _ = try f.accept(ReceiptFixtures.frame(calls: 1))
        let before = try f.client.fs.usage().bytes
        _ = try f.begin()
        let a = try ReceiptFixtures.authority(generation: "second")
        let h = try f.client.open(a, authorization: f.auth)
        XCTAssertThrowsError(try f.client.accept(ReceiptFixtures.frame(calls: 1), requestedCursor: 0, handle: h, authority: a, authorization: f.auth))
        XCTAssertEqual(try f.client.receipt(h, authority: a, authorization: f.auth).high, 0)
        let outcome = try ReceiptFixtures.outcome(f.a, result: Data(repeating: 0x5a, count: 700_000))
        _ = try f.outcome(outcome)
        let after = try f.client.fs.usage().bytes
        XCTAssertGreaterThan(after, before); XCTAssertLessThanOrEqual(after, 6<<20)
        try f.reopen(); XCTAssertTrue(try f.state() == .known(outcome))
    }
    func testPostPersistenceRevocationForReceiptPermissionOutcomeAndStatus() throws {
        for action in ["receipt", "permission", "outcome", "status", "inbox", "open"] {
            let f = try Fixture()
            if action != "receipt" { _ = try f.accept() }
            if action == "outcome" { _ = try f.begin() }
            f.fault = { point in
                if point == (["status", "inbox", "open"].contains(action) ? .beforePublication : .beforeDirectorySync) { f.auth.allowed = false }
            }
            switch action {
            case "receipt": XCTAssertThrowsError(try f.accept())
            case "permission": XCTAssertThrowsError(try f.begin())
            case "outcome": XCTAssertThrowsError(try f.outcome())
            case "inbox": XCTAssertThrowsError(try f.client.inbox(f.h, authority: f.a, authorization: f.auth))
            case "open": XCTAssertThrowsError(try f.client.open(f.a, authorization: f.auth))
            default: XCTAssertThrowsError(try f.state())
            }
            f.fault = { _ in }; f.auth.allowed = true
            if action == "permission" { XCTAssertTrue(try f.state() == .unknown) }
            if action == "outcome" { XCTAssertTrue(try f.state() == .known(ReceiptFixtures.outcome(f.a))) }
            XCTAssertEqual(try f.receipt().high, 4)
        }
    }
    func testPostPersistenceExpiryForEveryPrivatePublication() throws {
        for action in ["receipt", "permission", "outcome", "status", "inbox", "open"] {
            let f = try Fixture(expires: 1000)
            if action != "receipt" { _ = try f.accept() }
            if action == "outcome" { _ = try f.begin() }
            f.fault = { point in
                let boundary: ClientFault = ["status", "inbox", "open"].contains(action) ? .beforePublication : .beforeDirectorySync
                if point == boundary { f.clock.time = 1000 }
            }
            switch action {
            case "receipt": XCTAssertThrowsError(try f.accept())
            case "permission": XCTAssertThrowsError(try f.begin())
            case "outcome": XCTAssertThrowsError(try f.outcome())
            case "status": XCTAssertThrowsError(try f.state())
            case "open": XCTAssertThrowsError(try f.client.open(f.a, authorization: f.auth))
            default: XCTAssertThrowsError(try f.client.inbox(f.h, authority: f.a, authorization: f.auth))
            }
            f.fault = { _ in }; try f.client.maintenance()
            XCTAssertTrue(try f.client.readManifest().records.isEmpty)
            XCTAssertThrowsError(try f.client.open(f.a, authorization: f.auth))
        }
    }
}
