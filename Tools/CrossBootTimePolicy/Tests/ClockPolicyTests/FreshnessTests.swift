import XCTest
import Foundation
@testable import ClockPolicy

final class FreshnessTests: XCTestCase {
    func testDelayedSignedResponseChargesOriginalSendNotReceipt() throws {
        let wc = FixtureClock(), rc = FixtureClock(), w = try Witness(clock: wc)
        let originals = try pair(w, host: 5 * second), v = try Verifier(originals: originals, clock: rc)
        let a = try v.begin(purpose: .candidate), response = try w.respond(to: a.request)
        XCTAssertLessThan(try Verifier.signatureOnlyControl(response, originals: originals).nanoseconds,
                          try originals.records().host.deadline)
        rc.now += 3 * second; wc.now += 3 * second
        try v.receive(response, for: a)
        let result = try v.evaluate(a)
        XCTAssertEqual(result.outcome, .hostExpired)
        XCTAssertEqual(result.r0.nanoseconds, 100 * second)
        XCTAssertEqual(result.r1.nanoseconds, 103 * second)
        XCTAssertEqual(result.upper, 107 * second)
    }
    func testBlockingWorkDoesNotResetBracket() throws {
        let rc = FixtureClock(), w = try Witness(clock: FixtureClock())
        let (v, a) = try certified(w, pair(w, client: 5 * second), rc)
        let before = try v.evaluate(a); XCTAssertEqual(before.outcome, .eligible)
        rc.now += 3 * second
        let after = try v.evaluate(a)
        XCTAssertEqual(after.r0, before.r0); XCTAssertEqual(after.r1, before.r1)
        XCTAssertEqual(after.outcome, .clientExpired)
    }
    func testFreshCertificateReducesUncertaintyWithoutRenewal() throws {
        let wc = FixtureClock(), rc = FixtureClock(), w = try Witness(clock: wc)
        let originals = try pair(w, host: 30 * second), before = try originals.records()
        let (v, a) = try certified(w, originals, rc)
        rc.now += 5 * second; wc.now += 5 * second
        let old = try v.evaluate(a); try v.finish(a)
        let b = try v.begin(purpose: .candidate)
        try v.receive(w.respond(to: b.request), for: b)
        let fresh = try v.evaluate(b)
        XCTAssertLessThan(fresh.upper, old.upper)
        XCTAssertEqual(fresh.hostDeadline, before.host.deadline)
        XCTAssertEqual(fresh.clientDeadline, before.client.deadline)
    }
    func testUnobservedLossBoundedUseThenAgeRefusal() throws {
        let rc = FixtureClock()
        var witness: Witness? = try Witness(clock: FixtureClock())
        let originals = try pair(witness!)
        let (v, a) = try certified(witness!, originals, rc)
        witness = nil // verifier has not observed loss; no instantaneous failure detector is claimed
        rc.now += 9 * second; XCTAssertEqual(try v.evaluate(a).outcome, .eligible)
        rc.now += second + 1; refuses(.age) { _ = try v.evaluate(a) }
    }
    func testObservedWitnessLossPermanentlyInvalidates() throws {
        let rc = FixtureClock(), w = try Witness(clock: FixtureClock())
        let (v, a) = try certified(w, pair(w), rc)
        v.observeWitnessLoss()
        refuses(.invalidated) { _ = try v.evaluate(a) }
        refuses(.invalidated) { try v.observeWitnessIdentity(w.identity) }
        refuses(.invalidated) { _ = try v.begin(purpose: .candidate) }
    }
    func testReceiverRegressionBootAndProcessChangesLatch() throws {
        for kind in ["regression", "boot", "process"] {
            let rc = FixtureClock(), w = try Witness(clock: FixtureClock())
            let (v, a) = try certified(w, pair(w), rc)
            switch kind { case "regression": rc.now -= 1; case "boot": rc.boot = uuid(); default: rc.incarnation = uuid() }
            refuses(.clock) { _ = try v.evaluate(a) }
            refuses(.invalidated) { _ = try v.evaluate(a) }
        }
    }
    func testReceiverChangeBetweenSendAndReceiveRefuses() throws {
        let rc = FixtureClock(), w = try Witness(clock: FixtureClock())
        let v = try Verifier(originals: pair(w), clock: rc), a = try v.begin(purpose: .candidate)
        let response = try w.respond(to: a.request)
        rc.boot = uuid()
        refuses(.clock) { try v.receive(response, for: a) }
    }
    func testWitnessEpochAndRollbackFaultsLatch() throws {
        for kind in ["regression", "boot", "process"] {
            let wc = FixtureClock(), rc = FixtureClock(), w = try Witness(clock: wc)
            let v = try Verifier(originals: pair(w), clock: rc), a = try v.begin(purpose: .candidate)
            switch kind { case "regression": wc.now -= 1; case "boot": wc.boot = uuid(); default: wc.incarnation = uuid() }
            refuses(.clock) { _ = try w.respond(to: a.request) }
            refuses(.invalidated) { _ = try w.observe() }
        }
    }
    func testAuthenticatedWitnessRegressionAndWrongSampleBootRefuse() throws {
        for wrongBoot in [false, true] {
            let f = SigningFixture(), rc = FixtureClock(), v = try Verifier(originals: f.originals(), clock: rc)
            let a = try v.begin(purpose: .candidate), q = try Wire.decode(Challenge.self, a.request)
            let sample = Sample(boot: wrongBoot ? uuid() : f.boot, incarnation: f.incarnation,
                                nanoseconds: wrongBoot ? 100 * second : 100 * second - 1)
            refuses(.binding) { try v.receive(f.sign(q, sample: sample), for: a) }
            refuses(.invalidated) { _ = try v.evaluate(a) }
        }
    }
    func testDelayedResponseOlderThanTenSecondsRefusesAtReceipt() throws {
        let rc = FixtureClock(), w = try Witness(clock: FixtureClock())
        let v = try Verifier(originals: pair(w), clock: rc), a = try v.begin(purpose: .candidate)
        let response = try w.respond(to: a.request)
        rc.now += 10 * second + 1
        refuses(.age) { try v.receive(response, for: a) }
    }
}
