import XCTest
import Foundation
import CryptoKit
@testable import ClockPolicy

let second: UInt64 = 1_000_000_000
func uuid() -> String { UUID().uuidString.lowercased() }
final class FixtureClock: PolicyClock {
    var boot = uuid(), incarnation = uuid(), now: UInt64
    init(_ now: UInt64 = 100 * second) { self.now = now }
    func sample() throws -> Sample { Sample(boot: boot, incarnation: incarnation, nanoseconds: now) }
}
func refuses(_ error: Refusal, file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> Void) {
    XCTAssertThrowsError(try body(), file: file, line: line) { actual in
        XCTAssertEqual(actual as? Refusal, error, file: file, line: line)
    }
}
func pair(_ witness: Witness, host: UInt64 = 100 * second, client: UInt64 = 200 * second) throws -> Originals {
    let subject = uuid()
    return try Originals(pin: witness.identity,
        host: witness.register(subject: subject, role: .host, cap: host),
        client: witness.register(subject: subject, role: .client, cap: client))
}
func certified(_ witness: Witness, _ originals: Originals, _ clock: FixtureClock) throws -> (Verifier, Action) {
    let v = try Verifier(originals: originals, clock: clock)
    let action = try v.begin(purpose: .candidate)
    try v.receive(witness.respond(to: action.request), for: action)
    return (v, action)
}

final class PolicyTests: XCTestCase {
    func testIndependentExpiryAndExactDeadlineEquality() throws {
        for hostFirst in [true, false] {
            let wc = FixtureClock(), rc = FixtureClock(500 * second)
            let w = try Witness(clock: wc)
            let originals = try pair(w, host: (hostFirst ? 5 : 50) * second, client: (hostFirst ? 50 : 5) * second)
            let (v, a) = try certified(w, originals, rc)
            XCTAssertEqual(try v.evaluate(a).outcome, .eligible)
            rc.now += 2 * second - 1
            XCTAssertEqual(try v.evaluate(a).outcome, .eligible)
            rc.now += 1
            let equality = try v.evaluate(a)
            XCTAssertEqual(equality.upper, 105 * second)
            XCTAssertEqual(equality.outcome, hostFirst ? .hostExpired : .clientExpired)
        }
    }
    func testBothOriginalWindowsExpire() throws {
        let wc = FixtureClock(), rc = FixtureClock()
        let w = try Witness(clock: wc), originals = try pair(w, host: 3 * second, client: 4 * second)
        let (v, a) = try certified(w, originals, rc)
        rc.now += 2 * second
        XCTAssertEqual(try v.evaluate(a).outcome, .bothExpired)
    }
    func testOriginalRecordDeduplicationNeverRenewsEvenAfterExpiry() throws {
        let clock = FixtureClock(), w = try Witness(clock: clock), subject = uuid()
        let original = try w.register(subject: subject, role: .host, cap: 2 * second)
        clock.now += 500 * second
        XCTAssertEqual(try w.register(subject: subject, role: .host, cap: 2 * second), original)
        refuses(.conflict) { _ = try w.register(subject: subject, role: .host, cap: 3 * second) }
    }
    func testDurationCapacityAndOverflow() throws {
        let c = FixtureClock(), w = try Witness(clock: c)
        refuses(.binding) { _ = try w.register(subject: uuid(), role: .host, cap: 0) }
        refuses(.binding) { _ = try w.register(subject: uuid(), role: .host, cap: Profile.qualification.maximumDuration + 1) }
        _ = try w.register(subject: uuid(), role: .host, cap: Profile.qualification.maximumDuration)
        for _ in 1..<16 { _ = try w.register(subject: uuid(), role: .host, cap: second) }
        refuses(.capacity) { _ = try w.register(subject: uuid(), role: .host, cap: second) }
        let overflow = try Witness(clock: FixtureClock(UInt64.max - 1))
        refuses(.overflow) { _ = try overflow.register(subject: uuid(), role: .host, cap: 2) }
    }
    func testMaximumAgeChargesTwentyOneWitnessSeconds() throws {
        let wc = FixtureClock(), rc = FixtureClock(), w = try Witness(clock: wc)
        let (v, a) = try certified(w, pair(w), rc)
        rc.now += 10 * second
        XCTAssertEqual(try v.evaluate(a).upper, 121 * second)
        rc.now += 1
        refuses(.age) { _ = try v.evaluate(a) }
    }
    func testBoundOverflowAndInvalidBrackets() throws {
        let c = FixtureClock(0), r = try c.sample()
        refuses(.overflow) { _ = try upperBound(w: UInt64.max, r0: r, r1: r, r: r) }
        refuses(.overflow) { _ = try multiply(UInt64.max, 2) }
        c.now = 2
        let later = try c.sample()
        refuses(.clock) { _ = try upperBound(w: 0, r0: later, r1: r, r: later) }
        refuses(.clock) { _ = try upperBound(w: 0, r0: r, r1: later, r: r) }
        c.boot = uuid()
        refuses(.clock) { _ = try upperBound(w: 0, r0: r, r1: r, r: c.sample()) }
    }
    func testAdmittedRatesAndExactAssumptionBoundary() throws {
        let c = FixtureClock(0), r0 = try c.sample()
        c.now = 2 * second; let r = try c.sample()
        let upper = try upperBound(w: 100 * second, r0: r0, r1: r0, r: r)
        for witnessElapsed in [UInt64(0), second, 2 * second, 4 * second, 5 * second] {
            XCTAssertLessThanOrEqual(100 * second + witnessElapsed, upper)
        }
        XCTAssertEqual(upper, 105 * second)
    }
    func testViolatingRateFixtureExposesConditionalSafetyLimit() throws {
        let c = FixtureClock(0), r0 = try c.sample()
        c.now = 2 * second
        let upper = try upperBound(w: 100 * second, r0: r0, r1: r0, r: c.sample())
        let actualWitness = 105 * second + 1, deadline = upper + 1
        XCTAssertLessThan(upper, deadline) // candidate would allow under the assumed rate bound
        XCTAssertGreaterThanOrEqual(actualWitness, deadline) // violating clock is already expired
    }
    func testCanonicalAndBoundedWireDecoding() throws {
        let data = try Wire.encode(Profile.qualification)
        XCTAssertEqual(try Wire.decode(Profile.self, data), .qualification)
        refuses(.malformed) { _ = try Wire.decode(Profile.self, Data(repeating: 32, count: 65_537)) }
        var extra = String(decoding: data, as: UTF8.self); extra.insert(contentsOf: "\"unknown\":1,", at: extra.index(after: extra.startIndex))
        refuses(.malformed) { _ = try Wire.decode(Profile.self, Data(extra.utf8)) }
        var duplicate = String(decoding: data, as: UTF8.self); duplicate.insert(contentsOf: "\"factor\":2,", at: duplicate.index(after: duplicate.startIndex))
        refuses(.malformed) { _ = try Wire.decode(Profile.self, Data(duplicate.utf8)) }
    }
}
