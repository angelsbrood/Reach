import XCTest
import Foundation
import CryptoKit
@testable import ClockPolicy

/// Deliberate signer-controlled mutations; these are genuinely signed negative fixtures.
struct SigningFixture {
    let key = Curve25519.Signing.PrivateKey()
    let boot = uuid(), incarnation = uuid(), epoch = uuid(), subject = uuid()
    var identity: Identity { Identity(publicKey: key.publicKey.rawRepresentation, boot: boot, incarnation: incarnation, epoch: epoch) }
    func originals() throws -> Originals {
        func original(_ role: Role) throws -> Data {
            let record = Registration(domain: "reach-original-clock-registration-v1", profile: .qualification,
                witness: identity, subject: subject, role: role, anchor: 100 * second, cap: 200 * second, deadline: 300 * second)
            return try Wire.encode(Signed(record, key: key))
        }
        return try Originals(pin: identity, host: original(.host), client: original(.client))
    }
    func sign(_ challenge: Challenge, sample: Sample? = nil, domain: String = "reach-clock-certificate-v1") throws -> Data {
        try Wire.encode(Signed(Certificate(domain: domain, challenge: challenge,
            sample: sample ?? Sample(boot: boot, incarnation: incarnation, nanoseconds: 100 * second)), key: key))
    }
}

final class BindingTests: XCTestCase {
    func testSignedBindingMutationsInvalidateVerifierIncarnation() throws {
        for mutation in ["nonce", "purpose", "boot", "process", "epoch", "profile", "registrations", "domain"] {
            let f = SigningFixture(), c = FixtureClock()
            let v = try Verifier(originals: f.originals(), clock: c)
            let a = try v.begin(purpose: .candidate)
            let q = try Wire.decode(Challenge.self, a.request)
            let changedPin = Identity(publicKey: f.identity.publicKey, boot: f.boot, incarnation: f.incarnation, epoch: uuid())
            let changedProfile = Profile(domain: "reach-clock-qualification-v2", units: "continuous-monotonic-ns", factor: 2,
                error: second, maximumAge: 10 * second, maximumDuration: 86_400 * second)
            let mutated = Challenge(domain: q.domain, profile: mutation == "profile" ? changedProfile : q.profile,
                witness: mutation == "epoch" ? changedPin : q.witness,
                registrations: mutation == "registrations" ? q.registrations.reversed() : q.registrations,
                receiverBoot: mutation == "boot" ? uuid() : q.receiverBoot,
                receiverIncarnation: mutation == "process" ? uuid() : q.receiverIncarnation,
                nonce: mutation == "nonce" ? uuid() : q.nonce,
                purpose: mutation == "purpose" ? .blocking : q.purpose)
            let response = try f.sign(mutated, domain: mutation == "domain" ? "historical-decision" : "reach-clock-certificate-v1")
            refuses(mutation == "profile" ? .profile : .binding) { try v.receive(response, for: a) }
            refuses(.invalidated) { _ = try v.begin(purpose: .candidate) }
        }
    }
    func testSignatureFailureAndReplacementPin() throws {
        let wc = FixtureClock(), rc = FixtureClock(), w = try Witness(clock: wc)
        let originals = try pair(w), v = try Verifier(originals: originals, clock: rc)
        let a = try v.begin(purpose: .candidate)
        let signed = try Wire.decode(Signed.self, w.respond(to: a.request))
        struct Bad: Codable { let body: Data; let signature: Data }
        let bad = try Wire.encode(Bad(body: signed.body, signature: Data(repeating: 0, count: 64)))
        refuses(.signature) { try v.receive(bad, for: a) }
        let replacement = try Witness(clock: wc)
        let fresh = try Verifier(originals: originals, clock: rc)
        refuses(.binding) { try fresh.observeWitnessIdentity(replacement.identity) }
        refuses(.invalidated) { _ = try fresh.begin(purpose: .candidate) }
        refuses(.binding) { _ = try replacement.respond(to: a.request) }
        refuses(.signature) { _ = try Originals(pin: replacement.identity, host: originals.host, client: originals.client) }
    }
    func testRegistrationRoleAndSubjectSwapsRefuse() throws {
        let w = try Witness(clock: FixtureClock()), first = try pair(w), second = try pair(w)
        refuses(.binding) { _ = try Originals(pin: w.identity, host: first.client, client: first.host) }
        refuses(.binding) { _ = try Originals(pin: w.identity, host: first.host, client: second.client) }
    }
    func testWitnessReplayAndActionReplayCannotCreateFreshBracket() throws {
        let wc = FixtureClock(), rc = FixtureClock(), w = try Witness(clock: wc)
        let v = try Verifier(originals: pair(w), clock: rc)
        let a = try v.begin(purpose: .candidate), response = try w.respond(to: a.request)
        refuses(.replay) { _ = try w.respond(to: a.request) }
        try v.receive(response, for: a)
        refuses(.replay) { try v.receive(response, for: a) }
        refuses(.busy) { _ = try v.begin(purpose: .blocking) }
        try v.finish(a)
        refuses(.missing) { _ = try v.evaluate(a) }
        let b = try v.begin(purpose: .candidate)
        refuses(.binding) { try v.receive(response, for: b) }
    }
    func testNewProcessCannotImportOldResponseOrDecision() throws {
        let wc = FixtureClock(), rc = FixtureClock(), w = try Witness(clock: wc)
        let originals = try pair(w), v = try Verifier(originals: originals, clock: rc)
        let a = try v.begin(purpose: .candidate), response = try w.respond(to: a.request)
        try v.receive(response, for: a)
        let oldDecision = try Wire.encode(v.evaluate(a))
        let reopened = try Verifier(originals: originals, clock: FixtureClock())
        let fresh = try reopened.begin(purpose: .candidate)
        refuses(.binding) { try reopened.receive(response, for: fresh) }
        let other = try Verifier(originals: originals, clock: FixtureClock())
        let pending = try other.begin(purpose: .candidate)
        refuses(.malformed) { try other.receive(oldDecision, for: pending) }
    }
    func testMissingResponseAndWrongLocalHandle() throws {
        let w = try Witness(clock: FixtureClock()), originals = try pair(w)
        let v = try Verifier(originals: originals, clock: FixtureClock())
        let other = try Verifier(originals: originals, clock: FixtureClock())
        let a = try v.begin(purpose: .candidate), b = try other.begin(purpose: .candidate)
        refuses(.missing) { _ = try v.evaluate(a) }
        refuses(.missing) { try v.receive(w.respond(to: b.request), for: b) }
    }
}
