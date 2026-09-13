import Foundation

/// Opaque local action handle. It is not Codable and cannot import a historical decision.
public struct Action {
    fileprivate let token: UUID
    public let request: Data
    public let sent: Sample
}

public struct Evaluation: Codable, Equatable {
    public enum Outcome: String, Codable { case eligible, hostExpired, clientExpired, bothExpired }
    public let outcome: Outcome
    public let r0: Sample
    public let r1: Sample
    public let r: Sample
    public let witness: Sample
    public let upper: UInt64
    public let hostDeadline: UInt64
    public let clientDeadline: UInt64
}

/// Serial, one action at a time. No certificate persistence or bracket-import API exists.
public final class Verifier {
    private let originals: Originals
    private let host: Registration
    private let client: Registration
    private let clock: ClockTracker
    private struct Pending {
        let action: Action
        let challenge: Challenge
        let r0: Sample
        var r1: Sample?
        var witness: Sample?
    }
    private var pending: Pending?
    private var actions = 0
    private var lastWitness: UInt64
    public init(originals: Originals, clock: any PolicyClock) throws {
        let records = try originals.records()
        self.originals = originals; host = records.host; client = records.client
        self.clock = try ClockTracker(clock)
        lastWitness = max(host.anchor, client.anchor)
    }
    public func observeWitnessLoss() { clock.invalidate(); pending = nil }
    public func observeWitnessIdentity(_ identity: Identity) throws {
        guard !clock.invalid else { throw Refusal.invalidated }
        guard identity == originals.pin else {
            observeWitnessLoss(); throw Refusal.binding
        }
    }
    public func begin(purpose: Purpose) throws -> Action {
        guard !clock.invalid else { throw Refusal.invalidated }
        guard pending == nil else { throw Refusal.busy }
        guard actions < 64 else { throw Refusal.capacity }
        // Prepare all binding bytes before r0; only local state assignment precedes send.
        let challenge = Challenge(domain: "reach-clock-challenge-v1", profile: .qualification,
            witness: originals.pin, registrations: originals.digests,
            receiverBoot: clock.last.boot, receiverIncarnation: clock.last.incarnation,
            nonce: UUID().uuidString.lowercased(), purpose: purpose)
        let token = UUID(), request = try Wire.encode(challenge)
        let r0 = try clock.read()
        let action = Action(token: token, request: request, sent: r0)
        pending = Pending(action: action, challenge: challenge, r0: r0)
        actions += 1
        return action
    }
    public func receive(_ data: Data, for action: Action) throws {
        guard !clock.invalid else { throw Refusal.invalidated }
        guard var local = pending, local.action.token == action.token else { throw Refusal.missing }
        guard local.witness == nil else { throw Refusal.replay }
        do {
            let signed = try Wire.decode(Signed.self, data)
            let certificate = try signed.checked(Certificate.self, pin: originals.pin)
            try certificate.challenge.validate(pin: originals.pin)
            guard certificate.domain == "reach-clock-certificate-v1",
                  certificate.challenge == local.challenge,
                  certificate.sample.boot == originals.pin.boot,
                  certificate.sample.incarnation == originals.pin.incarnation,
                  certificate.sample.nanoseconds >= lastWitness else { throw Refusal.binding }
            // r1 includes bounded parsing, signature verification and selection work.
            let r1 = try clock.read()
            _ = try upperBound(w: certificate.sample.nanoseconds, r0: local.r0, r1: r1, r: r1)
            local.r1 = r1; local.witness = certificate.sample
            lastWitness = certificate.sample.nanoseconds
            pending = local
        } catch {
            // A bad response cannot leave an older usable certificate behind.
            observeWitnessLoss(); throw error
        }
    }
    public func evaluate(_ action: Action) throws -> Evaluation {
        guard !clock.invalid else { throw Refusal.invalidated }
        guard let local = pending, local.action.token == action.token,
              let r1 = local.r1, let w = local.witness else { throw Refusal.missing }
        let r = try clock.read()
        let upper = try upperBound(w: w.nanoseconds, r0: local.r0, r1: r1, r: r)
        let h = upper >= host.deadline, c = upper >= client.deadline
        let result: Evaluation.Outcome = h ? (c ? .bothExpired : .hostExpired) : (c ? .clientExpired : .eligible)
        return Evaluation(outcome: result, r0: local.r0, r1: r1, r: r, witness: w,
                          upper: upper, hostDeadline: host.deadline, clientDeadline: client.deadline)
    }
    public func finish(_ action: Action) throws {
        guard !clock.invalid else { throw Refusal.invalidated }
        guard pending?.action.token == action.token else { throw Refusal.missing }
        pending = nil
    }
    /// Diagnostic control only: authentication supplies no current elapsed-time bound.
    public static func signatureOnlyControl(_ data: Data, originals: Originals) throws -> Sample {
        _ = try originals.records()
        let signed = try Wire.decode(Signed.self, data)
        let c = try signed.checked(Certificate.self, pin: originals.pin)
        guard c.domain == "reach-clock-certificate-v1" else { throw Refusal.binding }
        try c.challenge.validate(pin: originals.pin)
        guard c.challenge.registrations == originals.digests,
              c.sample.boot == originals.pin.boot,
              c.sample.incarnation == originals.pin.incarnation else { throw Refusal.binding }
        return c.sample
    }
}

func upperBound(w: UInt64, r0: Sample, r1: Sample, r: Sample) throws -> UInt64 {
    guard r0.boot == r1.boot, r1.boot == r.boot,
          r0.incarnation == r1.incarnation, r1.incarnation == r.incarnation,
          r.nanoseconds >= r1.nanoseconds, r1.nanoseconds >= r0.nanoseconds
    else { throw Refusal.clock }
    let elapsed = r.nanoseconds - r0.nanoseconds
    guard elapsed <= Profile.qualification.maximumAge else { throw Refusal.age }
    return try add(try add(w, multiply(Profile.qualification.factor, elapsed)), Profile.qualification.error)
}
