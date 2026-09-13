import Foundation
import CryptoKit

/// Serial, process-memory-only issuer. Its private key and registrations cannot be restored.
public final class Witness {
    private let key = Curve25519.Signing.PrivateKey()
    private let clock: ClockTracker
    public let identity: Identity
    private var originals: [String: Data] = [:]
    private var usedNonces: Set<String> = []
    public init(clock: any PolicyClock) throws {
        let tracker = try ClockTracker(clock)
        self.clock = tracker
        identity = Identity(publicKey: key.publicKey.rawRepresentation,
                            boot: tracker.last.boot, incarnation: tracker.last.incarnation,
                            epoch: UUID().uuidString.lowercased())
    }
    public func observe() throws -> Sample { try clock.read() }
    public func register(subject: String, role: Role, cap: UInt64) throws -> Data {
        let now = try clock.read()
        guard validUUID(subject), cap > 0, cap <= Profile.qualification.maximumDuration
        else { throw Refusal.binding }
        let slot = subject + ":" + role.rawValue
        if let existing = originals[slot] {
            let record = try Wire.decode(Signed.self, existing).checked(Registration.self, pin: identity)
            guard record.cap == cap else { throw Refusal.conflict }
            return existing
        }
        guard originals.count < 16 else { throw Refusal.capacity }
        let record = Registration(domain: "reach-original-clock-registration-v1",
            profile: .qualification, witness: identity, subject: subject, role: role,
            anchor: now.nanoseconds, cap: cap, deadline: try add(now.nanoseconds, cap))
        let data = try Wire.encode(Signed(record, key: key))
        originals[slot] = data
        return data
    }
    public func respond(to data: Data) throws -> Data {
        let challenge = try Wire.decode(Challenge.self, data)
        try challenge.validate(pin: identity)
        let selected = try challenge.registrations.map { digest -> Registration in
            guard let bytes = originals.values.first(where: { Wire.digest($0) == digest })
            else { throw Refusal.binding }
            return try Wire.decode(Signed.self, bytes).checked(Registration.self, pin: identity)
        }
        guard selected[0].role == .host, selected[1].role == .client,
              selected[0].subject == selected[1].subject else { throw Refusal.binding }
        guard !usedNonces.contains(challenge.nonce) else { throw Refusal.replay }
        guard usedNonces.count < 128 else { throw Refusal.capacity }
        // Sample only after bounded decoding and original-registration selection.
        let sample = try clock.read()
        usedNonces.insert(challenge.nonce)
        return try Wire.encode(Signed(Certificate(domain: "reach-clock-certificate-v1",
                                                 challenge: challenge, sample: sample), key: key))
    }
}
