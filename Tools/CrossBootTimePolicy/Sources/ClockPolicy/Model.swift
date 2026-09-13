import Foundation
import CryptoKit

public enum Refusal: String, Error, CustomStringConvertible {
    case malformed, profile, binding, signature, capacity, conflict, replay
    case overflow, clock, invalidated, missing, age, busy
    public var description: String { rawValue }
}

/// Deliberate cooperating-rig assumptions, not platform rate/error guarantees.
public struct Profile: Codable, Equatable, Sendable {
    public let domain: String
    public let units: String
    public let factor: UInt64
    public let error: UInt64
    public let maximumAge: UInt64
    public let maximumDuration: UInt64
    public static let qualification = Profile(
        domain: "reach-clock-qualification-v1", units: "continuous-monotonic-ns",
        factor: 2, error: 1_000_000_000, maximumAge: 10_000_000_000,
        maximumDuration: 86_400_000_000_000)
}

public enum Wire {
    public static let maximumBytes = 65_536
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        guard data.count <= maximumBytes else { throw Refusal.capacity }
        return data
    }
    /// Canonical re-encoding also rejects duplicate/unknown keys and alternative encodings.
    public static func decode<T: Codable>(_ type: T.Type, _ data: Data) throws -> T {
        guard !data.isEmpty, data.count <= maximumBytes else { throw Refusal.malformed }
        do {
            let value = try JSONDecoder().decode(type, from: data)
            guard try encode(value) == data else { throw Refusal.malformed }
            return value
        } catch { throw Refusal.malformed }
    }
    public static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

public struct Signed: Codable, Equatable, Sendable {
    public let body: Data
    public let signature: Data
    init<T: Encodable>(_ value: T, key: Curve25519.Signing.PrivateKey) throws {
        body = try Wire.encode(value)
        signature = try key.signature(for: body)
    }
    func checked<T: Codable>(_ type: T.Type, pin: Identity) throws -> T {
        guard body.count <= Wire.maximumBytes, signature.count == 64,
              pin.publicKey.count == 32,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: pin.publicKey),
              key.isValidSignature(signature, for: body) else { throw Refusal.signature }
        return try Wire.decode(type, body)
    }
}

public struct Identity: Codable, Equatable, Sendable {
    public let publicKey: Data
    public let boot: String
    public let incarnation: String
    public let epoch: String
    func validate() throws {
        guard publicKey.count == 32, validUUID(boot), validUUID(incarnation),
              validUUID(epoch) else { throw Refusal.binding }
    }
}

public enum Role: String, Codable, Sendable { case host, client }
public enum Purpose: String, Codable, Sendable {
    case candidate = "qualification-candidate"
    case blocking = "qualification-post-blocking"
}

public struct Registration: Codable, Equatable, Sendable {
    let domain: String
    public let profile: Profile
    public let witness: Identity
    public let subject: String
    public let role: Role
    public let anchor: UInt64
    public let cap: UInt64
    public let deadline: UInt64
    func validate(pin: Identity) throws {
        guard domain == "reach-original-clock-registration-v1", profile == .qualification
        else { throw Refusal.profile }
        try witness.validate()
        guard witness == pin, validUUID(subject), cap > 0,
              cap <= profile.maximumDuration, try add(anchor, cap) == deadline
        else { throw Refusal.binding }
    }
}

/// Exact original signed bytes are the persistence boundary. No old runtime timestamp enters it.
public struct Originals: Codable, Equatable, Sendable {
    public let pin: Identity
    public let host: Data
    public let client: Data
    public init(pin: Identity, host: Data, client: Data) throws {
        self.pin = pin; self.host = host; self.client = client
        _ = try records()
    }
    public func records() throws -> (host: Registration, client: Registration) {
        try pin.validate()
        let h = try Wire.decode(Signed.self, host).checked(Registration.self, pin: pin)
        let c = try Wire.decode(Signed.self, client).checked(Registration.self, pin: pin)
        try h.validate(pin: pin); try c.validate(pin: pin)
        guard h.role == .host, c.role == .client, h.subject == c.subject
        else { throw Refusal.binding }
        return (h, c)
    }
    public var digests: [String] { [Wire.digest(host), Wire.digest(client)] }
}

public struct Challenge: Codable, Equatable, Sendable {
    let domain: String
    let profile: Profile
    let witness: Identity
    let registrations: [String]
    let receiverBoot: String
    let receiverIncarnation: String
    let nonce: String
    let purpose: Purpose
    func validate(pin: Identity) throws {
        guard domain == "reach-clock-challenge-v1", profile == .qualification
        else { throw Refusal.profile }
        guard witness == pin, registrations.count == 2,
              registrations.allSatisfy({ $0.count == 64 && $0.allSatisfy { $0.isHexDigit && !$0.isUppercase } }),
              validUUID(receiverBoot), validUUID(receiverIncarnation), validUUID(nonce)
        else { throw Refusal.binding }
    }
}

struct Certificate: Codable, Equatable {
    let domain: String
    let challenge: Challenge
    let sample: Sample
}

func validUUID(_ value: String) -> Bool {
    value.count == 36 && UUID(uuidString: value)?.uuidString.lowercased() == value
}
func add(_ a: UInt64, _ b: UInt64) throws -> UInt64 {
    let (result, overflow) = a.addingReportingOverflow(b)
    guard !overflow else { throw Refusal.overflow }; return result
}
func multiply(_ a: UInt64, _ b: UInt64) throws -> UInt64 {
    let (result, overflow) = a.multipliedReportingOverflow(by: b)
    guard !overflow else { throw Refusal.overflow }; return result
}
