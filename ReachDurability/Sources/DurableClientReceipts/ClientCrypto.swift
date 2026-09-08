import Foundation
import CryptoKit

enum ClientCrypto {
    // Header: magic + revision + record UUID + generation UUID; GCM nonce/tag; ownership MAC.
    static let overhead = 148
    static let zero = "00000000-0000-0000-0000-000000000000"
    struct AAD: Encodable { let version: Int; let mode: String?; let pair: String?; let root: String; let boot: String; let policy: String; let role: String; let record: String; let generation: String; let revision: UInt64 }
    struct Frame { let revision: UInt64; let record: String; let generation: String; let combined: Data; let aad: Data }
    static func ownershipKey(_ key: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: key, info: Data("S83/orphan-ownership/v1".utf8), outputByteCount: 32)
    }
    static func seal(_ plain: Data, role: String, record: String, generation: String, revision: UInt64,
                     environment e: ClientEnvironment, key: SymmetricKey, rootKey: SymmetricKey) throws -> Data {
        guard crUUID(record), crUUID(generation), revision > 0,
              plain.count <= (role == "manifest" ? ClientLimits.manifest : ClientLimits.snapshot) else { throw ClientError.full }
        let aad = try crEncode(AAD(version: e.authorityMode == .legacy ? 1 : 2, mode: e.authorityMode == .legacy ? nil : e.authorityMode.rawValue, pair: e.pairDigest, root: e.rootID, boot: e.boot, policy: e.policy, role: role, record: record, generation: generation, revision: revision))
        let box = try AES.GCM.seal(plain, using: key, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = box.combined else { throw ClientError.unavailable }
        let body = Data((e.authorityMode == .legacy ? "S83GCM01" : "S95GCM02").utf8)+crUInt(revision)+Data(record.utf8)+Data(generation.utf8)+combined
        let mac = Data(HMAC<SHA256>.authenticationCode(for: aad+body, using: ownershipKey(rootKey)))
        return body+mac
    }
    /// Authentication of orphan ownership does not recover a deleted generation key.
    static func inspect(_ input: Data, role: String, environment e: ClientEnvironment, rootKey: SymmetricKey) throws -> Frame {
        let data = Data(input)
        guard data.count >= overhead, data.count <= (role == "manifest" ? ClientLimits.manifest : ClientLimits.snapshot)+overhead,
              data.prefix(8) == Data((e.authorityMode == .legacy ? "S83GCM01" : "S95GCM02").utf8),
              let record = String(data: data[16..<52], encoding: .utf8), crUUID(record),
              let generation = String(data: data[52..<88], encoding: .utf8), crUUID(generation) else { throw ClientError.unavailable }
        let revision = data[8..<16].reduce(UInt64(0)) { ($0<<8)|UInt64($1) }
        guard revision > 0, role != "manifest" || generation == zero else { throw ClientError.unavailable }
        let aad = try crEncode(AAD(version: e.authorityMode == .legacy ? 1 : 2, mode: e.authorityMode == .legacy ? nil : e.authorityMode.rawValue, pair: e.pairDigest, root: e.rootID, boot: e.boot, policy: e.policy, role: role, record: record, generation: generation, revision: revision))
        guard HMAC<SHA256>.isValidAuthenticationCode(data.suffix(32), authenticating: aad+data.dropLast(32), using: ownershipKey(rootKey)) else { throw ClientError.unavailable }
        return Frame(revision: revision, record: record, generation: generation, combined: Data(data[88..<data.count-32]), aad: aad)
    }
    static func open(_ data: Data, role: String, environment: ClientEnvironment, key: SymmetricKey, rootKey: SymmetricKey) throws -> (Data, Frame) {
        let frame = try inspect(data, role: role, environment: environment, rootKey: rootKey)
        do { return (try AES.GCM.open(AES.GCM.SealedBox(combined: frame.combined), using: key, authenticating: frame.aad), frame) }
        catch { throw ClientError.unavailable }
    }
}
