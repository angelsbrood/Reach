import Foundation
import CryptoKit

enum LifecycleCrypto {
    static let overhead = 116
    struct Context: Encodable { let version = 1; let root: String; let boot: String; let policy: String; let role: String; let record: String }
    static func seal(_ plain: Data, role: String, record: String, identity: LifecycleIdentity, key: SymmetricKey) throws -> Data {
        guard ["catalog", "request"].contains(role), plain.count <= LifecycleLimits.catalog, lcUUID(record) else { throw LifecycleError.invalid("cipher input") }
        let context = Context(root: identity.incarnation, boot: identity.boot, policy: identity.clockPolicy, role: role, record: record)
        let box = try AES.GCM.seal(plain, using: key, nonce: AES.GCM.Nonce(), authenticating: lcEncode(context))
        guard let combined = box.combined else { throw LifecycleError.invalid("cipher frame") }
        return Data("S82GCM01".utf8) + Data(identity.incarnation.utf8) + Data(record.utf8) + lcUInt(UInt64(combined.count)) + combined
    }
    static func open(_ cipher: Data, role: String, record expected: String? = nil, identity: LifecycleIdentity, key: SymmetricKey) throws -> Data {
        guard (overhead...LifecycleLimits.catalog+overhead).contains(cipher.count), cipher.prefix(8) == Data("S82GCM01".utf8),
              String(data: cipher[8..<44], encoding: .utf8) == identity.incarnation,
              let record = String(data: cipher[44..<80], encoding: .utf8), lcUUID(record), expected == nil || record == expected,
              cipher[80..<88].reduce(UInt64(0), { ($0 << 8) | UInt64($1) }) == UInt64(cipher.count-88) else { throw LifecycleError.invalid("cipher framing/context") }
        let context = Context(root: identity.incarnation, boot: identity.boot, policy: identity.clockPolicy, role: role, record: record)
        do { return try AES.GCM.open(AES.GCM.SealedBox(combined: cipher[88...]), using: key, authenticating: lcEncode(context)) }
        catch { throw LifecycleError.invalid("cipher authentication") }
    }
}
