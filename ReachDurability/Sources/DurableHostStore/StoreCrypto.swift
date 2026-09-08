import Foundation
import CryptoKit

public struct StoreKeys {
    let metadata: SymmetricKey
    let content: SymmetricKey
    public init(metadata: Data, content: Data) throws {
        guard metadata.count == 32, content.count == 32, metadata != content else { throw StoreError.invalid("two independent 256-bit injected keys required") }
        self.metadata = SymmetricKey(data: metadata); self.content = SymmetricKey(data: content)
    }
}
enum StoreCrypto {
    static let overhead = 116
    static let magic = Data("S81GCM01".utf8)
    struct Context: Encodable {
        let version = 1
        let store: String
        let record: String
        let role: String
        let binding: String
        let producingEpoch: UInt64?
    }
    static func seal(_ plain: Data, identity: StoreIdentity, role: String, record: String, epoch: UInt64?, keys: StoreKeys) throws -> Data {
        guard storeUUID(record), plain.count <= limit(role) else { throw StoreError.invalid("cipher input/record") }
        let context = try Context(store: identity.storeID, record: record, role: role, binding: identity.bindingDigest, producingEpoch: epoch)
        let key = role == "manifest" ? keys.metadata : keys.content
        let sealed = try AES.GCM.seal(plain, using: key, nonce: AES.GCM.Nonce(), authenticating: storeEncode(context))
        guard let combined = sealed.combined, combined.count == plain.count+28 else { throw StoreError.invalid("AES-GCM framing") }
        return magic + Data(identity.storeID.utf8) + Data(record.utf8) + storeUInt(UInt64(combined.count)) + combined
    }
    static func open(_ bytes: Data, identity: StoreIdentity, role: String, record expected: String? = nil, epoch: UInt64?, keys: StoreKeys) throws -> Data {
        guard bytes.count >= overhead, bytes.count <= limit(role)+overhead, bytes.prefix(8) == magic,
              let store = String(data: bytes[8..<44], encoding: .utf8), store == identity.storeID,
              let record = String(data: bytes[44..<80], encoding: .utf8), storeUUID(record), expected == nil || expected == record else { throw StoreError.invalid("cipher frame/context") }
        var offset = 80
        let length = try storeReadUInt(bytes, &offset, UInt64.self)
        guard length == UInt64(bytes.count-offset), length <= UInt64(limit(role)+28) else { throw StoreError.invalid("cipher length") }
        let context = try Context(store: store, record: record, role: role, binding: identity.bindingDigest, producingEpoch: epoch)
        do {
            let box = try AES.GCM.SealedBox(combined: bytes[offset...])
            return try AES.GCM.open(box, using: role == "manifest" ? keys.metadata : keys.content, authenticating: storeEncode(context))
        } catch { throw StoreError.invalid("cipher authentication") }
    }
    static func limit(_ role: String) -> Int {
        switch role { case "manifest": StoreLimits.manifest; case "candidate": StoreLimits.candidate; default: StoreLimits.replay }
    }
}
