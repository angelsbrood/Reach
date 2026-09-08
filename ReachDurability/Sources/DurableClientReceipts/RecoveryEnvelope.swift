import Foundation
import CryptoKit
import RecoveryContract

/// Only opaque ownership fields and ciphertext are outside encryption.
struct RecoveryEnvelopeBody: Codable {
    var version=1
    let bootstrap:String, core:String, root:String, record:String, context:String, cipher:Data
}
struct RecoveryEnvelope: Codable { let body:RecoveryEnvelopeBody, mac:Data }
enum RecoveryEncryption {
    struct AAD: Encodable { let revision=RecoveryLimits.revision; let binding:RecoveryBinding; let record:String, context:String; let issued:UInt64, expires:UInt64; let retention: String? }
    static func ownership(_ root:SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial:root,info:Data("S86/ticket-orphan-ownership/v1".utf8),outputByteCount:32)
    }
    static func key(_ live:LiveClientRecord, record:String, binding:RecoveryBinding) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial:SymmetricKey(data:live.key),salt:Data(binding.core.utf8),
            info:Data("S86/ticket-content/v1\0".utf8)+Data(record.utf8)+Data(live.contextDigest.utf8),outputByteCount:32)
    }
    static func aad(_ live:LiveClientRecord, record:String, binding:RecoveryBinding) throws -> Data {
        try RecoveryCodec.encode(AAD(binding:binding,record:record,context:live.contextDigest,issued:live.issued,expires:live.expires,retention:live.retention?.digest))
    }
    static func seal(_ ticket:Data, live:LiveClientRecord, record:String, binding:RecoveryBinding, root:SymmetricKey) throws -> Data {
        guard binding.independent == (live.retention != nil), live.retention?.pair == binding.pair else { throw RecoveryError.unavailable }
        guard !ticket.isEmpty, ticket.count<=RecoveryLimits.ticket else { throw RecoveryError.full }
        let box=try AES.GCM.seal(ticket,using:key(live,record:record,binding:binding),nonce:AES.GCM.Nonce(),authenticating:aad(live,record:record,binding:binding))
        guard let combined=box.combined else { throw RecoveryError.unavailable }
        let body=RecoveryEnvelopeBody(version: binding.independent ? 2 : 1, bootstrap:binding.bootstrap,core:binding.core,root:binding.clientRoot,record:record,context:live.contextDigest,cipher:combined)
        let mac=Data(HMAC<SHA256>.authenticationCode(for:try RecoveryCodec.encode(body),using:ownership(root)))
        return try RecoveryCodec.encode(RecoveryEnvelope(body:body,mac:mac))
    }
    /// Reconstructible after identity/key pruning, without context or ticket decryption.
    static func inspect(_ data:Data, binding:RecoveryBinding, root:SymmetricKey) throws -> RecoveryEnvelopeBody {
        let envelope=try RecoveryCodec.decode(RecoveryEnvelope.self,data), b=envelope.body
        guard b.version==(binding.independent ? 2 : 1), crEqual(b.bootstrap,binding.bootstrap), crEqual(b.core,binding.core), crEqual(b.root,binding.clientRoot),
              crUUID(b.record), crDigest(b.context), (29...RecoveryLimits.ticket+28).contains(b.cipher.count), envelope.mac.count==32,
              HMAC<SHA256>.isValidAuthenticationCode(envelope.mac,authenticating:try RecoveryCodec.encode(b),using:ownership(root)) else { throw RecoveryError.unavailable }
        return b
    }
    static func open(_ data:Data, live:LiveClientRecord, record:String, binding:RecoveryBinding, root:SymmetricKey) throws -> Data {
        guard binding.independent == (live.retention != nil), live.retention?.pair == binding.pair else { throw RecoveryError.unavailable }
        let b=try inspect(data,binding:binding,root:root)
        guard b.record==record, b.context==live.contextDigest else { throw RecoveryError.unavailable }
        do { return try AES.GCM.open(AES.GCM.SealedBox(combined:b.cipher),using:key(live,record:record,binding:binding),authenticating:aad(live,record:record,binding:binding)) }
        catch { throw RecoveryError.unavailable }
    }
}
