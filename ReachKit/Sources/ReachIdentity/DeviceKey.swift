import Foundation
import Security

/// The device's identity key: Secure-Enclave-resident where the hardware
/// exists (software-backed in the simulator), permanent in the keychain,
/// minted once at the ceremony and never exported. Signatures are ECDSA
/// P-256 over the message (SHA-256 internally), DER-encoded — exactly what
/// the daemon's proof-of-possession check verifies.
public enum DeviceKey {
    public static let label = "systems.reach.device-key"

    public static func createOrLoad() throws -> SecKey {
        if let existing = try? load() {
            return existing
        }
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrLabel as String: label,
            ],
        ]
        #if !targetEnvironment(simulator)
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        #endif
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw IdentityError.importFailed("device key mint: \(error.map { "\($0.takeRetainedValue())" } ?? "unknown")")
        }
        return key
    }

    public static func load() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: label,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            throw IdentityError.identityNotFound(status)
        }
        return (item as! SecKey)
    }

    /// X9.63 public key bytes, as carried in `EnrollCertRequest`.
    public static func publicKeyX963(_ key: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw IdentityError.importFailed("no public key")
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw IdentityError.importFailed("public key export: \(error.map { "\($0.takeRetainedValue())" } ?? "unknown")")
        }
        return data
    }

    /// DER ECDSA signature over `message`.
    public static func sign(_ message: Data, with key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) as Data? else {
            throw IdentityError.importFailed("sign: \(error.map { "\($0.takeRetainedValue())" } ?? "unknown")")
        }
        return signature
    }

    /// Adds the issued certificate and returns the assembled identity the
    /// TLS layer uses.
    public static func installCertificate(_ certificateDER: Data) throws -> SecIdentity {
        let certificate = try IdentityStore.certificate(fromDER: certificateDER)
        let add: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: label,
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw IdentityError.keychainAddFailed(status)
        }
        return try KeychainIdentity.find(label: label)
    }
}
