import Foundation
import Security

/// Assembles a `SecIdentity` from raw key + certificate material via the
/// keychain — the only sanctioned route. The ceremony stores the device's
/// SecureEnclave key and issued certificate exactly this way; Phase 1's
/// hand-provisioned identities and the test suite use it with software keys.
public enum KeychainIdentity {
    /// Adds the private key (EC, X9.63 representation) and certificate DER
    /// under `label`, and returns the assembled identity.
    public static func store(privateKeyX963: Data, certificateDER: Data, label: String) throws -> SecIdentity {
        let keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(privateKeyX963 as CFData, keyAttributes as CFDictionary, &error) else {
            let underlying = error.map { "\($0.takeRetainedValue())" } ?? "unknown"
            throw IdentityError.importFailed("key import: \(underlying)")
        }
        let certificate = try IdentityStore.certificate(fromDER: certificateDER)

        let addKey: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: key,
            kSecAttrLabel as String: label,
        ]
        var status = SecItemAdd(addKey as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw IdentityError.keychainAddFailed(status)
        }

        let addCert: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: label,
        ]
        status = SecItemAdd(addCert as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw IdentityError.keychainAddFailed(status)
        }

        return try find(label: label)
    }

    public static func find(label: String) throws -> SecIdentity {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            throw IdentityError.identityNotFound(status)
        }
        return item as! SecIdentity
    }

    /// Removes the key and certificate stored under `label`. Best-effort;
    /// used by tests and re-provisioning.
    public static func remove(label: String) {
        for itemClass in [kSecClassIdentity, kSecClassCertificate, kSecClassKey] {
            let query: [String: Any] = [
                kSecClass as String: itemClass,
                kSecAttrLabel as String: label,
            ]
            SecItemDelete(query as CFDictionary)
        }
    }
}
