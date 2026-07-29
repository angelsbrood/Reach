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
        KeychainLock.acquire()
        defer { KeychainLock.release() }
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

    /// Stores a certificate alone — the cluster CA an app pinned at its
    /// enrollment, held so the pin survives relaunch.
    public static func storeCertificate(der: Data, label: String) throws {
        KeychainLock.acquire()
        defer { KeychainLock.release() }
        let certificate = try IdentityStore.certificate(fromDER: der)
        let add: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: label,
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw IdentityError.keychainAddFailed(status)
        }
    }

    public static func findCertificate(label: String) throws -> SecCertificate {
        try first(in: kSecClassCertificate, label: label)
    }

    public static func find(label: String) throws -> SecIdentity {
        try first(in: kSecClassIdentity, label: label)
    }

    /// The read half of the same problem `remove` has: on the macOS file
    /// keychain `kSecAttrLabel` does not constrain these classes, so a query
    /// for one label matches everything and `kSecMatchLimitOne` hands back
    /// whichever item sorts first — an identity that is not the one asked
    /// for, presented as though it were. (The iOS data-protection keychain
    /// does filter, so on device this has been returning the right answer by
    /// platform rather than by construction.)
    ///
    /// Ask for all of them and check the label here, where checking works.
    private static func first<T>(in itemClass: CFString, label: String) throws -> T {
        KeychainLock.acquire()
        defer { KeychainLock.release() }
        let query: [String: Any] = [
            kSecClass as String: itemClass,
            kSecAttrLabel as String: label,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true,
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess, let found = items as? [[String: Any]] else {
            throw IdentityError.identityNotFound(status)
        }
        for entry in found where matches(label, entry) {
            if let reference = entry[kSecValueRef as String], CFGetTypeID(reference as CFTypeRef) != 0 {
                return reference as! T
            }
        }
        throw IdentityError.identityNotFound(errSecItemNotFound)
    }

    /// Removes exactly this identity, by reference.
    ///
    /// The only reliable way to delete something from the macOS keychain is
    /// to hand back the thing itself. Labels do not survive the trip: for a
    /// certificate the keychain overwrites `kSecAttrLabel` with the subject's
    /// common name, so an item stored under "reach-test-server-<uuid>" comes
    /// back labelled "reachd" and no label query will ever find it again.
    ///
    /// `SecPKCS12Import` also adds to the default keychain as a side effect,
    /// so anything materialized through the PKCS#12 fallback needs this on
    /// the way out or it accumulates — which it has been doing, unnoticed,
    /// for as long as the suite has existed.
    public static func remove(identity: SecIdentity) {
        KeychainLock.acquire()
        defer { KeychainLock.release() }
        SecItemDelete([
            kSecClass as String: kSecClassIdentity,
            kSecValueRef as String: identity,
        ] as CFDictionary)

        var certificate: SecCertificate?
        if SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate {
            SecItemDelete([
                kSecClass as String: kSecClassCertificate,
                kSecValueRef as String: certificate,
            ] as CFDictionary)
        }
        var key: SecKey?
        if SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key {
            SecItemDelete([
                kSecClass as String: kSecClassKey,
                kSecValueRef as String: key,
            ] as CFDictionary)
        }
    }

    /// Removes the key and certificate stored under `label`.
    ///
    /// ⚠️ `kSecAttrLabel` in a bare `SecItemDelete` query is NOT a filter on
    /// macOS — the file-based keychain ignores it for these classes, so
    /// `SecItemDelete([kSecClass: kSecClassKey, kSecAttrLabel: "anything"])`
    /// matches every private key the process can see and deletes them. This
    /// function used to be exactly that, and it destroyed an Apple
    /// Development signing key on the developer's own machine.
    ///
    /// So: find candidates, compare the label in Swift where the comparison
    /// actually happens, and delete only those, one reference at a time.
    /// Nothing here deletes on the strength of a predicate the platform is
    /// free to ignore.
    public static func remove(label: String) {
        guard !label.isEmpty else { return }
        KeychainLock.acquire()
        defer { KeychainLock.release() }
        for itemClass in [kSecClassIdentity, kSecClassCertificate, kSecClassKey] {
            let query: [String: Any] = [
                kSecClass as String: itemClass,
                kSecAttrLabel as String: label,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecReturnRef as String: true,
                kSecReturnAttributes as String: true,
            ]
            var items: CFTypeRef?
            guard SecItemCopyMatching(query as CFDictionary, &items) == errSecSuccess,
                  let found = items as? [[String: Any]]
            else { continue }

            for entry in found where matches(label, entry) {
                guard let reference = entry[kSecValueRef as String] else { continue }
                SecItemDelete([
                    kSecClass as String: itemClass,
                    kSecValueRef as String: reference,
                ] as CFDictionary)
            }
        }
    }

    /// The label lives in `kSecAttrLabel` for certificates and identities and
    /// in `kSecAttrApplicationLabel` for keys; both are checked, and an entry
    /// carrying neither is left alone rather than assumed to be ours.
    private static func matches(_ label: String, _ attributes: [String: Any]) -> Bool {
        let candidates = [kSecAttrLabel as String, kSecAttrApplicationLabel as String]
        for key in candidates {
            if let text = attributes[key] as? String, text == label { return true }
            if let data = attributes[key] as? Data, String(decoding: data, as: UTF8.self) == label { return true }
        }
        return false
    }
}
