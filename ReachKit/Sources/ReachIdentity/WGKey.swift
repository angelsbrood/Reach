import CryptoKit
import Foundation
import Security

/// The device's mesh key: X25519, minted once and kept, stored as a keychain
/// generic password because Curve25519 is not a key type the Secure Enclave
/// holds (unlike `DeviceKey`, which is).
///
/// It used to be minted per ceremony and thrown away, and that one fact was
/// what made a re-pair destructive. `WireGuardHost.addPeer` is idempotent when
/// the key is already present, so a phone that brings back the same key needs
/// no new peer block — no eviction of the block it is still using, no rewritten
/// conf, and therefore no `wg-quick` from the operator before the mesh works
/// again. A fresh key every scan meant none of that was reachable: every
/// re-pair evicted a live peer and required a sudo, and the venue's own
/// sequence is a re-pair.
///
/// It also closes the window this key's absence opened. The peer install waits
/// on `EnrollComplete`, deliberately, so a ceremony that dies after the grant
/// leaves the host's conf untouched. With a stable key there is nothing to
/// reconcile: the host already admits this key, so a lost confirmation costs
/// the pairing nothing.
///
/// What is given up is per-scan mesh-key rotation, which was buying little —
/// the private key already sits in cleartext in `keeper-wg.conf` under the
/// app's Documents directory, which is weaker than this keychain item. What is
/// NOT given up is the proof of possession: its freshness lives in the
/// daemon's nonce, not in the key being new.
public enum WGKey {
    public static let service = "systems.reach.wg-key"
    private static let account = "mesh"

    public static func createOrLoad() throws -> Curve25519.KeyAgreement.PrivateKey {
        // The whole body, not each call: read-then-write is the shape that let
        // one QR admit two devices, and "no await in here" is a statement about
        // interleaving rather than about parallelism. Recursive, so the `load`
        // below re-enters safely.
        KeychainLock.acquire()
        defer { KeychainLock.release() }
        if let existing = try load() {
            return existing
        }
        let key = Curve25519.KeyAgreement.PrivateKey()
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecValueData as String: key.rawRepresentation,
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        // The lock above is per-process and the Keeper ships two of them — the
        // app and its tunnel extension share this access group — so a duplicate
        // is still reachable. Whichever key the host is told about has to be the
        // one on disk, so read the winner back rather than returning the loser.
        if status == errSecDuplicateItem {
            guard let winner = try load() else { throw IdentityError.keychainAddFailed(status) }
            return winner
        }
        guard status == errSecSuccess else { throw IdentityError.keychainAddFailed(status) }
        return key
    }

    /// nil when no key has been stored yet; throws when one is stored and will
    /// not load. Absent and unreadable are different answers — reading the
    /// second as the first would silently mint a new key and evict the peer
    /// block this device is using, which is the fault this type exists to fix.
    public static func load() throws -> Curve25519.KeyAgreement.PrivateKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        let status = KeychainLock.withLock { SecItemCopyMatching(query as CFDictionary, &item) }
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw IdentityError.identityNotFound(status)
        }
        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
    }
}
