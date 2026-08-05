import Foundation
import Security

/// The roads a cluster last answered on, kept beside the pin.
///
/// A granted app already holds three things that outlive its own reinstall:
/// its key, its certificate, and the pinned CA. What it does not hold is an
/// address. `HelloAck` declares every road the daemon answers on — mesh
/// included — but the hub kept that list in memory, so it died with the
/// process. Cold, off the LAN, an app had every right to dial and nowhere to
/// dial to: "reach it from anywhere" meant "from anywhere, provided you
/// started at home."
///
/// Lifetime parity is the whole argument for putting this in the keychain
/// rather than in a file. A reinstalled app keeps its grant today; it should
/// keep its roads with it.
///
/// Stored as a generic password rather than under a label, deliberately.
/// `kSecAttrLabel` is not a constraint on the macOS file keychain — the scar
/// is on `KeychainIdentity`, where every delete goes by `kSecValueRef` because
/// a bare label delete once destroyed a signing key. `kSecAttrService` and
/// `kSecAttrAccount` *are* that keychain's primary key for a generic password,
/// which is why `WGKey` can query on them bare and why this follows `WGKey`.
public enum ClusterRoads {
    public static let service = "systems.reach.cluster-roads"

    /// What the daemon said, narrowed to what a different device can use.
    /// JSON so a later field can arrive optional, the way `HelloAck.addrs`
    /// itself did.
    public struct Roads: Codable, Sendable, Equatable {
        public var addrs: [String]
        public var port: UInt16

        public init(addrs: [String], port: UInt16) {
            self.addrs = addrs
            self.port = port
        }
    }

    /// Records the roads for `label`, superseding whatever was there.
    ///
    /// Loopback is dropped on the way in. `LocalAddresses.ipv4()` seeds the
    /// list with `127.0.0.1` unconditionally because it doubles as the SAN
    /// set for the server certificate, so every declared set carries it — and
    /// read back in another process on another device it names that device,
    /// not the cluster. This is not the client-side classification the design
    /// ruled out: that ruling is about *ranking* roads, and this drops an
    /// address that cannot denote the cluster at all. Where the app really is
    /// on the cluster's own host, loopback is already its primary endpoint and
    /// the hub de-dupes candidates against that.
    ///
    /// A set that is empty after filtering leaves the store untouched rather
    /// than erasing it — a daemon that can currently see only itself has not
    /// learned that the roads it told us about last week are gone.
    public static func save(addrs: [String], port: UInt16, for label: String) throws {
        let roads = addrs.filter { !isLoopback($0) }
        guard !roads.isEmpty else { return }
        let data = try JSONEncoder().encode(Roads(addrs: roads, port: port))

        // The whole body, as `WGKey.createOrLoad` holds it: add-then-update is
        // a read-then-write by another name.
        KeychainLock.acquire()
        defer { KeychainLock.release() }

        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
            // A cold dial has to work before the first unlock after a reboot —
            // that is the whole point of the reboot case.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecValueData as String: data,
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecSuccess { return }
        guard status == errSecDuplicateItem else {
            throw IdentityError.keychainAddFailed(status)
        }

        // The tree's first `SecItemUpdate`, and the reason is atomicity rather
        // than taste. Delete-then-add is the convention next door in
        // `ReachEnrollment`, but here it opens a window in which a crash costs
        // the app every road it knew — the exact state this type exists to
        // prevent. The reason deletes elsewhere go by reference does not reach
        // this call: the query below is a generic password's real primary key.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
        ]
        let updated = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        guard updated == errSecSuccess else {
            throw IdentityError.keychainAddFailed(updated)
        }
    }

    /// nil when nothing has been stored for this label; throws when something
    /// has been and will not read back. Absent and unreadable are different
    /// answers — `WGKey.load`'s ruling, for the same reason it made there.
    /// Reading the second as the first would silently dial as though the app
    /// had never been answered, which is precisely the sentence the refusal is
    /// supposed to be able to tell apart.
    public static func load(for label: String) throws -> Roads? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        let status = KeychainLock.withLock { SecItemCopyMatching(query as CFDictionary, &item) }
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw IdentityError.roadsUnreadable(status)
        }
        do {
            return try JSONDecoder().decode(Roads.self, from: data)
        } catch {
            // `errSecDecode` is not a status the keychain returned — it is this
            // layer saying what happened in the keychain's own vocabulary, so
            // the sentence reads the same either way.
            throw IdentityError.roadsUnreadable(errSecDecode)
        }
    }

    /// Drops the roads for a label. By service and account, never by label:
    /// see the type's note on why that distinction is the safe one here.
    /// Absent is success — forgetting what was never known is done.
    public static func forget(for label: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
        ]
        let status = KeychainLock.withLock { SecItemDelete(query as CFDictionary) }
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw IdentityError.keychainAddFailed(status)
        }
    }

    private static func isLoopback(_ addr: String) -> Bool {
        let octets = addr.split(separator: ".")
        guard octets.count == 4, let first = UInt8(octets[0]) else { return false }
        return first == 127
    }
}
