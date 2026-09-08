import Foundation
import Security
import Darwin

/// Explicit file-Keychain selection for this disposable macOS candidate only.
public final class OwnedFileKeychain {
    public let location: String
    let reference: SecKeychain
    private let created: Bool
    public static func disableInteraction() throws {
        try RootKeyCodec.check(SecKeychainSetUserInteractionAllowed(false), "disable-file-keychain-ui")
        var allowed: DarwinBoolean = true
        try RootKeyCodec.check(SecKeychainGetUserInteractionAllowed(&allowed), "verify-file-keychain-ui")
        try RootKeyCodec.require(!allowed.boolValue)
    }
    static func path(_ keychain: SecKeychain) throws -> String {
        var buffer = [CChar](repeating: 0, count: 4096), count = UInt32(4096)
        try RootKeyCodec.check(SecKeychainGetPath(keychain, &count, &buffer), "container-path")
        try RootKeyCodec.require(count > 0 && count < 4096); return String(cString: buffer)
    }
    private static func validateLocation(_ path: String, exists: Bool) throws {
        _ = try RootKeyCodec.parent(path); try RootKeyCodec.require(path.hasSuffix(".keychain-db"))
        if exists { _ = try RootKeyCodec.regular(path, maximum: 64<<20) }
        else { var s = stat(); try RootKeyCodec.require(lstat(path, &s) != 0 && errno == ENOENT) }
    }
    public static func create(at path: String, password: String) throws -> OwnedFileKeychain {
        try disableInteraction(); try validateLocation(path, exists: false)
        let bytes = Data(password.utf8)
        try RootKeyCodec.require((32...128).contains(bytes.count) && password.unicodeScalars.allSatisfy { $0.isASCII && CharacterSet.alphanumerics.contains($0) })
        _ = try KeychainMetadata.read() // Existing usable default is mandatory before creation.
        var keychain: SecKeychain?
        try RootKeyCodec.check(bytes.withUnsafeBytes { SecKeychainCreate(path, UInt32(bytes.count), $0.baseAddress!, false, nil, &keychain) }, "create-owned-container")
        guard let keychain else { throw RootKeyError.unavailable }
        do { return try .init(path: path, reference: keychain, created: true) }
        catch {
            try RootKeyCodec.check(SecKeychainDelete(keychain), "cleanup-rejected-new-container")
            throw error
        }
    }
    public static func openExisting(at path: String) throws -> OwnedFileKeychain {
        try disableInteraction(); try validateLocation(path, exists: true)
        var keychain: SecKeychain?; try RootKeyCodec.check(SecKeychainOpen(path, &keychain), "open-existing-container")
        guard let keychain else { throw RootKeyError.unavailable }
        return try .init(path: path, reference: keychain, created: false)
    }
    private init(path: String, reference: SecKeychain, created: Bool) throws {
        location = path; self.reference = reference; self.created = created
        try Self.validateLocation(path, exists: true)
        try RootKeyCodec.require(Self.path(reference) == path)
        var state: SecKeychainStatus = 0; try RootKeyCodec.check(SecKeychainGetStatus(reference, &state), "existing-container-status")
    }
    public func lockOwned() throws {
        try RootKeyCodec.require(created); try RootKeyCodec.check(SecKeychainLock(reference), "lock-owned-container")
        var state: SecKeychainStatus = 0; try RootKeyCodec.check(SecKeychainGetStatus(reference, &state), "locked-container-status")
        try RootKeyCodec.require(state&kSecUnlockStateStatus == 0)
    }
    public func unlockOwned(password: String) throws {
        try RootKeyCodec.require(created); let bytes = Data(password.utf8); try RootKeyCodec.require((32...128).contains(bytes.count))
        try RootKeyCodec.check(bytes.withUnsafeBytes { SecKeychainUnlock(reference, UInt32(bytes.count), $0.baseAddress!, true) }, "explicit-owned-unlock")
    }
    public func deleteOwned() throws {
        try RootKeyCodec.require(created && Self.path(reference) == location); try Self.validateLocation(location, exists: true)
        try RootKeyCodec.check(SecKeychainDelete(reference), "delete-owned-container")
        var s = stat(); try RootKeyCodec.require(lstat(location, &s) != 0 && errno == ENOENT)
    }
}
/// Nonsecret metadata only; no credential/item enumeration and no setters.
public struct KeychainMetadata: Equatable {
    private let defaultPath: String, search: [String]
    public static func read() throws -> Self {
        var keychain: SecKeychain?; try RootKeyCodec.check(SecKeychainCopyDefault(&keychain), "default-metadata")
        guard let keychain else { throw RootKeyError.unavailable }
        let path = try OwnedFileKeychain.path(keychain)
        var s = stat(); try RootKeyCodec.require(lstat(path, &s) == 0 && s.st_mode&S_IFMT == S_IFREG)
        var state: SecKeychainStatus = 0; try RootKeyCodec.check(SecKeychainGetStatus(keychain, &state), "default-exists")
        var array: CFArray?; try RootKeyCodec.check(SecKeychainCopySearchList(&array), "search-metadata")
        guard let values = array as? [SecKeychain], values.count <= 128 else { throw RootKeyError.invalid }
        return try .init(defaultPath: path, search: values.map(OwnedFileKeychain.path))
    }
    public func preserves(_ before: Self, owned: Set<String>) -> Bool { defaultPath == before.defaultPath && search.filter { !owned.contains($0) } == before.search }
    /// Fresh retirement compares unrelated metadata at that operation, including
    /// when the selected owned container is already in the current search list.
    public func preservesUnrelated(_ before: Self, owned: Set<String>) -> Bool {
        defaultPath == before.defaultPath && !owned.contains(defaultPath) &&
            search.filter { !owned.contains($0) } == before.search.filter { !owned.contains($0) }
    }
    public func excludes(_ owned: Set<String>) -> Bool { !search.contains { owned.contains($0) } && !owned.contains(defaultPath) }
}
private struct ProtectedRootRecord: Codable {
    let version: Int, reference: RootKeyReference, binding: String, material: Data
}
public final class MacKeychainProvider: RootKeyProvider {
    private let container: OwnedFileKeychain
    private let access: [RootKeyRole: [FrozenWorker]]
    public init(container: OwnedFileKeychain, initialAccess: [RootKeyRole: [FrozenWorker]] = [:]) {
        self.container = container; access = initialAccess
    }
    private func query(_ reference: RootKeyReference) throws -> [String: Any] {
        try reference.validate()
        return [kSecClass as String:kSecClassGenericPassword, kSecMatchSearchList as String:[container.reference],
            kSecAttrService as String:reference.service, kSecAttrAccount as String:reference.account]
    }
    public func create(_ reference: RootKeyReference, binding: String) throws -> RootKeyMaterial {
        try RootKeyCodec.require(RootKeyCodec.digest(binding))
        guard let workers = access[reference.role], !workers.isEmpty, workers.count <= 3, Set(workers.map(\.path)).count == workers.count else { throw RootKeyError.invalid }
        var applications: [SecTrustedApplication] = []
        for worker in workers {
            try worker.validate(); var app: SecTrustedApplication?
            try RootKeyCodec.check(SecTrustedApplicationCreateFromPath(worker.path, &app), "frozen-worker-application")
            guard let app else { throw RootKeyError.unavailable }; applications.append(app)
        }
        var acl: SecAccess?
        try RootKeyCodec.check(SecAccessCreate("S85 disposable root key" as CFString, applications as CFArray, &acl), "new-item-access")
        guard let acl else { throw RootKeyError.unavailable }
        let bytes = try RootKeyCodec.random()
        let record = ProtectedRootRecord(version: 1, reference: reference, binding: binding, material: bytes)
        var q = try query(reference); q.removeValue(forKey: kSecMatchSearchList as String)
        q[kSecUseKeychain as String] = container.reference; q[kSecAttrAccess as String] = acl
        q[kSecValueData as String] = try RootKeyCodec.encode(record)
        try RootKeyCodec.check(SecItemAdd(q as CFDictionary, nil), "scoped-add-only")
        let loaded = try load(reference, binding: binding); try loaded.use { try RootKeyCodec.require($0 == bytes) }; return loaded
    }
    public func load(_ reference: RootKeyReference, binding: String) throws -> RootKeyMaterial {
        try RootKeyCodec.require(RootKeyCodec.digest(binding))
        var q = try query(reference); q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecReturnAttributes as String] = true; q[kSecReturnData as String] = true
        var result: CFTypeRef?; try RootKeyCodec.check(SecItemCopyMatching(q as CFDictionary, &result), "scoped-load-only")
        guard let attributes = result as? [String:Any], let bytes = attributes[kSecValueData as String] as? Data else { throw RootKeyError.invalid }
        try RootKeyCodec.require(bytes.count <= 4096 && attributes[kSecAttrService as String] as? String == reference.service && attributes[kSecAttrAccount as String] as? String == reference.account)
        let record = try RootKeyCodec.decode(ProtectedRootRecord.self, bytes)
        try RootKeyCodec.require(record.version == 1 && record.reference == reference && record.binding == binding)
        return try .init(record.material)
    }
    /// Disposable fixture cleanup only; exact validated record, container and selectors.
    public func deleteExact(_ reference: RootKeyReference, binding: String) throws {
        _ = try load(reference, binding: binding)
        try RootKeyCodec.check(SecItemDelete(query(reference) as CFDictionary), "delete-confirmed-scoped-record")
    }
}
