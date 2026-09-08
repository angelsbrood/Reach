import Foundation
import Darwin
import Security

/// The selected directory identity survives Keychain file rewrites.
public struct OwnedContainerIdentity: Codable, Equatable {
    public let root: String, device: Int32, inode: UInt64
    public var container: String { root + "/keys/role.keychain-db" }
    public init(root: String) throws {
        _ = try RootKeyCodec.parent(root); try RootKeyCodec.directory(root)
        try RootKeyCodec.require(RootKeyCodec.canonicalExisting(root) == root)
        var value = stat(); try RootKeyCodec.require(lstat(root, &value) == 0)
        self.root = root; device = value.st_dev; inode = UInt64(value.st_ino)
    }
    public func present() throws -> Bool {
        _ = try RootKeyCodec.parent(root); try RootKeyCodec.require(inode > 0)
        var value = stat()
        if lstat(root, &value) != 0 {
            try RootKeyCodec.require(errno == ENOENT); return false
        }
        try RootKeyCodec.directory(root)
        try RootKeyCodec.require(RootKeyCodec.canonicalExisting(root) == root && value.st_dev == device && UInt64(value.st_ino) == inode)
        return true
    }
}

/// Public exact selection; no key bytes or unlock credential are represented.
public struct OwnedContainerSelection: Codable, Equatable {
    public let version: Int, identity: OwnedContainerIdentity, boot: String, executable: FrozenWorker
    public let binding: String, references: [RootKeyReference], confirmations: [Data]
    public init(identity: OwnedContainerIdentity, boot: String, executable: FrozenWorker,
                binding: String, references: [RootKeyReference], confirmations: [Data]) {
        version = 1; self.identity = identity; self.boot = boot; self.executable = executable
        self.binding = binding; self.references = references; self.confirmations = confirmations
    }
    public func validate() throws {
        try RootKeyCodec.require(version == 1 && RootKeyCodec.uuid(boot) && RootKeyCodec.digest(binding))
        let roles = references.map(\.role)
        try RootKeyCodec.require(roles == [.hostCatalog, .hostTicket] || roles == [.clientMetadata])
        try RootKeyCodec.require(confirmations.count == references.count && confirmations.allSatisfy { $0.count == 32 } &&
            Set(references.map(\.identifier)).count == references.count && Set(references.map(\.bootstrap)).count == 1)
        for reference in references { try reference.validate() }
        _ = try RootKeyCodec.encode(self, limit: 64 << 10)
    }
    public func digest() throws -> String {
        try validate()
        return RootKeyCodec.hash(Data("S96/container-ownership/v1\0".utf8) + (try RootKeyCodec.encode(self, limit: 64 << 10)))
    }
}

/// Opening an existing Keychain does not create this capability. Its factory
/// requires the explicit selection digest and every available original key.
public final class OwnedContainerRetirement {
    private let selected: OwnedContainerSelection, container: OwnedFileKeychain
    private init(selected: OwnedContainerSelection, container: OwnedFileKeychain) {
        self.selected = selected; self.container = container
    }
    public static func authenticate(_ selected: OwnedContainerSelection, expectedDigest: String) throws -> OwnedContainerRetirement {
        try OwnedFileKeychain.disableInteraction(); try selected.validate()
        try RootKeyCodec.require(RootKeyCodec.digest(expectedDigest) && selected.digest() == expectedDigest && selected.boot == RootKeyCodec.boot())
        try selected.executable.validate()
        guard let running = Bundle.main.executableURL?.path else { throw RootKeyError.invalid }
        try RootKeyCodec.require(RootKeyCodec.canonicalExisting(running) == selected.executable.path && selected.identity.present())
        let container = try OwnedFileKeychain.openExisting(at: selected.identity.container)
        var state: SecKeychainStatus = 0
        try RootKeyCodec.check(SecKeychainGetStatus(container.reference, &state), "retirement-container-status")
        try RootKeyCodec.require(state & kSecUnlockStateStatus != 0)
        let provider = MacKeychainProvider(container: container)
        for (reference, confirmation) in zip(selected.references, selected.confirmations) {
            let key = try provider.load(reference, binding: selected.binding)
            try key.confirm(confirmation, reference: reference, binding: selected.binding)
        }
        return .init(selected: selected, container: container)
    }
    public func confirms(_ value: OwnedContainerSelection) -> Bool { selected == value }
    public func deleteAuthenticated() throws {
        try OwnedFileKeychain.disableInteraction()
        try RootKeyCodec.require(selected.identity.present() && OwnedFileKeychain.path(container.reference) == selected.identity.container)
        _ = try RootKeyCodec.regular(selected.identity.container, maximum: 64 << 20)
        try RootKeyCodec.check(SecKeychainDelete(container.reference), "delete-authenticated-owned-container")
        var value = stat()
        try RootKeyCodec.require(lstat(selected.identity.container, &value) != 0 && errno == ENOENT)
    }
}
