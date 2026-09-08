import Foundation
import Darwin
import DurableRootKeys
import DurableStoreBootstrap
import DurableSessionLifecycle
import DurableClientReceipts
import RequestPreparationContract

extension TransportContract {
    static func bootstrapPolicy() throws -> BootstrapPolicy { try .init(boot: RootKeyCodec.boot(), hostQuota: 1 << 30, clientQuota: 1 << 30) }
}

/// Initializer only: owns all creation/retirement capabilities. Workers receive
/// neither this object nor its keys; each reopens a separate confirmed selection.
public final class TransportRootOwner {
    public let root: String, backupExcluded: Bool
    private let container: OwnedFileKeychain, core: BootstrapCore, keys: BootstrapKeys, inode: UInt64
    private let metadata: KeychainMetadata
    private var retired = false, containerDeleted = false
    public init(root: String, modelSource: String, port: UInt16, provision: (String) throws -> TransportTLSProvision) throws {
        try TransportContract.currentUser()
        guard (49152...65535).contains(port) else { throw TransportRuntimeError.invalid }
        let executable = try LocalFiles.executable(), profile = try SelectedArtifactProfile(at: modelSource)
        try LocalFiles.createDirectory(root); self.root = root
        var info = stat(); guard lstat(root, &info) == 0 else { throw TransportRuntimeError.invalid }; inode = UInt64(info.st_ino)
        for role in ["host", "client", "keys", "model"] { try LocalFiles.createDirectory(root + "/" + role) }
        for name in SelectedArtifactProfile.fileNames.union(["profile.json"]) {
            try LocalFiles.writeNew(LocalFiles.read(modelSource + "/" + name, maximum: name == "weights.safetensors" ? 128 << 20 : 65536), to: root + "/model/" + name)
        }
        let installed = try SelectedArtifactProfile(at: root + "/model")
        guard installed.manifestDigest == profile.manifestDigest else { throw TransportRuntimeError.invalid }
        let pins = try TransportPins(provision(root))
        for role in ["host", "client"] {
            guard Set(try FileManager.default.contentsOfDirectory(atPath: root + "/" + role)) == ["identity.p12"] else { throw TransportRuntimeError.invalid }
        }
        backupExcluded = LocalFiles.excludeBackup(root)
        metadata = try KeychainMetadata.read()
        let password = try RootKeyCodec.random().map { String(format: "%02x", $0) }.joined()
        let created = try OwnedFileKeychain.create(at: root + "/keys/transport.keychain-db", password: password)
        var retained: BootstrapKeys?
        do {
            guard try KeychainMetadata.read().preserves(metadata, owned: [created.location]) else { throw TransportRuntimeError.invalid }
            let ready = try DurableStoreBootstrap.create(optIn: true, at: root + "/bootstrap", container: created.location, policy: TransportContract.bootstrapPolicy(), provider: { _ in
                MacKeychainProvider(container: created, initialAccess: Dictionary(uniqueKeysWithValues: RootKeyRole.allCases.map { ($0, [executable]) }))
            }, initializeStores: { core, material in
                retained = material
                let hostClock = SystemLifecycleClock(), clientClock = SystemClientClock()
                let host = try DurableSessionLifecycle.initialize(at: root + "/bootstrap/host", identity: .init(incarnation: core.hostID, clock: hostClock, quota: core.policy.hostQuota), keys: LocalRuntimeOwner.hostKeys(material), clock: hostClock)
                defer { host.close() }
                let client = try DurableClientReceipts(path: root + "/bootstrap/client", create: true, environment: .init(rootID: core.clientID, clock: clientClock, quota: core.policy.clientQuota), metadataKey: material.key(.clientMetadata).use { $0 }, clock: clientClock)
                client.close()
            })
            guard let ready, let material = retained else { throw TransportRuntimeError.unavailable }
            for role in [TransportRole.host, .client] {
                let archive = try LocalFiles.read(root + "/" + role.rawValue + "/identity.p12", maximum: 1 << 20)
                let binding = try TransportSelectionBinding(revision: TransportContract.revision, role: role, bootstrap: ready.core.binding(), profileDigest: installed.manifestDigest, archiveDigest: PreparationEncoding.hash(archive), executable: executable, descriptor: installed.preparer.policy.descriptor, pins: pins, port: port)
                try binding.validate(role: role)
                _ = try TransportIdentity(root: root, selection: binding, audit: TransportRoleAudit(role))
                let keyRole: RootKeyRole = role == .host ? .hostCatalog : .clientMetadata
                let confirmation = try material.key(keyRole).confirmation(ready.core.reference(keyRole), binding: PreparationEncoding.digest(binding))
                try LocalFiles.writeNew(TransportContract.encode(TransportSelection(binding: binding, confirmation: confirmation)), to: root + "/" + role.rawValue + "/selection.json")
            }
            core = ready.core; keys = material; container = created
        } catch { try created.deleteOwned(); throw error }
    }
    public func retire() throws {
        if retired { return }
        try LocalFiles.directory(root)
        var info = stat(); guard lstat(root, &info) == 0, UInt64(info.st_ino) == inode else { throw TransportRuntimeError.invalid }
        let hostClock = SystemLifecycleClock(), clientClock = SystemClientClock()
        let host = try DurableSessionLifecycle.reopen(at: root + "/bootstrap/host", identity: .init(incarnation: core.hostID, clock: hostClock, quota: core.policy.hostQuota), keys: LocalRuntimeOwner.hostKeys(keys), clock: hostClock)
        defer { host.close() }
        let client = try DurableClientReceipts(path: root + "/bootstrap/client", create: false, environment: .init(rootID: core.clientID, clock: clientClock, quota: core.policy.clientQuota), metadataKey: keys.key(.clientMetadata).use { $0 }, clock: clientClock)
        defer { client.close() }
        if !containerDeleted { try container.deleteOwned(); containerDeleted = true }
        let after = try KeychainMetadata.read()
        guard after.preserves(metadata, owned: [container.location]), after.excludes([container.location]) else { throw TransportRuntimeError.invalid }
        try FileManager.default.removeItem(atPath: root); retired = true
    }
    /// Used only by the trusted initializer's existing CLI issuer, never by peers.
    public static func writePrivate(_ bytes: Data, to path: String) throws {
        guard bytes.count <= 1 << 20 else { throw TransportRuntimeError.invalid }
        try LocalFiles.writeNew(bytes, to: path)
    }
}

private final class RoleKeyProvider: RootKeyProvider {
    let provider: MacKeychainProvider, audit: TransportRoleAudit
    init(_ provider: MacKeychainProvider, audit: TransportRoleAudit) { self.provider = provider; self.audit = audit }
    func create(_ reference: RootKeyReference, binding: String) throws -> RootKeyMaterial { throw TransportRuntimeError.invalid }
    func load(_ reference: RootKeyReference, binding: String) throws -> RootKeyMaterial {
        try audit.load(reference.role)
        return try provider.load(reference, binding: binding)
    }
}

/// This path never loads model artifacts or another role's selection/journal.
/// Shared core/parent/sibling directory metadata checks are bootstrap's contract.
struct AcquiredTransportRoot {
    let core: BootstrapCore, keys: BootstrapKeys, selection: TransportSelectionBinding, audit: TransportRoleAudit
    init(_ root: String, role: TransportRole) throws {
        try TransportContract.currentUser(); try LocalFiles.directory(root)
        let audit = TransportRoleAudit(role), executable = try LocalFiles.executable()
        let value = try JSONDecoder().decode(TransportSelection.self, from: LocalFiles.read(root + "/" + role.rawValue + "/selection.json", maximum: 64 << 10))
        try value.binding.validate(role: role)
        guard value.binding.executable == executable else { throw TransportRuntimeError.invalid }
        let path = root + "/keys/transport.keychain-db"
        guard let acquired = try DurableStoreBootstrap.acquire(optIn: true, at: root + "/bootstrap", role: role == .host ? .host : .client, policy: TransportContract.bootstrapPolicy(), provider: { core in
            guard core.container == path else { throw TransportRuntimeError.invalid }
            return RoleKeyProvider(MacKeychainProvider(container: try .openExisting(at: path)), audit: audit)
        }), value.binding.bootstrap == (try acquired.descriptor.core.binding()) else { throw TransportRuntimeError.unavailable }
        let keyRole: RootKeyRole = role == .host ? .hostCatalog : .clientMetadata
        try acquired.keys.key(keyRole).confirm(value.confirmation, reference: acquired.descriptor.core.reference(keyRole), binding: PreparationEncoding.digest(value.binding))
        self.core = acquired.descriptor.core; keys = acquired.keys; selection = value.binding; self.audit = audit
    }
}
