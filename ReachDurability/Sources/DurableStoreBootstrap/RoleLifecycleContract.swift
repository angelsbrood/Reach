import Foundation
import DurableRootKeys

public struct RoleLifecycleIdentity: Codable, Equatable {
    public let identity: OwnedContainerIdentity, receipt: String, executable: FrozenWorker
    public init(root: String, receipt: String, executable: FrozenWorker) throws {
        identity = try OwnedContainerIdentity(root: root); self.receipt = receipt; self.executable = executable
        try validate(root: root)
    }
    public func validate(root: String) throws {
        try RootKeyCodec.require(identity.root == root && identity.inode > 0 && !receipt.hasPrefix(root + "/") && receipt != root &&
            !root.hasPrefix(receipt + "/") && receipt.utf8.count <= 3072)
        _ = try RootKeyCodec.parent(receipt); try executable.validate()
    }
}

/// An immutable own-role control record outside the removable root. Its expected
/// digest comes from successful initialization, never from a later deletion target.
public struct RoleOwnershipReceipt: Codable {
    public let version: Int, ready: RoleBootstrapReady, container: OwnedContainerSelection
    public init(ready: RoleBootstrapReady) throws {
        guard let lifecycle = ready.core.lifecycle, ready.core.version == 2 else { throw BootstrapError.invalid }
        version = 1; self.ready = ready
        container = .init(identity: lifecycle.identity, boot: ready.core.boot, executable: lifecycle.executable,
            binding: try ready.core.binding(), references: ready.core.keys, confirmations: ready.confirmations)
        try validate()
    }
    public func validate() throws {
        let core = ready.core
        guard let lifecycle = core.lifecycle else { throw BootstrapError.invalid }
        try core.validateDescription(role: core.role, root: core.root)
        try RootKeyCodec.require(version == 1 && core.version == 2 && ready.state == "ready" &&
            container == OwnedContainerSelection(identity: lifecycle.identity, boot: core.boot, executable: lifecycle.executable,
                binding: try core.binding(), references: core.keys, confirmations: ready.confirmations))
        try container.validate(); _ = try RootKeyCodec.encode(self, limit: BootstrapLimits.record)
    }
    public func digest() throws -> String {
        try validate()
        return RootKeyCodec.hash(Data("S96/role-ownership-receipt/v1\0".utf8) + (try RootKeyCodec.encode(self, limit: BootstrapLimits.record)))
    }
}

public enum RoleLifecyclePhase: String, Codable { case creating, ready, retiring, retired }
struct RoleLifecycleState: Codable {
    let version: Int, phase: RoleLifecyclePhase, core: String, receipt: String?
    init(phase: RoleLifecyclePhase, core: String, receipt: String?) {
        version = 1; self.phase = phase; self.core = core; self.receipt = receipt
    }
}
