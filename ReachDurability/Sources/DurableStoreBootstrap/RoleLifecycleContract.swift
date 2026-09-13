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
        guard let lifecycle = ready.core.lifecycle, (2...5).contains(ready.core.version) else { throw BootstrapError.invalid }
        version = ready.core.ownershipVersion; self.ready = ready
        container = .init(identity: lifecycle.identity, boot: ready.core.boot, executable: lifecycle.executable,
            binding: try ready.core.binding(), references: ready.core.keys, confirmations: ready.confirmations)
        try validate()
    }
    public init(recoveryAuthority ready: RoleBootstrapReady) throws {
        try ready.core.validateForRecoveryAuthority()
        guard let lifecycle=ready.core.lifecycle else { throw BootstrapError.invalid }
        version=2; self.ready=ready
        container = .init(identity:lifecycle.identity,boot:ready.core.boot,executable:lifecycle.executable,
            binding:try ready.core.binding(),references:ready.core.keys,confirmations:ready.confirmations)
        try validateForRecoveryAuthority()
    }
    public func validate() throws { try validate(afterBootRetirement:false) }
    public func validateForAfterBootRetirement() throws { try validate(afterBootRetirement:true) }
    public func validateForRecoveryAuthority() throws {
        try ready.core.validateForRecoveryAuthority()
        try validate(afterBootRetirement:false, authority:true)
    }
    public func digestForRecoveryAuthority() throws -> String { try validateForRecoveryAuthority(); return try encodedDigest() }
    public init(nativeRecovery ready: RoleBootstrapReady) throws {
        try ready.core.validateForNativeRecovery()
        guard let lifecycle=ready.core.lifecycle else { throw BootstrapError.invalid }
        version=3; self.ready=ready
        container = .init(identity:lifecycle.identity,boot:ready.core.boot,executable:lifecycle.executable,binding:try ready.core.binding(),references:ready.core.keys,confirmations:ready.confirmations)
        try validateForNativeRecovery()
    }
    public func validateForNativeRecovery() throws { try validate(afterBootRetirement:false,native:true) }
    public func digestForNativeRecovery() throws -> String { try validateForNativeRecovery(); return try encodedDigest() }
    private func validate(afterBootRetirement: Bool, authority: Bool = false, native: Bool = false) throws {
        let core = ready.core
        guard let lifecycle = core.lifecycle else { throw BootstrapError.invalid }
        if native { try core.validateForNativeRecovery() }
        else if authority { try core.validateForRecoveryAuthority() }
        else if afterBootRetirement { try core.validateForAfterBootRetirement() }
        else { try core.validateDescription(role: core.role, root: core.root) }
        try RootKeyCodec.require(version == (core.ownershipVersion) && (2...5).contains(core.version) && ready.state == "ready" &&
            container == OwnedContainerSelection(identity: lifecycle.identity, boot: core.boot, executable: lifecycle.executable,
                binding: try core.binding(), references: core.keys, confirmations: ready.confirmations))
        try container.validate(); _ = try RootKeyCodec.encode(self, limit: BootstrapLimits.record)
    }
    public func digest() throws -> String { try validate(); return try encodedDigest() }
    public func digestForAfterBootRetirement() throws -> String { try validateForAfterBootRetirement(); return try encodedDigest() }
    private func encodedDigest() throws -> String {
        return RootKeyCodec.hash(Data((version == 3 ? "S101/role-ownership-receipt/v3\0" : version == 2 ? "S100/role-ownership-receipt/v2\0" : "S96/role-ownership-receipt/v1\0").utf8) + (try RootKeyCodec.encode(self, limit: BootstrapLimits.record)))
    }
}

public enum RoleLifecyclePhase: String, Codable { case creating, ready, retiring, retired }
struct RoleLifecycleState: Codable {
    let version: Int, phase: RoleLifecyclePhase, core: String, receipt: String?
    init(phase: RoleLifecyclePhase, core: String, receipt: String?, version: Int = 1) {
        self.version = version; self.phase = phase; self.core = core; self.receipt = receipt
    }
}

/// Cleanup authority after key deletion is confined to one observed boot/tuple.
struct RoleLifecycleCleanupObservation: Codable, Equatable {
    let version: Int, core: String, receipt: String, selection: String, boot: String, root: String
    let device: Int32, inode: UInt64
    init(receipt: RoleOwnershipReceipt, current: OwnedAfterBootRoot) throws {
        try receipt.validateForAfterBootRetirement(); try current.check()
        try RootKeyCodec.require(current.original == receipt.container.identity)
        version = receipt.ready.core.ownershipVersion; core = try receipt.ready.core.binding(); self.receipt = try receipt.digestForAfterBootRetirement()
        selection = try receipt.container.digest(); boot = try RootKeyCodec.boot()
        root = current.original.root; device = current.device; inode = current.inode
    }
    func confirm(receipt: RoleOwnershipReceipt, current: OwnedAfterBootRoot) throws {
        try RootKeyCodec.require(self == RoleLifecycleCleanupObservation(receipt:receipt,current:current))
    }
}
