import Foundation
import DurableRootKeys
import DurableStoreBootstrap

public enum IndependentUnlockError: Error { case verificationRefusedLocked, relockUnconfirmed }
public struct IndependentUnlockReport: Encodable {
    public let stage: String, role: String, bootstrap: String, receiptDigest: String
    public let phase: String
}

/// Explicit, content-free unlock. No generation owner, journal decryption,
/// model, clock renewal or replacement key is part of this operation.
public enum IndependentRoleUnlock {
    public static func unlock(receipt path: String, expectedDigest: String,
                              secretDescriptor: Int32) throws -> IndependentUnlockReport {
        let credential = try UnlockCredential(consumingDescriptor: secretDescriptor)
        defer { credential.close() }
        try TransportContract.currentUser()
        let (receipt, lease) = try RoleLifecycleLease.selectRetirement(receipt: path, expectedDigest: expectedDigest)
        defer { lease.close() }
        let core = receipt.ready.core
        guard core.version == 3, core.unlockPolicy == UnlockCredential.policy, let lifecycle = core.lifecycle,
              lifecycle.executable == (try LocalFiles.executable()), try lifecycle.identity.present() else { throw TransportRuntimeError.invalid }
        let phase = try lease.phase(receipt: receipt)
        guard phase == .ready || phase == .retiring else { throw TransportRuntimeError.invalid }
        func verifySelection() throws {
            guard try lease.phase(receipt: receipt) == phase, try lifecycle.identity.present() else { throw TransportRuntimeError.invalid }
            if phase == .ready { try lease.confirmReady(receipt.ready) }
            let actual = try RoleBootstrapStore.inspect(at: core.root, role: core.role)
            guard try RootKeyCodec.encode(actual,limit:64<<10) == RootKeyCodec.encode(receipt.ready,limit:64<<10) else { throw TransportRuntimeError.invalid }
            try IndependentRoleLifecycle.validateSelection(core)
        }
        try verifySelection()
        try lease.lockJournal()
        let changed: Bool
        do {
            changed = try OwnedContainerUnlock.perform(receipt.container, expectedDigest: receipt.container.digest(),
                policy: core.unlockPolicy!, credential: credential, verifySelection: verifySelection)
        } catch OwnedContainerUnlockError.relockUnconfirmed { throw IndependentUnlockError.relockUnconfirmed }
          catch OwnedContainerUnlockError.verificationRefusedLocked { throw IndependentUnlockError.verificationRefusedLocked }
        return .init(stage: changed ? "unlocked" : "already-unlocked", role: core.role.rawValue,
                     bootstrap: core.identifier, receiptDigest: expectedDigest, phase: phase.rawValue)
    }
}
