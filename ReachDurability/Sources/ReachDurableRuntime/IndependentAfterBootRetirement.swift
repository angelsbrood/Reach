import Foundation
import Darwin
import DurableRootKeys
import DurableStoreBootstrap

public enum IndependentAfterBootRetirementError: Error { case refusedLocked, relockUnconfirmed }

/// Explicit original-role cleanup; never acquires a generation or rebases a clock.
public enum IndependentAfterBootRetirement {
    public static func retire(receipt path: String, expectedDigest: String, secretDescriptor: Int32?,
        boundary: (IndependentRetirementBoundary) throws -> Void = { _ in }) throws -> IndependentRetirementReport {
        let credential = try secretDescriptor.map { try UnlockCredential(consumingDescriptor:$0) }
        defer { credential?.close() }
        try TransportContract.currentUser()
        let (receipt,lease) = try RoleLifecycleLease.selectAfterBootRetirement(receipt:path,expectedDigest:expectedDigest)
        defer { lease.close() }
        let core = receipt.ready.core, lifecycle = core.lifecycle!
        guard lifecycle.executable == (try LocalFiles.executable()) else { throw TransportRuntimeError.invalid }
        func result(_ stage: String) -> IndependentRetirementReport {
            .init(stage:stage,role:core.role.rawValue,bootstrap:core.identifier,receiptDigest:expectedDigest)
        }
        guard let current = try OwnedAfterBootRoot.open(lifecycle.identity) else {
            try credential?.consume { _ in }; return result("absent")
        }
        let phase = try lease.phase(receipt:receipt)
        guard phase == .ready || phase == .retiring else { throw TransportRuntimeError.invalid }
        var info = stat()
        let containerPresent = lstat(core.container,&info) == 0
        if !containerPresent { guard errno == ENOENT else { throw TransportRuntimeError.invalid } }
        let before = try KeychainMetadata.read()
        let owned: Set<String> = [core.container]
        guard before.preservesUnrelated(before,owned:owned) else { throw TransportRuntimeError.invalid }
        func removeAndFinish() throws -> IndependentRetirementReport {
            try lease.confirmAfterBootRetry(receipt:receipt,current:current)
            let after = try KeychainMetadata.read()
            guard after.preservesUnrelated(before,owned:owned), after.excludes(owned) else { throw TransportRuntimeError.invalid }
            try IndependentRoleLifecycle.removeSelectedRoot(core,current:current)
            try lease.finishAfterBootRetirement(receipt:receipt,current:current)
            return result("retired")
        }
        if !containerPresent {
            try lease.confirmAfterBootRetry(receipt:receipt,current:current)
            try lease.lockAfterBootJournal(current,required:false)
            try credential?.consume { _ in }
            return try removeAndFinish()
        }
        guard let credential else { throw TransportRuntimeError.invalid }
        func verifySelection() throws {
            try current.check()
            guard try lease.phase(receipt:receipt) == phase else { throw TransportRuntimeError.invalid }
            for member in ["agreement.json",core.role.rawValue+"/selection.json","bootstrap/ready.json","bootstrap/intent.json","keys/role.keychain-db"] {
                _ = try current.inspect(core.root+"/"+member)
            }
            let actual = try RoleBootstrapStore.inspectForAfterBootRetirement(at:core.root,role:core.role)
            guard try RootKeyCodec.encode(actual,limit:64<<10) == RootKeyCodec.encode(receipt.ready,limit:64<<10) else { throw TransportRuntimeError.invalid }
            try IndependentRoleLifecycle.validateSelection(core); try current.check()
        }
        try verifySelection(); try lease.lockAfterBootJournal(current,required:true)
        do {
            return try OwnedAfterBootRetirement.perform(receipt.container,expectedDigest:receipt.container.digest(),current:current,credential:credential,verifySelection:verifySelection) { authority in
                try lease.beginAfterBootRetirement(authority,receipt:receipt,current:current)
                try boundary(.authorized)
                try authority.deleteAuthenticated(); try boundary(.containerDeleted)
                return try removeAndFinish()
            }
        } catch OwnedAfterBootRetirementError.refusedLocked { throw IndependentAfterBootRetirementError.refusedLocked }
          catch OwnedAfterBootRetirementError.relockUnconfirmed { throw IndependentAfterBootRetirementError.relockUnconfirmed }
    }
}
