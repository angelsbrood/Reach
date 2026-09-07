import Foundation
import RecoveryContract

extension DurableClientReceipts {
    /// No caller content or permission is returned. Client key pruning precedes ticket unlink.
    public func maintainRecovery(in parent:String, binding:RecoveryBinding, hook:RecoveryHook = { _ in }) throws {
        try recoveryBinding(binding)
        try maintenance(); try hook(.afterClientMaintenance)
        let m=try readManifest(); _=try observe(m)
        guard m.ownerEpoch==ownerEpoch else { throw RecoveryError.stale }
        let live=Set(m.records.compactMap { $0.live == nil ? nil : $0.id })
        let directory=try recoveryDirectory(parent,binding:binding,fresh:false); defer { directory.close() }
        var orphans:[String]=[]
        for name in try directory.names() where name != "lock" {
            let body=try RecoveryEncryption.inspect(directory.read(name),binding:binding,root:rootKey)
            guard name == "pending" || name==RecoveryFileSystem.role(body.record) else { throw RecoveryError.unavailable }
            if !live.contains(body.record) { orphans.append(name) }
        }
        // Every candidate is authenticated before the first deletion. Pending live registrations remain incomplete.
        for name in orphans { try hook(.beforeOrphanDelete); try directory.unlink(name); try directory.sync(); try hook(.afterOrphanDelete) }
    }
}
