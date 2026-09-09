import Foundation
import Darwin
import DurableRootKeys

/// One own-role lease outside the removable root. Workers and retirement hold
/// this same exclusion before keys/journals and through resource release.
public final class RoleLifecycleLease {
    public let core: RoleBootstrapCore
    private let afterBootRetirement: Bool
    private let parent: String, receiptName: String, process = getpid(), created: Bool
    private var directory: Int32 = -1, lock: Int32 = -1, journal: Int32 = -1
    private var directoryInode: UInt64 = 0, lockInode: UInt64 = 0, device: Int32 = 0
    private var createdNames: [String] = []
    private var lockName: String { receiptName + ".lock" }
    private var stateName: String { receiptName + ".state.json" }
    private var nextName: String { receiptName + ".next" }
    private init(core: RoleBootstrapCore, create: Bool, afterBootRetirement: Bool = false) throws {
        guard (2...3).contains(core.version), let lifecycle = core.lifecycle else { throw BootstrapError.invalid }
        if afterBootRetirement {
            try RootKeyCodec.require(!create); try core.validateForAfterBootRetirement()
        } else { try core.validateDescription(role: core.role, root: core.root) }
        self.afterBootRetirement = afterBootRetirement
        self.core = core; created = create
        parent = try RootKeyCodec.parent(lifecycle.receipt)
        receiptName = URL(fileURLWithPath: lifecycle.receipt).lastPathComponent
        guard receiptName.utf8.count <= 200 else { throw BootstrapError.invalid }
        directory = open(parent, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        guard directory >= 0 else { throw BootstrapError.io("lifecycle-directory", errno) }
        do {
            var info = stat(); guard fstat(directory, &info) == 0 else { throw BootstrapError.invalid }
            directoryInode = UInt64(info.st_ino); device = info.st_dev
            if create {
                for name in [receiptName, lockName, stateName, nextName] {
                    var named = stat()
                    guard fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT else { throw BootstrapError.invalid }
                }
            }
            lock = openat(directory, lockName, O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|(create ? O_CREAT|O_EXCL : 0), 0o600)
            guard lock >= 0 else { throw BootstrapError.incomplete }
            if create { createdNames.append(lockName) }
            let locked = try regular(lock, empty: true); lockInode = UInt64(locked.st_ino)
            guard flock(lock, LOCK_EX|LOCK_NB) == 0 else { throw errno == EWOULDBLOCK ? BootstrapError.busy : BootstrapError.io("lifecycle-flock", errno) }
            try ensure()
            if create {
                try RootKeyCodec.require(lifecycle.identity.present())
                try writeNew(stateName, bytes: RootKeyCodec.encode(RoleLifecycleState(phase: .creating, core: core.binding(), receipt: nil), limit: BootstrapLimits.record))
            }
        } catch {
            if create { try? rollbackCreation() }
            close(); throw error
        }
    }
    public static func create(core: RoleBootstrapCore) throws -> RoleLifecycleLease { try .init(core: core, create: true) }
    public static func acquire(ready: RoleBootstrapReady) throws -> RoleLifecycleLease {
        let lease = try RoleLifecycleLease(core: ready.core, create: false)
        try lease.confirmReady(ready); return lease
    }
    public static func selectRetirement(receipt path: String, expectedDigest: String) throws -> (RoleOwnershipReceipt, RoleLifecycleLease) {
        _ = try RootKeyCodec.parent(path); _ = try RootKeyCodec.regular(path, maximum: BootstrapLimits.record, mode: 0o600)
        let receipt = try RootKeyCodec.decode(RoleOwnershipReceipt.self, Data(contentsOf: URL(fileURLWithPath: path)), limit: BootstrapLimits.record)
        try receipt.validate()
        try RootKeyCodec.require(receipt.digest() == expectedDigest && receipt.ready.core.lifecycle?.receipt == path)
        let lease = try RoleLifecycleLease(core: receipt.ready.core, create: false)
        _ = try lease.selectedReceipt(expectedDigest: expectedDigest)
        _ = try lease.phase(receipt: receipt)
        return (receipt, lease)
    }
    public static func selectAfterBootRetirement(receipt path: String, expectedDigest: String) throws -> (RoleOwnershipReceipt, RoleLifecycleLease) {
        _ = try RootKeyCodec.parent(path); _ = try RootKeyCodec.regular(path, maximum: BootstrapLimits.record, mode: 0o600)
        let receipt = try RootKeyCodec.decode(RoleOwnershipReceipt.self, Data(contentsOf: URL(fileURLWithPath:path)), limit:BootstrapLimits.record)
        try RootKeyCodec.require(receipt.digestForAfterBootRetirement() == expectedDigest && receipt.ready.core.lifecycle?.receipt == path)
        let lease = try RoleLifecycleLease(core:receipt.ready.core,create:false,afterBootRetirement:true)
        _ = try lease.selectedReceipt(expectedDigest:expectedDigest)
        _ = try lease.phase(receipt:receipt)
        return (receipt,lease)
    }
    private func receiptDigest(_ receipt: RoleOwnershipReceipt) throws -> String {
        try afterBootRetirement ? receipt.digestForAfterBootRetirement() : receipt.digest()
    }
    private func regular(_ fd: Int32, empty: Bool = false) throws -> stat {
        var value = stat()
        guard fstat(fd, &value) == 0 && value.st_mode&S_IFMT == S_IFREG && value.st_uid == getuid() && value.st_nlink == 1 &&
            value.st_mode&0o7777 == 0o600 && value.st_size >= 0 && value.st_size <= BootstrapLimits.record && (!empty || value.st_size == 0) else { throw BootstrapError.invalid }
        return value
    }
    private func ensure() throws {
        guard process == getpid(), directory >= 0, lock >= 0 else { throw BootstrapError.closed }
        try RootKeyCodec.directory(parent)
        var named = stat(), current = stat()
        guard lstat(parent, &current) == 0 && current.st_dev == device && UInt64(current.st_ino) == directoryInode &&
            fstatat(directory, lockName, &named, AT_SYMLINK_NOFOLLOW) == 0 && named.st_dev == device && UInt64(named.st_ino) == lockInode else { throw BootstrapError.invalid }
        _ = try regular(lock, empty: true)
    }
    private func read(_ name: String) throws -> Data {
        try ensure()
        let fd = openat(directory, name, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)
        guard fd >= 0 else { throw BootstrapError.incomplete }; defer { _ = Darwin.close(fd) }
        let before = try regular(fd)
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 && count <= BootstrapLimits.record - bytes.count else { throw BootstrapError.invalid }
            if count == 0 { break }; bytes.append(contentsOf: buffer.prefix(count))
        }
        let after = try regular(fd)
        guard before.st_ino == after.st_ino && before.st_size == after.st_size && bytes.count == after.st_size &&
            before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else { throw BootstrapError.invalid }
        return bytes
    }
    private func writeNew(_ name: String, bytes: Data) throws {
        try ensure(); guard bytes.count <= BootstrapLimits.record else { throw BootstrapError.invalid }
        let fd = openat(directory, name, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw BootstrapError.invalid }; defer { _ = Darwin.close(fd) }
        if created { createdNames.append(name) }
        try bytes.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count-offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw BootstrapError.io("lifecycle-write", errno) }; offset += count
            }
        }
        guard fsync(fd) == 0 && fsync(directory) == 0 else { throw BootstrapError.io("lifecycle-sync", errno) }
    }
    private func setPhase(_ phase: RoleLifecyclePhase, receipt: RoleOwnershipReceipt,
        recoveringAfterBootPending: Bool = false, afterPendingWrite: () throws -> Void = {}) throws {
        let bytes = try RootKeyCodec.encode(RoleLifecycleState(phase: phase, core: core.binding(), receipt: receiptDigest(receipt)), limit: BootstrapLimits.record)
        var recovered = false
        if recoveringAfterBootPending {
            try RootKeyCodec.require(afterBootRetirement && journal >= 0 && phase == .retiring && self.phase(receipt:receipt) == .ready)
            var named = stat()
            if fstatat(directory,nextName,&named,AT_SYMLINK_NOFOLLOW) == 0 {
                let fd = openat(directory,nextName,O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)
                guard fd >= 0 else { throw BootstrapError.invalid }; defer { _ = Darwin.close(fd) }
                let before = try regular(fd)
                try RootKeyCodec.require(before.st_dev == device && named.st_dev == before.st_dev && named.st_ino == before.st_ino)
                // Only the exact original-bound retiring bytes can be resumed.
                // The caller has freshly confirmed original-key authority.
                try RootKeyCodec.require(read(nextName) == bytes)
                let after = try regular(fd)
                try RootKeyCodec.require(before.st_ino == after.st_ino && before.st_size == after.st_size &&
                    before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
                    fstatat(directory,nextName,&named,AT_SYMLINK_NOFOLLOW) == 0 && named.st_dev == before.st_dev && named.st_ino == before.st_ino)
                guard fsync(fd) == 0 else { throw BootstrapError.io("lifecycle-pending-sync",errno) }
                recovered = true
            } else { try RootKeyCodec.require(errno == ENOENT) }
        }
        if !recovered { try writeNew(nextName, bytes: bytes) }
        try afterPendingWrite()
        guard renameat(directory, nextName, directory, stateName) == 0 && fsync(directory) == 0 else { throw BootstrapError.io("lifecycle-transition", errno) }
        createdNames.removeAll { $0 == nextName }
    }
    private func selectedReceipt(expectedDigest: String) throws -> RoleOwnershipReceipt {
        let receipt = try RootKeyCodec.decode(RoleOwnershipReceipt.self, read(receiptName), limit: BootstrapLimits.record)
        try RootKeyCodec.require(receipt.ready.core == core && receiptDigest(receipt) == expectedDigest)
        return receipt
    }
    public func confirmCreating(_ value: RoleBootstrapCore) throws {
        try ensure(); try RootKeyCodec.require(!afterBootRetirement && created && value == core && core.lifecycle!.identity.present())
        let state = try RootKeyCodec.decode(RoleLifecycleState.self, read(stateName), limit: BootstrapLimits.record)
        try RootKeyCodec.require(state.version == 1 && state.phase == .creating && state.core == core.binding() && state.receipt == nil)
    }
    public func publish(_ ready: RoleBootstrapReady) throws -> String {
        try confirmCreating(ready.core)
        let receipt = try RoleOwnershipReceipt(ready: ready)
        try writeNew(receiptName, bytes: RootKeyCodec.encode(receipt, limit: BootstrapLimits.record))
        try setPhase(.ready, receipt: receipt); try confirmReady(ready)
        return try receipt.digest()
    }
    public func confirmReady(_ ready: RoleBootstrapReady) throws {
        try ensure(); try RootKeyCodec.require(!afterBootRetirement && ready.core == core && core.lifecycle!.identity.present())
        let expected = try RoleOwnershipReceipt(ready: ready), receipt = try selectedReceipt(expectedDigest: expected.digest())
        try RootKeyCodec.require(phase(receipt: receipt) == .ready)
        var pending = stat()
        try RootKeyCodec.require(fstatat(directory, nextName, &pending, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT)
    }
    public func phase(receipt: RoleOwnershipReceipt) throws -> RoleLifecyclePhase {
        try ensure(); try RootKeyCodec.require(receipt.ready.core == core)
        let state = try RootKeyCodec.decode(RoleLifecycleState.self, read(stateName), limit: BootstrapLimits.record)
        try RootKeyCodec.require(state.version == 1 && state.core == core.binding() && state.receipt == receiptDigest(receipt) && state.phase != .creating)
        return state.phase
    }
    public func lockJournal() throws {
        try ensure(); try RootKeyCodec.require(core.lifecycle!.identity.present() && journal < 0)
        let path = core.root + "/bootstrap/" + core.role.rawValue + "/lock"
        _ = try RootKeyCodec.parent(path)
        journal = open(path, O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)
        guard journal >= 0 else { throw BootstrapError.incomplete }
        do {
            _ = try regular(journal, empty: true)
            guard flock(journal, LOCK_EX|LOCK_NB) == 0 else { throw errno == EWOULDBLOCK ? BootstrapError.busy : BootstrapError.io("retirement-journal", errno) }
        } catch { _ = Darwin.close(journal); journal = -1; throw error }
    }
    public func beginRetirement(_ authority: OwnedContainerRetirement, receipt: RoleOwnershipReceipt) throws {
        try confirmReady(receipt.ready)
        try RootKeyCodec.require(journal >= 0 && authority.confirms(receipt.container))
        try setPhase(.retiring, receipt: receipt)
    }
    public func finishRetirement(receipt: RoleOwnershipReceipt) throws {
        try RootKeyCodec.require(!afterBootRetirement && phase(receipt: receipt) == .retiring && !core.lifecycle!.identity.present())
        try setPhase(.retired, receipt: receipt)
    }
    public func lockAfterBootJournal(_ current: OwnedAfterBootRoot, required: Bool) throws {
        try ensure(); try RootKeyCodec.require(afterBootRetirement && current.original == core.lifecycle!.identity && journal < 0)
        try current.check()
        let path = core.root+"/bootstrap/"+core.role.rawValue+"/lock"
        var named = stat()
        if lstat(path,&named) != 0 {
            try RootKeyCodec.require(errno == ENOENT && !required); return
        }
        _ = try current.inspect(path)
        journal = open(path,O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)
        guard journal >= 0 else { throw BootstrapError.incomplete }
        do {
            let value = try regular(journal,empty:true)
            try RootKeyCodec.require(value.st_dev == named.st_dev && value.st_ino == named.st_ino)
            guard flock(journal,LOCK_EX|LOCK_NB) == 0 else { throw errno == EWOULDBLOCK ? BootstrapError.busy : BootstrapError.io("after-boot-journal",errno) }
            try current.check()
        } catch { _ = Darwin.close(journal); journal = -1; throw error }
    }
    public func beginAfterBootRetirement(_ authority: OwnedAfterBootRetirement, receipt: RoleOwnershipReceipt, current: OwnedAfterBootRoot) throws {
        try beginAfterBootRetirement(receipt:receipt,current:current,confirmAuthority:{
            try RootKeyCodec.require(authority.confirms(receipt.container,current:current))
        })
    }
    // Internal transaction seam for durable-write interruption tests. The public
    // entrypoint always requires the freshly confirmed original Keychain capability.
    func beginAfterBootRetirement(receipt: RoleOwnershipReceipt, current: OwnedAfterBootRoot,
        confirmAuthority: () throws -> Void, afterPendingWrite: () throws -> Void = {}) throws {
        try RootKeyCodec.require(afterBootRetirement && journal >= 0 && current.original == core.lifecycle!.identity)
        try confirmAuthority(); try current.check()
        let selected = try selectedReceipt(expectedDigest:receiptDigest(receipt))
        let phase = try phase(receipt:selected)
        try RootKeyCodec.require(phase == .ready || phase == .retiring)
        let observation = try RoleLifecycleCleanupObservation(receipt:receipt,current:current)
        let name = receiptName+".cleanup.json", temporary = receiptName+".cleanup.next"
        // Original-key authority permits replacing this cleanup-only observation.
        // A leftover owned temporary file carries no authority of its own.
        var info = stat()
        if fstatat(directory,temporary,&info,AT_SYMLINK_NOFOLLOW) == 0 {
            _ = try read(temporary)
            guard unlinkat(directory,temporary,0) == 0 else { throw BootstrapError.invalid }
        } else { try RootKeyCodec.require(errno == ENOENT) }
        if fstatat(directory,name,&info,AT_SYMLINK_NOFOLLOW) == 0 { _ = try read(name) }
        else { try RootKeyCodec.require(errno == ENOENT) }
        try writeNew(temporary,bytes:RootKeyCodec.encode(observation,limit:BootstrapLimits.record))
        guard renameat(directory,temporary,directory,name) == 0 && fsync(directory) == 0 else { throw BootstrapError.io("cleanup-observation",errno) }
        if phase == .ready { try setPhase(.retiring,receipt:receipt,recoveringAfterBootPending:true,afterPendingWrite:afterPendingWrite) }
        try confirmAfterBootRetry(receipt:receipt,current:current)
    }
    public func confirmAfterBootRetry(receipt: RoleOwnershipReceipt, current: OwnedAfterBootRoot) throws {
        try RootKeyCodec.require(afterBootRetirement && phase(receipt:receipt) == .retiring)
        _ = try selectedReceipt(expectedDigest:receiptDigest(receipt))
        let observation = try RootKeyCodec.decode(RoleLifecycleCleanupObservation.self,read(receiptName+".cleanup.json"),limit:BootstrapLimits.record)
        try observation.confirm(receipt:receipt,current:current)
    }
    public func finishAfterBootRetirement(receipt: RoleOwnershipReceipt, current: OwnedAfterBootRoot) throws {
        try RootKeyCodec.require(afterBootRetirement && current.original == core.lifecycle!.identity && phase(receipt:receipt) == .retiring && current.absent())
        try setPhase(.retired,receipt:receipt)
    }
    /// Only an invocation that exclusively created these names can roll them back.
    public func rollbackCreation() throws {
        guard created else { throw BootstrapError.invalid }
        if lockInode == 0 { close(); return }
        try ensure()
        for name in createdNames.reversed() where name != lockName {
            if unlinkat(directory, name, 0) != 0 && errno != ENOENT { throw BootstrapError.io("lifecycle-rollback", errno) }
        }
        if unlinkat(directory, lockName, 0) != 0 && errno != ENOENT { throw BootstrapError.io("lifecycle-rollback-lock", errno) }
        _ = fsync(directory); close()
    }
    public func close() {
        if journal >= 0 { _ = Darwin.close(journal); journal = -1 }
        if lock >= 0 { _ = Darwin.close(lock); lock = -1 }
        if directory >= 0 { _ = Darwin.close(directory); directory = -1 }
    }
    deinit { close() }
}
