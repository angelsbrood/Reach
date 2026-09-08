import Foundation
import Darwin
import DurableHostStore
import ReachWire

/// Narrow raw-role teardown. It never decrypts a damaged child, and it holds the
/// stable child lock until every file and the recorded directory are removed.
final class ChildRetirementGuard {
    let parent: OwnedDirectory
    let name: String
    let directory: OwnedDirectory
    private var lock: Int32 = -1
    private let inode: UInt64
    init(parent: OwnedDirectory, name: String, allowIncomplete: Bool) throws {
        guard LifecycleFileSystem.childRole(name) else { throw LifecycleError.invalid("retirement locator") }
        self.parent = parent; self.name = name; directory = try OwnedDirectory(parent: parent, name: name)
        var s = stat(); guard fstat(directory.fd, &s) == 0 else { throw LifecycleError.io("retirement directory", errno) }; inode = UInt64(s.st_ino)
        do {
            let names = try directory.names(maximum: StoreLimits.files, allowed: LifecycleFileSystem.storeRole)
            for role in names { _ = try directory.info(role, maximum: role == "lock" ? 0 : StoreLimits.candidate+116) }
            if names.contains("lock") {
                lock = openat(directory.fd, "lock", O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
                guard lock >= 0 else { throw LifecycleError.io("retirement lock open", errno) }
                var actual = stat()
                guard fstat(lock, &actual) == 0, actual.st_ino == (try directory.info("lock", maximum: 0)).st_ino else { throw LifecycleError.invalid("retirement lock identity") }
                guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw errno == EWOULDBLOCK ? LifecycleError.busy : LifecycleError.io("retirement lock", errno) }
            } else {
                // The only allowed missing-lock state is an empty directory:
                // before initialization or after locked teardown unlinked lock.
                guard allowIncomplete, names.isEmpty else { throw LifecycleError.cleanupBlocked }
            }
        } catch { close(); throw error }
    }
    deinit { close() }
    func close() { if lock >= 0 { _ = Darwin.close(lock); lock = -1 }; directory.close() }
    func remove(afterFile: () throws -> Void) throws {
        let roles = try directory.names(maximum: StoreLimits.files, allowed: LifecycleFileSystem.storeRole)
        for role in roles where role != "lock" {
            try directory.unlink(role, maximum: StoreLimits.candidate+116); try afterFile()
        }
        try directory.sync()
        if roles.contains("lock") {
            guard lock >= 0 else { throw LifecycleError.cleanupBlocked }
            try directory.unlink("lock", maximum: 0); try afterFile()
        }
        var current = stat()
        guard fstatat(parent.fd, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
              UInt64(current.st_ino) == inode, current.st_mode & S_IFMT == S_IFDIR else { throw LifecycleError.invalid("retirement directory identity") }
        guard unlinkat(parent.fd, name, AT_REMOVEDIR) == 0 else { throw LifecycleError.io("retirement directory removal", errno) }
        try parent.sync()
    }
}
extension DurableSessionLifecycle {
    func retire(_ id: String, disposition: String) throws {
        var d = try catalog.load(); let now = try catalog.time(&d)
        guard let i = d.records.firstIndex(where: { $0.id == id }) else { return }
        if d.records[i].phase == .tombstone { return }
        if d.records[i].phase == .retiring { try finishRetirement(id); return }
        guard let work = d.records[i].work else { throw LifecycleError.invalid("retirement work") }
        children.removeValue(forKey: id)?.close()
        // Read actual committed ending when authority is available. Damaged
        // content leaves that ending unknown; it is never replaced with a fake
        // cancellation WireEvent or interpreted as an uncommitted tool effect.
        if try catalog.files.children.exists(LifecycleFileSystem.childName(work.child)) {
            do {
                let request = try catalog.request(d.records[i])
                let identity = try StoreIdentity(storeID: work.child, provider: request.provider)
                let store = try DurableHostStore.reopen(at: catalog.files.childPath(work.child), identity: identity, keys: work.keys.storeKeys())
                defer { store.close() }
                let state = try store.snapshot(); d.records[i].high = state.high
                if let candidate = state.candidate {
                    struct Ending: Decodable { let terminal: WireFinishReason? }
                    d.records[i].ending = try JSONDecoder().decode(Ending.self, from: candidate.commit.data).terminal
                }
            } catch StoreError.busy { throw LifecycleError.busy }
            catch { d.records[i].nonResumable = true }
        }
        let guardFile: ChildRetirementGuard?
        if try catalog.files.children.exists(LifecycleFileSystem.childName(work.child)) {
            guardFile = try ChildRetirementGuard(parent: catalog.files.children, name: LifecycleFileSystem.childName(work.child), allowIncomplete: true)
        } else { guardFile = nil }
        defer { guardFile?.close() }
        try fault(.beforeRetirementIntent)
        d.records[i].phase = .retiring; d.records[i].disposition = disposition
        d.records[i].cleanup = .init(request: work.request, child: work.child)
        d.records[i].work = nil // keys/contact/content leave authoritative catalog before deletion
        if d.records[i].identity!.ticketExpiry <= now { d.records[i].identity = nil }
        try catalog.replace(d); try fault(.afterRetirementIntent)
        try completeDeletion(id, held: guardFile)
    }
    func finishRetirement(_ id: String) throws {
        children.removeValue(forKey: id)?.close()
        var d = try catalog.load(); let now = try catalog.time(&d)
        guard let i = d.records.firstIndex(where: { $0.id == id }), d.records[i].phase == .retiring,
              let cleanup = d.records[i].cleanup else { return }
        // Retirement may have started under a valid ticket. Remove identity that
        // expired since then before another fallible lock or deletion attempt.
        // A failed catalog replacement aborts cleanup; it is never treated as saved.
        if let identity = d.records[i].identity, identity.ticketExpiry <= now {
            d.records[i].identity = nil; try catalog.replace(d)
        }
        let guardFile: ChildRetirementGuard?
        if let child = cleanup.child, try catalog.files.children.exists(LifecycleFileSystem.childName(child)) {
            guardFile = try ChildRetirementGuard(parent: catalog.files.children, name: LifecycleFileSystem.childName(child), allowIncomplete: true)
        } else { guardFile = nil }
        defer { guardFile?.close() }
        try completeDeletion(id, held: guardFile)
    }
    private func completeDeletion(_ id: String, held: ChildRetirementGuard?) throws {
        var d = try catalog.load()
        guard let i = d.records.firstIndex(where: { $0.id == id }), d.records[i].phase == .retiring,
              let cleanup = d.records[i].cleanup else { throw LifecycleError.invalid("durable cleanup intent") }
        try held?.remove { try self.fault(.duringContentDeletion) }
        if let request = cleanup.request, try catalog.files.requests.exists(LifecycleFileSystem.requestName(request)) {
            try catalog.files.requests.unlink(LifecycleFileSystem.requestName(request), maximum: LifecycleLimits.request+LifecycleCrypto.overhead)
            try catalog.files.requests.sync(); try fault(.duringContentDeletion)
        }
        try fault(.afterContentDeletion)
        let now = try catalog.time(&d)
        if d.records[i].identity.map({ $0.ticketExpiry <= now }) ?? true { d.records.remove(at: i) }
        else { d.records[i].phase = .tombstone; d.records[i].cleanup = nil }
        try catalog.replace(d); try fault(.afterTombstone)
    }
}
