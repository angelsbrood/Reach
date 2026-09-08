import Foundation
import Darwin

struct StoreFileInfo { let size: Int; let allocated: Int; let inode: UInt64 }
/// The caller supplies a trusted private root. Final components are fd-relative
/// and no-follow; this does not promise arbitrary-ancestor or racing-attacker safety.
final class StoreFileSystem {
    private(set) var directory: Int32 = -1
    private(set) var lock: Int32 = -1
    private let process = getpid()
    private var lockInode: UInt64 = 0
    private var lockDevice: Int32 = 0
    let path: String
    init(path: String, create: Bool) throws {
        self.path = path
        if create, mkdir(path, 0o700) != 0 { throw StoreError.io("fresh store directory", errno) }
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid(), info.st_mode & 0o7777 == 0o700 else { throw StoreError.invalid("private root kind/owner/mode") }
        directory = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directory >= 0 else { throw StoreError.io("open private root", errno) }
        do {
            var opened = stat()
            guard fstat(directory, &opened) == 0, opened.st_ino == info.st_ino, opened.st_dev == info.st_dev else { throw StoreError.invalid("opened root identity") }
            let flags = O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | (create ? O_CREAT | O_EXCL : 0)
            lock = openat(directory, "lock", flags, 0o600)
            guard lock >= 0 else { throw StoreError.io("open stable lock", errno) }
            let checked = try validateFD(lock, role: "lock")
            lockInode = UInt64(checked.st_ino); lockDevice = checked.st_dev
            guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw errno == EWOULDBLOCK ? StoreError.busy : StoreError.io("lock", errno) }
            guard fcntl(lock, F_GETFD) & FD_CLOEXEC != 0 else { throw StoreError.invalid("lock close-on-exec") }
            _ = try scan()
        } catch { close(); throw error }
    }
    deinit { close() }
    func ensure() throws {
        if getpid() != process { close(); throw StoreError.closed }
        guard directory >= 0, lock >= 0 else { throw StoreError.closed }
        let fd = try validateFD(lock, role: "lock")
        var named = stat()
        guard fstatat(directory, "lock", &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_ino == fd.st_ino, named.st_dev == fd.st_dev, UInt64(fd.st_ino) == lockInode, fd.st_dev == lockDevice else { throw StoreError.invalid("stable lock inode") }
    }
    func close() {
        // A post-fork copy cannot use this object or explicitly unlock the parent's
        // shared lock. No lock FD is duplicated; close-on-exec closes inherited FDs.
        if lock >= 0 { _ = Darwin.close(lock); lock = -1 }
        if directory >= 0 { _ = Darwin.close(directory); directory = -1 }
    }
    static func known(_ role: String) -> Bool {
        if role == "current" || role == "lock" { return true }
        guard role.count == 42, (role.hasPrefix("b-") || role.hasPrefix("t-")), role.hasSuffix(".bin") else { return false }
        return storeUUID(String(role.dropFirst(2).dropLast(4)))
    }
    private func validateFD(_ fd: Int32, role: String) throws -> stat {
        var s = stat()
        guard fstat(fd, &s) == 0, s.st_mode & S_IFMT == S_IFREG, s.st_uid == getuid(), s.st_mode & 0o7777 == 0o600,
              s.st_nlink == 1, s.st_size >= 0, s.st_size <= StoreLimits.candidate+StoreCrypto.overhead,
              role != "lock" || s.st_size == 0 else { throw StoreError.invalid("store file kind/owner/mode/links/length") }
        return s
    }
    func scan() throws -> [String: StoreFileInfo] {
        try ensure()
        let duplicate = dup(directory)
        guard duplicate >= 0 else { throw StoreError.io("directory scan", errno) }
        _ = fcntl(duplicate, F_SETFD, FD_CLOEXEC)
        guard let stream = fdopendir(duplicate) else { _ = Darwin.close(duplicate); throw StoreError.io("directory stream", errno) }
        defer { closedir(stream) }; rewinddir(stream)
        var result: [String: StoreFileInfo] = [:]
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw StoreError.io("directory enumeration", errno) }
                break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) { $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) } }
            if name == "." || name == ".." { continue }
            guard Self.known(name), result.count < StoreLimits.files else { throw StoreError.invalid("unknown role/file count") }
            let fd = openat(directory, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw StoreError.io("inspect store role", errno) }
            let info: stat
            do { info = try validateFD(fd, role: name) } catch { _ = Darwin.close(fd); throw error }
            _ = Darwin.close(fd)
            guard info.st_blocks >= 0, info.st_blocks <= Int64(StoreLimits.allocation/512) else { throw StoreError.full }
            result[name] = .init(size: Int(info.st_size), allocated: Int(info.st_blocks)*512, inode: UInt64(info.st_ino))
        }
        guard result.values.reduce(0, { $0 + $1.allocated }) <= StoreLimits.allocation else { throw StoreError.full }
        return result
    }
    func read(_ role: String, maximum: Int) throws -> Data {
        try ensure(); guard Self.known(role) else { throw StoreError.invalid("read role") }
        let fd = openat(directory, role, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw StoreError.io("read authoritative role", errno) }
        defer { _ = Darwin.close(fd) }
        let before = try validateFD(fd, role: role)
        guard before.st_size <= maximum else { throw StoreError.invalid("read length cap") }
        var data = Data(); var buffer = [UInt8](repeating: 0, count: 64*1024)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw StoreError.io("file read", errno) }
            if count == 0 { break }
            guard count <= maximum-data.count else { throw StoreError.invalid("growing file") }
            data.append(contentsOf: buffer.prefix(count))
        }
        let after = try validateFD(fd, role: role)
        guard before.st_ino == after.st_ino, before.st_dev == after.st_dev, before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              data.count == after.st_size else { throw StoreError.invalid("changed file") }
        return data
    }
    func writeNew(_ role: String, bytes: Data) throws {
        try ensure()
        guard Self.known(role), role != "lock", role != "current", bytes.count <= StoreLimits.candidate+StoreCrypto.overhead,
              try scan().count < StoreLimits.files else { throw StoreError.full }
        let fd = openat(directory, role, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw StoreError.io("exclusive ciphertext create", errno) }
        defer { _ = Darwin.close(fd) }
        _ = try validateFD(fd, role: role)
        try bytes.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count-offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw StoreError.io("ciphertext write", errno) }; offset += count
            }
        }
        guard fsync(fd) == 0 else { throw StoreError.io("file sync", errno) }
    }
    func replaceCurrent(with temporary: String) throws {
        try ensure(); guard temporary.hasPrefix("t-"), Self.known(temporary) else { throw StoreError.invalid("manifest temporary role") }
        _ = try scan()
        guard renameat(directory, temporary, directory, "current") == 0 else { throw StoreError.io("manifest replacement", errno) }
    }
    func syncDirectory() throws { try ensure(); guard fsync(directory) == 0 else { throw StoreError.io("directory sync", errno) } }
    func removeUnreferenced(_ roles: [String]) throws {
        let known = try scan()
        for role in roles {
            guard known[role] != nil, Self.known(role), role.hasPrefix("b-") || role.hasPrefix("t-") else { throw StoreError.invalid("orphan cleanup role") }
            guard unlinkat(directory, role, 0) == 0 else { throw StoreError.io("orphan unlink", errno) }
        }
        if !roles.isEmpty { try syncDirectory() }
    }
}
