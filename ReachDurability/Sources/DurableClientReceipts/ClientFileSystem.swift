import Foundation
import Darwin

struct ClientUsage { var bytes = 0; var files = 0 }
/// Trusted ancestors and cooperating owners. All final components are fd-relative/no-follow.
final class ClientFileSystem {
    private(set) var fd: Int32 = -1
    private var lock: Int32 = -1
    private let pid = getpid()
    private var inode: ino_t = 0
    init(path: String, create: Bool) throws {
        if create { guard mkdir(path, 0o700) == 0 else { throw ClientError.io("fresh root", errno) } }
        fd = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ClientError.io("root open", errno) }
        do {
            var s = stat()
            guard fstat(fd, &s) == 0, s.st_mode & S_IFMT == S_IFDIR, s.st_uid == getuid(),
                  s.st_mode & 0o7777 == 0o700 else { throw ClientError.invalid("owned root") }
            lock = openat(fd, "lock", O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0), 0o600)
            guard lock >= 0 else { throw ClientError.io("lock open", errno) }
            inode = try info("lock").st_ino
            guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw errno == EWOULDBLOCK ? ClientError.busy : ClientError.io("root lock", errno) }
            guard fcntl(lock, F_GETFD) & FD_CLOEXEC != 0 else { throw ClientError.invalid("lock lifetime") }
            _ = try usage()
        } catch { close(); throw error }
    }
    deinit { close() }
    func close() { if lock >= 0 { _ = Darwin.close(lock); lock = -1 }; if fd >= 0 { _ = Darwin.close(fd); fd = -1 } }
    func ensure() throws {
        guard pid == getpid(), fd >= 0, lock >= 0 else { throw ClientError.closed }
        var s = stat()
        guard fstat(lock, &s) == 0, s.st_ino == inode, try info("lock").st_ino == inode else { throw ClientError.stale }
    }
    static func role(_ name: String) -> Bool {
        if ["current", "prepared", "lock"].contains(name) { return true }
        return name.utf8.count == 42 && name.hasPrefix("s-") && name.hasSuffix(".bin") && crUUID(String(name.dropFirst(2).dropLast(4)))
    }
    func info(_ name: String) throws -> stat {
        guard Self.role(name) else { throw ClientError.invalid("role") }
        var s = stat()
        let maximum = name == "lock" ? 0 : (name.hasPrefix("s-") ? ClientLimits.snapshot : ClientLimits.manifest)+ClientCrypto.overhead
        guard fstatat(fd, name, &s, AT_SYMLINK_NOFOLLOW) == 0, s.st_mode & S_IFMT == S_IFREG,
              s.st_uid == getuid(), s.st_mode & 0o7777 == 0o600, s.st_nlink == 1,
              s.st_size >= 0, s.st_size <= maximum, s.st_blocks >= 0,
              s.st_blocks <= Int64(ClientLimits.allocation/512) else { throw ClientError.invalid("owned file kind/mode/links/length") }
        return s
    }
    func exists(_ name: String) throws -> Bool {
        guard Self.role(name) else { throw ClientError.invalid("role") }
        var s = stat()
        if fstatat(fd, name, &s, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        guard errno == ENOENT else { throw ClientError.io("existence", errno) }; return false
    }
    func names() throws -> [String] {
        try ensure(); let copy = dup(fd)
        guard copy >= 0 else { throw ClientError.io("scan", errno) }
        _ = fcntl(copy, F_SETFD, FD_CLOEXEC)
        guard let stream = fdopendir(copy) else { _ = Darwin.close(copy); throw ClientError.io("scan stream", errno) }
        defer { closedir(stream) }; rewinddir(stream)
        var result: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(stream) else { guard errno == 0 else { throw ClientError.io("scan read", errno) }; break }
            let name = withUnsafePointer(to: &entry.pointee.d_name) { $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) } }
            if name == "." || name == ".." { continue }
            guard result.count < ClientLimits.files, Self.role(name) else { throw ClientError.invalid("unknown role/count") }
            _ = try info(name); result.append(name)
        }
        return result
    }
    func usage() throws -> ClientUsage {
        try ensure(); var s = stat()
        guard fstat(fd, &s) == 0, s.st_blocks >= 0 else { throw ClientError.invalid("directory allocation") }
        var result = ClientUsage(bytes: Int(s.st_blocks)*512)
        for name in try names() { let s = try info(name); result.bytes += Int(s.st_blocks)*512; result.files += 1 }
        guard result.bytes <= ClientLimits.allocation else { throw ClientError.full }; return result
    }
    func read(_ name: String) throws -> Data {
        let before = try info(name)
        let file = openat(fd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard file >= 0 else { throw ClientError.io("read open", errno) }; defer { _ = Darwin.close(file) }
        var opened = stat()
        guard fstat(file, &opened) == 0, opened.st_ino == before.st_ino, opened.st_dev == before.st_dev else { throw ClientError.invalid("read identity") }
        var result = Data(), buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = Darwin.read(file, &buffer, buffer.count)
            if n < 0 && errno == EINTR { continue }
            guard n >= 0 else { throw ClientError.io("read", errno) }; if n == 0 { break }
            guard n <= Int(before.st_size)-result.count else { throw ClientError.invalid("growing file") }
            result.append(contentsOf: buffer.prefix(n))
        }
        var after = stat()
        guard fstat(file, &after) == 0, result.count == before.st_size, after.st_size == before.st_size,
              after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec, after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec else { throw ClientError.invalid("changed file") }
        return result
    }
    func writeNew(_ name: String, _ data: Data) throws {
        guard Self.role(name), data.count <= (name.hasPrefix("s-") ? ClientLimits.snapshot : ClientLimits.manifest)+ClientCrypto.overhead else { throw ClientError.full }
        let file = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw ClientError.io("exclusive write", errno) }; defer { _ = Darwin.close(file) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.write(file, bytes.baseAddress!.advanced(by: offset), bytes.count-offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw ClientError.io("write", errno) }; offset += n
            }
        }
        guard fsync(file) == 0 else { throw ClientError.io("file sync", errno) }; _ = try info(name)
    }
    func selectPrepared() throws {
        _ = try info("prepared")
        guard renameat(fd, "prepared", fd, "current") == 0 else { throw ClientError.io("manifest rename", errno) }
    }
    func sync() throws { guard fsync(fd) == 0 else { throw ClientError.io("directory sync", errno) } }
    func unlink(_ name: String) throws {
        guard name != "current", name != "lock" else { throw ClientError.invalid("control unlink") }
        _ = try info(name); guard unlinkat(fd, name, 0) == 0 else { throw ClientError.io("unlink", errno) }
    }
}
