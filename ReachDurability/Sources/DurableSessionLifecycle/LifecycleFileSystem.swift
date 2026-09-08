import Foundation
import Darwin
import DurableHostStore

struct LifecycleUsage { var bytes = 0; var files = 0 }
/// Trusted owned roots only. Final components are no-follow and fd-relative;
/// arbitrary ancestors and adversarial same-user races are outside this candidate.
final class OwnedDirectory {
    private(set) var fd: Int32
    init(path: String) throws {
        fd = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw LifecycleError.io("directory open", errno) }
        do { try validate() } catch { close(); throw error }
    }
    init(parent: OwnedDirectory, name: String) throws {
        fd = openat(parent.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw LifecycleError.io("relative directory open", errno) }
        do { try validate() } catch { close(); throw error }
    }
    deinit { close() }
    func close() { if fd >= 0 { _ = Darwin.close(fd); fd = -1 } }
    func validate() throws {
        var s = stat()
        guard fd >= 0, fstat(fd, &s) == 0, s.st_mode & S_IFMT == S_IFDIR, s.st_uid == getuid(), s.st_mode & 0o7777 == 0o700 else { throw LifecycleError.invalid("owned directory") }
    }
    func allocatedBytes() throws -> Int {
        try validate(); var s = stat()
        guard fstat(fd, &s) == 0, s.st_blocks >= 0, s.st_blocks <= Int64(LifecycleLimits.allocation/512) else { throw LifecycleError.invalid("directory allocation") }
        return Int(s.st_blocks)*512
    }
    func names(maximum: Int, allowed: (String) -> Bool) throws -> [String] {
        try validate()
        let copy = dup(fd)
        guard copy >= 0 else { throw LifecycleError.io("directory scan", errno) }
        _ = fcntl(copy, F_SETFD, FD_CLOEXEC)
        guard let stream = fdopendir(copy) else { _ = Darwin.close(copy); throw LifecycleError.io("directory stream", errno) }
        defer { closedir(stream) }; rewinddir(stream)
        var result: [String] = []
        while true {
            errno = 0
            guard let item = readdir(stream) else { guard errno == 0 else { throw LifecycleError.io("directory enumeration", errno) }; break }
            let name = withUnsafePointer(to: &item.pointee.d_name) { $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) } }
            if name == "." || name == ".." { continue }
            guard result.count < maximum, allowed(name) else { throw LifecycleError.invalid("unknown role/count") }
            result.append(name)
        }
        return result
    }
    func info(_ name: String, maximum: Int) throws -> stat {
        var s = stat()
        guard fstatat(fd, name, &s, AT_SYMLINK_NOFOLLOW) == 0, s.st_mode & S_IFMT == S_IFREG,
              s.st_uid == getuid(), s.st_mode & 0o7777 == 0o600, s.st_nlink == 1,
              s.st_size >= 0, s.st_size <= maximum, s.st_blocks >= 0,
              s.st_blocks <= Int64(LifecycleLimits.allocation/512) else { throw LifecycleError.invalid("owned file kind/links/mode/length") }
        return s
    }
    func exists(_ name: String) throws -> Bool {
        var s = stat()
        if fstatat(fd, name, &s, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        guard errno == ENOENT else { throw LifecycleError.io("role existence", errno) }; return false
    }
    func read(_ name: String, maximum: Int) throws -> Data {
        let before = try info(name, maximum: maximum)
        let file = openat(fd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard file >= 0 else { throw LifecycleError.io("role read", errno) }
        defer { _ = Darwin.close(file) }
        var opened = stat()
        guard fstat(file, &opened) == 0, opened.st_ino == before.st_ino, opened.st_dev == before.st_dev else { throw LifecycleError.invalid("opened file identity") }
        var result = Data(), buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = Darwin.read(file, &buffer, buffer.count)
            if n < 0 && errno == EINTR { continue }
            guard n >= 0 else { throw LifecycleError.io("bounded read", errno) }
            if n == 0 { break }
            guard n <= maximum-result.count else { throw LifecycleError.invalid("growing role") }; result.append(contentsOf: buffer.prefix(n))
        }
        var after = stat()
        guard fstat(file, &after) == 0, after.st_size == before.st_size, result.count == after.st_size,
              after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec, after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec else { throw LifecycleError.invalid("changed role") }
        return result
    }
    func writeNew(_ name: String, bytes: Data, maximum: Int) throws {
        guard bytes.count <= maximum else { throw LifecycleError.full }
        let file = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw LifecycleError.io("exclusive role create", errno) }
        defer { _ = Darwin.close(file) }
        try bytes.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = Darwin.write(file, raw.baseAddress!.advanced(by: offset), raw.count-offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw LifecycleError.io("ciphertext write", errno) }; offset += n
            }
        }
        guard fsync(file) == 0 else { throw LifecycleError.io("file sync", errno) }
        _ = try info(name, maximum: maximum)
    }
    func sync() throws { guard fsync(fd) == 0 else { throw LifecycleError.io("directory sync", errno) } }
    func unlink(_ name: String, maximum: Int) throws {
        _ = try info(name, maximum: maximum)
        guard unlinkat(fd, name, 0) == 0 else { throw LifecycleError.io("owned unlink", errno) }
    }
}
final class LifecycleFileSystem {
    let path: String
    let root: OwnedDirectory
    let requests: OwnedDirectory
    let children: OwnedDirectory
    private(set) var lock: Int32 = -1
    private let pid = getpid()
    private var inode: UInt64 = 0
    init(path: String, create: Bool) throws {
        self.path = path
        if create, mkdir(path, 0o700) != 0 { throw LifecycleError.io("fresh catalog root", errno) }
        root = try OwnedDirectory(path: path)
        if create {
            guard mkdirat(root.fd, "requests", 0o700) == 0, mkdirat(root.fd, "children", 0o700) == 0 else { throw LifecycleError.io("fresh role directories", errno) }
        }
        requests = try OwnedDirectory(parent: root, name: "requests"); children = try OwnedDirectory(parent: root, name: "children")
        do {
            lock = openat(root.fd, "lock", O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0), 0o600)
            guard lock >= 0 else { throw LifecycleError.io("root lock open", errno) }
            inode = UInt64(try root.info("lock", maximum: 0).st_ino)
            guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw errno == EWOULDBLOCK ? LifecycleError.busy : LifecycleError.io("root lock", errno) }
            guard fcntl(lock, F_GETFD) & FD_CLOEXEC != 0 else { throw LifecycleError.invalid("root lock lifetime") }
            _ = try usage()
        } catch { close(); throw error }
    }
    deinit { close() }
    func ensure() throws {
        if pid != getpid() { close(); throw LifecycleError.closed }
        guard lock >= 0 else { throw LifecycleError.closed }
        var s = stat()
        guard fstat(lock, &s) == 0, UInt64(s.st_ino) == inode,
              try root.info("lock", maximum: 0).st_ino == s.st_ino else { throw LifecycleError.stale }
    }
    func close() { if lock >= 0 { _ = Darwin.close(lock); lock = -1 }; children.close(); requests.close(); root.close() }
    static func childName(_ id: String) -> String { "g-"+id }
    static func requestName(_ id: String) -> String { "r-"+id+".bin" }
    static func requestRole(_ name: String) -> Bool { name.count == 42 && name.hasPrefix("r-") && name.hasSuffix(".bin") && lcUUID(String(name.dropFirst(2).dropLast(4))) }
    static func childRole(_ name: String) -> Bool { name.count == 38 && name.hasPrefix("g-") && lcUUID(String(name.dropFirst(2))) }
    static func storeRole(_ name: String) -> Bool {
        if ["current", "lock"].contains(name) { return true }
        return name.count == 42 && (name.hasPrefix("b-") || name.hasPrefix("t-")) && name.hasSuffix(".bin") && lcUUID(String(name.dropFirst(2).dropLast(4)))
    }
    func childPath(_ id: String) throws -> String { guard lcUUID(id) else { throw LifecycleError.invalid("child locator") }; return path+"/children/"+Self.childName(id) }
    func usage() throws -> LifecycleUsage {
        try ensure()
        var usage = LifecycleUsage(bytes: try root.allocatedBytes()+requests.allocatedBytes()+children.allocatedBytes())
        for name in try root.names(maximum: 5, allowed: { ["current","prepared","lock","requests","children"].contains($0) }) where name != "requests" && name != "children" {
            let s = try root.info(name, maximum: name == "lock" ? 0 : LifecycleLimits.catalog+LifecycleCrypto.overhead)
            usage.bytes += Int(s.st_blocks)*512; usage.files += 1
        }
        for name in try requests.names(maximum: 65, allowed: Self.requestRole) {
            let s = try requests.info(name, maximum: LifecycleLimits.request+LifecycleCrypto.overhead)
            usage.bytes += Int(s.st_blocks)*512; usage.files += 1
        }
        for name in try children.names(maximum: 64, allowed: Self.childRole) {
            let directory = try OwnedDirectory(parent: children, name: name); defer { directory.close() }
            var childBytes = try directory.allocatedBytes()
            for role in try directory.names(maximum: StoreLimits.files, allowed: Self.storeRole) {
                let s = try directory.info(role, maximum: role == "lock" ? 0 : StoreLimits.candidate+116)
                childBytes += Int(s.st_blocks)*512; usage.files += 1
            }
            guard childBytes <= StoreLimits.allocation else { throw LifecycleError.full }; usage.bytes += childBytes
        }
        guard usage.bytes <= LifecycleLimits.allocation, usage.files <= LifecycleLimits.files else { throw LifecycleError.full }
        return usage
    }
    func reserve(quota: Int, child: Bool, request: Bool = false) throws {
        let usage = try usage()
        let next = LifecycleLimits.metadataReserve + (child ? StoreLimits.reservation : 0) + (request ? LifecycleLimits.request+65536 : 0)
        guard next <= quota, usage.bytes <= quota-next, usage.files <= LifecycleLimits.files-(request ? 2 : 1) else { throw LifecycleError.full }
    }
}
