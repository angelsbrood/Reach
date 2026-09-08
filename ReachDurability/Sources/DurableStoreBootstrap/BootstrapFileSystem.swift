import Foundation
import Darwin
import DurableRootKeys

/// Trusted private ancestors; exact no-follow roles and a short bootstrap lock.
final class BootstrapFileSystem {
    let path: String
    private var directory: Int32 = -1, lock: Int32 = -1
    private let process = getpid()
    private var inode: UInt64 = 0, device: Int32 = 0, lockInode: UInt64 = 0
    init(path: String, fresh: Bool) throws {
        self.path = path; _ = try RootKeyCodec.parent(path)
        if fresh, mkdir(path, 0o700) != 0 { throw BootstrapError.io("exclusive-bootstrap-root", errno) }
        try RootKeyCodec.directory(path)
        directory = Darwin.open(path, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        guard directory >= 0 else { throw BootstrapError.io("bootstrap-directory", errno) }
        do {
            var s = stat(); guard fstat(directory, &s) == 0 else { throw BootstrapError.io("bootstrap-stat", errno) }
            inode = UInt64(s.st_ino); device = s.st_dev
            lock = openat(directory, "bootstrap.lock", O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|(fresh ? O_CREAT|O_EXCL : 0), 0o600)
            guard lock >= 0 else { throw BootstrapError.io("bootstrap-lock", errno) }
            let info = try validate(lock, role: "bootstrap.lock"); lockInode = UInt64(info.st_ino)
            guard flock(lock, LOCK_EX|LOCK_NB) == 0 else { throw errno == EWOULDBLOCK ? BootstrapError.busy : BootstrapError.io("bootstrap-flock", errno) }
            _ = try scan()
        } catch { close(); throw error }
    }
    deinit { close() }
    func close() {
        if lock >= 0 { _ = Darwin.close(lock); lock = -1 }
        if directory >= 0 { _ = Darwin.close(directory); directory = -1 }
    }
    private func ensure() throws {
        guard process == getpid(), lock >= 0, directory >= 0 else { throw BootstrapError.closed }
        var root = stat(), named = stat()
        guard lstat(path, &root) == 0, UInt64(root.st_ino) == inode, root.st_dev == device,
              fstatat(directory,"bootstrap.lock",&named,AT_SYMLINK_NOFOLLOW) == 0,
              UInt64(named.st_ino) == lockInode, named.st_dev == device else { throw BootstrapError.invalid }
        _ = try validate(lock, role: "bootstrap.lock")
    }
    private func validate(_ fd: Int32, role: String) throws -> stat {
        var s = stat()
        guard fstat(fd,&s) == 0, s.st_mode&S_IFMT == S_IFREG, s.st_uid == getuid(), s.st_mode&0o7777 == 0o600,
              s.st_nlink == 1, s.st_size >= 0, s.st_size <= BootstrapLimits.record,
              role != "bootstrap.lock" || s.st_size == 0 else { throw BootstrapError.invalid }; return s
    }
    func scan() throws -> Set<String> {
        try ensure(); let duplicate = dup(directory)
        guard duplicate >= 0 else { throw BootstrapError.io("bootstrap-scan",errno) }
        _ = fcntl(duplicate,F_SETFD,FD_CLOEXEC)
        guard let stream = fdopendir(duplicate) else { _ = Darwin.close(duplicate); throw BootstrapError.io("bootstrap-stream",errno) }
        defer { closedir(stream) }; rewinddir(stream)
        var names = Set<String>(), allocated = 0
        while true {
            errno = 0
            guard let entry = readdir(stream) else { guard errno == 0 else { throw BootstrapError.io("bootstrap-readdir",errno) }; break }
            let name = withUnsafePointer(to: &entry.pointee.d_name) { $0.withMemoryRebound(to:CChar.self,capacity:1024) { String(cString:$0) } }
            if name == "." || name == ".." { continue }
            guard ["bootstrap.lock","intent.json","ready.json","selection.tmp","host","client"].contains(name), names.count < 6 else { throw BootstrapError.invalid }
            let isJournal = name == "host" || name == "client"
            let fd = openat(directory,name,O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW|(isJournal ? O_DIRECTORY : 0))
            guard fd >= 0 else { throw BootstrapError.io("bootstrap-role",errno) }
            defer { _ = Darwin.close(fd) }
            if isJournal {
                var s = stat(); guard fstat(fd,&s) == 0, s.st_mode&S_IFMT == S_IFDIR, s.st_uid == getuid(), s.st_mode&0o7777 == 0o700 else { throw BootstrapError.invalid }
            } else {
                let s = try validate(fd,role:name)
                guard s.st_blocks >= 0, s.st_blocks <= BootstrapLimits.storage/512 else { throw BootstrapError.invalid }
                allocated += Int(s.st_blocks)*512
            }
            names.insert(name)
        }
        guard allocated <= BootstrapLimits.storage else { throw BootstrapError.invalid }; return names
    }
    func read(_ role: String) throws -> Data {
        try ensure(); guard role == "intent.json" || role == "ready.json" else { throw BootstrapError.invalid }
        let fd = openat(directory,role,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)
        guard fd >= 0 else { throw BootstrapError.incomplete }; defer { _ = Darwin.close(fd) }
        let before = try validate(fd,role:role); var bytes = Data(), buffer = [UInt8](repeating:0,count:65536)
        while true {
            let n = Darwin.read(fd,&buffer,buffer.count)
            if n < 0 && errno == EINTR { continue }
            guard n >= 0 else { throw BootstrapError.io("bootstrap-read",errno) }; if n == 0 { break }
            guard n <= BootstrapLimits.record-bytes.count else { throw BootstrapError.invalid }; bytes.append(contentsOf:buffer.prefix(n))
        }
        let after = try validate(fd,role:role)
        guard before.st_ino == after.st_ino, before.st_size == after.st_size, bytes.count == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else { throw BootstrapError.invalid }
        return bytes
    }
    func write(_ role: String, bytes: Data, hook: BootstrapHook) throws {
        try ensure(); guard role == "intent.json" || role == "selection.tmp", bytes.count <= BootstrapLimits.record else { throw BootstrapError.invalid }
        _ = try scan(); let fd = openat(directory,role,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
        guard fd >= 0 else { throw BootstrapError.io("exclusive-bootstrap-record",errno) }; defer { _ = Darwin.close(fd) }
        _ = try validate(fd,role:role)
        try bytes.withUnsafeBytes { data in
            var offset = 0
            while offset < data.count {
                let n = Darwin.write(fd,data.baseAddress!.advanced(by:offset),data.count-offset)
                if n < 0 && errno == EINTR { continue }; guard n > 0 else { throw BootstrapError.io("bootstrap-write",errno) }; offset += n
            }
        }
        try hook(.beforeFileSync); guard fsync(fd) == 0 else { throw BootstrapError.io("bootstrap-file-sync",errno) }
    }
    func selectReady(hook: BootstrapHook) throws {
        try ensure(); let names = try scan(); guard names.contains("selection.tmp"), !names.contains("ready.json") else { throw BootstrapError.invalid }
        try hook(.beforeReadyRename)
        guard renameat(directory,"selection.tmp",directory,"ready.json") == 0 else { throw BootstrapError.io("bootstrap-ready-rename",errno) }
        try hook(.afterReadyRename); try hook(.beforeReadySync); try sync()
    }
    func sync() throws { try ensure(); guard fsync(directory) == 0 else { throw BootstrapError.io("bootstrap-directory-sync",errno) } }
    func journal(_ role: BootstrapRole) throws -> String {
        guard try scan().contains(role.rawValue) else { throw BootstrapError.incomplete }; return path+"/"+role.rawValue
    }
    func syncJournals() throws {
        for role in [BootstrapRole.host,.client] {
            _ = try journal(role); let fd = openat(directory,role.rawValue,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW)
            guard fd >= 0 else { throw BootstrapError.io("journal-sync-open",errno) }; defer { _ = Darwin.close(fd) }
            guard fsync(fd) == 0 else { throw BootstrapError.io("journal-directory-sync",errno) }
        }
        try sync()
    }
}
