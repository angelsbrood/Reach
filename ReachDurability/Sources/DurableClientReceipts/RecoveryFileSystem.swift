import Foundation
import Darwin
import RecoveryContract

/// Short sidecar lock acquired only while the client owner lock is already held.
final class RecoveryFileSystem {
    private var fd:Int32 = -1, lock:Int32 = -1
    private let pid=getpid()
    private var inode:ino_t=0, device:dev_t=0, lockInode:ino_t=0
    let path:String
    static func canonical(_ path:String) throws -> String {
        guard let p=realpath(path,nil) else { throw RecoveryError.unavailable }; defer { free(p) }; return String(cString:p)
    }
    static func role(_ record:String) -> String { "t-"+record+".bin" }
    static func validRole(_ name:String) -> Bool {
        if name=="lock" || name=="pending" { return true }
        return name.utf8.count==42 && name.hasPrefix("t-") && name.hasSuffix(".bin") && crUUID(String(name.dropFirst(2).dropLast(4)))
    }
    init(parent:String,binding:RecoveryBinding,fresh:Bool) throws {
        try binding.validate(); guard try Self.canonical(parent)==parent else { throw RecoveryError.invalid }
        var s=stat(); guard lstat(parent,&s)==0, s.st_mode&S_IFMT==S_IFDIR, s.st_uid==getuid(),s.st_mode&0o7777==0o700 else { throw RecoveryError.invalid }
        path=parent+"/tickets-"+binding.bootstrap
        if fresh { guard mkdir(path,0o700)==0 else { throw RecoveryError.io("fresh-ticket-directory",errno) } }
        fd=Darwin.open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        guard fd>=0 else { throw RecoveryError.unavailable }
        do {
            guard fstat(fd,&s)==0,s.st_mode&S_IFMT==S_IFDIR,s.st_uid==getuid(),s.st_mode&0o7777==0o700 else { throw RecoveryError.invalid }
            inode=s.st_ino; device=s.st_dev
            lock=openat(fd,"lock",O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|(fresh ? O_CREAT|O_EXCL : 0),0o600)
            guard lock>=0 else { throw RecoveryError.incomplete }; lockInode=try info("lock").st_ino
            var opened=stat(); guard fstat(lock,&opened)==0,opened.st_ino==lockInode,opened.st_dev==device else { throw RecoveryError.invalid }
            guard flock(lock,LOCK_EX|LOCK_NB)==0 else { throw errno==EWOULDBLOCK ? RecoveryError.busy : RecoveryError.io("ticket-lock",errno) }
            _=try names()
            if fresh {
                try sync(); let parentFD=Darwin.open(parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
                guard parentFD>=0 else { throw RecoveryError.unavailable }; defer { _=Darwin.close(parentFD) }
                guard fsync(parentFD)==0 else { throw RecoveryError.io("ticket-parent-sync",errno) }
            }
        } catch { close(); throw error }
    }
    deinit { close() }
    func close() { if lock>=0 { _=Darwin.close(lock); lock = -1 }; if fd>=0 { _=Darwin.close(fd); fd = -1 } }
    func ensure() throws {
        guard pid==getpid(),fd>=0,lock>=0 else { throw RecoveryError.unavailable }
        var named=stat(),held=stat()
        guard lstat(path,&named)==0,named.st_ino==inode,named.st_dev==device,
              fstat(lock,&held)==0,held.st_ino==lockInode,try info("lock").st_ino==lockInode else { throw RecoveryError.stale }
    }
    func info(_ name:String) throws -> stat {
        guard Self.validRole(name) else { throw RecoveryError.invalid }; var s=stat()
        guard fstatat(fd,name,&s,AT_SYMLINK_NOFOLLOW)==0,s.st_mode&S_IFMT==S_IFREG,s.st_uid==getuid(),
              s.st_mode&0o7777==0o600,s.st_nlink==1,s.st_size>=0,s.st_size<=(name=="lock" ? 0 : RecoveryLimits.envelope),
              s.st_blocks>=0,s.st_blocks<=RecoveryLimits.directory/512 else { throw RecoveryError.invalid }; return s
    }
    func exists(_ name:String) throws -> Bool {
        try ensure(); guard Self.validRole(name) else { throw RecoveryError.invalid }; var s=stat()
        if fstatat(fd,name,&s,AT_SYMLINK_NOFOLLOW)==0 { _=try info(name); return true }
        guard errno==ENOENT else { throw RecoveryError.io("ticket-existence",errno) }; return false
    }
    func names() throws -> [String] {
        try ensure(); let copy=dup(fd); guard copy>=0 else { throw RecoveryError.io("ticket-scan",errno) }
        _=fcntl(copy,F_SETFD,FD_CLOEXEC)
        guard let stream=fdopendir(copy) else { _=Darwin.close(copy); throw RecoveryError.unavailable }; defer { closedir(stream) }; rewinddir(stream)
        var result:[String]=[],allocation=0,envelopes=0
        while true {
            errno=0; guard let entry=readdir(stream) else { guard errno==0 else { throw RecoveryError.io("ticket-scan-read",errno) }; break }
            let name=withUnsafePointer(to:&entry.pointee.d_name) { $0.withMemoryRebound(to:CChar.self,capacity:1024) { String(cString:$0) } }
            if name=="." || name==".." { continue }
            guard result.count<RecoveryLimits.records+2,Self.validRole(name) else { throw RecoveryError.full }
            let s=try info(name); allocation+=Int(s.st_blocks)*512
            if name.hasPrefix("t-") { envelopes+=1 }
            guard allocation<=RecoveryLimits.directory,envelopes<=RecoveryLimits.records else { throw RecoveryError.full }; result.append(name)
        }
        return result
    }
    func read(_ name:String) throws -> Data {
        try ensure(); let before=try info(name); guard name != "lock" else { throw RecoveryError.invalid }
        let file=openat(fd,name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC); guard file>=0 else { throw RecoveryError.unavailable }; defer { _=Darwin.close(file) }
        var opened=stat(); guard fstat(file,&opened)==0,opened.st_ino==before.st_ino,opened.st_dev==before.st_dev else { throw RecoveryError.invalid }
        var data=Data(),buffer=[UInt8](repeating:0,count:RecoveryLimits.envelope)
        while true {
            let n=Darwin.read(file,&buffer,buffer.count)
            if n<0 && errno==EINTR { continue }; guard n>=0 else { throw RecoveryError.io("ticket-read",errno) }; if n==0 { break }
            guard n<=Int(before.st_size)-data.count else { throw RecoveryError.invalid }; data.append(contentsOf:buffer.prefix(n))
        }
        var after=stat(); guard fstat(file,&after)==0,after.st_size==before.st_size,data.count==before.st_size,
              before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec,before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec else { throw RecoveryError.invalid }; return data
    }
    func write(_ bytes:Data,hook:RecoveryHook) throws {
        let names=try names(); guard !names.contains("pending"),names.filter({$0.hasPrefix("t-")}).count<RecoveryLimits.records,bytes.count<=RecoveryLimits.envelope else { throw RecoveryError.full }
        try hook(.beforeEnvelopeWrite)
        let file=openat(fd,"pending",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600); guard file>=0 else { throw RecoveryError.io("ticket-exclusive-write",errno) }; defer { _=Darwin.close(file) }
        try bytes.withUnsafeBytes { raw in
            var offset=0
            while offset<raw.count {
                let n=Darwin.write(file,raw.baseAddress!.advanced(by:offset),raw.count-offset)
                if n<0 && errno==EINTR { continue }; guard n>0 else { throw RecoveryError.io("ticket-write",errno) }; offset+=n
            }
        }
        try hook(.beforeEnvelopeSync); guard fsync(file)==0 else { throw RecoveryError.io("ticket-file-sync",errno) }; _=try self.names()
    }
    func select(_ role:String) throws {
        try ensure(); guard role.hasPrefix("t-"),Self.validRole(role),!(try exists(role)) else { throw RecoveryError.invalid }
        _=try info("pending"); guard renameat(fd,"pending",fd,role)==0 else { throw RecoveryError.io("ticket-select",errno) }
    }
    func sync() throws { try ensure(); guard fsync(fd)==0 else { throw RecoveryError.io("ticket-directory-sync",errno) } }
    func unlink(_ name:String) throws {
        try ensure(); guard name != "lock" else { throw RecoveryError.invalid }; _=try info(name)
        guard unlinkat(fd,name,0)==0 else { throw RecoveryError.io("ticket-unlink",errno) }
    }
}
extension DurableClientReceipts {
    func recoveryDirectory(_ parent:String,binding:RecoveryBinding,fresh:Bool) throws -> RecoveryFileSystem {
        try recoveryBinding(binding)
        var path=[CChar](repeating:0,count:Int(MAXPATHLEN))
        guard fcntl(fs.fd,F_GETPATH,&path)==0 else { throw RecoveryError.unavailable }
        let client=try RecoveryFileSystem.canonical(String(cString:path)), expected=(client as NSString).deletingLastPathComponent as NSString
        guard expected.deletingLastPathComponent==parent else { throw RecoveryError.invalid }
        return try RecoveryFileSystem(parent:parent,binding:binding,fresh:fresh)
    }
}
