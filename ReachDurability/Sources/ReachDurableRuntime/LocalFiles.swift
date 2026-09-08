import Foundation
import Darwin
import DurableRootKeys

public enum LocalRuntimeError: Error { case invalid, unsupported, incomplete, busy, refused, stopped }

/// Fixed owner-only roles, no fallback to a daemon or credential default.
enum LocalFiles {
    static func directory(_ path:String) throws {
        try RootKeyCodec.directory(path)
        guard try RootKeyCodec.canonicalExisting(path)==path else { throw LocalRuntimeError.invalid }
    }
    static func read(_ path:String,maximum:Int) throws -> Data {
        _=try RootKeyCodec.parent(path)
        let fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)
        guard fd>=0 else { throw LocalRuntimeError.incomplete };defer { _=Darwin.close(fd) }
        var before=stat();guard fstat(fd,&before)==0,before.st_mode&S_IFMT==S_IFREG,before.st_uid==getuid(),before.st_nlink==1,
            before.st_mode&0o7777==0o600,before.st_size>=0,before.st_size<=maximum else { throw LocalRuntimeError.invalid }
        var bytes=Data(),buffer=[UInt8](repeating:0,count:65536)
        while true {
            let count=Darwin.read(fd,&buffer,buffer.count)
            if count<0 && errno==EINTR { continue }
            guard count>=0,count<=maximum-bytes.count else { throw LocalRuntimeError.invalid }
            if count==0 { break };bytes.append(contentsOf:buffer.prefix(count))
        }
        var after=stat();guard fstat(fd,&after)==0,before.st_ino==after.st_ino,before.st_size==after.st_size,
            before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec,before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec,
            bytes.count==after.st_size else { throw LocalRuntimeError.invalid }
        return bytes
    }
    static func writeNew(_ bytes:Data,to path:String) throws {
        _=try RootKeyCodec.parent(path)
        let fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
        guard fd>=0 else { throw LocalRuntimeError.invalid };defer { _=Darwin.close(fd) }
        try bytes.withUnsafeBytes { raw in
            var offset=0
            while offset<raw.count {
                let count=Darwin.write(fd,raw.baseAddress!.advanced(by:offset),raw.count-offset)
                if count<0 && errno==EINTR { continue }
                guard count>0 else { throw LocalRuntimeError.invalid };offset+=count
            }
        }
        guard fsync(fd)==0 else { throw LocalRuntimeError.invalid }
        let parent=try RootKeyCodec.parent(path),dir=open(parent,O_RDONLY|O_DIRECTORY|O_CLOEXEC)
        guard dir>=0 else { throw LocalRuntimeError.invalid };defer { _=Darwin.close(dir) }
        guard fsync(dir)==0 else { throw LocalRuntimeError.invalid }
    }
    static func createDirectory(_ path:String) throws {
        _=try RootKeyCodec.parent(path)
        guard mkdir(path,0o700)==0 else { throw LocalRuntimeError.invalid }
        try directory(path)
    }
    static func excludeBackup(_ path:String) -> Bool {
        var url=URL(fileURLWithPath:path,isDirectory:true),values=URLResourceValues();values.isExcludedFromBackup=true
        do { try url.setResourceValues(values);return try url.resourceValues(forKeys:[.isExcludedFromBackupKey]).isExcludedFromBackup==true }
        catch { return false }
    }
    static func executable() throws -> FrozenWorker {
        guard let path=Bundle.main.executableURL?.path else { throw LocalRuntimeError.invalid }
        let canonical=try RootKeyCodec.canonicalExisting(path)
        _=try RootKeyCodec.parent(canonical);_=try RootKeyCodec.regular(canonical,maximum:192<<20,mode:0o700)
        let value=try FrozenWorker(path:canonical,sha256:RootKeyCodec.hash(Data(contentsOf:URL(fileURLWithPath:canonical))))
        try value.validate();return value
    }
}
