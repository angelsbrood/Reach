import Foundation
import Darwin

/// Descriptors own numeric sockets, never a pathname's cleanup authority.
public final class SocketFD {
    public private(set) var value:Int32
    public init(_ value:Int32) throws {
        self.value=value
        var one:Int32=1
        guard value>=0,fcntl(value,F_SETFD,FD_CLOEXEC)==0,
              fcntl(value,F_SETFL,fcntl(value,F_GETFL)|O_NONBLOCK)==0,
              setsockopt(value,SOL_SOCKET,SO_NOSIGPIPE,&one,socklen_t(MemoryLayout<Int32>.size))==0 else {
            if value>=0 {Darwin.close(value)};self.value = -1;throw AccessError.io
        }
    }
    public func close() {if value>=0 {Darwin.close(value);value = -1}}
    deinit {close()}
}

public struct UnixEndpoint {
    public let path:String,root:String,uid:UInt32
    public init(path:String,uid:UInt32) throws {
        let components=path.split(separator:"/",omittingEmptySubsequences:false)
        guard path.hasPrefix("/"),!path.utf8.contains(0),path.utf8.count+1<=104,
              components.dropFirst().allSatisfy({!$0.isEmpty && $0 != "." && $0 != ".."}),
              uid==getuid() else {throw AccessError.path}
        self.path=path;root=(path as NSString).deletingLastPathComponent;self.uid=uid
        guard root != "/",!path.hasSuffix("/") else {throw AccessError.path}
    }
    public func validateRoot(empty:Bool=false) throws {
        var st=stat()
        guard lstat(root,&st)==0,(st.st_mode&S_IFMT)==S_IFDIR,(st.st_mode&0o777)==0o700,st.st_uid==uid else {throw AccessError.permissions}
        guard let resolved=realpath(root,nil) else {throw AccessError.path};defer {free(resolved)}
        guard String(cString:resolved)==root else {throw AccessError.path}
        if empty {guard try FileManager.default.contentsOfDirectory(atPath:root).isEmpty else {throw AccessError.occupied}}
    }
    public func validateSocket() throws {
        try validateRoot();var st=stat()
        guard lstat(path,&st)==0,(st.st_mode&S_IFMT)==S_IFSOCK,(st.st_mode&0o777)==0o600,st.st_uid==uid else {throw AccessError.permissions}
    }
    private func withAddress<T>(_ body:(UnsafePointer<sockaddr>,socklen_t)throws->T) throws -> T {
        var address=sockaddr_un();address.sun_family=sa_family_t(AF_UNIX);address.sun_len=UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of:&address.sun_path) { buffer in
            buffer.initializeMemory(as:UInt8.self,repeating:0)
            for (i,b) in path.utf8.enumerated() {buffer[i]=b}
        }
        return try withUnsafePointer(to:&address) { pointer in
            try pointer.withMemoryRebound(to:sockaddr.self,capacity:1) {try body($0,socklen_t(MemoryLayout<sockaddr_un>.size))}
        }
    }
    public func listen() throws -> SocketFD {
        try validateRoot(empty:true)
        let fd=try SocketFD(Darwin.socket(AF_UNIX,SOCK_STREAM,0))
        guard try withAddress({Darwin.bind(fd.value,$0,$1)})==0 else {throw AccessError.occupied}
        guard chmod(path,0o600)==0,Darwin.listen(fd.value,1)==0 else {throw AccessError.io}
        try validateSocket();return fd
    }
    public func connect(deadline:IODeadline) throws -> SocketFD {
        try deadline.check();try validateSocket()
        let fd=try SocketFD(Darwin.socket(AF_UNIX,SOCK_STREAM,0))
        let result=try withAddress {Darwin.connect(fd.value,$0,$1)}
        if result != 0 {
            guard errno==EINPROGRESS else {throw AccessError.io}
            try SocketIO.wait(fd.value,events:Int16(POLLOUT),deadline:deadline)
            var error:Int32=0,length=socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd.value,SOL_SOCKET,SO_ERROR,&error,&length)==0,error==0 else {throw AccessError.io}
        }
        try deadline.check();try peer(fd);return fd
    }
    public func accept(_ listener:SocketFD) throws -> SocketFD? {
        var p=pollfd(fd:listener.value,events:Int16(POLLIN),revents:0)
        let n=poll(&p,1,250)
        if n==0 || (n<0 && errno==EINTR) {return nil}
        guard n>0,p.revents&Int16(POLLNVAL|POLLERR|POLLHUP)==0 else {throw AccessError.io}
        let value=Darwin.accept(listener.value,nil,nil)
        if value<0 && (errno==EAGAIN || errno==EINTR) {return nil}
        return try SocketFD(value)
    }
    public func peer(_ fd:SocketFD) throws {
        var user:uid_t=0,group:gid_t=0
        guard getpeereid(fd.value,&user,&group)==0,user==uid else {throw AccessError.peer}
    }
}
