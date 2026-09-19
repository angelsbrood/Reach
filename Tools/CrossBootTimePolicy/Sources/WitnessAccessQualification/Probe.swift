import Foundation
import Darwin
import ClockPolicy
import WitnessAccess

nonisolated(unsafe) private var interruptions:Int32=0

/// Explicit qualification modes; none are service work-socket commands.
func probe(_ options:Options) throws {
    try options.allow(["endpoint","behavior","keychains"])
    if options.mode=="network-probe" {
        let endpoint=try UnixEndpoint(path:options.value("endpoint"),uid:getuid())
        let deniedUnix:Bool
        do {let fd=try endpoint.listen();fd.close();deniedUnix=false} catch {deniedUnix=true}
        func ip(_ family:Int32)->Bool {
            let fd=socket(family,SOCK_STREAM,0);guard fd>=0 else {return errno==EPERM || errno==EACCES};defer {close(fd)}
            let result:Int32
            if family==AF_INET {
                var a=sockaddr_in();a.sin_len=UInt8(MemoryLayout<sockaddr_in>.size);a.sin_family=sa_family_t(AF_INET);a.sin_addr.s_addr=inet_addr("127.0.0.1")
                result=withUnsafePointer(to:&a){$0.withMemoryRebound(to:sockaddr.self,capacity:1){bind(fd,$0,socklen_t(MemoryLayout<sockaddr_in>.size))}}
            } else {
                var a=sockaddr_in6();a.sin6_len=UInt8(MemoryLayout<sockaddr_in6>.size);a.sin6_family=sa_family_t(AF_INET6);a.sin6_addr=in6addr_loopback
                result=withUnsafePointer(to:&a){$0.withMemoryRebound(to:sockaddr.self,capacity:1){bind(fd,$0,socklen_t(MemoryLayout<sockaddr_in6>.size))}}
            }
            return result<0 && (errno==EPERM || errno==EACCES)
        }
        let ipv4=ip(AF_INET),ipv6=ip(AF_INET6)
        let key=open(try options.value("keychains"),O_RDONLY|O_NOFOLLOW)
        let deniedKeys=key<0 && (errno==EPERM || errno==EACCES);if key>=0 {close(key)}
        struct Result:Encodable {let stage="network-probe",otherUnixDenied:Bool,ipv4BindDenied:Bool,ipv6BindDenied:Bool,keychainReadDenied:Bool}
        try emit(Result(otherUnixDenied:deniedUnix,ipv4BindDenied:ipv4,ipv6BindDenied:ipv6,keychainReadDenied:deniedKeys))
        guard deniedUnix,ipv4,ipv6,deniedKeys else {throw AccessError.permissions};return
    }
    let endpoint=try UnixEndpoint(path:options.value("endpoint"),uid:getuid()),clock=SystemClock()
    let behavior=options.values["--behavior"] ?? "echo"
    let before=try clock.sample()
    struct Ready:Encodable {let stage="probe-ready",pid:Int32}
    struct Result:Encodable {let stage="probe-result",behavior:String,bytes:Int,elapsed:UInt64,peerUID:UInt32,noSigpipe:Int32,error:String?;var phase:String?;var signals:Int32?}
    if options.mode=="probe-server" {
        let listener=try endpoint.listen();defer {listener.close()};try emit(Ready(pid:getpid()))
        if behavior=="connect-stall" {usleep(5_250_000);return}
        var accepted:SocketFD?
        while accepted==nil {accepted=try endpoint.accept(listener)}
        let fd=accepted!;defer {fd.close()}
        let start=try clock.sample(),deadline=try IODeadline(start:start,clock:clock)
        try endpoint.peer(fd)
        if behavior=="write-stall" {
            var small:Int32=1024
            guard setsockopt(fd.value,SOL_SOCKET,SO_RCVBUF,&small,socklen_t(MemoryLayout<Int32>.size))==0 else {throw AccessError.io}
            usleep(5_250_000);return
        }
        let body=try SocketIO.readFrame(from:fd,deadline:deadline);try SocketIO.expectEOF(fd,deadline:deadline)
        switch behavior {
        case "echo":try SocketIO.writeFrame(body,to:fd,deadline:deadline)
        case "stall","interrupt":usleep(5_250_000)
        case "partial":try SocketIO.writeBytes(Data([0,0,0,2,65]),to:fd,deadline:deadline)
        case "trailing":try SocketIO.writeFrame(body,to:fd,deadline:deadline);try SocketIO.writeBytes(Data([0]),to:fd,deadline:deadline)
        case "oversize":try SocketIO.writeBytes(Data([0,1,0,1]),to:fd,deadline:deadline)
        case "drip":
            try SocketIO.writeBytes(Data([0,0,0,64]),to:fd,deadline:deadline)
            for _ in 0..<64 {try SocketIO.writeBytes(Data([65]),to:fd,deadline:deadline);usleep(200_000)}
        default:throw AccessError.selection
        }
        fd.close()
        try emit(Result(behavior:behavior,bytes:body.count,elapsed:try clock.sample().nanoseconds-start.nanoseconds,peerUID:getuid(),noSigpipe:1,error:nil))
    } else {
        let deadline=try IODeadline(start:before,clock:clock)
        var phase="connect"
        if behavior=="interrupt" {
            signal(SIGUSR1,{_ in interruptions+=1});siginterrupt(SIGUSR1,1)
        }
        do {
            if behavior=="connect-stall" {
                var queued:[SocketFD]=[]
                defer {queued.forEach {$0.close()}}
                for _ in 0..<16 {queued.append(try endpoint.connect(deadline:deadline))}
                throw AccessError.frame // A full queue must refuse or exhaust the original deadline.
            }
            let fd=try endpoint.connect(deadline:deadline);defer {fd.close()}
            var value:Int32=0,length=socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd.value,SOL_SOCKET,SO_NOSIGPIPE,&value,&length)==0,value==1 else {throw AccessError.io}
            let body=Data(repeating:65,count:behavior=="write-stall" ? 65536 : 8192)
            phase="write"
            if behavior=="write-stall" {
                var small:Int32=1024
                guard setsockopt(fd.value,SOL_SOCKET,SO_SNDBUF,&small,socklen_t(MemoryLayout<Int32>.size))==0 else {throw AccessError.io}
                try SocketIO.writeFrame(body,to:fd,deadline:deadline)
            } else {
            // Partial header/body delivery uses the same product deadline.
            try SocketIO.writeBytes(Data([0,0]),to:fd,deadline:deadline);usleep(1000)
            try SocketIO.writeBytes(Data([32,0])+body.prefix(137),to:fd,deadline:deadline);usleep(1000)
            try SocketIO.writeBytes(body.dropFirst(137),to:fd,deadline:deadline)
            }
            try SocketIO.halfClose(fd,deadline:deadline);phase="read"
            let result=try SocketIO.readFrame(from:fd,deadline:deadline);try SocketIO.expectEOF(fd,deadline:deadline)
            guard result==body else {throw AccessError.frame}
            try emit(Result(behavior:behavior,bytes:result.count,elapsed:try clock.sample().nanoseconds-before.nanoseconds,peerUID:getuid(),noSigpipe:value,error:nil))
        } catch {
            try emit(Result(behavior:behavior,bytes:0,elapsed:try clock.sample().nanoseconds-before.nanoseconds,peerUID:getuid(),noSigpipe:1,error:String(describing:error),phase:phase,signals:interruptions))
            throw error
        }
    }
}
