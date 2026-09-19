import Foundation
import Darwin
import ClockPolicy

/// One absolute continuous-clock budget, including connect and all partial I/O.
public final class IODeadline {
    public static let maximumNanoseconds:UInt64=5_000_000_000
    public let start:Sample
    let clock:any PolicyClock,end:UInt64
    private var last:UInt64
    private(set) var clockFailure:Error?
    public init(start:Sample,clock:any PolicyClock) throws {
        self.start=start;self.clock=clock;last=start.nanoseconds
        let (end,overflow)=start.nanoseconds.addingReportingOverflow(Self.maximumNanoseconds)
        guard !overflow else {throw AccessError.overflow};self.end=end
    }
    func remaining() throws -> UInt64 {
        if let clockFailure {throw clockFailure}
        let now:Sample
        do {
            now=try clock.sample()
            guard now.boot==start.boot,now.incarnation==start.incarnation,now.nanoseconds>=last else {throw Refusal.clock}
        } catch {
            clockFailure=error // A later healthy read cannot erase an observed I/O-clock fault.
            throw error
        }
        last=now.nanoseconds;guard now.nanoseconds<end else {throw AccessError.timeout}
        return end-now.nanoseconds
    }
    public func check() throws {_=try remaining()}
}

public enum SocketIO {
    static func wait(_ fd:Int32,events:Int16,deadline:IODeadline) throws {
        while true {
            let left=try deadline.remaining(),ms=Int32((left+999_999)/1_000_000)
            var p=pollfd(fd:fd,events:events,revents:0)
            let n=poll(&p,1,ms)
            try deadline.check()
            if n<0 && errno==EINTR {continue}
            guard n>=0,p.revents&Int16(POLLNVAL)==0 else {throw AccessError.io}
            if n>0 {return}
        }
    }
    public static func writeBytes(_ bytes:Data,to fd:SocketFD,deadline:IODeadline) throws {
        var offset=0
        try bytes.withUnsafeBytes { raw in
            while offset<raw.count {
                try deadline.check()
                let n=Darwin.send(fd.value,raw.baseAddress!.advanced(by:offset),raw.count-offset,0)
                if n<0 && errno==EINTR {continue}
                if n<0 && (errno==EAGAIN || errno==EWOULDBLOCK) {try wait(fd.value,events:Int16(POLLOUT),deadline:deadline);continue}
                guard n>0 else {throw AccessError.io};offset+=n
            }
        }
        try deadline.check()
    }
    private static func read(_ count:Int,from fd:SocketFD,deadline:IODeadline) throws -> Data {
        var bytes=[UInt8](repeating:0,count:count),offset=0
        while offset<count {
            try deadline.check()
            let n=bytes.withUnsafeMutableBytes {Darwin.recv(fd.value,$0.baseAddress!.advanced(by:offset),count-offset,0)}
            if n<0 && errno==EINTR {continue}
            if n<0 && (errno==EAGAIN || errno==EWOULDBLOCK) {try wait(fd.value,events:Int16(POLLIN),deadline:deadline);continue}
            guard n>0 else {throw AccessError.frame};offset+=n
        }
        try deadline.check();return Data(bytes)
    }
    public static func readFrame(from fd:SocketFD,deadline:IODeadline) throws -> Data {
        let header=try read(4,from:fd,deadline:deadline)
        let count=header.reduce(UInt32(0)){($0<<8)|UInt32($1)}
        guard count>0,count<=Wire.maximumBytes else {throw AccessError.frame}
        return try read(Int(count),from:fd,deadline:deadline)
    }
    public static func writeFrame(_ bytes:Data,to fd:SocketFD,deadline:IODeadline) throws {
        guard !bytes.isEmpty,bytes.count<=Wire.maximumBytes else {throw AccessError.frame}
        let count=UInt32(bytes.count)
        try writeBytes(Data([UInt8(count>>24),UInt8((count>>16)&255),UInt8((count>>8)&255),UInt8(count&255)])+bytes,to:fd,deadline:deadline)
    }
    public static func halfClose(_ fd:SocketFD,deadline:IODeadline) throws {
        try deadline.check();guard shutdown(fd.value,SHUT_WR)==0 else {throw AccessError.io};try deadline.check()
    }
    public static func expectEOF(_ fd:SocketFD,deadline:IODeadline) throws {
        while true {
            try deadline.check();var byte:UInt8=0
            let n=Darwin.recv(fd.value,&byte,1,0)
            if n<0 && errno==EINTR {continue}
            if n<0 && (errno==EAGAIN || errno==EWOULDBLOCK) {try wait(fd.value,events:Int16(POLLIN),deadline:deadline);continue}
            guard n==0 else {throw AccessError.frame};try deadline.check();return
        }
    }
    public static func exchange(_ request:Data,endpoint:UnixEndpoint,deadline:IODeadline) throws -> Data {
        let fd=try endpoint.connect(deadline:deadline);defer {fd.close()}
        try writeFrame(request,to:fd,deadline:deadline);try halfClose(fd,deadline:deadline)
        let response=try readFrame(from:fd,deadline:deadline);try expectEOF(fd,deadline:deadline);return response
    }
}
