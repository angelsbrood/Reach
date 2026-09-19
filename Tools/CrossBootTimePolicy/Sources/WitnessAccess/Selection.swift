import Foundation
import Darwin
import ClockPolicy

public enum AccessError:String,Error { case selection, path, permissions, occupied, peer, io, timeout, frame, overflow }

public struct PairSelection:Codable,Equatable,Sendable {
    public let subject:String,hostCap:UInt64,clientCap:UInt64
    public init(subject:String,hostCap:UInt64,clientCap:UInt64) {self.subject=subject;self.hostCap=hostCap;self.clientCap=clientCap}
}

public enum Provisioning {
    public static func selections(_ input:[PairSelection]) throws -> [PairSelection] {
        var unique:[String:PairSelection]=[:]
        for p in input {
            guard UUID(uuidString:p.subject)?.uuidString.lowercased()==p.subject,
                  p.hostCap>0,p.clientCap>0,p.hostCap<=Profile.qualification.maximumDuration,
                  p.clientCap<=Profile.qualification.maximumDuration else {throw AccessError.selection}
            if let old=unique[p.subject],old != p {throw Refusal.conflict}
            unique[p.subject]=p
        }
        guard (1...8).contains(unique.count) else {throw Refusal.capacity}
        return unique.values.sorted {$0.subject<$1.subject}
    }
    static func issue(_ input:[PairSelection],pin:Identity,register:(String,Role,UInt64)throws->Data) throws -> [Originals] {
        let selected=try selections(input) // Validate the complete set before any registration.
        return try selected.map { p in
            let host=try register(p.subject,.host,p.hostCap),client=try register(p.subject,.client,p.clientCap)
            return try Originals(pin:pin,host:host,client:client)
        }
    }
}

public struct Descriptor:Codable,Equatable,Sendable {
    public let version:Int,profile:Profile,endpoint:String,uid:UInt32,identity:Identity,pairs:[Originals]
    init(endpoint:String,uid:UInt32,identity:Identity,pairs:[Originals]) throws {
        version=1;profile = .qualification;self.endpoint=endpoint;self.uid=uid;self.identity=identity;self.pairs=pairs
        try validate();_ = try Wire.encode(self)
    }
    func validate() throws {
        guard version==1,profile == .qualification,uid==getuid(),(1...8).contains(pairs.count) else {throw AccessError.selection}
        _=try UnixEndpoint(path:endpoint,uid:uid)
        var subjects=Set<String>()
        for pair in pairs {
            let records=try pair.records()
            guard pair.pin==identity,subjects.insert(records.host.subject).inserted else {throw AccessError.selection}
        }
    }
    public static func load(path:String,expectedSHA256:String) throws -> Descriptor {
        let bytes=try PublicFile.read(path)
        return try checked(bytes,expectedSHA256:expectedSHA256)
    }
    public static func checked(_ bytes:Data,expectedSHA256:String) throws -> Descriptor {
        // No field is adopted before the separately supplied complete selection digest.
        guard expectedSHA256.count==64,Wire.digest(bytes)==expectedSHA256 else {throw AccessError.selection}
        let value=try Wire.decode(Self.self,bytes);try value.validate();return value
    }
    public func select(subject:String) throws -> Originals {
        try validate()
        guard let pair=try pairs.first(where:{try $0.records().host.subject==subject}) else {throw AccessError.selection}
        return pair
    }
}

public enum PublicFile {
    public static func read(_ path:String) throws -> Data {
        let fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);guard fd>=0 else {throw AccessError.path};defer {close(fd)}
        var st=stat();guard fstat(fd,&st)==0,(st.st_mode&S_IFMT)==S_IFREG,(st.st_mode&0o777)==0o600,
              st.st_uid==getuid(),st.st_size>0,st.st_size<=Wire.maximumBytes else {throw AccessError.permissions}
        var result=Data(),buffer=[UInt8](repeating:0,count:4096)
        while true {
            let n=Darwin.read(fd,&buffer,buffer.count)
            if n<0 && errno==EINTR {continue}
            guard n>=0 else {throw AccessError.io};if n==0 {break}
            guard result.count+n<=Wire.maximumBytes else {throw AccessError.frame};result.append(contentsOf:buffer.prefix(n))
        }
        return result
    }
    public static func writeNew(_ bytes:Data,to path:String) throws {
        guard !bytes.isEmpty,bytes.count<=Wire.maximumBytes else {throw AccessError.frame}
        let fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600);guard fd>=0 else {throw AccessError.occupied};defer {close(fd)}
        var offset=0
        try bytes.withUnsafeBytes { raw in
            while offset<raw.count {
                let n=Darwin.write(fd,raw.baseAddress!.advanced(by:offset),raw.count-offset)
                if n<0 && errno==EINTR {continue};guard n>0 else {throw AccessError.io};offset+=n
            }
        }
        guard fsync(fd)==0 else {throw AccessError.io}
    }
}
