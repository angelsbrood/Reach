import Foundation
import CryptoKit

public enum RecoveryError: Error, Equatable { case invalid, unavailable, incomplete, unauthorized, expired, stale, busy, full, io(String, Int32) }
public enum RecoveryLimits {
    public static let ticket = 4096, envelope = 16<<10, directory = 8<<20, records = 64, summaries = 64<<10
    public static let revision = "s86-original-ticket-v1"
}
public enum RecoveryFault: String {
    case afterManifest, beforeSnapshot, afterSnapshot, beforePublication
    case beforeEnvelopeWrite, beforeEnvelopeSync, beforeSelection, afterSelection, beforeDirectorySync, afterEnvelope
    case afterClientMaintenance, beforeOrphanDelete, afterOrphanDelete
}
public typealias RecoveryHook = (RecoveryFault) throws -> Void
/// Constructed from authenticated S85 identity; never obtained from an envelope.
public struct RecoveryBinding: Codable {
    public let bootstrap: String, core: String, clientRoot: String, host: String, boot: String, hostPolicy: String, clientPolicy: String
    public init(bootstrap: String, core: String, clientRoot: String, host: String, boot: String, hostPolicy: String, clientPolicy: String) {
        self.bootstrap=bootstrap; self.core=core; self.clientRoot=clientRoot; self.host=host; self.boot=boot; self.hostPolicy=hostPolicy; self.clientPolicy=clientPolicy
    }
    public func validate() throws {
        guard [bootstrap,clientRoot,host,boot].allSatisfy(RecoveryCodec.uuid), RecoveryCodec.digest(core),
              !hostPolicy.isEmpty, !clientPolicy.isEmpty, hostPolicy.utf8.count<=256, clientPolicy.utf8.count<=256 else { throw RecoveryError.invalid }
    }
}
/// A selection from one owner/selected snapshot, not authority or a context index.
public struct RecoverySummary: Codable, Equatable {
    public let record: String, contextDigest: String
    public let ownerEpoch: UInt64, snapshotRevision: UInt64, issued: UInt64, expires: UInt64, high: UInt64
    public let terminal: Bool, calls: Int
    public init(record: String, contextDigest: String, ownerEpoch: UInt64, snapshotRevision: UInt64,
                issued: UInt64, expires: UInt64, high: UInt64, terminal: Bool, calls: Int) {
        self.record=record; self.contextDigest=contextDigest; self.ownerEpoch=ownerEpoch; self.snapshotRevision=snapshotRevision
        self.issued=issued; self.expires=expires; self.high=high; self.terminal=terminal; self.calls=calls
    }
}
public enum RecoveryCodec {
    public static func encode<T: Encodable>(_ value: T, maximum: Int = RecoveryLimits.envelope) throws -> Data {
        let e=JSONEncoder(); e.outputFormatting=[.sortedKeys,.withoutEscapingSlashes]
        let data=try e.encode(value); guard data.count<=maximum else { throw RecoveryError.full }; return data
    }
    public static func decode<T: Codable>(_ type: T.Type, _ data: Data, maximum: Int = RecoveryLimits.envelope) throws -> T {
        guard data.count<=maximum else { throw RecoveryError.full }
        let value=try JSONDecoder().decode(type,from:data); guard try encode(value,maximum:maximum)==data else { throw RecoveryError.invalid }; return value
    }
    public static func uuid(_ value: String) -> Bool { value.utf8.count==36 && UUID(uuidString:value)?.uuidString.lowercased()==value }
    public static func digest(_ value: String) -> Bool { value.utf8.count==64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    public static func hash(_ data: Data) -> String { SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined() }
}
/// Read-only parsing of the accepted ticket format. Only the existing host verifies its MAC.
public struct RecoveryTicketClaims: Codable {
    public struct Caller: Codable { public let principal: String, device: String, app: String }
    public let version: Int, incarnation: String, boot: String, policy: String, namespace: String, caller: Caller, issued: UInt64, expires: UInt64
    public static func parse(_ input: Data) throws -> Self {
        let data=Data(input); guard (41...RecoveryLimits.ticket).contains(data.count) else { throw RecoveryError.invalid }
        let n=data.prefix(8).reduce(UInt64(0)) { ($0<<8)|UInt64($1) }
        guard n==data.count-40 else { throw RecoveryError.invalid }
        let claims=try RecoveryCodec.decode(Self.self,Data(data[8..<data.count-32]),maximum:RecoveryLimits.ticket)
        guard claims.version==1, RecoveryCodec.uuid(claims.namespace), claims.issued>0, claims.expires>claims.issued else { throw RecoveryError.invalid }
        return claims
    }
}
