import Foundation
import CryptoKit
import Darwin

public enum ClientError: Error, Equatable {
    case invalid(String), io(String, Int32), unauthorized, expired, stale, busy, closed, full, unavailable
}
public enum ClientLimits {
    public static let context = 1<<20, outcome = 1<<20, manifest = 1<<20, snapshot = 64<<20
    public static let batch = 8<<20, replay = (16<<20)+4, records = 64, calls = 256, files = 132
    public static let allocation = 2<<30, metadataReserve = (2<<20)+(64<<10)
    public static let session: UInt64 = 86_400_000_000_000
}
public protocol ClientClock { var policy: String { get }; func now() throws -> UInt64 }
public struct SystemClientClock: ClientClock {
    public init() {}
    public var policy: String { "system-monotonic-raw-ns-v1" }
    public func now() throws -> UInt64 {
        let value = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
        guard value > 0 else { throw ClientError.invalid("clock") }; return value
    }
}
public struct ClientEnvironment {
    public let rootID: String
    public let boot: String
    public let policy: String
    public let quota: Int
    public init(rootID: String = UUID().uuidString.lowercased(), clock: any ClientClock, quota: Int = ClientLimits.allocation) throws {
        self.rootID = rootID; self.boot = try Self.bootIdentity(); self.policy = clock.policy; self.quota = quota
        try validate(clock)
    }
    func validate(_ clock: any ClientClock) throws {
        guard crUUID(rootID), boot == (try Self.bootIdentity()), crEqual(policy, clock.policy),
              policy == "system-monotonic-raw-ns-v1" || policy.hasPrefix("fixture-ns-v1:"),
              (ClientLimits.metadataReserve...ClientLimits.allocation).contains(quota) else { throw ClientError.invalid("environment") }
        try crID(policy)
    }
    public static func bootIdentity() throws -> String {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, (2...256).contains(size) else { throw ClientError.io("boot identity", errno) }
        var bytes = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0, bytes.last == 0 else { throw ClientError.io("boot identity read", errno) }
        let result = String(decoding: bytes.dropLast().map { UInt8(bitPattern: $0) }, as: UTF8.self).lowercased()
        guard crUUID(result) else { throw ClientError.invalid("boot identity") }; return result
    }
}
public struct ClientCaller: Codable {
    public let principal: String, device: String, app: String
    public init(principal: String, device: String, app: String) { self.principal = principal; self.device = device; self.app = app }
    func validate() throws { try crID(principal); try crID(device); try crID(app) }
}
public struct ClientContext: Codable {
    public let version: Int
    public let caller: ClientCaller
    public let host: String, store: String, namespace: String, generation: String, request: String, operation: String
    public let upstreamDigest: String, route: String, projection: String, revision: String
    public let issued: UInt64, expires: UInt64
    public init(caller: ClientCaller, host: String, store: String, namespace: String, generation: String,
                request: String, operation: String, upstreamDigest: String, route: String,
                projection: String = "s80-events-v1", revision: String, issued: UInt64, expires: UInt64) {
        version = 1; self.caller = caller; self.host = host; self.store = store; self.namespace = namespace
        self.generation = generation; self.request = request; self.operation = operation; self.upstreamDigest = upstreamDigest
        self.route = route; self.projection = projection; self.revision = revision; self.issued = issued; self.expires = expires
    }
    func validate() throws {
        try caller.validate()
        for id in [host, store, namespace, generation, request, operation, route, revision] { try crID(id) }
        guard version == 1, projection == "s80-events-v1", crDigest(upstreamDigest), issued > 0,
              expires > issued, expires <= (try crAdd(issued, ClientLimits.session)),
              try crEncode(self).count <= ClientLimits.context else { throw ClientError.invalid("context") }
    }
}
/// Immutable and trusted. Reopen must retain the original authority, not mint a later expiry.
public final class ClientAuthority {
    public let context: ClientContext
    public let bytes: Data
    let identity: String, namespace: String, anchor: String
    public init(_ context: ClientContext) throws {
        try context.validate(); self.context = context; bytes = try crEncode(context)
        namespace = crDomain("namespace", [Data(context.namespace.utf8)])
        identity = crDomain("generation", [Data(context.namespace.utf8), Data(context.generation.utf8)])
        anchor = crDomain("authority", [try crEncode(context.caller), Data(context.host.utf8), Data(context.store.utf8),
            crUInt(context.issued), crUInt(context.expires)])
    }
}
public final class ClientAuthorization {
    public var caller: ClientCaller
    public var allowed: Bool
    public init(caller: ClientCaller, allowed: Bool = true) { self.caller = caller; self.allowed = allowed }
    func check(_ authority: ClientAuthority, now: UInt64) throws {
        try caller.validate()
        guard allowed, try crEncode(caller) == crEncode(authority.context.caller) else { throw ClientError.unauthorized }
        guard now >= authority.context.issued, now < authority.context.expires else { throw ClientError.expired }
    }
}
public struct ClientHandle { public let record: String; public let ownerEpoch: UInt64 }
public struct DurableReceipt: Equatable {
    public let contextDigest: String
    public let revision: UInt64, high: UInt64
    public let terminal: Bool
    public let registeredCalls: Int
}
public enum ClientFault: String {
    case afterSnapshot, beforeManifestRename, afterManifestRename, beforeDirectorySync
    case afterInbox, beforeIntent, afterIntent, afterOutcome, beforePublication
    case afterRetirement, duringDeletion, afterDeletion
}
public typealias ClientFaultHook = (ClientFault) throws -> Void
func crEncode<T: Encodable>(_ value: T) throws -> Data { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return try e.encode(value) }
func crID(_ s: String) throws { guard !s.isEmpty, s.utf8.count <= 256 else { throw ClientError.invalid("identifier") } }
func crUUID(_ s: String) -> Bool { s.utf8.count == 36 && UUID(uuidString: s)?.uuidString.lowercased() == s }
func crDigest(_ s: String) -> Bool { s.utf8.count == 64 && s.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
func crEqual(_ a: String, _ b: String) -> Bool { Data(a.utf8) == Data(b.utf8) }
func crHash(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }
func crUInt(_ n: UInt64) -> Data { var n = n.bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
func crAdd(_ a: UInt64, _ b: UInt64) throws -> UInt64 { let c = a.addingReportingOverflow(b); guard !c.overflow else { throw ClientError.invalid("arithmetic overflow") }; return c.partialValue }
func crDomain(_ role: String, _ fields: [Data]) -> String {
    var d = Data("S83/v1/".utf8) + Data(role.utf8) + Data([0])
    for field in fields { d += crUInt(UInt64(field.count)); d += field }; return crHash(d)
}
public func clientRandomKey() -> Data { SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }
