import Foundation
import Darwin
import CryptoKit
import Security
import DurableHostStore
import ResumableMLXProvider
import ReachWire

public enum LifecycleError: Error, Equatable {
    case invalid(String), io(String, Int32), unauthorized, ticket, expired, stale, busy, closed, uncertain, full, queued, retired, nonResumable, cleanupBlocked
}
public enum LifecycleLimits {
    public static let request = 1024*1024, catalog = 1024*1024, ticket = 4096, records = 64
    public static let allocation = 2*1024*1024*1024, files = 1092
    public static let metadataReserve = 2*catalog + 64*1024
    public static let second: UInt64 = 1_000_000_000
    public static let wait = 120*second, inflight = 900*second, terminal = 600*second, session = 86400*second
}
public protocol LifecycleClock { var policy: String { get }; func now() throws -> UInt64 }
public struct SystemLifecycleClock: LifecycleClock {
    public init() {}
    public var policy: String { "system-monotonic-raw-ns-v1" }
    public func now() throws -> UInt64 {
        let time = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
        guard time > 0 else { throw LifecycleError.invalid("system clock") }; return time
    }
}
public final class FixtureLifecycleClock: LifecycleClock {
    public let policy: String
    public var time: UInt64
    public init(id: String, time: UInt64) throws { try lcID(id); policy = "fixture-ns-v1:"+id; self.time = time }
    public func now() throws -> UInt64 { guard time > 0 else { throw LifecycleError.invalid("fixture clock") }; return time }
}
public struct LifecycleIdentity {
    public let incarnation: String
    public let boot: String
    public let clockPolicy: String
    public let quota: Int
    public init(incarnation: String = UUID().uuidString.lowercased(), clock: any LifecycleClock, quota: Int = LifecycleLimits.allocation) throws {
        self.incarnation = incarnation; boot = try StoreEnvironment.bootIdentity(); clockPolicy = clock.policy; self.quota = quota
        try validate(clock)
    }
    func validate(_ clock: any LifecycleClock) throws {
        guard lcUUID(incarnation), boot == (try StoreEnvironment.bootIdentity()), clock.policy == clockPolicy,
              clockPolicy == "system-monotonic-raw-ns-v1" || clockPolicy.hasPrefix("fixture-ns-v1:"),
              (LifecycleLimits.metadataReserve...LifecycleLimits.allocation).contains(quota) else { throw LifecycleError.invalid("root/boot/clock/quota") }
        try lcID(clockPolicy)
    }
}
public struct LifecycleKeys {
    let catalog: SymmetricKey
    let ticket: SymmetricKey
    public init(catalog: Data, ticket: Data) throws {
        guard catalog.count == 32, ticket.count == 32, catalog != ticket else { throw LifecycleError.invalid("independent injected root keys") }
        self.catalog = SymmetricKey(data: catalog); self.ticket = SymmetricKey(data: ticket)
    }
}
public struct CallerIdentity: Codable, Equatable {
    public var principal: String
    public var device: String
    public var app: String
    public init(principal: String, device: String, app: String) { self.principal = principal; self.device = device; self.app = app }
    func validate() throws { try lcID(principal); try lcID(device); try lcID(app) }
}
/// Current trusted synthetic authorization, supplied anew on every caller API.
public final class LifecycleAuthorization {
    public var caller: CallerIdentity
    public var allowed: Bool
    public init(caller: CallerIdentity, allowed: Bool) { self.caller = caller; self.allowed = allowed }
    func validate() throws { guard allowed else { throw LifecycleError.unauthorized }; try caller.validate() }
}
public enum LifecyclePhase: String, Codable {
    case queued, allocating, preparing, active, recovering, terminal, retiring, tombstone
    var reservesExecution: Bool { [.allocating, .preparing, .active, .recovering].contains(self) }
}
public struct LifecycleAttachment: Equatable {
    public let record: String
    public let ownerEpoch: UInt64
    public let epoch: UInt64
}
public struct LifecycleStatus {
    public let phase: LifecyclePhase
    public let attachment: LifecycleAttachment?
    public let high: UInt64
    public let providerEnding: WireFinishReason?
    public let disposition: String?
    public let resumable: Bool
}
public enum LifecycleFault: String {
    case beforeCatalogRename, afterCatalogRename, beforeCatalogSync
    case afterAllocating, afterDirectoryCreated, afterEmptyChild, afterPreparing, afterC0, afterChildTerminal
    case beforeRetirementIntent, afterRetirementIntent, duringContentDeletion, afterContentDeletion, afterTombstone
}
public typealias LifecycleFaultHook = (LifecycleFault) throws -> Void
struct GenerationSecrets: Codable {
    var metadata: Data
    var content: Data
    init() throws { metadata = try lcRandom(); content = try lcRandom(); try validate() }
    func validate() throws { guard metadata.count == 32, content.count == 32, metadata != content else { throw LifecycleError.invalid("generation keys") } }
    func storeKeys() throws -> StoreKeys { try validate(); return try .init(metadata: metadata, content: content) }
}
struct LifecycleRequest: Codable {
    var version = 1
    var namespace: String
    var generation: String
    var caller: CallerIdentity
    var provider: ProviderBinding
    func validate() throws {
        guard version == 1, lcUUID(namespace), case .supported = ResumableMLXProvider.assess(provider),
              try lcEncode(self).count <= LifecycleLimits.request else { throw LifecycleError.invalid("request binding") }
        try lcID(generation); try caller.validate()
    }
}
struct OperationIdentity: Codable {
    var namespace: String
    var generation: String
    var caller: CallerIdentity
    var ticketExpiry: UInt64
    var requestDigest: String
    var operationDigest: String
}
struct LifecycleTimes: Codable {
    var admitted: UInt64
    var queueUntil: UInt64
    var absoluteUntil: UInt64
    var lastContact: UInt64
    var attached = true
    var attachmentEpoch: UInt64 = 1
    var detachedUntil: UInt64?
    var transitionStartedAt: UInt64?
    var terminalUntil: UInt64?
}
struct LifecycleWork: Codable { var request: String; var child: String; var keys: GenerationSecrets; var times: LifecycleTimes }
struct LifecycleCleanup: Codable { var request: String?; var child: String? }
struct LifecycleRecord: Codable {
    var id: String
    var identity: OperationIdentity?
    var phase: LifecyclePhase
    var work: LifecycleWork?
    var cleanup: LifecycleCleanup?
    var ending: WireFinishReason?
    var disposition: String?
    var high: UInt64 = 0
    var nonResumable = false
}
func lcEncode<T: Encodable>(_ value: T) throws -> Data { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return try e.encode(value) }
func lcHash(_ value: Data) -> String { SHA256.hash(data: value).map { String(format: "%02x", $0) }.joined() }
func lcID(_ value: String) throws { guard !value.isEmpty, value.utf8.count <= 256 else { throw LifecycleError.invalid("bounded identifier") } }
func lcUUID(_ value: String) -> Bool { value.utf8.count == 36 && UUID(uuidString: value)?.uuidString.lowercased() == value }
func lcDigest(_ value: String) -> Bool { value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
func lcAdd(_ time: UInt64, _ duration: UInt64) throws -> UInt64 { let next = time.addingReportingOverflow(duration); guard !next.overflow else { throw LifecycleError.invalid("clock/epoch overflow") }; return next.partialValue }
func lcRandom() throws -> Data {
    var data = Data(count: 32)
    guard data.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else { throw LifecycleError.invalid("synthetic key CSPRNG") }
    return data
}
func lcUInt(_ value: UInt64) -> Data { var big = value.bigEndian; return withUnsafeBytes(of: &big) { Data($0) } }
