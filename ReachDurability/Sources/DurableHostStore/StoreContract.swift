import Foundation
import Darwin
import CryptoKit
import ResumableMLXProvider
import ReachWire

public enum StoreError: Error, Equatable { case invalid(String), io(String, Int32), busy, closed, stale, full, uncertain, replayRequired, noCommittedGeneration }
public enum StoreLimits {
    public static let candidate = 192*1024*1024
    public static let replay = 16*1024*1024 + 4
    public static let manifest = 1024*1024
    public static let allocation = 512*1024*1024
    public static let files = 16
    public static let commits = 4096
    public static let events = 65_536
    // Full prepared candidate + full aggregate replay + manifest, cipher framing,
    // and conservative allocation rounding, while the old set remains present.
    public static let reservation = candidate + replay + manifest + 64*1024
}
public struct StoreIdentity {
    public var storeID: String
    public var bootID: String
    public var provider: ProviderBinding
    public init(storeID: String = UUID().uuidString.lowercased(), provider: ProviderBinding) throws {
        self.storeID = storeID; bootID = try StoreEnvironment.bootIdentity(); self.provider = provider
        try validate()
    }
    var bindingBytes: Data { get throws { try storeEncode(provider) } }
    var bindingDigest: String { get throws { try storeHash(bindingBytes) } }
    func validate() throws {
        guard storeUUID(storeID), !bootID.isEmpty, bootID.utf8.count <= 256,
              bootID == (try StoreEnvironment.bootIdentity()) else { throw StoreError.invalid("store/boot identity") }
        guard case .supported = ResumableMLXProvider.assess(provider) else { throw StoreError.invalid("provider declaration") }
    }
}
public enum StoreEnvironment {
    public static func bootIdentity() throws -> String {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, (2...256).contains(size) else { throw StoreError.io("boot identity", errno) }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0, buffer.last == 0 else { throw StoreError.io("boot identity read", errno) }
        let value = String(decoding: buffer.dropLast().map { UInt8(bitPattern: $0) }, as: UTF8.self)
        guard UUID(uuidString: value) != nil else { throw StoreError.invalid("boot identity value") }
        return value.lowercased()
    }
}
/// Explicit version-bound host projection of public S80 descriptor bytes. This
/// does not access provider internals or replace ProviderCandidate validation.
struct StoreCommitProjection: Codable {
    var version: Int
    var operationID: String
    var route: ProviderRoute
    var ordinal: UInt64
    var previousID: String?
    var checkpointDigest: String
    var eventsDigest: String
    var terminal: WireFinishReason?
    init(_ candidate: ProviderCandidate, identity: StoreIdentity) throws {
        let checked = try ProviderCandidate(data: candidate.data)
        self = try JSONDecoder().decode(Self.self, from: checked.commit.data)
        struct Header: Decodable { let version: Int; let binding: ProviderBinding }
        let header = try JSONDecoder().decode(Header.self, from: checked.checkpointBytes)
        guard version == 1, header.version == 1, ordinal < UInt64(StoreLimits.commits),
              try storeEncode(header.binding) == identity.bindingBytes,
              checkpointDigest == storeHash(checked.checkpointBytes), eventsDigest == storeHash(checked.eventBytes) else { throw StoreError.invalid("public provider projection/binding") }
    }
}
public enum StoreFaultPoint: String, Codable {
    case afterCandidateBlob, afterReplayBlob, beforeManifestReplace, afterManifestReplace, beforeDirectorySync
    case afterCommitBeforeAck, afterAckBeforePublication
}
/// Synchronous observer/fault hook for selected-root IO and owned process-death
/// tests. Throwing never authorizes publication; no asynchronous work is started.
public typealias StoreFaultHook = (StoreFaultPoint) throws -> Void
func storeEncode<T: Encodable>(_ value: T) throws -> Data {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return try e.encode(value)
}
func storeHash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
func storeUUID(_ value: String) -> Bool { value.utf8.count == 36 && UUID(uuidString: value)?.uuidString.lowercased() == value }
func storeDigest(_ value: String) -> Bool { value.utf8.count == 64 && value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) }
func storeUInt<T: FixedWidthInteger>(_ value: T) -> Data { var be = value.bigEndian; return withUnsafeBytes(of: &be) { Data($0) } }
func storeReadUInt<T: FixedWidthInteger>(_ data: Data, _ offset: inout Int, _ type: T.Type) throws -> T {
    let count = MemoryLayout<T>.size
    guard offset >= 0, offset <= data.count, count <= data.count-offset else { throw StoreError.invalid("binary length") }
    var value: T = 0
    for byte in data[offset..<offset+count] { value = (value << 8) | T(byte) }
    offset += count; return value
}
