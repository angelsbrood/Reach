import Foundation
import CryptoKit

public enum HandoffError: Error, Equatable { case invalid, unavailable, oversized, closed }
public enum HandoffContract {
    public static let revision = "s84-host-client-v1"
    public static let control = 2<<20, replayMessage = 12<<20, context = 1<<20, batch = 8<<20
    public static func encode<T: Encodable>(_ value: T, maximum: Int = control) throws -> Data {
        let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try e.encode(value); guard data.count <= maximum else { throw HandoffError.oversized }; return data
    }
    public static func decode<T: Codable>(_ type: T.Type, _ input: Data, maximum: Int = control) throws -> T {
        guard input.count <= maximum else { throw HandoffError.oversized }
        let result = try JSONDecoder().decode(type, from: input)
        guard try encode(result, maximum: maximum) == input else { throw HandoffError.invalid }; return result
    }
    public static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    public static func digest(_ text: String) -> Bool { text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    public static func uuid(_ text: String) -> Bool { text.utf8.count == 36 && UUID(uuidString: text)?.uuidString.lowercased() == text }
    public static func uint(_ n: UInt64) -> Data { var value = n.bigEndian; return withUnsafeBytes(of: &value) { Data($0) } }
    public static func add(_ a: UInt64, _ b: UInt64) throws -> UInt64 { let c = a.addingReportingOverflow(b); guard !c.overflow else { throw HandoffError.invalid }; return c.partialValue }
    public static func equal(_ a: String, _ b: String) -> Bool { Data(a.utf8) == Data(b.utf8) }
}
/// Length-prefixed exact bytes, streamed without constructing an aggregate replay payload.
public struct HandoffDigest {
    private var value = SHA256()
    public init(_ domain: String, context: Data) { append(Data("S84/v1/".utf8)+Data(domain.utf8)); append(context) }
    public mutating func append(_ bytes: Data) { value.update(data: HandoffContract.uint(UInt64(bytes.count))); value.update(data: bytes) }
    public mutating func finish() -> String { value.finalize().map { String(format: "%02x", $0) }.joined() }
}
public struct HandoffBatch: Codable {
    public var first: UInt64, count: Int, commit: String, bytes: Data, skip: Int
    public init(first: UInt64, count: Int, commit: String, bytes: Data, skip: Int = 0) {
        self.first = first; self.count = count; self.commit = commit; self.bytes = bytes; self.skip = skip
    }
    public func last() throws -> UInt64 {
        guard first > 0, (1...4096).contains(count), HandoffContract.digest(commit), bytes.count <= HandoffContract.batch,
              (0..<count).contains(skip) else { throw HandoffError.invalid }
        let last = try HandoffContract.add(first, UInt64(count-1)); guard last <= 65536 else { throw HandoffError.invalid }; return last
    }
}
public struct HandoffWitness: Codable, Equatable {
    public var version = 1
    public var policy = HandoffContract.revision
    public var context: String, clientRoot: String, revision: UInt64, high: UInt64, terminal: Bool
    public var prefix: String, registrations: Int, calls: String
    public init(context: String, clientRoot: String, revision: UInt64, high: UInt64, terminal: Bool,
                prefix: String, registrations: Int, calls: String) {
        self.context = context; self.clientRoot = clientRoot; self.revision = revision; self.high = high; self.terminal = terminal
        self.prefix = prefix; self.registrations = registrations; self.calls = calls
    }
    public func validate(expectedRoot: String) throws {
        guard version == 1, policy == HandoffContract.revision, HandoffContract.uuid(clientRoot), HandoffContract.uuid(expectedRoot),
              HandoffContract.equal(clientRoot, expectedRoot), [context, prefix, calls].allSatisfy(HandoffContract.digest),
              high <= 65536, (high == 0 ? revision == 0 && !terminal && registrations == 0 : revision > 0),
              (0...32).contains(registrations) else { throw HandoffError.invalid }
    }
    public func disposition() throws -> String {
        var digest = HandoffDigest("receipt-disposition", context: Data())
        digest.append(try HandoffContract.encode(self)); return "durable-receipt-v1:"+digest.finish()
    }
}
public struct HandoffPrefix {
    private var batches: HandoffDigest, calls: HandoffDigest
    public private(set) var high: UInt64 = 0, batchCount = 0, registrations = 0
    private var framedBytes = 4
    private var ids = Set<Data>()
    public init(context: Data) { batches = .init("full-prefix", context: context); calls = .init("ordered-calls", context: context) }
    public mutating func append(_ batch: HandoffBatch) throws {
        guard batch.first == (try HandoffContract.add(high, 1)), batchCount < 4095,
              framedBytes+88+batch.bytes.count <= (16<<20)+4 else { throw HandoffError.invalid }
        high = try batch.last(); batchCount += 1; framedBytes += 88+batch.bytes.count
        batches.append(HandoffContract.uint(batch.first)); batches.append(HandoffContract.uint(UInt64(batch.count)))
        batches.append(Data(batch.commit.utf8)); batches.append(batch.bytes)
    }
    public mutating func register(id: Data, name: Data, arguments: Data) throws {
        guard !id.isEmpty, id.count <= 256, !name.isEmpty, name.count <= 1024, arguments.count <= HandoffContract.batch,
              ids.insert(id).inserted, registrations < 32 else { throw HandoffError.invalid }
        calls.append(id); calls.append(name); calls.append(arguments); registrations += 1
    }
    public mutating func digests() -> (String, String) {
        batches.append(HandoffContract.uint(UInt64(batchCount))); calls.append(HandoffContract.uint(UInt64(registrations)))
        return (batches.finish(), calls.finish())
    }
}
/// Private request/reply vocabulary. Encoded payloads never belong in retained logs.
