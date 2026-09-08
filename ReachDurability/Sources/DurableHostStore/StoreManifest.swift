import Foundation
import ResumableMLXProvider
import ReachWire

struct StoreBlobReference: Codable {
    var record: String
    var epoch: UInt64
    var cipherBytes: Int
    var cipherDigest: String
    var name: String { "b-" + record + ".bin" }
    func validate(epoch currentEpoch: UInt64, role: String) throws {
        guard storeUUID(record), epoch > 0, epoch <= currentEpoch,
              (StoreCrypto.overhead...StoreCrypto.limit(role)+StoreCrypto.overhead).contains(cipherBytes), storeDigest(cipherDigest) else { throw StoreError.invalid("blob reference") }
    }
}
struct StoreManifest: Codable {
    var version = 1
    var storeID: String
    var bootID: String
    var bindingDigest: String
    var epoch: UInt64
    var commit: Data?
    var candidate: StoreBlobReference?
    var replay: StoreBlobReference?
    var high: UInt64 = 0
    var batches: Int = 0
    var terminal: WireFinishReason?
}
public struct StoreReplayFrame: Equatable {
    public let firstSequence: UInt64
    public let count: Int
    public let providerCommit: String
    public let eventBytes: Data
    public let skipPrefix: Int
}
struct StoreReplayBatch {
    var first: UInt64
    var count: Int
    var ordinal: UInt64
    var commit: String
    var bytes: Data
}
struct StoreReplay {
    static let headerBytes = 88
    var batches: [StoreReplayBatch] = []
    var high: UInt64 { batches.last.map { $0.first + UInt64($0.count)-1 } ?? 0 }
    var encodedSize: Int { 4 + batches.reduce(0) { $0 + Self.headerBytes + $1.bytes.count } }
    static func events(_ bytes: Data) throws -> [WireEvent] {
        guard bytes.count <= ProviderCandidate.maximumControlBytes else { throw StoreError.invalid("replay batch size") }
        let events = try JSONDecoder().decode([WireEvent].self, from: bytes)
        guard events.count <= 4096 else { throw StoreError.invalid("replay batch event count") }; return events
    }
    func encoded() throws -> Data {
        guard encodedSize <= StoreLimits.replay else { throw StoreError.full }
        var data = storeUInt(UInt32(encodedSize-4))
        for b in batches {
            data += storeUInt(b.first) + storeUInt(UInt32(b.count)) + storeUInt(b.ordinal)
            data += Data(b.commit.utf8) + storeUInt(UInt32(b.bytes.count)) + b.bytes
        }
        return data
    }
    init() {}
    init(data: Data) throws {
        guard data.count <= StoreLimits.replay else { throw StoreError.invalid("replay container size") }
        var offset = 0
        let length = try storeReadUInt(data, &offset, UInt32.self)
        guard Int(length) == data.count-4 else { throw StoreError.invalid("replay framing") }
        var expected: UInt64 = 1, previousOrdinal: UInt64 = 0, identities = Set<String>()
        while offset < data.count {
            guard batches.count < StoreLimits.commits, Self.headerBytes <= data.count-offset else { throw StoreError.invalid("replay record bound") }
            let first = try storeReadUInt(data, &offset, UInt64.self), count = try storeReadUInt(data, &offset, UInt32.self)
            let ordinal = try storeReadUInt(data, &offset, UInt64.self)
            guard let commit = String(data: data[offset..<offset+64], encoding: .utf8), storeDigest(commit), identities.insert(commit).inserted else { throw StoreError.invalid("replay commit") }
            offset += 64
            let size = try storeReadUInt(data, &offset, UInt32.self)
            guard (1...4096).contains(count), first == expected, ordinal > previousOrdinal, ordinal < UInt64(StoreLimits.commits),
                  size <= ProviderCandidate.maximumControlBytes, Int(size) <= data.count-offset,
                  first <= UInt64(StoreLimits.events), UInt64(count) <= UInt64(StoreLimits.events)-first+1 else { throw StoreError.invalid("replay sequence/count/length") }
            let bytes = Data(data[offset..<offset+Int(size)]); offset += Int(size)
            let values = try Self.events(bytes)
            guard values.count == Int(count) else { throw StoreError.invalid("decoded replay count") }
            batches.append(.init(first: first, count: Int(count), ordinal: ordinal, commit: commit, bytes: bytes))
            expected += UInt64(count); previousOrdinal = ordinal
        }
        _ = try terminal()
    }
    func terminal() throws -> WireFinishReason? {
        var ending: WireFinishReason?
        for (i, batch) in batches.enumerated() {
            let values = try Self.events(batch.bytes)
            for (j, event) in values.enumerated() {
                if case .finished(let reason) = event {
                    guard ending == nil, i == batches.count-1, j == values.count-1 else { throw StoreError.invalid("replay terminal order") }
                    ending = reason
                }
            }
        }
        return ending
    }
    func appending(_ candidate: ProviderCandidate, projection: StoreCommitProjection) throws -> StoreReplay {
        let count = try Self.events(candidate.eventBytes).count
        var next = self
        if count > 0 {
            guard high <= UInt64(StoreLimits.events)-UInt64(count) else { throw StoreError.full }
            next.batches.append(.init(first: high+1, count: count, ordinal: projection.ordinal, commit: candidate.commit.identity, bytes: candidate.eventBytes))
        }
        guard next.encodedSize <= StoreLimits.replay else { throw StoreError.full }
        return next
    }
    func frames(after cursor: UInt64) throws -> [StoreReplayFrame] {
        guard cursor <= high else { throw StoreError.invalid("cursor above committed high") }
        return batches.compactMap { b in
            let last = b.first + UInt64(b.count)-1
            guard last > cursor else { return nil }
            let skip = cursor >= b.first ? Int(cursor-b.first+1) : 0
            return .init(firstSequence: b.first, count: b.count, providerCommit: b.commit, eventBytes: b.bytes, skipPrefix: skip)
        }
    }
}
public struct StoreSnapshot {
    public let candidate: ProviderCandidate?
    public let high: UInt64
    public let epoch: UInt64
    public let terminal: Bool
}
struct StoreLoaded {
    var manifest: StoreManifest
    var candidate: ProviderCandidate?
    var replay: StoreReplay
    var snapshot: StoreSnapshot { .init(candidate: candidate, high: manifest.high, epoch: manifest.epoch, terminal: manifest.terminal != nil) }
}
