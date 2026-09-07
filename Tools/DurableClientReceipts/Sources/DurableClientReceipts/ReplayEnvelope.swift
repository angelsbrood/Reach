import Foundation
import ReachWire

/// Local version-bound projection of S81 StoreReplayFrame; no host authenticity claim.
public struct ReplayEnvelope: Codable {
    public let version: Int
    public let firstSequence: UInt64
    public let count: Int
    public let providerCommit: String
    public let eventBytes: Data
    public let skipPrefix: Int
    public init(firstSequence: UInt64, count: Int, providerCommit: String, eventBytes: Data, skipPrefix: Int = 0) {
        version = 1; self.firstSequence = firstSequence; self.count = count; self.providerCommit = providerCommit
        self.eventBytes = eventBytes; self.skipPrefix = skipPrefix
    }
    func validate(cursor: UInt64, high: UInt64) throws -> [WireEvent] {
        guard version == 1, firstSequence > 0, (1...4096).contains(count), eventBytes.count <= ClientLimits.batch,
              crDigest(providerCommit), cursor <= high else { throw ClientError.invalid("replay envelope") }
        let last = try crAdd(firstSequence, UInt64(count-1))
        guard last > cursor else { throw ClientError.invalid("replay request excludes batch") }
        let expected = cursor >= firstSequence ? Int(cursor-firstSequence+1) : 0
        guard skipPrefix == expected else { throw ClientError.invalid("skip prefix") }
        let events = try ClientEvents.decode(eventBytes)
        guard events.count == count else { throw ClientError.invalid("event count") }; return events
    }
}
// Source-faithful S80 ProviderEvents validation. Intentionally independent of native modules.
public enum ClientEvents {
    public static func encode(_ events: [WireEvent]) throws -> Data {
        guard events.count <= 4096 else { throw ClientError.full }
        var terminals = 0, usages = 0, complete = false
        for (i, event) in events.enumerated() {
            switch event {
            case .responseAppend(let entry, _, let segment, let count):
                if let entry { try crID(entry) }; if let segment { try crID(segment) }
                guard count == 1 else { throw ClientError.invalid("chunk count") }
            case .toolCallAppendArguments(let entry, let id, let name, _, let count):
                if let entry { try crID(entry) }; try crID(id)
                guard !name.isEmpty, name.utf8.count <= 1024, count == 1 else { throw ClientError.invalid("whole tool call") }
            case .usage(let input, let output):
                usages += 1
                guard (0...33*65_536).contains(input), (0...33*65_536).contains(output) else { throw ClientError.invalid("usage") }
            case .finished(let reason):
                terminals += 1
                guard i == events.count-1 else { throw ClientError.invalid("terminal order") }
                if case .complete = reason { complete = true }
                if case .error(let message) = reason { guard !message.isEmpty, message.utf8.count <= 4096 else { throw ClientError.invalid("error length") } }
            default: throw ClientError.invalid("unsupported event projection")
            }
        }
        guard terminals <= 1 else { throw ClientError.invalid("terminal count") }
        if complete {
            guard usages == 1, events.count >= 2, case .usage = events[events.count-2] else { throw ClientError.invalid("success usage tail") }
        } else if usages != 0 { throw ClientError.invalid("non-success usage") }
        let bytes = try crEncode(events)
        guard bytes.count <= ClientLimits.batch else { throw ClientError.full }; return bytes
    }
    public static func decode(_ bytes: Data) throws -> [WireEvent] {
        guard bytes.count <= ClientLimits.batch else { throw ClientError.full }
        let events = try JSONDecoder().decode([WireEvent].self, from: bytes)
        guard try encode(events) == bytes else { throw ClientError.invalid("canonical event bytes") }; return events
    }
}
struct InboxBatch: Codable {
    let first: UInt64, count: Int, commit: String, bytes: Data
    init(_ frame: ReplayEnvelope) { first = frame.firstSequence; count = frame.count; commit = frame.providerCommit; bytes = frame.eventBytes }
    func matches(_ frame: ReplayEnvelope) -> Bool {
        first == frame.firstSequence && count == frame.count && crEqual(commit, frame.providerCommit) && bytes == frame.eventBytes
    }
}
