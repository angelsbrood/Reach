import Foundation
import ReachWire
import MLXLMCommon
import MLXGuidedGeneration
import RequiredToolCoordinator
import AllowedToolCoordinator

struct ProviderDescriptor: Codable {
    var version = 1
    var operationID: String
    var route: ProviderRoute
    var ordinal: UInt64
    var previousID: String?
    var checkpointDigest: String
    var eventsDigest: String
    var terminal: WireFinishReason?
}
public struct ProviderCommit: Equatable, Sendable, Codable {
    public let data: Data
    public var identity: String { providerHash(data) }
    public init(data: Data) throws {
        guard data.count <= 16*1024 else { throw ProviderError.oversized }
        let d = try JSONDecoder().decode(ProviderDescriptor.self, from: data)
        try providerID(d.operationID)
        guard d.version == 1, providerHashValid(d.checkpointDigest), providerHashValid(d.eventsDigest),
              d.ordinal == 0 ? d.previousID == nil : d.previousID.map(providerHashValid) == true,
              try providerEncode(d) == data else { throw ProviderError.invalid("commit descriptor") }
        self.data = data
    }
    init(_ descriptor: ProviderDescriptor) throws { try self.init(data: providerEncode(descriptor)) }
    func descriptor() throws -> ProviderDescriptor { try JSONDecoder().decode(ProviderDescriptor.self, from: data) }
    public init(from decoder: Decoder) throws { try self.init(data: decoder.singleValueContainer().decode(Data.self)) }
    public func encode(to encoder: Encoder) throws { var c = encoder.singleValueContainer(); try c.encode(data) }
}
struct ProviderCheckpointDocument: Codable {
    var version = 1
    var binding: ProviderBinding
    var ordinal: UInt64
    var previousID: String?
    var phase: String
    var terminal: WireFinishReason?
    var child: Data
}
struct ProviderCandidateDocument: Codable {
    var version = 1
    var commit: ProviderCommit
    var checkpoint: Data
    var events: Data
}

/// Frozen local JSON bytes. The descriptor hashes the checkpoint and event payloads;
/// the checkpoint has no descriptor digest, avoiding recursive hashing. Neither
/// this value nor a serialized pending flag is evidence of a durable host commit.
public struct ProviderCandidate: Equatable, Sendable {
    public static let maximumCheckpointBytes = 128*1024*1024
    public static let maximumControlBytes = 8*1024*1024
    public static let maximumBytes = 192*1024*1024
    public let data: Data
    public let commit: ProviderCommit
    public let checkpointBytes: Data
    public let eventBytes: Data
    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes else { throw ProviderError.oversized }
        let doc = try JSONDecoder().decode(ProviderCandidateDocument.self, from: data)
        guard doc.version == 1, doc.checkpoint.count <= Self.maximumCheckpointBytes,
              doc.events.count <= Self.maximumControlBytes else { throw ProviderError.oversized }
        let c = try doc.commit.descriptor()
        guard c.checkpointDigest == providerHash(doc.checkpoint), c.eventsDigest == providerHash(doc.events) else { throw ProviderError.invalid("candidate digests") }
        let cp = try JSONDecoder().decode(ProviderCheckpointDocument.self, from: doc.checkpoint)
        guard cp.version == 1, cp.binding.lane.route == c.route,
              Data(cp.binding.operationID.utf8) == Data(c.operationID.utf8), cp.ordinal == c.ordinal, cp.previousID == c.previousID,
              cp.phase.utf8.count <= 64,
              try providerEncode(cp.terminal) == providerEncode(c.terminal) else { throw ProviderError.invalid("checkpoint/descriptor join") }
        let events = try ProviderEvents.decode(doc.events)
        guard try providerEncode(ProviderEvents.ending(events)) == providerEncode(c.terminal),
              c.ordinal != 0 || (events.isEmpty && c.terminal == nil) else { throw ProviderError.invalid("event/terminal/C0 join") }
        let cap: Int
        switch c.route {
        case .ordinary: cap = ResumableTextCheckpoint.maximumBytes
        case .guided: cap = ResumableGuidedCheckpoint.maximumBytes
        case .required: cap = RequiredToolCheckpoint.maximumBytes
        case .allowed: cap = AllowedToolCheckpoint.maximumBytes
        }
        guard cp.child.count <= cap else { throw ProviderError.oversized }
        var control = cp; control.child = Data()
        guard try providerEncode(control).count + doc.events.count + doc.commit.data.count <= Self.maximumControlBytes else { throw ProviderError.oversized }
        guard try providerEncode(cp) == doc.checkpoint, try providerEncode(doc) == data else { throw ProviderError.invalid("canonical candidate encoding") }
        self.data = data; commit = doc.commit; checkpointBytes = doc.checkpoint; eventBytes = doc.events
    }
    init(checkpoint: ProviderCheckpointDocument, events: Data) throws {
        let bytes = try providerEncode(checkpoint)
        guard bytes.count <= Self.maximumCheckpointBytes else { throw ProviderError.oversized }
        let commit = try ProviderCommit(.init(operationID: checkpoint.binding.operationID, route: checkpoint.binding.lane.route,
            ordinal: checkpoint.ordinal, previousID: checkpoint.previousID, checkpointDigest: providerHash(bytes),
            eventsDigest: providerHash(events), terminal: checkpoint.terminal))
        try self.init(data: providerEncode(ProviderCandidateDocument(commit: commit, checkpoint: bytes, events: events)))
    }
    func checkpoint() throws -> ProviderCheckpointDocument { try JSONDecoder().decode(ProviderCheckpointDocument.self, from: checkpointBytes) }
}
