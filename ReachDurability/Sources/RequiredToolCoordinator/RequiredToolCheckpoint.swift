import Foundation
import MLXGuidedGeneration
import MLXLMCommon
import ReachWire

public enum RequiredToolPhase: String, Codable, Sendable { case generating, ready, emitted }

struct RequiredToolCounts: Codable, Equatable {
    var prompt: Int
    var sampled: Int
    var forced: Int
    var intercepted: Int
    var consumed: Int
    var accepted: Int
    init(_ view: ResumableGuidedCheckpointView) {
        prompt = view.promptTokens; sampled = view.sampledTokens; forced = view.forcedTokens
        intercepted = view.interceptedEndings; consumed = view.consumedTokens; accepted = view.acceptedTokens
    }
}
struct RequiredToolControl: Codable {
    var binding: RequiredToolBinding
    var childDigest: String
    var whole: Data
    var phase: RequiredToolPhase
    var outcome: ResumableGuidedEnd?
    var call: RequiredToolCall?
    var counts: RequiredToolCounts
}
struct RequiredToolDocument: Codable {
    var version = 1
    var child: Data
    var control: RequiredToolControl
}

/// Envelope decoding checks bounded bytes/checksums only. Use coordinator restore
/// for native child acceptance and cross-layer consistency validation.
public struct RequiredToolCheckpoint: Equatable, Sendable {
    public static let maximumBytes = 32 * 1024 * 1024
    public static let maximumControlBytes = 1024 * 1024
    public let data: Data
    struct Envelope: Codable { var payload: Data; var sha256: String }

    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes else { throw RequiredToolError.oversized }
        self.data = data; _ = try document()
    }
    init(document: RequiredToolDocument, records: [WireEvent] = []) throws {
        try Self.checkBounds(document, records: records)
        let payload = try requiredEncoder().encode(document)
        guard payload.count <= Self.maximumBytes else { throw RequiredToolError.oversized }
        let bytes = try requiredEncoder().encode(Envelope(payload: payload, sha256: ResumableGuidedValues.digest(payload)))
        guard bytes.count <= Self.maximumBytes else { throw RequiredToolError.oversized }
        data = bytes
    }
    static func checkBounds(_ d: RequiredToolDocument, records: [WireEvent] = []) throws {
        guard d.child.count <= ResumableGuidedCheckpoint.maximumBytes,
              d.control.whole.count <= RequiredToolContract.maximumEnvelopeBytes,
              (d.control.call?.argumentsJSON.utf8.count ?? 0) <= RequiredToolContract.maximumArgumentsBytes,
              records.count <= 3 else { throw RequiredToolError.oversized }
        var excludingChild = d; excludingChild.child = Data()
        guard try requiredEncoder().encode(excludingChild).count + requiredEncoder().encode(records).count <= maximumControlBytes else {
            throw RequiredToolError.oversized
        }
    }
    func document() throws -> RequiredToolDocument {
        do {
            let e = try JSONDecoder().decode(Envelope.self, from: data)
            guard e.payload.count <= Self.maximumBytes,
                  ResumableGuidedValues.digest(e.payload) == e.sha256 else { throw RequiredToolError.invalid("outer checksum") }
            struct Header: Decodable { let version: Int }
            guard try JSONDecoder().decode(Header.self, from: e.payload).version == 1 else { throw RequiredToolError.incompatible }
            let d = try JSONDecoder().decode(RequiredToolDocument.self, from: e.payload)
            try Self.checkBounds(d)
            guard d.control.childDigest == ResumableGuidedValues.digest(d.child) else { throw RequiredToolError.invalid("child checksum binding") }
            return d
        } catch let error as RequiredToolError { throw error }
        catch { throw RequiredToolError.invalid("outer encoding") }
    }
}
