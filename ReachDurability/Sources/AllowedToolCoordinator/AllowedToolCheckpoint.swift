import Foundation
import MLXGuidedGeneration
import MLXLMCommon
import ReachWire
import RequiredToolCoordinator

public enum AllowedPhase: String, Codable, Sendable { case probe, routeReady, guided, callReady, interpass, finalReady, finalEmitted }
public enum AllowedRoute: String, Codable, Sendable { case prose, calls, schema }
enum AllowedOutcome: String, Codable { case complete, cancelled, unknownTool, incompleteGuidance }
struct AllowedGuidedSummary: Codable, Equatable {
    var prompt: Int
    var sampled: Int
    var forced: Int
    var intercepted: Int
    var consumed: Int
    var accepted: Int
    var terminal: ResumableGuidedEnd?
    init(_ v: ResumableGuidedCheckpointView) {
        prompt = v.promptTokens; sampled = v.sampledTokens; forced = v.forcedTokens; intercepted = v.interceptedEndings
        consumed = v.consumedTokens; accepted = v.acceptedTokens; terminal = v.terminalReason
    }
}
struct AllowedContribution: Codable {
    var index: Int
    var kind: AllowedPassKind
    var inputDigest: String
    var prompt: Int
    var output: Int
    var call: RequiredToolCall?
}
struct AllowedControl: Codable {
    var binding: AllowedToolBinding
    var childKind: AllowedPassKind = .probe
    var childDigest: String
    var phase: AllowedPhase = .probe
    var route: AllowedRoute?
    // S76 cannot reconstruct these historical bytes/order/typed arguments.
    var records: [ResumableToolCallRecord] = []
    var proseDelivered: Int = 0
    var probe: ResumableToolGenerationCheckpointView
    var current: AllowedPreparedPass?
    var guided: AllowedGuidedSummary?
    var whole = Data()
    var schemaReturnedBytes: Int = 0
    var completed: [AllowedContribution] = []
    var deliveredCalls: Int = 0
    var outcome: AllowedOutcome?
    var cancelledFrom: AllowedPhase?

    var proposals: [ToolCall] { records.compactMap { if case .toolCall(let c) = $0 { return c }; return nil } }
    func usage() throws -> (Int, Int) {
        var input = probe.promptTokens, output = probe.generationTokens
        for pass in completed {
            let i = input.addingReportingOverflow(pass.prompt), o = output.addingReportingOverflow(pass.output)
            guard !i.overflow, !o.overflow, i.partialValue <= 33*65_536, o.partialValue <= 33*65_536 else { throw AllowedToolError.oversized }
            input = i.partialValue; output = o.partialValue
        }
        return (input, output)
    }
}
struct AllowedDocument: Codable {
    var version = 1
    var control: AllowedControl
    var child: Data
}

public struct AllowedToolCheckpoint: Equatable, Sendable {
    public static let maximumBytes = 64*1024*1024
    public static let maximumControlBytes = 4*1024*1024
    public static let maximumBatchBytes = 96*1024*1024
    public let data: Data
    struct Envelope: Codable { var payload: Data; var sha256: String }
    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes else { throw AllowedToolError.oversized }
        self.data = data; _ = try document()
    }
    init(document: AllowedDocument, records: [WireEvent] = []) throws {
        try Self.bounds(document, records: records)
        let payload = try allowedEncode(document)
        guard payload.count <= Self.maximumBytes else { throw AllowedToolError.oversized }
        let bytes = try allowedEncode(Envelope(payload: payload, sha256: allowedDigest(payload)))
        guard bytes.count <= Self.maximumBytes else { throw AllowedToolError.oversized }
        data = bytes
    }
    static func bounds(_ d: AllowedDocument, records: [WireEvent] = []) throws {
        let c = d.control
        guard d.child.count <= (c.childKind == .probe ? ResumableToolGenerationCheckpoint.maximumBytes : ResumableGuidedCheckpoint.maximumBytes),
              c.records.count <= 4096, c.proposals.count <= 32, c.completed.count <= 32,
              c.whole.count <= 256*1024, (c.current?.messages.count ?? 0) <= 512*1024,
              (c.current?.tokens.count ?? 0) <= 65_536, records.count <= 4096,
              c.phase != .finalEmitted || records.count <= 3 else { throw AllowedToolError.oversized }
        var prose = 0
        for record in c.records {
            if case .response(let bytes) = record {
                guard bytes.count <= 512*1024 - prose else { throw AllowedToolError.oversized }; prose += bytes.count
            }
        }
        for call in c.proposals {
            guard let id = call.id, !id.isEmpty, id.utf8.count <= 256, !call.function.name.isEmpty, call.function.name.utf8.count <= 1024 else {
                throw AllowedToolError.invalid("proposal ID/name")
            }
            _ = try allowedArguments(call)
        }
        for summary in c.completed {
            guard (summary.call?.argumentsJSON.utf8.count ?? 0) <= 256*1024 else { throw AllowedToolError.oversized }
        }
        var controlOnly = d; controlOnly.child = Data()
        guard try allowedEncode(controlOnly).count + allowedEncode(records).count <= maximumControlBytes else { throw AllowedToolError.oversized }
    }
    func document() throws -> AllowedDocument {
        do {
            let e = try JSONDecoder().decode(Envelope.self, from: data)
            guard e.payload.count <= Self.maximumBytes, allowedDigest(e.payload) == e.sha256 else { throw AllowedToolError.invalid("outer checksum") }
            struct Header: Decodable { let version: Int }
            guard try JSONDecoder().decode(Header.self, from: e.payload).version == 1 else { throw AllowedToolError.incompatible }
            let d = try JSONDecoder().decode(AllowedDocument.self, from: e.payload)
            try Self.bounds(d)
            guard d.control.childDigest == allowedDigest(d.child) else { throw AllowedToolError.invalid("retained child checksum") }
            return d
        } catch let error as AllowedToolError { throw error }
        catch { throw AllowedToolError.invalid("outer encoding") }
    }
}
