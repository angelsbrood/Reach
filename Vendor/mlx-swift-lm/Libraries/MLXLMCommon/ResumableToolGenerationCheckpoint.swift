import Foundation

enum ToolGenerationDisposition: String, Codable, Sendable {
    case active, normalFinished, cancelledFrozen
}

struct ToolGenerationDocument: Codable {
    var version = 1
    var policy = "S76-ordered-proposal-cancel-discard-v1"
    var textCandidate = "bd3fb02e7fab42887593512599de64ecb4d7c7c242d91359d37158d2a8227113"
    var parserCandidate = "c7ae60342894f77b58e3b5cb51a11b0a1251db95a7bbc9386307eb17cec27ffd"
    var text: Data
    var parser: Data
    // Retained: raw tokens do not determine the number of nonempty text chunks.
    // Parser sequence is derived: forwardedChunks plus one normal EOS, never cancel.
    var forwardedChunks: UInt64
    var disposition: ToolGenerationDisposition

    func validate() throws {
        guard version == 1, policy == "S76-ordered-proposal-cancel-discard-v1",
            textCandidate == "bd3fb02e7fab42887593512599de64ecb4d7c7c242d91359d37158d2a8227113",
            parserCandidate == "c7ae60342894f77b58e3b5cb51a11b0a1251db95a7bbc9386307eb17cec27ffd" else {
            throw ResumableTokenError.incompatible
        }
        let t = try ResumableTextCheckpoint(data: text).document()
        let raw = try ResumableTokenCheckpoint(data: t.raw).document()
        let p = try ResumableToolCallCheckpoint(data: parser).document()
        // Full raw value/codec validation is completed by S73 restore, even for
        // terminal values. document() alone is not raw value validation.
        guard t.output.rawDigest == ResumableTokenCheckpoint.digest(t.raw),
            t.output.rawCount == raw.tokenCount, t.output.promptCount == raw.promptCount,
            (0...65_536).contains(t.output.rawCount), forwardedChunks <= 999_999 else {
            throw ResumableTokenError.invalid("tool generation positions")
        }
        let normal = disposition == .normalFinished
        guard p.sequence == forwardedChunks + (normal ? 1 : 0), p.finished == normal,
            forwardedChunks <= UInt64(t.output.rawCount) + (normal ? 1 : 0) else {
            throw ResumableTokenError.invalid("parser operation join")
        }
        if t.output.rawCount == 0 {
            guard forwardedChunks == 0 else { throw ResumableTokenError.invalid("tool generation C0") }
        }
        switch disposition {
        case .active:
            guard t.output.terminal == nil else { throw ResumableTokenError.invalid("active join") }
        case .normalFinished:
            guard t.output.terminal == .stop || t.output.terminal == .length else {
                throw ResumableTokenError.invalid("normal ending join")
            }
        case .cancelledFrozen:
            guard t.output.terminal == .cancelled else { throw ResumableTokenError.invalid("cancelled join") }
        }
    }
}

/// Immutable local value; checksum detects ordinary corruption, not arbitrary forgery.
/// Construction checks encoding/joins; restore also performs full child validation.
public struct ResumableToolGenerationCheckpoint: Equatable, Sendable {
    public static let maximumBytes = 32 * 1024 * 1024
    public let data: Data

    init(document: ToolGenerationDocument) throws {
        guard document.text.count <= ResumableTextCheckpoint.maximumBytes,
            document.parser.count <= ResumableToolCallCheckpoint.maximumBytes else {
            throw ResumableTokenError.oversized
        }
        let payload = try ToolCheckpointEncoding.encode(document)
        guard payload.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        let encoded = try ToolCheckpointEncoding.encode(ResumableTokenCheckpoint.Envelope(
            payload: payload, sha256: ResumableTokenCheckpoint.digest(payload)))
        guard encoded.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        data = encoded
    }
    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        self.data = data
        _ = try document()
    }
    func document() throws -> ToolGenerationDocument {
        guard data.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        let envelope = try JSONDecoder().decode(ResumableTokenCheckpoint.Envelope.self, from: data)
        guard ResumableTokenCheckpoint.digest(envelope.payload) == envelope.sha256 else {
            throw ResumableTokenError.invalid("tool generation checksum")
        }
        let document = try JSONDecoder().decode(ToolGenerationDocument.self, from: envelope.payload)
        try document.validate()
        return document
    }
}
