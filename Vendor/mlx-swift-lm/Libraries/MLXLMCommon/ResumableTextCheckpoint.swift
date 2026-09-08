// Local candidate: composed raw-token and plain-text output snapshot.

import Foundation

struct ResumableTextState: Codable {
    var options: ResumableTextOptions
    var rawDigest: String
    var segmentTokens: [Int] = []
    var segment: Data = Data()
    // Position within the current segment whose decode produced the stored segment.
    // Incomplete byte tokens can extend segmentTokens without advancing this position.
    var emittedTokenCount: Int = 0
    var buffer: Data = Data()
    var stopped: Bool = false
    var promptCount: Int
    var generationCount: Int = 0
    var rawCount: Int = 0
    var lastToken: Int?
    // Non-nil always means terminal already returned atomically. There is no queue.
    var terminal: ResumableTextEnd?

    static let maximumTextBytes = 256 * 1024

    static func string(_ data: Data) throws -> String {
        guard data.count <= maximumTextBytes else { throw ResumableTokenError.oversized }
        guard let string = String(data: data, encoding: .utf8), Data(string.utf8) == data else {
            throw ResumableTokenError.invalid("output UTF-8")
        }
        return string
    }

    @discardableResult
    static func checkDecode(_ tokenizer: any Tokenizer, tokens: [Int]) throws -> String {
        let value = tokenizer.decode(tokenIds: tokens)
        guard value.utf8.count <= maximumTextBytes else { throw ResumableTokenError.oversized }
        return value
    }

    func validate(raw: ResumableDocument, rawData: Data, tokenizer: any Tokenizer) throws {
        try raw.options.validate()
        try options.validate(vocabulary: raw.options.vocabularySize)
        guard rawDigest == ResumableTokenCheckpoint.digest(rawData),
            promptCount == raw.promptCount, (1...65_536).contains(promptCount),
            rawCount == raw.tokenCount, (0...raw.options.maximumTokens).contains(rawCount),
            generationCount >= 0, generationCount <= rawCount,
            (rawCount == 0) == (lastToken == nil),
            lastToken.map({ (0..<raw.options.vocabularySize).contains($0) }) ?? true,
            segmentTokens.count <= generationCount, segmentTokens.count <= 65_536,
            segmentTokens.allSatisfy({ (0..<raw.options.vocabularySize).contains($0) && !options.intercepts($0) }),
            (0...segmentTokens.count).contains(emittedTokenCount) else {
            throw ResumableTokenError.invalid("raw/output binding or counters")
        }
        let intercepted = lastToken.map(options.intercepts) ?? false
        guard generationCount == rawCount - (intercepted ? 1 : 0),
            (generationCount == 0) == segmentTokens.isEmpty,
            intercepted || lastToken == segmentTokens.last else {
            throw ResumableTokenError.invalid("output token accounting")
        }
        let segmentString = try Self.string(segment)
        let bufferString = try Self.string(buffer)
        guard buffer.count <= 4096 else { throw ResumableTokenError.oversized }
        let expectedSegment = emittedTokenCount == 0 ? "" : try Self.checkDecode(tokenizer,
            tokens: Array(segmentTokens.prefix(emittedTokenCount)))
        guard Data(expectedSegment.utf8) == segment else {
            throw ResumableTokenError.invalid("detokenizer emitted segment")
        }
        if emittedTokenCount < segmentTokens.count {
            try Self.checkDecode(tokenizer, tokens: segmentTokens)
            try Self.checkDecode(tokenizer, tokens: [segmentTokens.last!])
            var detokenizer = NaiveStreamingDetokenizer(tokenizer: tokenizer)
            detokenizer.segmentTokens = segmentTokens; detokenizer.segment = segmentString
            guard detokenizer.next() == nil else {
                throw ResumableTokenError.invalid("unsettled detokenizer output")
            }
        }
        switch terminal {
        case nil:
            guard !stopped, !intercepted,
                !raw.exhausted || (raw.options.maximumTokens == 0 && rawCount == 0) else {
                throw ResumableTokenError.invalid("active output lifecycle")
            }
        case .stop:
            guard rawCount > 0, intercepted != stopped else {
                throw ResumableTokenError.invalid("stop reason")
            }
        case .length:
            guard raw.exhausted, !stopped, !intercepted else {
                throw ResumableTokenError.invalid("length reason")
            }
        case .cancelled:
            guard !stopped, !intercepted else { throw ResumableTokenError.invalid("cancel reason") }
        }
        guard terminal == nil || buffer.isEmpty else {
            throw ResumableTokenError.invalid("terminal buffer was not drained")
        }
        if terminal == nil {
            var check = StopStringFilter(stopStrings: Set(options.stopStrings))
            let result = check.process(bufferString)
            guard result.text == nil, !result.stopped, Data(check.buffer.utf8) == buffer else {
                throw ResumableTokenError.invalid("partial stop buffer")
            }
        }
    }
}

struct ResumableTextDocument: Codable {
    var version: Int = 1
    var rawSchema: Int = 2
    var rawCandidate: String = ResumableTextCheckpoint.rawCandidate
    var raw: Data
    var output: ResumableTextState
}

/// Bounded immutable value. Checksums detect accidental corruption, not attacker changes.
/// No encryption, host durability, acknowledgment cursor, timing or external effects.
public struct ResumableTextCheckpoint: Equatable, Sendable {
    public static let maximumBytes = 16 * 1024 * 1024
    public static let maximumOutputBytes = 1024 * 1024
    public static let rawCandidate = "35a3be79e989c39ae568f97a70baf8bdb5b75f3161919803cc8a1530a0db63ab"
    public let data: Data

    init(document: ResumableTextDocument) throws {
        guard document.raw.count <= ResumableTokenCheckpoint.maximumBytes,
            document.output.segmentTokens.count <= 65_536,
            document.output.segment.count <= ResumableTextState.maximumTextBytes,
            document.output.buffer.count <= 4096 else { throw ResumableTokenError.oversized }
        guard try ResumableTokenCheckpoint.encoder().encode(document.output).count <= Self.maximumOutputBytes else {
            throw ResumableTokenError.oversized
        }
        let payload = try ResumableTokenCheckpoint.encoder().encode(document)
        guard payload.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        let data = try ResumableTokenCheckpoint.encoder().encode(ResumableTokenCheckpoint.Envelope(
            payload: payload, sha256: ResumableTokenCheckpoint.digest(payload)))
        guard data.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        self.data = data
    }

    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        self.data = data
        _ = try document()
    }

    func document() throws -> ResumableTextDocument {
        guard data.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        do {
            let envelope = try JSONDecoder().decode(ResumableTokenCheckpoint.Envelope.self, from: data)
            guard ResumableTokenCheckpoint.digest(envelope.payload) == envelope.sha256 else {
                throw ResumableTokenError.invalid("text checksum")
            }
            struct Header: Decodable { let version: Int; let rawSchema: Int; let rawCandidate: String }
            let header = try JSONDecoder().decode(Header.self, from: envelope.payload)
            guard header.version == 1, header.rawSchema == 2, header.rawCandidate == Self.rawCandidate else {
                throw ResumableTokenError.incompatible
            }
            let document = try JSONDecoder().decode(ResumableTextDocument.self, from: envelope.payload)
            guard document.raw.count <= ResumableTokenCheckpoint.maximumBytes,
                document.output.segmentTokens.count <= 65_536,
                try ResumableTokenCheckpoint.encoder().encode(document.output).count <= Self.maximumOutputBytes else {
                throw ResumableTokenError.oversized
            }
            return document
        } catch let error as ResumableTokenError { throw error }
        catch { throw ResumableTokenError.invalid("text checkpoint encoding") }
    }
}
