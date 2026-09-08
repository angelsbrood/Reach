// Local candidate: paused, explicitly parser-disabled plain-text output.

import Foundation

/// The owner attests that the tokenizer/configuration is immutable, deterministic,
/// side-effect-free and has bounded decode cost. IDs are explicit; no template,
/// tokenizer construction, implicit EOS lookup or tool parser is used here.
public struct ResumableTextOptions: Codable, Sendable {
    public let tokenizerIdentity: String
    public let stopTokenIDs: [Int]
    public let unknownTokenID: Int?
    public let stopStrings: [String]

    public init(tokenizerIdentity: String, stopTokenIDs: Set<Int> = [],
                unknownTokenID: Int? = nil, stopStrings: Set<String> = []) throws {
        guard stopTokenIDs.count <= 256, stopStrings.count <= 32,
            stopStrings.allSatisfy({ $0.utf8.count <= 4096 }) else {
            throw ResumableTokenError.oversized
        }
        self.tokenizerIdentity = tokenizerIdentity
        self.stopTokenIDs = stopTokenIDs.sorted()
        self.unknownTokenID = unknownTokenID
        self.stopStrings = StopStringFilter(stopStrings: stopStrings).stopStrings
    }

    func validate(vocabulary: Int) throws {
        guard (1...65_536).contains(vocabulary),
            !tokenizerIdentity.isEmpty, tokenizerIdentity.utf8.count <= 1024,
            stopTokenIDs.count <= 256, stopTokenIDs == Set(stopTokenIDs).sorted(),
            stopTokenIDs.allSatisfy({ (0..<vocabulary).contains($0) }),
            unknownTokenID.map({ (0..<vocabulary).contains($0) }) ?? true,
            stopStrings.count <= 32,
            stopStrings.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 4096 }) else {
            throw ResumableTokenError.invalid("text options")
        }
        let normalized = StopStringFilter(stopStrings: Set(stopStrings)).stopStrings
        guard try ResumableTokenCheckpoint.encoder().encode(normalized)
            == ResumableTokenCheckpoint.encoder().encode(stopStrings) else {
            throw ResumableTokenError.invalid("normalized stops")
        }
    }

    func intercepts(_ token: Int) -> Bool {
        stopTokenIDs.contains(token) || unknownTokenID == token
    }
}

public enum ResumableTextEnd: String, Codable, Sendable { case stop, length, cancelled }

/// Semantic counts only. Timing and throughput are caller-owned telemetry.
public struct ResumableTextCompletion: Codable, Equatable, Sendable {
    public let reason: ResumableTextEnd
    public let promptTokens: Int
    public let generationTokens: Int
    public let rawTokens: Int
}

/// Text is stored as UTF-8 bytes so equality does not use Unicode canonical equivalence.
public enum ResumableTextRecord: Codable, Equatable, Sendable {
    case text(Data)
    case terminal(ResumableTextCompletion)
}

/// Serially confined pull wrapper; no work runs between calls, and no records are queued.
/// Each batch and its post-batch snapshot are returned atomically. The caller owns the
/// returned records and any later publication. This is not a host acknowledgment journal.
public final class ResumableTextOutput {
    public struct Batch {
        /// The consumed raw token, including intercepted EOS/unknown, or nil for a
        /// zero-limit/cancel transition. Text generation usage excludes intercepted IDs.
        public let token: Int?
        public let records: [ResumableTextRecord]
        public let checkpoint: ResumableTextCheckpoint
    }

    private var raw: ResumableTokenDriver?
    private var rawCheckpoint: ResumableTokenCheckpoint
    private let options: ResumableTextOptions
    private var detokenizer: NaiveStreamingDetokenizer
    private var filter: StopStringFilter
    private var emittedTokenCount: Int
    private let promptCount: Int
    private var generationCount: Int
    private var rawCount: Int
    private var lastToken: Int?
    public private(set) var terminalReason: ResumableTextEnd?
    public private(set) var isClosed = false

    private init(raw: ResumableTokenDriver, checkpoint: ResumableTokenCheckpoint,
                 tokenizer: any Tokenizer, state: ResumableTextState) throws {
        self.raw = raw; rawCheckpoint = checkpoint; options = state.options
        detokenizer = NaiveStreamingDetokenizer(tokenizer: tokenizer)
        detokenizer.segmentTokens = state.segmentTokens
        detokenizer.segment = try ResumableTextState.string(state.segment)
        filter = StopStringFilter(stopStrings: Set(state.options.stopStrings))
        filter.buffer = try ResumableTextState.string(state.buffer)
        filter.stopped = state.stopped
        emittedTokenCount = state.emittedTokenCount; promptCount = state.promptCount
        generationCount = state.generationCount; rawCount = state.rawCount
        lastToken = state.lastToken; terminalReason = state.terminal
        if terminalReason != nil { raw.close(); self.raw = nil }
    }

    public static func prepare(model: any LanguageModel, tokens: [Int],
                               identity: ResumableTokenIdentity, rawOptions: ResumableTokenOptions,
                               cacheSpecs: [ResumableCacheSpec], codecs: ResumableStateCodecs = .init(),
                               tokenizer: any Tokenizer, options: ResumableTextOptions) throws -> ResumableTextOutput {
        try options.validate(vocabulary: rawOptions.vocabularySize)
        let raw = try ResumableTokenDriver.prepare(model: model, tokens: tokens, identity: identity,
            options: rawOptions, cacheSpecs: cacheSpecs, codecs: codecs)
        do {
            let checkpoint = try raw.capture()
            let state = ResumableTextState(options: options,
                rawDigest: ResumableTokenCheckpoint.digest(checkpoint.data), promptCount: tokens.count)
            let output = try ResumableTextOutput(raw: raw, checkpoint: checkpoint, tokenizer: tokenizer, state: state)
            _ = try output.capture()
            return output
        } catch { raw.close(); throw error }
    }

    /// Validates bounded value state before restoring the raw child. No model, prefill,
    /// sample, reseed or generation replay. The deterministic tokenizer may decode a
    /// bounded current segment for validation; the captured emitted segment is retained.
    public static func restore(_ checkpoint: ResumableTextCheckpoint, model: any LanguageModel,
                               identity: ResumableTokenIdentity, rawOptions: ResumableTokenOptions,
                               cacheSpecs: [ResumableCacheSpec], codecs: ResumableStateCodecs = .init(),
                               tokenizer: any Tokenizer, options: ResumableTextOptions) throws -> ResumableTextOutput {
        try ResumableTokenDriver.assess(identity: identity, options: rawOptions, cacheSpecs: cacheSpecs)
        try options.validate(vocabulary: rawOptions.vocabularySize)
        let document = try checkpoint.document()
        let child = try ResumableTokenCheckpoint(data: document.raw)
        let rawDocument = try child.document()
        guard try ResumableTokenCheckpoint.encoder().encode(document.output.options)
            == ResumableTokenCheckpoint.encoder().encode(options) else { throw ResumableTokenError.incompatible }
        try document.output.validate(raw: rawDocument, rawData: document.raw, tokenizer: tokenizer)
        let driver = try ResumableTokenDriver.restore(child, model: model, identity: identity,
            options: rawOptions, cacheSpecs: cacheSpecs, codecs: codecs)
        do {
            return try ResumableTextOutput(raw: driver, checkpoint: child, tokenizer: tokenizer, state: document.output)
        } catch { driver.close(); throw error }
    }

    public func capture() throws -> ResumableTextCheckpoint {
        guard !isClosed else { throw ResumableTokenError.closed }
        let state = ResumableTextState(options: options,
            rawDigest: ResumableTokenCheckpoint.digest(rawCheckpoint.data),
            segmentTokens: detokenizer.segmentTokens, segment: Data(detokenizer.segment.utf8),
            emittedTokenCount: emittedTokenCount, buffer: Data(filter.buffer.utf8), stopped: filter.stopped,
            promptCount: promptCount, generationCount: generationCount, rawCount: rawCount,
            lastToken: lastToken, terminal: terminalReason)
        return try ResumableTextCheckpoint(document: .init(raw: rawCheckpoint.data, output: state))
    }

    /// One raw step, up to two text chunks and one terminal record. S72's lookahead is
    /// already settled before it returns a token. On output stop we discard that unused
    /// pending work; no new model call occurs after the output terminal.
    public func advance() throws -> Batch? {
        guard !isClosed else { throw ResumableTokenError.closed }
        guard terminalReason == nil else { return nil }
        do {
            guard let raw else { throw ResumableTokenError.invalid("missing raw driver") }
            guard let step = try raw.advance() else { return try finish(.length, token: nil, records: []) }
            rawCheckpoint = step.checkpoint; rawCount += 1; lastToken = step.token
            if options.intercepts(step.token) { return try finish(.stop, token: step.token, records: []) }
            generationCount += 1
            guard detokenizer.segmentTokens.count < 65_536 else { throw ResumableTokenError.oversized }
            detokenizer.append(token: step.token)
            // Preflight both decode inputs next() may use (including newline reset).
            // Determinism is the owner's contract; growth is checked before filtering.
            try ResumableTextState.checkDecode(detokenizer.tokenizer, tokens: detokenizer.segmentTokens)
            try ResumableTextState.checkDecode(detokenizer.tokenizer, tokens: [step.token])
            var records: [ResumableTextRecord] = []
            if let chunk = detokenizer.next() {
                emittedTokenCount = detokenizer.segmentTokens.count
                let result = filter.process(chunk)
                if let text = result.text { records.append(.text(Data(text.utf8))) }
            }
            if filter.stopped { return try finish(.stop, token: step.token, records: records) }
            if raw.exhausted { return try finish(.length, token: step.token, records: records) }
            return try batch(token: step.token, records: records)
        } catch { close(); throw error }
    }

    /// Cancellation is an explicit atomic terminal transition, flushing only an unmatched
    /// stop prefix. Repeated cancel or advance on a terminal checkpoint returns nil.
    public func cancel() throws -> Batch? {
        guard !isClosed else { throw ResumableTokenError.closed }
        guard terminalReason == nil else { return nil }
        do { return try finish(.cancelled, token: nil, records: []) }
        catch { close(); throw error }
    }

    private func finish(_ reason: ResumableTextEnd, token: Int?, records: [ResumableTextRecord]) throws -> Batch {
        var records = records
        if let text = filter.finish() { records.append(.text(Data(text.utf8))) }
        terminalReason = reason
        records.append(.terminal(.init(reason: reason, promptTokens: promptCount,
            generationTokens: generationCount, rawTokens: rawCount)))
        raw?.close(); raw = nil
        return try batch(token: token, records: records)
    }

    private func batch(token: Int?, records: [ResumableTextRecord]) throws -> Batch {
        let checkpoint = try capture()
        // Account for returned records as well as retained output state, even though no
        // queue exists. Actual JSON sizes include enum/base64 overhead.
        let stateBytes = try ResumableTokenCheckpoint.encoder().encode(checkpoint.document().output).count
        let recordBytes = try ResumableTokenCheckpoint.encoder().encode(records).count
        guard records.count <= 3, stateBytes + recordBytes <= ResumableTextCheckpoint.maximumOutputBytes else {
            throw ResumableTokenError.oversized
        }
        return .init(token: token, records: records, checkpoint: checkpoint)
    }

    /// Silent discard, distinct from cancel's terminal batch. Saved older checkpoints
    /// remain usable; this closed object cannot advance or capture. No model call.
    public func close() {
        guard !isClosed else { return }
        isClosed = true; raw?.close(); raw = nil
        detokenizer.segmentTokens = []; detokenizer.segment = ""; filter.buffer = ""
    }
}
