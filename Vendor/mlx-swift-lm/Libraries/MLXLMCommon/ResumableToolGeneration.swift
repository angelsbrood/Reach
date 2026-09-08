import Foundation

/// The nested S75 codec preserves typed arguments, negative-zero bits and UTF-8 bytes.
public enum ResumableToolGenerationRecord: Codable, Sendable {
    case parsed(ResumableToolCallRecord)
    case terminal(ResumableTextCompletion)
}

/// One serially confined, unconstrained generation/proposal pass. Both children are
/// exclusively owned and settled at public boundaries; no work runs between calls.
public final class ResumableToolGeneration {
    public struct Batch: Encodable {
        public let token: Int?
        public let records: [ResumableToolGenerationRecord]
        public let checkpoint: ResumableToolGenerationCheckpoint
        private enum CodingKeys: CodingKey { case token, records, checkpoint }
        public func encode(to encoder: Encoder) throws {
            var values = encoder.container(keyedBy: CodingKeys.self)
            try values.encodeIfPresent(token, forKey: .token)
            try values.encode(records, forKey: .records)
            try values.encode(checkpoint.data, forKey: .checkpoint)
        }
    }
    public static let maximumBatchBytes = 48 * 1024 * 1024
    public static let maximumRecordBytes = 2 * 1024 * 1024
    public private(set) var isClosed = false
    public private(set) var terminalReason: ResumableTextEnd?
    private var text: ResumableTextOutput?
    private var parser: ResumableToolCallProcessor?
    private var saved: ResumableToolGenerationCheckpoint
    private var forwarded: UInt64

    private init(text: ResumableTextOutput, parser: ResumableToolCallProcessor,
                 saved: ResumableToolGenerationCheckpoint, forwarded: UInt64) {
        self.text = text; self.parser = parser; self.saved = saved; self.forwarded = forwarded
        terminalReason = text.terminalReason
        if terminalReason != nil { releaseChildren() }
    }
    public static func prepare(model: any LanguageModel, tokens: [Int], identity: ResumableTokenIdentity,
                               rawOptions: ResumableTokenOptions, cacheSpecs: [ResumableCacheSpec],
                               codecs: ResumableStateCodecs = .init(), tokenizer: any Tokenizer,
                               options: ResumableTextOptions, configuration: ResumableToolCallConfiguration,
                               namespace: String) throws -> ResumableToolGeneration {
        // Reject parser/configuration errors before the raw driver's settled lookahead.
        let parser = try ResumableToolCallProcessor.prepare(configuration: configuration, namespace: namespace)
        var text: ResumableTextOutput?
        do {
            let child = try ResumableTextOutput.prepare(model: model, tokens: tokens, identity: identity,
                rawOptions: rawOptions, cacheSpecs: cacheSpecs, codecs: codecs, tokenizer: tokenizer, options: options)
            text = child
            let document = ToolGenerationDocument(text: try child.capture().data, parser: try parser.capture().data,
                forwardedChunks: 0, disposition: .active)
            try document.validate()
            return try .init(text: child, parser: parser, saved: .init(document: document), forwarded: 0)
        } catch { text?.close(); parser.close(); throw error }
    }
    /// Full S73/S75 restore, even for terminal frozen values. No model/prefill/sample,
    /// output emission or parser EOS. Terminal children are validated and then closed.
    public static func restore(_ checkpoint: ResumableToolGenerationCheckpoint, model: any LanguageModel,
                               identity: ResumableTokenIdentity, rawOptions: ResumableTokenOptions,
                               cacheSpecs: [ResumableCacheSpec], codecs: ResumableStateCodecs = .init(),
                               tokenizer: any Tokenizer, options: ResumableTextOptions,
                               configuration: ResumableToolCallConfiguration, namespace: String) throws -> ResumableToolGeneration {
        let d = try checkpoint.document()
        let parser = try ResumableToolCallProcessor.restore(.init(data: d.parser), configuration: configuration, namespace: namespace)
        do {
            let text = try ResumableTextOutput.restore(.init(data: d.text), model: model, identity: identity,
                rawOptions: rawOptions, cacheSpecs: cacheSpecs, codecs: codecs, tokenizer: tokenizer, options: options)
            return .init(text: text, parser: parser, saved: checkpoint, forwarded: d.forwardedChunks)
        } catch { parser.close(); throw error }
    }
    public func capture() throws -> ResumableToolGenerationCheckpoint {
        guard !isClosed else { throw ResumableTokenError.closed }
        return saved
    }
    public func advance() throws -> Batch? {
        guard !isClosed else { throw ResumableTokenError.closed }
        guard terminalReason == nil else { return nil }
        do {
            guard let text, let parser, let child = try text.advance() else {
                throw ResumableTokenError.invalid("missing active child")
            }
            var records: [ResumableToolGenerationRecord] = []
            var terminal: ResumableTextCompletion?
            for record in child.records {
                switch record {
                case .text(let bytes):
                    guard terminal == nil else { throw ResumableTokenError.invalid("text after terminal") }
                    guard !bytes.isEmpty else { continue }
                    guard bytes.count <= 64 * 1024, forwarded < 999_999 else { throw ResumableTokenError.oversized }
                    guard let chunk = String(data: bytes, encoding: .utf8), Data(chunk.utf8) == bytes else {
                        throw ResumableTokenError.invalid("forwarded UTF-8")
                    }
                    records += try parser.consume(chunk).records.map { .parsed($0) }
                    forwarded += 1
                case .terminal(let completion):
                    guard terminal == nil, completion.reason != .cancelled else {
                        throw ResumableTokenError.invalid("normal terminal")
                    }
                    terminal = completion
                }
            }
            if let terminal {
                guard let final = try parser.finish() else { throw ResumableTokenError.invalid("duplicate parser EOS") }
                records += final.records.map { .parsed($0) }
                records.append(.terminal(terminal))
            }
            return try settle(token: child.token, records: records, text: child.checkpoint,
                parser: parser.capture(), disposition: terminal == nil ? .active : .normalFinished,
                terminal: terminal?.reason)
        } catch { close(); throw error }
    }
    /// Discard S73's cancellation flush; freeze and close S75 without consume/EOS.
    /// An unfinished buffered parser is legitimate only under cancelledFrozen.
    public func cancel() throws -> Batch? {
        guard !isClosed else { throw ResumableTokenError.closed }
        guard terminalReason == nil else { return nil }
        do {
            let frozen = try saved.document().parser
            guard let text, let child = try text.cancel(), child.token == nil else {
                throw ResumableTokenError.invalid("missing cancellation child")
            }
            let endings = child.records.compactMap { record -> ResumableTextCompletion? in
                if case .terminal(let completion) = record { return completion }; return nil
            }
            guard endings.count == 1, endings[0].reason == .cancelled else {
                throw ResumableTokenError.invalid("cancellation terminal")
            }
            return try settle(token: nil, records: [.terminal(endings[0])], text: child.checkpoint,
                parser: .init(data: frozen), disposition: .cancelledFrozen, terminal: .cancelled)
        } catch { close(); throw error }
    }
    private func settle(token: Int?, records: [ResumableToolGenerationRecord], text: ResumableTextCheckpoint,
                        parser: ResumableToolCallCheckpoint, disposition: ToolGenerationDisposition,
                        terminal: ResumableTextEnd?) throws -> Batch {
        let document = ToolGenerationDocument(text: text.data, parser: parser.data,
            forwardedChunks: forwarded, disposition: disposition)
        try document.validate()
        let next = try ResumableToolGenerationCheckpoint(document: document)
        let batch = Batch(token: token, records: records, checkpoint: next)
        try Self.validateBatch(batch)
        saved = next; terminalReason = terminal
        if terminal != nil { releaseChildren() }
        return batch
    }
    static func validateBatch(_ batch: Batch) throws {
        let terminals = batch.records.filter { if case .terminal = $0 { return true }; return false }.count
        guard batch.records.count <= 4097, batch.records.count - terminals <= 4096, terminals <= 1,
            try ToolCheckpointEncoding.encode(batch.records).count <= maximumRecordBytes,
            try ToolCheckpointEncoding.encode(batch).count <= maximumBatchBytes else {
            throw ResumableTokenError.oversized
        }
    }
    private func releaseChildren() { text?.close(); parser?.close(); text = nil; parser = nil }
    public func close() { isClosed = true; releaseChildren() }
}
