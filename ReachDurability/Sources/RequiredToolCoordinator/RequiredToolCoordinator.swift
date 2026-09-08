import Foundation
import MLXGuidedGeneration
import MLXLMCommon
import ReachWire

/// Synchronous exclusive owner. Empty batches expose settled private progress;
/// a ready checkpoint precedes the one final three-event delivery batch.
public final class RequiredToolCoordinator {
    public struct Batch {
        public let events: [WireEvent]
        public let checkpoint: RequiredToolCheckpoint
    }
    private var child: ResumableGuidedGeneration?
    private let tokenizer: any Tokenizer
    private var document: RequiredToolDocument
    public private(set) var isClosed = false
    public var phase: RequiredToolPhase { document.control.phase }

    private init(child: ResumableGuidedGeneration, tokenizer: any Tokenizer, document: RequiredToolDocument) {
        self.child = child; self.tokenizer = tokenizer; self.document = document
    }
    public static func prepare(binding: RequiredToolBinding, model: any LanguageModel, tokens: [Int],
                               tokenizer: any Tokenizer, codecs: ResumableStateCodecs = .init()) throws -> RequiredToolCoordinator {
        try binding.validate()
        guard try ResumableTokenIdentity.inputDigest(tokens) == binding.identity.input else { throw RequiredToolError.incompatible }
        let child = try ResumableGuidedGeneration.prepare(model: model, tokens: tokens, identity: binding.identity,
            cacheSpecs: binding.cacheSpecs, codecs: codecs, tokenizer: tokenizer, specification: binding.specification, options: binding.options)
        do {
            let saved = try child.capture()
            let view = try ResumableGuidedCheckpointView(checkpoint: saved, validatedOperation: child, tokenizer: tokenizer)
            let control = RequiredToolControl(binding: binding, childDigest: ResumableGuidedValues.digest(saved.data),
                whole: Data(), phase: .generating, outcome: nil, call: nil, counts: .init(view))
            let live = RequiredToolCoordinator(child: child, tokenizer: tokenizer, document: .init(child: saved.data, control: control))
            try live.validate(view); _ = try live.capture(); return live
        } catch { child.close(); throw error }
    }
    public static func restore(_ saved: RequiredToolCheckpoint, expected: RequiredToolBinding,
                               model: any LanguageModel, tokenizer: any Tokenizer,
                               codecs: ResumableStateCodecs = .init()) throws -> RequiredToolCoordinator {
        try expected.validate()
        let d = try saved.document()
        guard try requiredEncoder().encode(d.control.binding) == requiredEncoder().encode(expected) else { throw RequiredToolError.incompatible }
        let checkpoint = try ResumableGuidedCheckpoint(data: d.child)
        // Full native validation is mandatory even for ready and emitted state.
        let child = try ResumableGuidedGeneration.restore(checkpoint, model: model, identity: expected.identity,
            cacheSpecs: expected.cacheSpecs, codecs: codecs, tokenizer: tokenizer, specification: expected.specification, options: expected.options)
        do {
            let view = try ResumableGuidedCheckpointView(checkpoint: checkpoint, validatedOperation: child, tokenizer: tokenizer)
            let live = RequiredToolCoordinator(child: child, tokenizer: tokenizer, document: d)
            try live.validate(view); return live
        } catch { child.close(); throw error }
    }
    public func capture() throws -> RequiredToolCheckpoint {
        guard !isClosed else { throw RequiredToolError.closed }
        return try .init(document: document)
    }
    public func advance() throws -> Batch? {
        guard !isClosed else { throw RequiredToolError.closed }
        if phase == .emitted { return nil }
        do {
            if phase == .ready { return try deliver() }
            guard let child, let batch = try child.advance() else { throw RequiredToolError.invalid("missing active child") }
            return try settle(batch)
        } catch { close(); throw error }
    }
    public func cancel() throws -> Batch? {
        guard !isClosed else { throw RequiredToolError.closed }
        if phase == .emitted { return nil }
        do {
            if phase == .ready { return try deliver() }
            guard let child, let batch = try child.cancel() else { throw RequiredToolError.invalid("missing cancellable child") }
            return try settle(batch)
        } catch { close(); throw error }
    }
    private func settle(_ batch: ResumableGuidedGeneration.Batch) throws -> Batch {
        guard let child else { throw RequiredToolError.closed }
        for record in batch.records {
            if case .text(let bytes) = record {
                guard bytes.count <= RequiredToolContract.maximumEnvelopeBytes - document.control.whole.count else { throw RequiredToolError.oversized }
                document.control.whole.append(bytes)
            }
        }
        document.child = batch.checkpoint.data
        document.control.childDigest = ResumableGuidedValues.digest(document.child)
        let view = try ResumableGuidedCheckpointView(checkpoint: batch.checkpoint, validatedOperation: child, tokenizer: tokenizer)
        document.control.counts = .init(view)
        document.control.outcome = view.terminalReason
        switch view.terminalReason {
        case nil: break
        case .complete:
            document.control.call = try RequiredToolContract.parseEnvelope(document.control.whole, tools: document.control.binding.tools)
            document.control.phase = .ready
        case .incomplete, .cancelled: document.control.phase = .emitted
        }
        try validate(view)
        let records: [WireEvent]
        switch view.terminalReason {
        case .incomplete: records = [.finished(.error(Self.incompleteMessage))]
        case .cancelled: records = [.finished(.cancelled)]
        default: records = []
        }
        return try self.batch(records)
    }
    public static let incompleteMessage = "Required tool arguments did not reach accepted EOS within the generation budget."
    private func deliver() throws -> Batch {
        guard let call = document.control.call, document.control.outcome == .complete else { throw RequiredToolError.invalid("ready outcome") }
        let c = document.control, b = c.binding
        let events: [WireEvent] = [
            .toolCallAppendArguments(entryID: b.entryID, id: b.callID, name: call.name, content: call.argumentsJSON, tokenCount: 1),
            .usage(inputTokens: c.counts.prompt, outputTokens: c.counts.sampled + c.counts.forced),
            .finished(.complete)]
        document.control.phase = .emitted
        return try batch(events)
    }
    private func batch(_ records: [WireEvent]) throws -> Batch {
        .init(events: records, checkpoint: try .init(document: document, records: records))
    }
    private func validate(_ view: ResumableGuidedCheckpointView) throws {
        let c = document.control
        guard c.whole == view.cumulativeEmittedBytes, c.counts == RequiredToolCounts(view), c.outcome == view.terminalReason else {
            throw RequiredToolError.invalid("outer buffer/counters/terminal join")
        }
        switch c.phase {
        case .generating:
            guard c.outcome == nil, c.call == nil else { throw RequiredToolError.invalid("active outer join") }
        case .ready, .emitted:
            guard let end = c.outcome, c.phase != .ready || end == .complete else { throw RequiredToolError.invalid("settled outer join") }
            if end == .complete {
                guard view.interceptedEndings == 1, c.call == (try RequiredToolContract.parseEnvelope(view.cumulativeEmittedBytes, tools: c.binding.tools)) else {
                    throw RequiredToolError.invalid("completed selected call join")
                }
            } else if c.call != nil { throw RequiredToolError.invalid("call without completion") }
        }
        try RequiredToolCheckpoint.checkBounds(document)
    }
    public func close() { isClosed = true; child?.close(); child = nil }
}
