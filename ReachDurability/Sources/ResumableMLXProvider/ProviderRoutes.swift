import Foundation
import MLXLMCommon
import MLXGuidedGeneration
import RequiredToolCoordinator
import AllowedToolCoordinator
import ReachWire

enum ProviderChild {
    case ordinary(ResumableTextOutput, ProviderTextBinding)
    case guided(ResumableGuidedGeneration, ProviderGuidedBinding)
    case required(RequiredToolCoordinator)
    case allowed(AllowedToolCoordinator)
    static func prepare(_ binding: ProviderBinding, _ runtime: ProviderRuntime) throws -> ProviderChild {
        switch (binding.lane, runtime) {
        case (.ordinary(let b), .ordinary(let r)):
            return try .ordinary(.prepare(model: r.model(), tokens: b.tokens, identity: b.model.identity, rawOptions: b.options,
                cacheSpecs: b.model.cacheSpecs, codecs: r.codecs, tokenizer: r.tokenizer, options: b.text), b)
        case (.guided(let b), .guided(let r)):
            return try .guided(.prepare(model: r.model(), tokens: b.tokens, identity: b.model.identity,
                cacheSpecs: b.model.cacheSpecs, codecs: r.codecs, tokenizer: r.tokenizer, specification: b.specification, options: b.options), b)
        case (.required(let b, let tokens), .required(let r)):
            return try .required(.prepare(binding: b, model: r.model(), tokens: tokens, tokenizer: r.tokenizer, codecs: r.codecs))
        case (.allowed(let b), .allowed(let r)): return try .allowed(.prepare(binding: b, runtime: r))
        default: throw ProviderError.unsupported("runtime route")
        }
    }
    static func restore(_ checkpoint: ProviderCheckpointDocument, _ runtime: ProviderRuntime) throws -> ProviderChild {
        let bytes = checkpoint.child
        switch (checkpoint.binding.lane, runtime) {
        case (.ordinary(let b), .ordinary(let r)):
            return try .ordinary(.restore(.init(data: bytes), model: r.model(), identity: b.model.identity, rawOptions: b.options,
                cacheSpecs: b.model.cacheSpecs, codecs: r.codecs, tokenizer: r.tokenizer, options: b.text), b)
        case (.guided(let b), .guided(let r)):
            return try .guided(.restore(.init(data: bytes), model: r.model(), identity: b.model.identity,
                cacheSpecs: b.model.cacheSpecs, codecs: r.codecs, tokenizer: r.tokenizer, specification: b.specification, options: b.options), b)
        case (.required(let b, _), .required(let r)):
            return try .required(.restore(.init(data: bytes), expected: b, model: r.model(), tokenizer: r.tokenizer, codecs: r.codecs))
        case (.allowed(let b), .allowed(let r)): return try .allowed(.restore(.init(data: bytes), expected: b, runtime: r))
        default: throw ProviderError.unsupported("runtime route")
        }
    }
    var phase: String {
        switch self {
        case .ordinary(let c, _): "ordinary." + (c.terminalReason?.rawValue ?? "active")
        case .guided(let c, _): "guided." + (c.terminalReason?.rawValue ?? "active")
        case .required(let c): "required." + c.phase.rawValue
        case .allowed(let c): "allowed." + c.phase.rawValue
        }
    }
    func validateTerminal(_ terminal: WireFinishReason?) throws {
        let expected: WireFinishReason?
        switch self {
        case .ordinary(let c, _):
            expected = c.terminalReason.map { $0 == .cancelled ? .cancelled : .complete }
        case .guided(let c, _):
            expected = c.terminalReason.map { $0 == .complete ? .complete : $0 == .cancelled ? .cancelled : .error(ProviderEvents.incomplete) }
        case .required(let c):
            guard (terminal != nil) == (c.phase == .emitted) else { throw ProviderError.invalid("required terminal phase") }; return
        case .allowed(let c):
            guard (terminal != nil) == (c.phase == .finalEmitted) else { throw ProviderError.invalid("allowed terminal phase") }; return
        }
        guard try providerEncode(expected) == providerEncode(terminal) else { throw ProviderError.invalid("native terminal reason") }
    }
    func capture() throws -> Data {
        switch self {
        case .ordinary(let c, _): try c.capture().data
        case .guided(let c, _): try c.capture().data
        case .required(let c): try c.capture().data
        case .allowed(let c): try c.capture().data
        }
    }
    func step(cancel: Bool) throws -> [WireEvent] {
        switch self {
        case .ordinary(let c, let b):
            guard let result = try cancel ? c.cancel() : c.advance() else { throw ProviderError.invalid("missing ordinary transition") }
            return try ProviderEvents.ordinary(result.records, b)
        case .guided(let c, let b):
            guard let result = try cancel ? c.cancel() : c.advance() else { throw ProviderError.invalid("missing guided transition") }
            return try ProviderEvents.guided(result.records, b)
        case .required(let c):
            guard let result = try cancel ? c.cancel() : c.advance() else { throw ProviderError.invalid("missing required transition") }; return result.events
        case .allowed(let c):
            guard let result = try cancel ? c.cancel() : c.advance() else { throw ProviderError.invalid("missing allowed transition") }; return result.events
        }
    }
    func close() {
        switch self { case .ordinary(let c, _): c.close(); case .guided(let c, _): c.close(); case .required(let c): c.close(); case .allowed(let c): c.close() }
    }
}
