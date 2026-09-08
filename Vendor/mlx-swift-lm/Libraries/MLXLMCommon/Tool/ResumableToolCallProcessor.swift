import Foundation

/// Response equality/serialization uses exact UTF-8 bytes. Tool arguments retain
/// the pinned parser's JSONValue types through the tagged checkpoint codec.
public enum ResumableToolCallRecord: Codable, Sendable {
    case response(Data)
    case toolCall(ToolCall)
    private enum Payload: Codable {
        case response(Data)
        case call(id: Data, name: Data, arguments: ToolCheckpointJSON)
    }
    public func encode(to encoder: Encoder) throws {
        switch self {
        case .response(let bytes):
            _=try ToolCheckpointEncoding.string(bytes,maximum:512*1024)
            try Payload.response(bytes).encode(to:encoder)
        case .toolCall(let call):
            guard let id=call.id else { throw ResumableToolCallError.invalid("missing normalized ID") }
            try ToolCheckpointEncoding.id(id)
            guard call.function.name.utf8.count<=4096 else { throw ResumableToolCallError.oversized }
            try Payload.call(id:Data(id.utf8),name:Data(call.function.name.utf8),arguments:ToolCheckpointJSON(.object(call.function.arguments))).encode(to:encoder)
        }
    }
    public init(from decoder: Decoder) throws {
        switch try Payload(from:decoder) {
        case .response(let bytes):
            _=try ToolCheckpointEncoding.string(bytes,maximum:512*1024); self = .response(bytes)
        case .call(let bytes,let name,let arguments):
            let id=try ToolCheckpointEncoding.string(bytes,maximum:256); try ToolCheckpointEncoding.id(id)
            guard case .object(let arguments)=try arguments.value() else { throw ResumableToolCallError.invalid("arguments object") }
            self = try .toolCall(.init(function:.init(name:ToolCheckpointEncoding.string(name,maximum:4096),arguments:arguments),id:id))
        }
    }
}

/// Exclusively owns the actual ordered parser at drained chunk/EOS boundaries.
/// A failed consume/finish closes this facade and returns no usable partial batch.
/// Earlier independent frozen checkpoints remain valid. No tool is executed.
public final class ResumableToolCallProcessor {
    public struct Batch {
        public let records: [ResumableToolCallRecord]
        public let checkpoint: ResumableToolCallCheckpoint
    }
    public let configuration: ResumableToolCallConfiguration
    public let namespace: String
    public private(set) var isClosed=false
    public private(set) var isFinished: Bool
    private var sequence: UInt64
    private var processor: ToolCallProcessor?
    private init(configuration: ResumableToolCallConfiguration, namespace: String, processor: ToolCallProcessor, sequence: UInt64, finished: Bool) {
        self.configuration=configuration; self.namespace=namespace; self.processor=processor
        self.sequence=sequence; self.isFinished=finished
    }
    public static func prepare(configuration: ResumableToolCallConfiguration,
                               namespace: String = UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased()) throws -> ResumableToolCallProcessor {
        let allocation=ToolCallIDSequence(namespace:namespace)
        try allocation.validate(format:configuration.format,issued:[])
        let parser=ToolCallProcessor(format:configuration.format,tools:try configuration.validatedTools())
        try parser.enableResumable(allocation)
        let result=ResumableToolCallProcessor(configuration:configuration,namespace:namespace,processor:parser,sequence:0,finished:false)
        _=try result.capture(); return result
    }
    public static func restore(_ checkpoint: ResumableToolCallCheckpoint, configuration: ResumableToolCallConfiguration,
                               namespace: String) throws -> ResumableToolCallProcessor {
        _=try configuration.validatedTools()
        let document=try checkpoint.document()
        guard try ToolCheckpointEncoding.encode(configuration)==ToolCheckpointEncoding.encode(document.configuration),
            namespace==document.parser.allocation.namespace else { throw ResumableToolCallError.incompatible }
        let parser=ToolCallProcessor(format:configuration.format,tools:try configuration.validatedTools())
        try parser.restoreResumable(document.parser)
        return .init(configuration:configuration,namespace:namespace,processor:parser,sequence:document.sequence,finished:document.finished)
    }
    public func capture() throws -> ResumableToolCallCheckpoint {
        guard !isClosed, let processor else { throw ResumableToolCallError.closed }
        let document=ToolCallCheckpointDocument(configuration:configuration,parser:try processor.captureResumable(),sequence:sequence,finished:isFinished)
        try document.validate()
        return try .init(document:document)
    }
    public func consume(_ chunk: String) throws -> Batch {
        guard !isClosed else { throw ResumableToolCallError.closed }
        guard !isFinished else { throw ResumableToolCallError.finished }
        do {
            guard chunk.utf8.count<=64*1024 else { throw ResumableToolCallError.oversized }
            guard sequence<1_000_000, let processor else { throw ResumableToolCallError.exhausted }
            let output=processor.processChunkOutputs(chunk); sequence+=1
            return try batch(output)
        } catch { close(); throw error }
    }
    public func finish() throws -> Batch? {
        guard !isClosed else { throw ResumableToolCallError.closed }
        guard !isFinished else { return nil }
        do {
            guard sequence<1_000_000, let processor else { throw ResumableToolCallError.exhausted }
            let output=processor.processEOSOutputs(); sequence+=1; isFinished=true
            return try batch(output)
        } catch { close(); throw error }
    }
    private func batch(_ output: [ToolCallProcessor.Output]) throws -> Batch {
        guard output.count<=4096 else { throw ResumableToolCallError.oversized }
        let records:[ResumableToolCallRecord]=output.map {
            switch $0 { case .response(let text): return .response(Data(text.utf8)); case .toolCall(let call): return .toolCall(call) }
        }
        let checkpoint=try capture()
        try Self.validateBatch(records,checkpoint:checkpoint)
        return .init(records:records,checkpoint:checkpoint)
    }
    static func validateBatch(_ records:[ResumableToolCallRecord], checkpoint:ResumableToolCallCheckpoint) throws {
        guard records.count<=4096 else { throw ResumableToolCallError.oversized }
        struct EncodedBatch: Encodable { let records:[ResumableToolCallRecord]; let checkpoint:Data }
        guard try ToolCheckpointEncoding.encode(EncodedBatch(records:records,checkpoint:checkpoint.data)).count<=2*1024*1024 else { throw ResumableToolCallError.oversized }
    }
    public func close() { isClosed=true; processor=nil }
}
