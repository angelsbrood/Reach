// Local candidate: versioned supported-state checkpoint values.

import CryptoKit
import Foundation
import MLX

public enum ResumableTokenError: Error, Equatable {
    case unsupported(String)
    case invalid(String)
    case incompatible
    case closed
    case oversized
}

/// A bounded, independent tensor value. The byte order is bound by the backend identity.
/// This format is for compatible local execution, not portable tensor interchange.
public struct ResumableTensor: Codable, Equatable, Sendable {
    public let shape: [Int]
    public let dtype: String
    public let bytes: Data

    public init(capturing array: MLXArray) throws {
        shape = array.shape
        dtype = String(describing: array.dtype)
        // Check dimensions and size before synchronizing/copying the supported array.
        let size = try Self.byteCount(shape: shape, dtype: dtype)
        guard size <= ResumableTokenCheckpoint.maximumBytes else {
            throw ResumableTokenError.oversized
        }
        bytes = array.asData(access: .copy).data
        try validate()
    }

    static func type(_ name: String) throws -> DType {
        switch name {
        case "float16": .float16
        case "bfloat16": .bfloat16
        case "float32": .float32
        case "int32": .int32
        case "uint32": .uint32
        case "int64": .int64
        case "uint8": .uint8
        default: throw ResumableTokenError.unsupported("tensor dtype")
        }
    }

    static func byteCount(shape: [Int], dtype: String) throws -> Int {
        guard shape.count <= 8 else { throw ResumableTokenError.invalid("tensor rank") }
        var size = try type(dtype).size
        for dim in shape {
            guard dim > 0, dim <= 1_048_576,
                size <= ResumableTokenCheckpoint.maximumBytes / dim
            else { throw ResumableTokenError.invalid("tensor dimensions/size") }
            size *= dim
        }
        return size
    }

    func validate() throws {
        guard try Self.byteCount(shape: shape, dtype: dtype) == bytes.count else {
            throw ResumableTokenError.invalid("tensor byte length")
        }
    }

    public func restored() throws -> MLXArray {
        try validate()
        return MLXArray(bytes, shape, dtype: try Self.type(dtype))
    }
}

/// Codecs must be pure, deterministic value encoders/decoders, without model or external
/// side effects. Capture MLX arrays as ResumableTensor values, never retain live references.
public struct ResumableStatePayload: Codable, Equatable, Sendable {
    public let metadata: Data
    public let tensors: [ResumableTensor]

    public init(metadata: Data = Data(), tensors: [ResumableTensor] = []) {
        self.metadata = metadata
        self.tensors = tensors
    }

    func validate() throws {
        guard metadata.count <= 65_536, tensors.count <= 128 else {
            throw ResumableTokenError.oversized
        }
        for tensor in tensors { try tensor.validate() }
    }
}

struct ResumableCodecDescriptor: Codable, Equatable {
    let id: String
    let type: String
    let schema: Int
}

struct ResumableStateEntry: Codable {
    let descriptor: ResumableCodecDescriptor
    let payload: ResumableStatePayload
}

/// Value-type registration set. Every present State key must match its exact registered
/// Swift type. The full registration schema is bound even when state is initially nil.
public struct ResumableStateCodecs {
    struct Codec {
        let descriptor: ResumableCodecDescriptor
        let encode: (Any) throws -> ResumableStatePayload
        let decode: (ResumableStatePayload) throws -> Any
    }
    private var codecs: [String: Codec] = [:]

    public init() {}

    public mutating func register<T>(
        _ key: LMOutput.Key<T>, type: String, schema: Int,
        encode: @escaping (T) throws -> ResumableStatePayload,
        decode: @escaping (ResumableStatePayload) throws -> T
    ) throws {
        guard codecs[key.id] == nil, codecs.count < 64,
            !key.id.isEmpty, key.id.utf8.count <= 256,
            !type.isEmpty, type.utf8.count <= 256, schema > 0
        else { throw ResumableTokenError.invalid("duplicate/conflicting codec registration") }
        codecs[key.id] = Codec(
            descriptor: .init(id: key.id, type: type, schema: schema),
            encode: { value in
                guard Swift.type(of: value) == T.self, let typed = value as? T else {
                    throw ResumableTokenError.unsupported("model state type")
                }
                let result = try encode(typed)
                try result.validate()
                return result
            }, decode: { try decode($0) })
    }

    var descriptors: [ResumableCodecDescriptor] {
        codecs.values.map(\.descriptor).sorted { $0.id < $1.id }
    }

    func capture(_ state: LMOutput.State?) throws -> [ResumableStateEntry]? {
        guard let state else { return nil }
        return try state.checkpointContents.keys.sorted().map { id in
            guard let codec = codecs[id], let value = state.checkpointContents[id] else {
                throw ResumableTokenError.unsupported("unregistered model state key")
            }
            return try .init(descriptor: codec.descriptor, payload: codec.encode(value))
        }
    }

    func restore(_ entries: [ResumableStateEntry]?) throws -> LMOutput.State? {
        guard let entries else { return nil }
        guard entries.count <= codecs.count else { throw ResumableTokenError.incompatible }
        var seen = Set<String>()
        // Validate every envelope before invoking any registered decoder.
        for entry in entries {
            let id = entry.descriptor.id
            guard seen.insert(id).inserted,
                codecs[id]?.descriptor == entry.descriptor
            else { throw ResumableTokenError.incompatible }
            try entry.payload.validate()
        }
        var contents: [String: Any] = [:]
        for entry in entries {
            contents[entry.descriptor.id] = try codecs[entry.descriptor.id]!.decode(entry.payload)
        }
        return LMOutput.State(checkpointContents: contents)
    }
}

/// Exact supported cache layout, supplied by the model owner before any forward call.
public struct ResumableCacheSpec: Codable, Equatable, Sendable {
    // A separate live-storage ceiling. Schema 2 restores the captured allocation
    // length so source and restored drivers cross this boundary on the same step.
    static let maximumLiveTensorBytes = 8 * 1024 * 1024
    public enum Kind: String, Codable, Sendable { case simple, rotating }
    public let kind: Kind
    public let heads: Int
    public let keyDimension: Int
    public let valueDimension: Int
    public let dtype: String
    public let maxSize: Int
    public let keep: Int
    public let allocationStep: Int

    public init(kind: Kind, heads: Int, keyDimension: Int, valueDimension: Int,
                dtype: String = "float32", maxSize: Int = 0, keep: Int = 0,
                allocationStep: Int = 256) {
        self.kind = kind; self.heads = heads; self.keyDimension = keyDimension
        self.valueDimension = valueDimension; self.dtype = dtype
        self.maxSize = maxSize; self.keep = keep; self.allocationStep = allocationStep
    }

    func validate() throws {
        guard (1...8192).contains(heads), (1...8192).contains(keyDimension),
            (1...8192).contains(valueDimension),
            ["float16", "bfloat16", "float32"].contains(dtype),
            (1...4096).contains(allocationStep)
        else { throw ResumableTokenError.unsupported("cache layout") }
        switch kind {
        case .simple:
            guard maxSize == 0, keep == 0, allocationStep == 256 else {
                throw ResumableTokenError.unsupported("simple cache configuration")
            }
        case .rotating:
            guard (1...65_536).contains(maxSize), keep >= 0, keep < maxSize else {
                throw ResumableTokenError.unsupported("rotating cache configuration")
            }
        }
    }

    func validateLive(_ cache: KVCache) throws {
        guard (kind == .simple && Swift.type(of: cache) == KVCacheSimple.self)
            || (kind == .rotating && Swift.type(of: cache) == RotatingKVCache.self),
            cache.offset >= 0, cache.offset <= 1_048_576
        else { throw ResumableTokenError.unsupported("live cache family/offset") }
        if let simple = cache as? KVCacheSimple, simple.step != allocationStep {
            throw ResumableTokenError.unsupported("simple cache allocation step")
        }
        let arrays = cache.innerState()
        guard arrays.count == (cache.offset == 0 ? 0 : 2) else {
            throw ResumableTokenError.invalid("live cache storage count")
        }
        for (i, array) in arrays.enumerated() {
            guard array.ndim == 4, array.shape[0] == 1, array.shape[1] == heads,
                array.shape[2] > 0,
                array.shape[3] == (i == 0 ? keyDimension : valueDimension),
                String(describing: array.dtype) == dtype,
                array.nbytes <= Self.maximumLiveTensorBytes,
                kind != .simple || array.shape[2] >= cache.offset
            else { throw ResumableTokenError.unsupported("live cache storage shape/dtype/size") }
        }
        guard arrays.count < 2 || arrays[0].shape[2] == arrays[1].shape[2] else {
            throw ResumableTokenError.invalid("live cache storage lengths")
        }
    }

    func makeCache() -> KVCache {
        switch kind {
        case .simple: KVCacheSimple()
        case .rotating: RotatingKVCache(maxSize: maxSize, keep: keep, step: allocationStep)
        }
    }
}

struct ResumableCacheRecord: Codable {
    let offset: Int
    // Logical state omits unused spare capacity. Keep its length, not its bytes:
    // pinned cache growth depends on this physical allocation even before wrap.
    let allocationLength: Int
    let metadata: [String]
    let tensors: [ResumableTensor]

    init(capturing cache: KVCache, spec: ResumableCacheSpec, consumed: Int, window: Int) throws {
        guard (spec.kind == .simple && Swift.type(of: cache) == KVCacheSimple.self)
            || (spec.kind == .rotating && Swift.type(of: cache) == RotatingKVCache.self)
        else { throw ResumableTokenError.unsupported("cache family/subclass") }
        if let simple = cache as? KVCacheSimple, simple.step != spec.allocationStep {
            throw ResumableTokenError.unsupported("simple cache allocation step")
        }
        try spec.validateLive(cache)
        offset = cache.offset
        allocationLength = cache.innerState().first?.dim(2) ?? 0
        metadata = cache.metaState
        // Settle all owned storage, including spare allocation, before freezing logical state.
        eval(cache.innerState())
        tensors = try cache.state.map { try ResumableTensor(capturing: $0) }
        try validate(spec: spec, consumed: consumed, window: window)
    }

    func validate(spec: ResumableCacheSpec, consumed: Int, window: Int) throws {
        try spec.validate()
        guard offset == consumed, offset >= 0, offset <= 1_048_576 else {
            throw ResumableTokenError.invalid("cache offset")
        }
        guard tensors.count == (offset == 0 ? 0 : 2) else {
            throw ResumableTokenError.invalid("cache tensor count")
        }
        for (i, t) in tensors.enumerated() {
            try t.validate()
            guard t.dtype == spec.dtype, t.shape.count == 4,
                t.shape[0] == 1, t.shape[1] == spec.heads,
                t.shape[3] == (i == 0 ? spec.keyDimension : spec.valueDimension)
            else { throw ResumableTokenError.invalid("cache shape/dtype") }
        }
        let length = tensors.first?.shape[2] ?? 0
        guard allocationLength >= length, (allocationLength == 0) == (offset == 0) else {
            throw ResumableTokenError.invalid("cache allocation length")
        }
        let dtypeSize = try ResumableTensor.type(spec.dtype).size
        for dimension in [spec.keyDimension, spec.valueDimension] {
            let rowBytes = spec.heads * dimension * dtypeSize
            guard allocationLength <= ResumableCacheSpec.maximumLiveTensorBytes / rowBytes else {
                throw ResumableTokenError.invalid("cache allocation byte bound")
            }
        }
        if spec.kind == .rotating, allocationLength > spec.maxSize + window - 1 {
            throw ResumableTokenError.invalid("rotating cache allocation length")
        }
        guard tensors.count < 2 || tensors[1].shape[2] == length else {
            throw ResumableTokenError.invalid("cache key/value lengths")
        }
        switch spec.kind {
        case .simple:
            guard metadata == [""], length == offset else {
                throw ResumableTokenError.invalid("simple cache metadata")
            }
        case .rotating:
            guard metadata.count == 5,
                metadata.prefix(4).map({ Int($0) }) == [spec.keep, spec.maxSize, spec.allocationStep, offset],
                let index = Int(metadata[4]), index >= 0, index <= length,
                length <= offset, length <= spec.maxSize + window - 1
            else { throw ResumableTokenError.invalid("rotating cache metadata") }
            if offset <= spec.maxSize {
                guard length == offset, index == offset else {
                    throw ResumableTokenError.invalid("rotating cache initial cursor")
                }
            } else {
                guard length >= spec.maxSize,
                    (length > spec.maxSize ? index == length : index > spec.keep)
                else { throw ResumableTokenError.invalid("rotating cache wrapped cursor") }
            }
        }
    }

    func restore(spec: ResumableCacheSpec) throws -> KVCache {
        // Called only after complete record validation; never apply unchecked legacy setters.
        var cache = spec.makeCache()
        if !tensors.isEmpty {
            cache.state = try tensors.map { tensor in
                let logical = try tensor.restored()
                let padding = allocationLength - tensor.shape[2]
                guard padding > 0 else { return logical }
                var spareShape = tensor.shape
                spareShape[2] = padding
                return concatenated([logical, MLXArray.zeros(spareShape, dtype: logical.dtype)], axis: 2)
            }
            // The legacy Simple setter infers offset from physical array length.
            // Restore the captured logical offset after reconstructing its capacity.
            if let simple = cache as? KVCacheSimple { simple.offset = offset }
        }
        cache.metaState = metadata
        return cache
    }
}

struct ResumableRingRecord: Codable {
    let buffer: [Int32]
    let count: Int
    let writeIndex: Int

    func validate(capacity: Int, vocabulary: Int) throws {
        guard buffer.count == capacity, count >= 0, count <= capacity,
            writeIndex >= 0, writeIndex < capacity,
            (count == capacity || writeIndex == count),
            buffer.allSatisfy({ $0 >= 0 && $0 < vocabulary })
        else { throw ResumableTokenError.invalid("processor ring") }
    }
}

struct ResumableDocument: Codable {
    var version: Int = 2
    var identity: ResumableTokenIdentity
    var options: ResumableTokenOptions
    var cacheSpecs: [ResumableCacheSpec]
    var codecs: [ResumableCodecDescriptor]
    var promptCount: Int
    var tokenCount: Int
    var pending: Int?
    var exhausted: Bool
    var randomKey: ResumableTensor?
    var randomDraws: Int
    var rings: [ResumableRingRecord?]
    var caches: [ResumableCacheRecord]
    var state: [ResumableStateEntry]?
}

/// Frozen value; the checksum detects accidental corruption, not hostile modification.
/// This is not encrypted production storage or a crash-safe host transaction.
public struct ResumableTokenCheckpoint: Sendable, Equatable {
    public static let maximumBytes = 8 * 1024 * 1024
    public let data: Data
    struct Envelope: Codable { let payload: Data; let sha256: String }

    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    init(document: ResumableDocument) throws {
        let payload = try Self.encoder().encode(document)
        guard payload.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        let data = try Self.encoder().encode(Envelope(payload: payload, sha256: Self.digest(payload)))
        guard data.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        self.data = data
    }

    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        self.data = data
        _ = try document()
    }

    func document() throws -> ResumableDocument {
        guard data.count <= Self.maximumBytes else { throw ResumableTokenError.oversized }
        do {
            let envelope = try JSONDecoder().decode(Envelope.self, from: data)
            guard Self.digest(envelope.payload) == envelope.sha256 else {
                throw ResumableTokenError.invalid("checksum")
            }
            // Reject previous formats before decoding schema-specific cache fields.
            struct Header: Decodable { let version: Int }
            let header = try JSONDecoder().decode(Header.self, from: envelope.payload)
            guard header.version == 2 else { throw ResumableTokenError.incompatible }
            return try JSONDecoder().decode(ResumableDocument.self, from: envelope.payload)
        } catch let error as ResumableTokenError { throw error }
        catch { throw ResumableTokenError.invalid("checkpoint encoding") }
    }
}
