import Foundation
import CryptoKit

public enum ResumableToolCallError: Error { case closed, finished, oversized, incompatible, invalid(String), exhausted }

enum ToolCheckpointEncoding {
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder=JSONEncoder(); encoder.outputFormatting=[.sortedKeys,.withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    static func digest(_ data: Data) -> String { SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined() }
    static func string(_ bytes: Data, maximum: Int = 256*1024) throws -> String {
        guard bytes.count<=maximum else { throw ResumableToolCallError.oversized }
        guard let text=String(data:bytes,encoding:.utf8) else { throw ResumableToolCallError.invalid("UTF-8") }
        return text
    }
    static func id(_ id: String) throws {
        guard !id.isEmpty, id.utf8.count<=256 else { throw ResumableToolCallError.invalid("call ID") }
    }
}

// A tagged codec preserves Int vs Double (including negative zero) rather than
// round-tripping JSONValue's untagged decoder, which prefers Int for 1.0.
indirect enum ToolCheckpointJSON: Codable, Sendable {
    case null, bool(Bool), integer(Int), number(UInt64), text(Data)
    case array([ToolCheckpointJSON]), object([Entry])
    struct Entry: Codable, Sendable { let key: Data; let value: ToolCheckpointJSON }
    init(_ value: JSONValue, depth: Int = 0) throws {
        guard depth<=16 else { throw ResumableToolCallError.oversized }
        switch value {
        case .null: self = .null
        case .bool(let v): self = .bool(v)
        case .int(let v): self = .integer(v)
        case .double(let v):
            guard v.isFinite else { throw ResumableToolCallError.invalid("nonfinite JSON") }
            self = .number(v.bitPattern)
        case .string(let v):
            guard v.utf8.count<=256*1024 else { throw ResumableToolCallError.oversized }
            self = .text(Data(v.utf8))
        case .array(let v):
            guard v.count<=4096 else { throw ResumableToolCallError.oversized }
            self = .array(try v.map { try .init($0,depth:depth+1) })
        case .object(let v):
            guard v.count<=4096 else { throw ResumableToolCallError.oversized }
            self = .object(try v.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }.map {
                guard $0.utf8.count<=4096 else { throw ResumableToolCallError.oversized }
                return try Entry(key:Data($0.utf8),value:.init(v[$0]!,depth:depth+1))
            })
        }
    }
    func value(depth: Int = 0) throws -> JSONValue {
        guard depth<=16 else { throw ResumableToolCallError.oversized }
        switch self {
        case .null: return .null
        case .bool(let v): return .bool(v)
        case .integer(let v): return .int(v)
        case .number(let v):
            let number=Double(bitPattern:v)
            guard number.isFinite else { throw ResumableToolCallError.invalid("nonfinite JSON") }
            return .double(number)
        case .text(let v): return try .string(ToolCheckpointEncoding.string(v))
        case .array(let v):
            guard v.count<=4096 else { throw ResumableToolCallError.oversized }
            return try .array(v.map { try $0.value(depth:depth+1) })
        case .object(let v):
            guard v.count<=4096 else { throw ResumableToolCallError.oversized }
            var object:[String:JSONValue]=[:]; var previous:Data?
            for entry in v {
                let key=try ToolCheckpointEncoding.string(entry.key,maximum:4096)
                guard object[key]==nil, previous.map({ $0.lexicographicallyPrecedes(entry.key) }) ?? true else {
                    throw ResumableToolCallError.invalid("JSON object keys")
                }
                object[key]=try entry.value.value(depth:depth+1); previous=entry.key
            }
            return .object(object)
        }
    }
}

/// Explicit JSON configuration only: no closures or arbitrary Sendable objects.
public struct ResumableToolCallConfiguration: Codable, Sendable {
    public let format: ToolCallFormat
    let offered: ToolCheckpointJSON?
    public init(format: ToolCallFormat, tools: [[String:JSONValue]]? = nil) throws {
        self.format=format
        offered=try tools.map { try ToolCheckpointJSON(.array($0.map { .object($0) })) }
        _=try validatedTools()
    }
    func validatedTools() throws -> [[String:any Sendable]]? {
        guard try ToolCheckpointEncoding.encode(self).count<=64*1024 else { throw ResumableToolCallError.oversized }
        guard let offered else { return nil }
        guard case .array(let values)=try offered.value() else { throw ResumableToolCallError.invalid("offered tools") }
        return try values.map {
            guard case .object(let object)=$0 else { throw ResumableToolCallError.invalid("offered tool object") }
            return object.mapValues { $0.sendableValue }
        }
    }
}

struct ToolCallIDSequence: Codable, Sendable {
    static let maximumAttempts: UInt64 = 8192
    var version="sha256-counter-v1"
    var namespace: String
    var position: UInt64 = 0
    func candidate(format: ToolCallFormat, at index: UInt64) -> String {
        let hex=ToolCheckpointEncoding.digest(Data("S75-ID-v1:\(namespace):\(index)".utf8))
        return format == .mistral ? String(hex.prefix(9)).uppercased() : "call_"+String(hex.prefix(32))
    }
    func validate(format: ToolCallFormat, issued: Set<String>) throws {
        guard version=="sha256-counter-v1", namespace.utf8.count==32,
            namespace.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
            position<=Self.maximumAttempts else { throw ResumableToolCallError.invalid("ID allocation") }
        for index in 0..<position {
            guard issued.contains(candidate(format:format,at:index)) else { throw ResumableToolCallError.invalid("ID allocation/issued join") }
        }
    }
    mutating func next(format: ToolCallFormat, issued: inout Set<String>) throws -> String {
        while position<Self.maximumAttempts {
            let id=candidate(format:format,at:position); position+=1
            if issued.insert(id).inserted { return id }
        }
        throw ResumableToolCallError.exhausted
    }
}

struct ToolProcessorCheckpointState: Codable, Sendable {
    var boundary="ordered-drained-v1"
    var state: String
    var buffer: Data
    var issued: [Data]
    var allocation: ToolCallIDSequence
    func validate(format: ToolCallFormat) throws {
        guard boundary=="ordered-drained-v1", issued.count<=4096 else { throw ResumableToolCallError.invalid("ordered boundary/ID count") }
        let text=try ToolCheckpointEncoding.string(buffer)
        var ids=Set<String>(); var previous:Data?
        for bytes in issued {
            let id=try ToolCheckpointEncoding.string(bytes,maximum:256); try ToolCheckpointEncoding.id(id)
            guard ids.insert(id).inserted, previous.map({ $0.lexicographicallyPrecedes(bytes) }) ?? true else {
                throw ResumableToolCallError.invalid("issued ID set")
            }
            previous=bytes
        }
        try allocation.validate(format:format,issued:ids)
        let parser=format.createParser(), scanner=JSONLeadingObjectScanner(startCharacter:"{")
        switch state {
        case "normal":
            guard text.isEmpty else { throw ResumableToolCallError.invalid("normal buffer") }
        case "potentialToolCall":
            guard let tag=parser.startTag, !text.isEmpty, tag.hasPrefix(text), text != tag else {
                throw ResumableToolCallError.invalid("partial tag")
            }
        case "collectingToolCall":
            if let tag=parser.startTag {
                guard text.hasPrefix(tag), parser.endTag.map({ !text.contains($0) }) ?? true else {
                    throw ResumableToolCallError.invalid("tagged buffer")
                }
            } else {
                guard format == .llama3, text.hasPrefix("{"), scanner.splitLeadingObject(from:text)==nil else {
                    throw ResumableToolCallError.invalid("inline buffer")
                }
            }
        case "collectingJSONToolCall":
            guard format == .json, text.hasPrefix("{"), text.count<=32_768,
                scanner.splitLeadingObject(from:text)==nil else { throw ResumableToolCallError.invalid("bare JSON buffer") }
            if case .invalidObject=scanner.evaluatePrefix(in:text) { throw ResumableToolCallError.invalid("bare JSON prefix") }
        default: throw ResumableToolCallError.invalid("parser state")
        }
    }
}

struct ToolCallCheckpointDocument: Codable, Sendable {
    var version=1
    var compatibility="mlx-swift-lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;S75-ordered-v1"
    var configuration: ResumableToolCallConfiguration
    var parser: ToolProcessorCheckpointState
    var sequence: UInt64 = 0
    var finished=false
    func validate() throws {
        guard version==1, compatibility=="mlx-swift-lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;S75-ordered-v1" else { throw ResumableToolCallError.incompatible }
        _=try configuration.validatedTools(); try parser.validate(format:configuration.format)
        guard sequence<=1_000_000,
            !finished || (sequence>0 && parser.state=="normal" && parser.buffer.isEmpty),
            sequence>0 || (!finished && parser.state=="normal" && parser.issued.isEmpty && parser.allocation.position==0) else {
                throw ResumableToolCallError.invalid("finished/sequence")
        }
    }
}

public struct ResumableToolCallCheckpoint: Equatable, Sendable {
    public static let maximumBytes=1024*1024
    public let data: Data
    struct Envelope: Codable { var payload: Data; var sha256: String }
    init(document: ToolCallCheckpointDocument) throws {
        let payload=try ToolCheckpointEncoding.encode(document)
        guard payload.count<=Self.maximumBytes else { throw ResumableToolCallError.oversized }
        let encoded=try ToolCheckpointEncoding.encode(Envelope(payload:payload,sha256:ToolCheckpointEncoding.digest(payload)))
        guard encoded.count<=Self.maximumBytes else { throw ResumableToolCallError.oversized }
        data=encoded
    }
    public init(data: Data) throws {
        guard data.count<=Self.maximumBytes else { throw ResumableToolCallError.oversized }
        self.data=data; _=try document()
    }
    func document() throws -> ToolCallCheckpointDocument {
        guard data.count<=Self.maximumBytes else { throw ResumableToolCallError.oversized }
        let envelope=try JSONDecoder().decode(Envelope.self,from:data)
        guard ToolCheckpointEncoding.digest(envelope.payload)==envelope.sha256 else { throw ResumableToolCallError.invalid("checksum") }
        let document=try JSONDecoder().decode(ToolCallCheckpointDocument.self,from:envelope.payload)
        try document.validate(); return document
    }
}
