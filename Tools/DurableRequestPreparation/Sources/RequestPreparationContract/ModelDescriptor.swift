import Foundation
import ReachWire
import RecoveryContract

public enum PreparationError: Error { case unsupported, oversized, identity, template, tokens }

/// Immutable owner attestation of selected local artifacts. This portable value
/// deliberately has no native runtime, tokenizer closure, or MLX dependency.
public struct ModelDescriptor: Codable, Equatable, Sendable {
    public static let legacyRevision="s89-public-chat-tools-v1"
    public static let allowedRevision="s91-public-chat-allowed-v1"
    public static let schemaRevision="s90-public-chat-schema-v1"
    public let model: String, configuration: String, weights: String, backend: String, dependency: String
    public let tokenizerAlgorithm: String, template: String, vocabulary: [String]
    public let codec: String, nativePolicy: String
    public let revision: String
    public init(model: String, configuration: String, weights: String, backend: String, dependency: String,
                tokenizerAlgorithm: String, template: String, vocabulary: [String], codec: String, nativePolicy: String,
                revision: String = ModelDescriptor.legacyRevision) throws {
        self.model=model; self.configuration=configuration; self.weights=weights; self.backend=backend; self.dependency=dependency
        self.tokenizerAlgorithm=tokenizerAlgorithm; self.template=template; self.vocabulary=vocabulary
        self.codec=codec; self.nativePolicy=nativePolicy; self.revision=revision
        try validate()
    }
    public func validate() throws {
        guard [Self.legacyRevision,Self.schemaRevision,Self.allowedRevision].contains(revision), !template.isEmpty, template.utf8.count<=8192,
              [model,configuration,weights,backend,dependency,tokenizerAlgorithm,codec,nativePolicy].allSatisfy({ !$0.isEmpty && $0.utf8.count<=1024 }),
              (1...4096).contains(vocabulary.count), vocabulary.allSatisfy({ !$0.isEmpty && $0.utf8.count<=256 && !$0.utf8.contains(0) }),
              vocabulary.reduce(0,{$0+$1.utf8.count})<=256*1024 else { throw PreparationError.identity }
    }
    public var identity: String { get throws { try validate(); return try PreparationEncoding.digest(self) } }
    public var tokenizerIdentity: String { get throws {
        struct Value: Encodable { let algorithm:String, template:String, vocabulary:[String] }
        return try PreparationEncoding.digest(Value(algorithm:tokenizerAlgorithm,template:template,vocabulary:vocabulary))
    } }
}
public enum PreparationEncoding {
    public static func encode<T:Encodable>(_ value:T) throws -> Data {
        let encoder=JSONEncoder(); encoder.outputFormatting=[.sortedKeys,.withoutEscapingSlashes]; return try encoder.encode(value)
    }
    /// Enter the schema's throwing Encodable boundary, then borrow its concrete
    /// portable tree without first allocating a serialized copy. The pinned
    /// WireGenerationSchema encoder emits one single-value JSON object.
    public static func schemaValue(_ schema:WireGenerationSchema) throws -> WireJSONValue {
        let capture=SchemaValueCapture()
        try schema.encode(to:capture)
        guard !capture.refused,let value=capture.value else { throw PreparationError.unsupported }
        return value
    }
    public static func digest<T:Encodable>(_ value:T) throws -> String { try RecoveryCodec.hash(encode(value)) }
    public static func hash(_ data:Data) -> String { RecoveryCodec.hash(data) }
    public static func isDigest(_ value:String) -> Bool { value.utf8.count==64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
}

/// Only the concrete portable schema's single-value object is admitted. Other
/// encoder shapes refuse rather than serialize an unbounded intermediate value.
private final class SchemaValueCapture: Encoder, SingleValueEncodingContainer, UnkeyedEncodingContainer {
    let codingPath:[CodingKey]=[]
    let userInfo:[CodingUserInfoKey:Any]=[:]
    let count=0
    var value:WireJSONValue?
    var refused=false
    func singleValueContainer() -> any SingleValueEncodingContainer { self }
    func container<Key:CodingKey>(keyedBy type:Key.Type) -> KeyedEncodingContainer<Key> {
        refused=true;return .init(RefusingSchemaKeys<Key>())
    }
    func unkeyedContainer() -> any UnkeyedEncodingContainer { refused=true;return self }
    func nestedContainer<Key:CodingKey>(keyedBy type:Key.Type) -> KeyedEncodingContainer<Key> { container(keyedBy:type) }
    func nestedUnkeyedContainer() -> any UnkeyedEncodingContainer { unkeyedContainer() }
    func superEncoder() -> any Encoder { refused=true;return self }
    func encode<T:Encodable>(_ value:T) throws {
        guard !refused,self.value==nil,let object=value as? [String:WireJSONValue] else { throw PreparationError.unsupported }
        self.value = .object(object)
    }
    func encodeNil() throws { throw PreparationError.unsupported }
    func encode(_ value:Bool) throws { throw PreparationError.unsupported }
    func encode(_ value:String) throws { throw PreparationError.unsupported }
    func encode(_ value:Double) throws { throw PreparationError.unsupported }
    func encode(_ value:Float) throws { throw PreparationError.unsupported }
    func encode(_ value:Int) throws { throw PreparationError.unsupported }
    func encode(_ value:Int8) throws { throw PreparationError.unsupported }
    func encode(_ value:Int16) throws { throw PreparationError.unsupported }
    func encode(_ value:Int32) throws { throw PreparationError.unsupported }
    func encode(_ value:Int64) throws { throw PreparationError.unsupported }
    func encode(_ value:UInt) throws { throw PreparationError.unsupported }
    func encode(_ value:UInt8) throws { throw PreparationError.unsupported }
    func encode(_ value:UInt16) throws { throw PreparationError.unsupported }
    func encode(_ value:UInt32) throws { throw PreparationError.unsupported }
    func encode(_ value:UInt64) throws { throw PreparationError.unsupported }
}
private struct RefusingSchemaKeys<Key:CodingKey>: KeyedEncodingContainerProtocol {
    let codingPath:[CodingKey]=[]
    func encodeNil(forKey key:Key) throws { throw PreparationError.unsupported }
    func encode<T:Encodable>(_ value:T,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:Bool,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:String,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:Double,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:Float,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:Int,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:Int8,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:Int16,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:Int32,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:Int64,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:UInt,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:UInt8,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:UInt16,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:UInt32,forKey key:Key) throws { throw PreparationError.unsupported }
    func encode(_ value:UInt64,forKey key:Key) throws { throw PreparationError.unsupported }
    func nestedContainer<NestedKey:CodingKey>(keyedBy type:NestedKey.Type,forKey key:Key) -> KeyedEncodingContainer<NestedKey> { .init(RefusingSchemaKeys<NestedKey>()) }
    func nestedUnkeyedContainer(forKey key:Key) -> any UnkeyedEncodingContainer { SchemaValueCapture().unkeyedContainer() }
    func superEncoder() -> any Encoder { SchemaValueCapture().superEncoder() }
    func superEncoder(forKey key:Key) -> any Encoder { superEncoder() }
}
