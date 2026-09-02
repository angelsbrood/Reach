import Foundation

/// JSON's value space, without FoundationModels or an `Any` crossing the
/// Sendable boundary. Transcript metadata, structured content, tool arguments,
/// and schema literals all use this one representation.
public enum WireJSONValue: Codable, Sendable, Equatable {
    case null
    case bool(Bool)
    case integer(Int64)
    case unsigned(UInt64)
    case number(Double)
    case string(String)
    case array([WireJSONValue])
    case object([String: WireJSONValue])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Int64.self) { self = .integer(value) }
        else if let value = try? container.decode(UInt64.self) { self = .unsigned(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([WireJSONValue].self) { self = .array(value) }
        else if let value = try? container.decode([String: WireJSONValue].self) { self = .object(value) }
        else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "value is outside JSON's finite value space"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .unsigned(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }
}

/// The exact JSON-Schema value carried by Foundation Models, represented
/// without importing that framework. Unknown schema keywords are ignored on
/// decode just as `GenerationSchema` ignored them in the frozen macOS codec;
/// arbitrary property/definition names and JSON literals remain intact.
public struct WireGenerationSchema: Codable, Sendable, Equatable {
    private var root: WireJSONValue?
    private var deferredEncodingError: String?
    private var canonicalResponseFormatName: String?
    private var canonicalResponseFormatDescription: String?
    // A native value can be valid even when a future native encoding cannot
    // yet be represented by this portable model. Keep its own encoded bytes
    // only as a local fallback for the source-compatible Apple getter; they
    // are never emitted onto the wire while the portable conversion failed.
    var deferredNativeJSON: Data?

    public init(jsonValue: WireJSONValue) throws {
        root = try Self.normalized(jsonValue, codingPath: [])
        deferredEncodingError = nil
        canonicalResponseFormatName = Self.schemaName(for: jsonValue)
        canonicalResponseFormatDescription = root.flatMap { Self.schemaDescription(for: $0) }
        deferredNativeJSON = nil
#if canImport(FoundationModels)
        do {
            try validateNativeFoundationModelsValue()
        } catch {
            throw DecodingError.dataCorrupted(.init(
                codingPath: [],
                debugDescription: "Foundation Models rejected the generation schema",
                underlyingError: error
            ))
        }
#endif
    }

    init(deferredEncodingError: String, nativeJSON: Data? = nil) {
        root = nil
        self.deferredEncodingError = deferredEncodingError
        canonicalResponseFormatName = nil
        canonicalResponseFormatDescription = nil
        deferredNativeJSON = nativeJSON
    }

    public var jsonValue: WireJSONValue {
        precondition(root != nil, deferredEncodingError ?? "schema is not encodable")
        return root!
    }

    public init(from decoder: Decoder) throws {
        let rawValue = try WireJSONValue(from: decoder)
        root = try Self.normalized(rawValue, codingPath: decoder.codingPath)
        deferredEncodingError = nil
        canonicalResponseFormatName = Self.schemaName(for: rawValue)
        canonicalResponseFormatDescription = root.flatMap { Self.schemaDescription(for: $0) }
        deferredNativeJSON = nil
#if canImport(FoundationModels)
        do {
            try validateNativeFoundationModelsValue()
        } catch {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Foundation Models rejected the generation schema",
                underlyingError: error
            ))
        }
#endif
    }

    public func encode(to encoder: Encoder) throws {
        guard let root else {
            throw WirePortableValueError(deferredEncodingError ?? "schema is not encodable")
        }
        try root.encode(to: encoder)
    }

    var responseFormatIdentity: (name: String, description: String?)? {
        guard let name = canonicalResponseFormatName else { return nil }
        return (name, canonicalResponseFormatDescription)
    }

    private static func schemaDescription(for value: WireJSONValue) -> String? {
        guard case .object(let object) = value,
              case .string(let description)? = object["description"]
        else { return nil }
        return description
    }

    private static func schemaName(for value: WireJSONValue) -> String? {
        guard case .object(let object) = value else { return nil }
        if case .string(let constant)? = object["const"] {
            return constant
        }
        if case .string(let reference)? = object["$ref"] {
            return definitionName(in: reference)
        }
        if object["anyOf"] != nil, case .string(let title)? = object["title"] {
            return title
        }
        guard case .string(let type)? = object["type"] else { return nil }
        switch type {
        case "array":
            guard let items = object["items"], let itemName = schemaName(for: items) else { return nil }
            return "Array<\(itemName)>"
        case "boolean": return "Bool"
        case "integer": return "Int"
        case "null": return "Null"
        case "number": return "Double"
        case "object":
            guard case .string(let title)? = object["title"] else { return nil }
            return title
        case "string":
            if case .string(let title)? = object["title"] { return title }
            return "String"
        default:
            return nil
        }
    }

    private static let schemaTypes: Set<String> = [
        "array", "boolean", "integer", "null", "number", "object", "string",
    ]

    private static func normalized(_ value: WireJSONValue, codingPath: [any CodingKey]) throws -> WireJSONValue {
        guard case .object(let object) = value else {
            throw corrupted("generation schema must be a JSON object", codingPath: codingPath)
        }

        let rawDefinitions: [String: WireJSONValue]
        if case .object(let definitions)? = object["$defs"] {
            rawDefinitions = definitions
        } else {
            rawDefinitions = [:]
        }

        let preparedRoot = prepareSchema(.object(object), placement: .root)
        let root = try canonicalSchema(preparedRoot.value, codingPath: codingPath, allowsReference: false)
        var definitionIndex: [String: [WireJSONValue]] = [:]
        for definition in rawDefinitions.values {
            indexDefinition(definition, in: &definitionIndex)
        }
        for definition in preparedRoot.inlineDefinitions {
            indexDefinition(definition, in: &definitionIndex)
        }
        var definitions: [String: CanonicalSchema] = [:]
        var reachable: Set<String> = []
        var pending = Array(root.references)
        while let name = pending.popLast() {
            guard reachable.insert(name).inserted else { continue }
            guard let candidates = definitionIndex[name], !candidates.isEmpty else {
                throw corrupted("generation schema contains an undefined $ref", codingPath: codingPath)
            }
            guard candidates.count == 1 else {
                throw corrupted("generation schema contains a duplicate type", codingPath: codingPath)
            }
            let preparedDefinition = prepareSchema(candidates[0], placement: .definition)
            for inlineDefinition in preparedDefinition.inlineDefinitions {
                if let insertedName = indexDefinition(inlineDefinition, in: &definitionIndex),
                   reachable.contains(insertedName),
                   definitionIndex[insertedName, default: []].count > 1
                {
                    throw corrupted("generation schema contains a duplicate type", codingPath: codingPath)
                }
            }
            let definition = try canonicalSchema(
                preparedDefinition.value,
                codingPath: codingPath,
                allowsReference: false
            )
            guard definition.title == name else {
                throw corrupted("generation schema contains an undefined $ref", codingPath: codingPath)
            }
            definitions[name] = definition
            pending.append(contentsOf: definition.references)
        }

        guard case .object(var result) = root.value else {
            throw corrupted("generation schema must be a JSON object", codingPath: codingPath)
        }
        if !reachable.isEmpty {
            result["$defs"] = .object(Dictionary(uniqueKeysWithValues: reachable.map { name in
                (name, definitions[name]!.value)
            }))
        }
        return .object(result)
    }

    private struct CanonicalSchema {
        var value: WireJSONValue
        var references: Set<String>
        var title: String?
    }

    private enum SchemaPlacement {
        case root
        case definition
        case property
        case nested

        var hoistsNamedComposite: Bool {
            self == .property || self == .nested
        }
    }

    private struct PreparedSchema {
        var value: WireJSONValue
        var inlineDefinitions: [WireJSONValue]
    }

    /// Foundation Models flattens named nested objects and unions into the
    /// root definition table. Descriptions belong to an object property, not
    /// to array items or union choices, while the hoisted definition keeps its
    /// own description.
    private static func prepareSchema(
        _ value: WireJSONValue,
        placement: SchemaPlacement
    ) -> PreparedSchema {
        guard case .object(var object) = value else {
            return PreparedSchema(value: value, inlineDefinitions: [])
        }

        if object["const"] != nil || object["$ref"] != nil {
            if placement == .nested {
                object.removeValue(forKey: "description")
            }
            return PreparedSchema(value: .object(object), inlineDefinitions: [])
        }

        if case .array(let rawChoices)? = object["anyOf"] {
            var choices: [WireJSONValue] = []
            var definitions: [WireJSONValue] = []
            for rawChoice in rawChoices {
                let choice = prepareSchema(rawChoice, placement: .nested)
                choices.append(choice.value)
                definitions.append(contentsOf: choice.inlineDefinitions)
            }
            object["anyOf"] = .array(choices)
            if placement.hoistsNamedComposite,
               case .string(let title)? = object["title"]
            {
                definitions.append(.object(object))
                var reference: [String: WireJSONValue] = ["$ref": .string(title)]
                if placement == .property, let description = object["description"] {
                    reference["description"] = description
                }
                return PreparedSchema(value: .object(reference), inlineDefinitions: definitions)
            }
            return PreparedSchema(value: .object(object), inlineDefinitions: definitions)
        }

        guard case .string(let type)? = object["type"] else {
            return PreparedSchema(value: .object(object), inlineDefinitions: [])
        }

        if type == "array", let rawItems = object["items"] {
            let items = prepareSchema(rawItems, placement: .nested)
            object["items"] = items.value
            if placement == .nested {
                object.removeValue(forKey: "description")
            }
            return PreparedSchema(value: .object(object), inlineDefinitions: items.inlineDefinitions)
        }

        if type == "object" {
            var definitions: [WireJSONValue] = []
            if case .object(var properties)? = object["properties"],
               case .array(let rawOrder)? = object["x-order"],
               rawOrder.allSatisfy({ if case .string = $0 { true } else { false } })
            {
                let admitted = Set(rawOrder.compactMap { value -> String? in
                    guard case .string(let name) = value else { return nil }
                    return name
                })
                for name in admitted {
                    guard let rawProperty = properties[name] else { continue }
                    let property = prepareSchema(rawProperty, placement: .property)
                    properties[name] = property.value
                    definitions.append(contentsOf: property.inlineDefinitions)
                }
                object["properties"] = .object(properties)
            }
            if placement.hoistsNamedComposite,
               case .string(let title)? = object["title"]
            {
                definitions.append(.object(object))
                var reference: [String: WireJSONValue] = ["$ref": .string(title)]
                if placement == .property, let description = object["description"] {
                    reference["description"] = description
                }
                return PreparedSchema(value: .object(reference), inlineDefinitions: definitions)
            }
            return PreparedSchema(value: .object(object), inlineDefinitions: definitions)
        }

        if type == "string", object["enum"] != nil,
           placement == .property || placement == .nested
        {
            object.removeValue(forKey: "title")
        }
        if placement == .nested {
            object.removeValue(forKey: "description")
        }
        return PreparedSchema(value: .object(object), inlineDefinitions: [])
    }

    @discardableResult
    private static func indexDefinition(
        _ definition: WireJSONValue,
        in index: inout [String: [WireJSONValue]]
    ) -> String? {
        guard case .object(let object) = definition,
              case .string(let title)? = object["title"]
        else { return nil }
        index[title, default: []].append(definition)
        return title
    }

    private static func canonicalSchema(
        _ value: WireJSONValue,
        codingPath: [any CodingKey],
        allowsReference: Bool
    ) throws -> CanonicalSchema {
        guard case .object(let object) = value else {
            throw corrupted("generation schema must be a JSON object", codingPath: codingPath)
        }

        if let value = object["const"] {
            guard case .string(let constant) = value else {
                throw corrupted("generation schema const must be a string", codingPath: codingPath)
            }
            return CanonicalSchema(value: .object(["const": .string(constant)]), references: [], title: nil)
        }

        if let value = object["$ref"] {
            guard allowsReference else {
                throw corrupted("root generation schema cannot be a $ref", codingPath: codingPath)
            }
            guard case .string(let reference) = value,
                  let name = definitionName(in: reference)
            else {
                throw corrupted("generation schema $ref is unsupported", codingPath: codingPath)
            }
            return CanonicalSchema(
                value: .object(["$ref": .string(canonicalReference(to: name))]),
                references: [name],
                title: nil
            )
        }

        if let value = object["anyOf"] {
            guard case .array(let rawChoices) = value, !rawChoices.isEmpty else {
                throw corrupted("generation schema anyOf must be a nonempty array", codingPath: codingPath)
            }
            let title = try requiredString("title", in: object, codingPath: codingPath)
            var choices: [WireJSONValue] = []
            var references: Set<String> = []
            for rawChoice in rawChoices {
                let choice = try canonicalSchema(rawChoice, codingPath: codingPath, allowsReference: true)
                choices.append(choice.value)
                references.formUnion(choice.references)
            }
            var result: [String: WireJSONValue] = [
                "anyOf": .array(choices),
                "title": .string(title),
            ]
            if let description = try optionalString("description", in: object, codingPath: codingPath) {
                result["description"] = .string(description)
            }
            return CanonicalSchema(value: .object(result), references: references, title: title)
        }

        guard case .string(let type)? = object["type"], schemaTypes.contains(type) else {
            throw corrupted("generation schema type is unsupported", codingPath: codingPath)
        }

        switch type {
        case "array":
            guard let rawItems = object["items"] else {
                throw corrupted("generation schema array requires items", codingPath: codingPath)
            }
            let items = try canonicalSchema(rawItems, codingPath: codingPath, allowsReference: true)
            var result: [String: WireJSONValue] = ["items": items.value, "type": .string(type)]
            if let value = object["minItems"] {
                result["minItems"] = try canonicalInteger(value, key: "minItems", codingPath: codingPath)
            }
            if let value = object["maxItems"] {
                result["maxItems"] = try canonicalInteger(value, key: "maxItems", codingPath: codingPath)
            }
            return CanonicalSchema(value: .object(result), references: items.references, title: nil)

        case "object":
            let title = try requiredString("title", in: object, codingPath: codingPath)
            guard case .bool = object["additionalProperties"] else {
                throw corrupted("generation schema object requires boolean additionalProperties", codingPath: codingPath)
            }
            guard case .object(let rawProperties)? = object["properties"] else {
                throw corrupted("generation schema object requires properties", codingPath: codingPath)
            }
            let rawRequired = try stringArray("required", in: object, codingPath: codingPath)
            let order = try stringArray("x-order", in: object, codingPath: codingPath)
            guard Set(order).count == order.count else {
                throw corrupted("generation schema x-order contains a duplicate property", codingPath: codingPath)
            }

            var canonicalProperties: [String: CanonicalSchema] = [:]
            for (name, rawProperty) in rawProperties {
                var property = try canonicalSchema(rawProperty, codingPath: codingPath, allowsReference: true)
                if case .object(let rawPropertyObject) = rawProperty,
                   let description = try optionalString(
                       "description",
                       in: rawPropertyObject,
                       codingPath: codingPath
                   ),
                   case .object(var propertyValue) = property.value
                {
                    propertyValue["description"] = .string(description)
                    property.value = .object(propertyValue)
                }
                canonicalProperties[name] = property
            }
            var properties: [String: WireJSONValue] = [:]
            var references: Set<String> = []
            for name in order {
                guard let property = canonicalProperties[name] else {
                    throw corrupted("generation schema x-order names a missing property", codingPath: codingPath)
                }
                properties[name] = property.value
                references.formUnion(property.references)
            }
            let admittedNames = Set(order)
            let requiredNames = Set(rawRequired).intersection(admittedNames)
            let required = order.filter(requiredNames.contains)
            var result: [String: WireJSONValue] = [
                "additionalProperties": .bool(false),
                "properties": .object(properties),
                "required": .array(required.map(WireJSONValue.string)),
                "title": .string(title),
                "type": .string(type),
                "x-order": .array(order.map(WireJSONValue.string)),
            ]
            if let description = try optionalString("description", in: object, codingPath: codingPath) {
                result["description"] = .string(description)
            }
            return CanonicalSchema(value: .object(result), references: references, title: title)

        case "string":
            if let value = object["enum"] {
                guard case .array(let rawValues) = value else {
                    throw corrupted("generation schema enum must be a string array", codingPath: codingPath)
                }
                var values: [String] = []
                for rawValue in rawValues {
                    guard case .string(let value) = rawValue else {
                        throw corrupted("generation schema enum must contain strings", codingPath: codingPath)
                    }
                    values.append(value)
                }
                let title = try optionalString("title", in: object, codingPath: codingPath)
                if title != nil, values.isEmpty {
                    throw corrupted("named string generation schema requires a nonempty enum", codingPath: codingPath)
                }
                var result: [String: WireJSONValue] = [
                    "enum": .array(values.map(WireJSONValue.string)),
                    "type": .string(type),
                ]
                if let pattern = try validatedPattern(in: object, codingPath: codingPath) {
                    result["pattern"] = .string(pattern)
                }
                if let title {
                    result["title"] = .string(title)
                    if let description = try optionalString("description", in: object, codingPath: codingPath) {
                        result["description"] = .string(description)
                    }
                }
                return CanonicalSchema(value: .object(result), references: [], title: title)
            }
            guard object["title"] == nil else {
                throw corrupted("named string generation schema requires enum", codingPath: codingPath)
            }
            if let pattern = try validatedPattern(in: object, codingPath: codingPath) {
                return CanonicalSchema(
                    value: .object(["pattern": .string(pattern), "type": .string(type)]),
                    references: [],
                    title: nil
                )
            }
            return CanonicalSchema(value: .object(["type": .string(type)]), references: [], title: nil)

        case "integer":
            var result: [String: WireJSONValue] = ["type": .string(type)]
            if let value = object["minimum"] {
                result["minimum"] = try canonicalInteger(value, key: "minimum", codingPath: codingPath)
            }
            if let value = object["maximum"] {
                result["maximum"] = try canonicalInteger(value, key: "maximum", codingPath: codingPath)
            }
            return CanonicalSchema(value: .object(result), references: [], title: nil)

        case "number":
            var result: [String: WireJSONValue] = ["type": .string(type)]
            if let value = object["minimum"] {
                result["minimum"] = try canonicalNumber(value, key: "minimum", codingPath: codingPath)
            }
            if let value = object["maximum"] {
                result["maximum"] = try canonicalNumber(value, key: "maximum", codingPath: codingPath)
            }
            return CanonicalSchema(value: .object(result), references: [], title: nil)

        default:
            return CanonicalSchema(value: .object(["type": .string(type)]), references: [], title: nil)
        }
    }

    private static func requiredString(
        _ key: String,
        in object: [String: WireJSONValue],
        codingPath: [any CodingKey]
    ) throws -> String {
        guard case .string(let value)? = object[key] else {
            throw corrupted("generation schema requires string \(key)", codingPath: codingPath)
        }
        return value
    }

    private static func optionalString(
        _ key: String,
        in object: [String: WireJSONValue],
        codingPath: [any CodingKey]
    ) throws -> String? {
        guard let rawValue = object[key] else { return nil }
        guard case .string(let value) = rawValue else {
            throw corrupted("generation schema \(key) must be a string", codingPath: codingPath)
        }
        return value
    }

    private static func stringArray(
        _ key: String,
        in object: [String: WireJSONValue],
        codingPath: [any CodingKey]
    ) throws -> [String] {
        guard case .array(let rawValues)? = object[key] else {
            throw corrupted("generation schema requires string array \(key)", codingPath: codingPath)
        }
        return try rawValues.map { rawValue in
            guard case .string(let value) = rawValue else {
                throw corrupted("generation schema \(key) must contain strings", codingPath: codingPath)
            }
            return value
        }
    }

    private static func canonicalInteger(
        _ value: WireJSONValue,
        key: String,
        codingPath: [any CodingKey]
    ) throws -> WireJSONValue {
        switch value {
        case .integer(let value) where Int(exactly: value) != nil:
            return .integer(value)
        case .unsigned(let value) where Int(exactly: value) != nil:
            return .integer(Int64(value))
        default:
            throw corrupted("generation schema \(key) must be an integer", codingPath: codingPath)
        }
    }

    private static func validatedPattern(
        in object: [String: WireJSONValue],
        codingPath: [any CodingKey]
    ) throws -> String? {
        guard let rawPattern = object["pattern"] else { return nil }
        guard case .string(let pattern) = rawPattern else {
            throw corrupted("generation schema pattern must be a string", codingPath: codingPath)
        }
        do {
            _ = try Regex<AnyRegexOutput>(pattern)
        } catch {
            throw corrupted("generation schema pattern is invalid", codingPath: codingPath)
        }
        return pattern
    }

    private static func canonicalNumber(
        _ value: WireJSONValue,
        key: String,
        codingPath: [any CodingKey]
    ) throws -> WireJSONValue {
        switch value {
        case .integer(let value):
            return .number(Double(value))
        case .unsigned(let value):
            return .number(Double(value))
        case .number(let value):
            return .number(value)
        default:
            throw corrupted("generation schema \(key) must be a number", codingPath: codingPath)
        }
    }

    private static func definitionName(in reference: String) -> String? {
        let prefix = "#/$defs/"
        guard reference.hasPrefix(prefix) else {
            return reference.isEmpty ? nil : reference
        }
        let token = String(reference.dropFirst(prefix.count))
        guard !token.isEmpty, !token.contains("/") else { return nil }
        var result = ""
        var index = token.startIndex
        while index < token.endIndex {
            if token[index] == "~" {
                let next = token.index(after: index)
                guard next < token.endIndex else { return nil }
                switch token[next] {
                case "0": result.append("~")
                case "1": result.append("/")
                default: return nil
                }
                index = token.index(after: next)
            } else {
                result.append(token[index])
                index = token.index(after: index)
            }
        }
        return result
    }

    private static func canonicalReference(to name: String) -> String {
        let token = name
            .replacingOccurrences(of: "~", with: "~0")
            .replacingOccurrences(of: "/", with: "~1")
        return "#/$defs/\(token)"
    }

    private static func corrupted(
        _ description: String,
        codingPath: [any CodingKey]
    ) -> DecodingError {
        .dataCorrupted(.init(codingPath: codingPath, debugDescription: description))
    }
}

struct WirePortableValueError: Error, CustomStringConvertible, LocalizedError {
    let description: String

    init(_ description: String) { self.description = description }
    var errorDescription: String? { description }
}

/// FoundationModels' transcript JSON, modeled at the wire boundary. This is
/// the sole Codable source used by both Darwin and Linux. The native framework
/// conversion lives in `FoundationModelsBridge.swift`.
public struct WireTranscript: Codable, Sendable, Equatable, RandomAccessCollection {
    public typealias Index = Int
    public typealias Element = Entry

    private static let typeName = "FoundationModels.Transcript"
    private static let formatVersion = "1.1"

    private var storedEntries: [Entry]
    private var deferredEncodingError: String?
    var deferredNativeJSON: Data?

    public init(entries: some Sequence<Entry> = []) {
        storedEntries = Array(entries)
        deferredEncodingError = nil
        deferredNativeJSON = nil
    }

    init(deferredEncodingError: String, nativeJSON: Data? = nil) {
        storedEntries = []
        self.deferredEncodingError = deferredEncodingError
        deferredNativeJSON = nativeJSON
    }

    public var entries: [Entry] {
        get { storedEntries }
        set {
            storedEntries = newValue
            deferredEncodingError = nil
            deferredNativeJSON = nil
        }
    }

    public var startIndex: Int { storedEntries.startIndex }
    public var endIndex: Int { storedEntries.endIndex }
    public subscript(position: Int) -> Entry { storedEntries[position] }

    private enum CodingKeys: String, CodingKey { case transcript, type, version }
    private struct Payload: Codable, Sendable, Equatable { var entries: [Entry] }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        let version = try container.decode(String.self, forKey: .version)
        guard type == Self.typeName, version == Self.formatVersion else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "unsupported transcript type or version"
            ))
        }
        storedEntries = try container.decode(Payload.self, forKey: .transcript).entries
        deferredEncodingError = nil
        deferredNativeJSON = nil
#if canImport(FoundationModels)
        do {
            try validateNativeFoundationModelsValue()
        } catch {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Foundation Models rejected the transcript",
                underlyingError: error
            ))
        }
#endif
    }

    public func encode(to encoder: Encoder) throws {
        if let deferredEncodingError { throw WirePortableValueError(deferredEncodingError) }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Payload(entries: storedEntries), forKey: .transcript)
        try container.encode(Self.typeName, forKey: .type)
        try container.encode(Self.formatVersion, forKey: .version)
    }

    public enum Entry: Sendable, Equatable {
        case instructions(Instructions)
        case prompt(Prompt)
        case toolCalls(ToolCalls)
        case toolOutput(ToolOutput)
        case response(Response)
        case reasoning(Reasoning)
    }

    public enum Segment: Sendable, Equatable {
        case text(TextSegment)
        case structure(StructuredSegment)
    }

    public struct TextSegment: Sendable, Equatable {
        public var id: String
        public var content: String
        public init(id: String = UUID().uuidString, content: String) {
            self.id = id
            self.content = content
        }
    }

    public struct StructuredSegment: Sendable, Equatable {
        public var id: String
        public var source: String
        public var content: WireJSONValue
        public init(id: String = UUID().uuidString, source: String, content: WireJSONValue) {
            self.id = id
            self.source = source
            self.content = content
        }
    }

    public struct Instructions: Sendable, Equatable {
        public var id: String
        public var segments: [Segment]
        public var toolDefinitions: [ToolDefinition]
        public init(id: String = UUID().uuidString, segments: [Segment], toolDefinitions: [ToolDefinition] = []) {
            self.id = id
            self.segments = segments
            self.toolDefinitions = toolDefinitions
        }
    }

    public struct ToolDefinition: Sendable, Equatable {
        public var name: String
        public var description: String
        public var parameters: WireGenerationSchema
        public init(name: String, description: String, parameters: WireGenerationSchema) {
            self.name = name
            self.description = description
            self.parameters = parameters
        }
    }

    public struct Prompt: Sendable, Equatable {
        public var id: String
        public var segments: [Segment]
        public var options: [String: WireJSONValue]
        public var responseFormat: ResponseFormat?
        public var contextOptions: [String: WireJSONValue]
        public var metadata: [String: WireJSONValue]

        public init(
            id: String = UUID().uuidString,
            segments: [Segment],
            options: [String: WireJSONValue] = [:],
            responseFormat: ResponseFormat? = nil,
            contextOptions: [String: WireJSONValue] = [:],
            metadata: [String: WireJSONValue] = [:]
        ) {
            self.id = id
            self.segments = segments
            self.options = options
            self.responseFormat = responseFormat
            self.contextOptions = contextOptions
            self.metadata = metadata
        }
    }

    public struct ResponseFormat: Sendable, Equatable {
        public var name: String
        public var description: String?
        public var schema: WireGenerationSchema
        public init(name: String, description: String? = nil, schema: WireGenerationSchema) {
            if let identity = schema.responseFormatIdentity {
                self.name = identity.name
                self.description = identity.description
            } else {
                self.name = name
                self.description = description
            }
            self.schema = schema
        }
    }

    public struct ToolCalls: Sendable, Equatable {
        public var id: String
        public var calls: [ToolCall]
        public init(id: String = UUID().uuidString, calls: [ToolCall]) {
            self.id = id
            self.calls = calls
        }
    }

    public struct ToolCall: Sendable, Equatable {
        public var id: String
        public var name: String
        public var argumentsJSON: String
        public var metadata: [String: WireJSONValue]
        public init(id: String, name: String, argumentsJSON: String, metadata: [String: WireJSONValue] = [:]) {
            self.id = id
            self.name = name
            self.argumentsJSON = argumentsJSON
            self.metadata = metadata
        }
    }

    public struct ToolOutput: Sendable, Equatable {
        public var id: String
        public var toolCallID: String
        public var toolName: String
        public var segments: [Segment]
        public init(id: String, toolCallID: String? = nil, toolName: String, segments: [Segment]) {
            let toolCallID = toolCallID ?? id
            self.id = toolCallID
            self.toolCallID = toolCallID
            self.toolName = toolName
            self.segments = segments
        }
    }

    public struct Response: Sendable, Equatable {
        public var id: String
        public var assetIDs: [String]
        public var segments: [Segment]
        public var metadata: [String: WireJSONValue]
        public init(
            id: String = UUID().uuidString,
            assetIDs: [String] = [],
            segments: [Segment],
            metadata: [String: WireJSONValue]? = nil
        ) {
            self.id = id
            self.segments = segments
            let canonical = Self.canonicalAssets(assetIDs: assetIDs, metadata: metadata ?? [:])
            self.assetIDs = canonical.assetIDs
            self.metadata = canonical.metadata
        }

        fileprivate static func canonicalAssets(
            assetIDs: [String],
            metadata: [String: WireJSONValue]
        ) -> (assetIDs: [String], metadata: [String: WireJSONValue]) {
            var metadata = metadata
            if !assetIDs.isEmpty {
                metadata["assetIDs"] = .array(assetIDs.map(WireJSONValue.string))
                return (assetIDs, metadata)
            }
            if case .array(let values)? = metadata["assetIDs"],
               values.allSatisfy({ if case .string = $0 { true } else { false } })
            {
                return (
                    values.compactMap { value in
                        guard case .string(let assetID) = value else { return nil }
                        return assetID
                    },
                    metadata
                )
            }
            return ([], metadata)
        }
    }

    public struct Reasoning: Sendable, Equatable {
        public var id: String
        public var segments: [Segment]
        public var signature: Data?
        public var metadata: [String: WireJSONValue]
        public init(
            id: String = UUID().uuidString,
            segments: [Segment],
            signature: Data? = nil,
            metadata: [String: WireJSONValue] = [:]
        ) {
            self.id = id
            self.segments = segments
            self.signature = signature
            self.metadata = metadata
        }
    }
}

extension WireTranscript.Segment: Codable {
    private enum CodingKeys: String, CodingKey { case id, text, type, structure }
    private enum StructureKeys: String, CodingKey { case content, source }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .type) {
        case "text":
            self = .text(.init(
                id: try container.decode(String.self, forKey: .id),
                content: try container.decode(String.self, forKey: .text)
            ))
        case "structure":
            let nested = try container.nestedContainer(keyedBy: StructureKeys.self, forKey: .structure)
            self = .structure(.init(
                id: try container.decode(String.self, forKey: .id),
                source: try nested.decode(String.self, forKey: .source),
                content: try nested.decode(WireJSONValue.self, forKey: .content)
            ))
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: container, debugDescription: "unknown transcript segment")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .text(let value):
            try container.encode(value.id, forKey: .id)
            try container.encode(value.content, forKey: .text)
            try container.encode("text", forKey: .type)
        case .structure(let value):
            try container.encode(value.id, forKey: .id)
            try container.encode("structure", forKey: .type)
            var nested = container.nestedContainer(keyedBy: StructureKeys.self, forKey: .structure)
            try nested.encode(value.content, forKey: .content)
            try nested.encode(value.source, forKey: .source)
        }
    }
}

extension WireTranscript.Entry: Codable {
    private enum CodingKeys: String, CodingKey {
        case assets, contents, contextOptions, id, metadata, options, reasoning, responseFormat, role, toolCallID, toolCalls, toolName, tools
    }
    private enum ToolWrapperKeys: String, CodingKey { case function, type }
    private enum ToolKeys: String, CodingKey { case description, name, parameters }
    private enum CallKeys: String, CodingKey { case arguments, id, metadata, name }
    private enum ReasoningKeys: String, CodingKey { case contents, signature }
    private enum FormatKeys: String, CodingKey { case jsonSchema, type }
    private enum JSONSchemaKeys: String, CodingKey { case description, name, schema }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let role = try container.decode(String.self, forKey: .role)
        let id = try container.decode(String.self, forKey: .id)
        switch role {
        case "instructions":
            var tools: [WireTranscript.ToolDefinition] = []
            if container.contains(.tools) {
                var values = try container.nestedUnkeyedContainer(forKey: .tools)
                while !values.isAtEnd {
                    let wrapper = try values.nestedContainer(keyedBy: ToolWrapperKeys.self)
                    guard try wrapper.decode(String.self, forKey: .type) == "function" else {
                        throw DecodingError.dataCorruptedError(forKey: .type, in: wrapper, debugDescription: "unknown transcript tool type")
                    }
                    let function = try wrapper.nestedContainer(keyedBy: ToolKeys.self, forKey: .function)
                    tools.append(.init(
                        name: try function.decode(String.self, forKey: .name),
                        description: try function.decode(String.self, forKey: .description),
                        parameters: try function.decode(WireGenerationSchema.self, forKey: .parameters)
                    ))
                }
            }
            self = .instructions(.init(
                id: id,
                segments: try container.decode([WireTranscript.Segment].self, forKey: .contents),
                toolDefinitions: tools
            ))
        case "user":
            let responseFormat: WireTranscript.ResponseFormat?
            if container.contains(.responseFormat) {
                let format = try container.nestedContainer(keyedBy: FormatKeys.self, forKey: .responseFormat)
                guard try format.decode(String.self, forKey: .type) == "jsonSchema" else {
                    throw DecodingError.dataCorruptedError(forKey: .type, in: format, debugDescription: "unknown transcript response format")
                }
                let schema = try format.nestedContainer(keyedBy: JSONSchemaKeys.self, forKey: .jsonSchema)
                _ = try schema.decode(String.self, forKey: .name)
                _ = try schema.decodeIfPresent(String.self, forKey: .description)
                let decodedSchema = try schema.decode(WireGenerationSchema.self, forKey: .schema)
                guard let identity = decodedSchema.responseFormatIdentity else {
                    throw DecodingError.dataCorruptedError(
                        forKey: .schema,
                        in: schema,
                        debugDescription: "generation schema has no response-format identity"
                    )
                }
                responseFormat = .init(
                    name: identity.name,
                    description: identity.description,
                    schema: decodedSchema
                )
            } else {
                responseFormat = nil
            }
            self = .prompt(.init(
                id: id,
                segments: try container.decode([WireTranscript.Segment].self, forKey: .contents),
                options: try container.decodeIfPresent([String: WireJSONValue].self, forKey: .options) ?? [:],
                responseFormat: responseFormat,
                contextOptions: try container.decodeIfPresent([String: WireJSONValue].self, forKey: .contextOptions) ?? [:],
                metadata: try container.decodeIfPresent([String: WireJSONValue].self, forKey: .metadata) ?? [:]
            ))
        case "response" where container.contains(.toolCalls):
            var calls: [WireTranscript.ToolCall] = []
            var values = try container.nestedUnkeyedContainer(forKey: .toolCalls)
            while !values.isAtEnd {
                let call = try values.nestedContainer(keyedBy: CallKeys.self)
                let arguments = try call.decode(String.self, forKey: .arguments)
                do {
                    _ = try JSONDecoder().decode(WireJSONValue.self, from: Data(arguments.utf8))
                } catch {
                    throw DecodingError.dataCorruptedError(
                        forKey: .arguments,
                        in: call,
                        debugDescription: "transcript tool-call arguments must contain valid JSON"
                    )
                }
                calls.append(.init(
                    id: try call.decode(String.self, forKey: .id),
                    name: try call.decode(String.self, forKey: .name),
                    argumentsJSON: arguments,
                    metadata: try call.decodeIfPresent([String: WireJSONValue].self, forKey: .metadata) ?? [:]
                ))
            }
            self = .toolCalls(.init(id: id, calls: calls))
        case "tool":
            let toolCallID = try container.decode(String.self, forKey: .toolCallID)
            self = .toolOutput(.init(
                id: toolCallID,
                toolCallID: toolCallID,
                toolName: try container.decode(String.self, forKey: .toolName),
                segments: try container.decode([WireTranscript.Segment].self, forKey: .contents)
            ))
        case "response":
            var metadata = try container.decodeIfPresent(
                [String: WireJSONValue].self,
                forKey: .metadata
            ) ?? [:]
            let assetIDs: [String]
            let explicitAssetIDs = try container.decodeIfPresent([String].self, forKey: .assets) ?? []
            if !explicitAssetIDs.isEmpty {
                assetIDs = explicitAssetIDs
                metadata["assetIDs"] = .array(explicitAssetIDs.map(WireJSONValue.string))
            } else if case .array(let values)? = metadata["assetIDs"],
                      values.allSatisfy({ if case .string = $0 { true } else { false } })
            {
                assetIDs = values.compactMap { value in
                    guard case .string(let assetID) = value else { return nil }
                    return assetID
                }
            } else {
                assetIDs = []
            }
            self = .response(.init(
                id: id,
                assetIDs: assetIDs,
                segments: try container.decode([WireTranscript.Segment].self, forKey: .contents),
                metadata: metadata
            ))
        case "reasoning":
            let reasoning = try container.nestedContainer(keyedBy: ReasoningKeys.self, forKey: .reasoning)
            self = .reasoning(.init(
                id: id,
                segments: try reasoning.decode([WireTranscript.Segment].self, forKey: .contents),
                signature: try reasoning.decodeIfPresent(Data.self, forKey: .signature),
                metadata: try container.decodeIfPresent([String: WireJSONValue].self, forKey: .metadata) ?? [:]
            ))
        default:
            throw DecodingError.dataCorruptedError(forKey: .role, in: container, debugDescription: "unknown transcript entry")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .instructions(let value):
            try container.encode(value.segments, forKey: .contents)
            try container.encode(value.id, forKey: .id)
            try container.encode("instructions", forKey: .role)
            if !value.toolDefinitions.isEmpty {
                var tools = container.nestedUnkeyedContainer(forKey: .tools)
                for value in value.toolDefinitions {
                    var wrapper = tools.nestedContainer(keyedBy: ToolWrapperKeys.self)
                    try wrapper.encode("function", forKey: .type)
                    var function = wrapper.nestedContainer(keyedBy: ToolKeys.self, forKey: .function)
                    try function.encode(value.description, forKey: .description)
                    try function.encode(value.name, forKey: .name)
                    try function.encode(value.parameters, forKey: .parameters)
                }
            }
        case .prompt(let value):
            try container.encode(value.segments, forKey: .contents)
            try container.encode(value.contextOptions, forKey: .contextOptions)
            try container.encode(value.id, forKey: .id)
            if !value.metadata.isEmpty { try container.encode(value.metadata, forKey: .metadata) }
            try container.encode(value.options, forKey: .options)
            if let value = value.responseFormat {
                var format = container.nestedContainer(keyedBy: FormatKeys.self, forKey: .responseFormat)
                try format.encode("jsonSchema", forKey: .type)
                var schema = format.nestedContainer(keyedBy: JSONSchemaKeys.self, forKey: .jsonSchema)
                guard let identity = value.schema.responseFormatIdentity else {
                    throw EncodingError.invalidValue(
                        value.schema,
                        .init(
                            codingPath: encoder.codingPath,
                            debugDescription: "generation schema has no response-format identity"
                        )
                    )
                }
                try schema.encodeIfPresent(identity.description, forKey: .description)
                try schema.encode(identity.name, forKey: .name)
                try schema.encode(value.schema, forKey: .schema)
            }
            try container.encode("user", forKey: .role)
        case .toolCalls(let value):
            try container.encode(value.id, forKey: .id)
            try container.encode("response", forKey: .role)
            var calls = container.nestedUnkeyedContainer(forKey: .toolCalls)
            for value in value.calls {
                do {
                    _ = try JSONDecoder().decode(WireJSONValue.self, from: Data(value.argumentsJSON.utf8))
                } catch {
                    throw EncodingError.invalidValue(
                        value.argumentsJSON,
                        .init(
                            codingPath: encoder.codingPath,
                            debugDescription: "transcript tool-call arguments must contain valid JSON",
                            underlyingError: error
                        )
                    )
                }
                var call = calls.nestedContainer(keyedBy: CallKeys.self)
                try call.encode(value.argumentsJSON, forKey: .arguments)
                try call.encode(value.id, forKey: .id)
                if !value.metadata.isEmpty { try call.encode(value.metadata, forKey: .metadata) }
                try call.encode(value.name, forKey: .name)
            }
        case .toolOutput(let value):
            try container.encode(value.segments, forKey: .contents)
            try container.encode(value.toolCallID, forKey: .id)
            try container.encode("tool", forKey: .role)
            try container.encode(value.toolCallID, forKey: .toolCallID)
            try container.encode(value.toolName, forKey: .toolName)
        case .response(let value):
            let canonical = WireTranscript.Response.canonicalAssets(
                assetIDs: value.assetIDs,
                metadata: value.metadata
            )
            if !canonical.assetIDs.isEmpty { try container.encode(canonical.assetIDs, forKey: .assets) }
            try container.encode(value.segments, forKey: .contents)
            try container.encode(value.id, forKey: .id)
            if !canonical.metadata.isEmpty { try container.encode(canonical.metadata, forKey: .metadata) }
            try container.encode("response", forKey: .role)
        case .reasoning(let value):
            try container.encode(value.id, forKey: .id)
            if !value.metadata.isEmpty { try container.encode(value.metadata, forKey: .metadata) }
            var reasoning = container.nestedContainer(keyedBy: ReasoningKeys.self, forKey: .reasoning)
            try reasoning.encode(value.segments, forKey: .contents)
            try reasoning.encodeIfPresent(value.signature, forKey: .signature)
            try container.encode("reasoning", forKey: .role)
        }
    }
}
