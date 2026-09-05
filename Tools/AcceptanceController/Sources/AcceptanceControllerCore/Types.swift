import Foundation

public enum ControllerError: Error, Equatable, CustomStringConvertible, Sendable {
    case usage(String)
    case input(String)
    case ownership(String)
    case process(String)
    case result(String)
    case evidence(String)
    case publication(String)
    case verification(String)

    public var description: String {
        switch self {
        case .usage(let value): "usage:\(value)"
        case .input(let value): "input:\(value)"
        case .ownership(let value): "ownership:\(value)"
        case .process(let value): "process:\(value)"
        case .result(let value): "result:\(value)"
        case .evidence(let value): "evidence:\(value)"
        case .publication(let value): "publication:\(value)"
        case .verification(let value): "verification:\(value)"
        }
    }
}

public enum WorkloadOutcome: String, Codable, Sendable {
    case pass
    case stop
    case controllerFailure
}

public enum ResultKind: String, Codable, Sendable {
    case ok
    case stop
    case refusal
}

public enum TypedValue: Equatable, Sendable, Codable {
    case boolean(Bool)
    case integer(Int64)
    case string(String)
    case digest(String)

    private enum CodingKeys: String, CodingKey { case type, value }
    private enum Kind: String, Codable { case boolean, integer, string, digest }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard values.allKeys.count == 2 else {
            throw DecodingError.dataCorruptedError(forKey: .type, in: values, debugDescription: "typed-value-shape")
        }
        switch try values.decode(Kind.self, forKey: .type) {
        case .boolean: self = .boolean(try values.decode(Bool.self, forKey: .value))
        case .integer: self = .integer(try values.decode(Int64.self, forKey: .value))
        case .string: self = .string(try values.decode(String.self, forKey: .value))
        case .digest: self = .digest(try values.decode(String.self, forKey: .value))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .boolean(let value):
            try values.encode(Kind.boolean, forKey: .type)
            try values.encode(value, forKey: .value)
        case .integer(let value):
            try values.encode(Kind.integer, forKey: .type)
            try values.encode(value, forKey: .value)
        case .string(let value):
            try values.encode(Kind.string, forKey: .type)
            try values.encode(value, forKey: .value)
        case .digest(let value):
            try values.encode(Kind.digest, forKey: .type)
            try values.encode(value, forKey: .value)
        }
    }

    public var publicString: String {
        switch self {
        case .boolean(let value): String(value)
        case .integer(let value): String(value)
        case .string(let value), .digest(let value): value
        }
    }
}

public struct ResultEnvelope: Equatable, Sendable, Codable {
    public let version: Int
    public let actionID: String
    public let ordinal: Int
    public let kind: ResultKind
    public let fields: [String: TypedValue]
    public let reasonCode: String?

    public init(
        version: Int = 1,
        actionID: String,
        ordinal: Int,
        kind: ResultKind,
        fields: [String: TypedValue],
        reasonCode: String? = nil
    ) {
        self.version = version
        self.actionID = actionID
        self.ordinal = ordinal
        self.kind = kind
        self.fields = fields
        self.reasonCode = reasonCode
    }
}

public struct ActionSpec: Codable, Equatable, Sendable {
    public let id: String
    public let ordinal: Int
    public let executable: String
    public let arguments: [String]
    public let environment: [String: String]
    public let workingDirectory: String
    public let workDeadlineNanoseconds: UInt64
    public let settlementDeadlineNanoseconds: UInt64
    public let expectedKind: ResultKind
    public let allowedReasonCodes: [String]

    public init(
        id: String,
        ordinal: Int,
        executable: String,
        arguments: [String] = [],
        environment: [String: String] = [:],
        workingDirectory: String,
        workDeadlineNanoseconds: UInt64,
        settlementDeadlineNanoseconds: UInt64,
        expectedKind: ResultKind = .ok,
        allowedReasonCodes: [String] = []
    ) {
        self.id = id
        self.ordinal = ordinal
        self.executable = executable
        self.arguments = arguments
        self.environment = environment
        self.workingDirectory = workingDirectory
        self.workDeadlineNanoseconds = workDeadlineNanoseconds
        self.settlementDeadlineNanoseconds = settlementDeadlineNanoseconds
        self.expectedKind = expectedKind
        self.allowedReasonCodes = allowedReasonCodes
    }
}

public struct RunSpec: Codable, Equatable, Sendable {
    public let version: Int
    public let runID: String
    public let scratchRoot: String
    public let packetPath: String
    public let launchSnapshotPath: String
    public let launchSnapshotDigest: String
    public let sourceManifestPath: String
    public let sourceManifestDigest: String
    public let executableDigest: String
    public let actions: [ActionSpec]

    public init(
        version: Int = 1,
        runID: String,
        scratchRoot: String,
        packetPath: String,
        launchSnapshotPath: String,
        launchSnapshotDigest: String,
        sourceManifestPath: String,
        sourceManifestDigest: String,
        executableDigest: String,
        actions: [ActionSpec]
    ) {
        self.version = version
        self.runID = runID
        self.scratchRoot = scratchRoot
        self.packetPath = packetPath
        self.launchSnapshotPath = launchSnapshotPath
        self.launchSnapshotDigest = launchSnapshotDigest
        self.sourceManifestPath = sourceManifestPath
        self.sourceManifestDigest = sourceManifestDigest
        self.executableDigest = executableDigest
        self.actions = actions
    }
}

public struct ActionRecord: Codable, Equatable, Sendable {
    public enum State: String, Codable, Sendable { case started, settled, notStarted }

    public let ordinal: Int
    public let actionID: String
    public let state: State
    public let rawT0: UInt64?
    public let rawT1: UInt64?
    public let workDeadline: UInt64?
    public let settlementDeadline: UInt64?
    public let termination: String?
    public let exitCode: Int32?
    public let signal: Int32?
    public let processID: Int32?
    public let timeoutDetectedAt: UInt64?
    public let termSentAt: UInt64?
    public let killSentAt: UInt64?
    public let groupAbsentAt: UInt64?
    public let stdoutDigest: String?
    public let stderrDigest: String?
    public let stdoutBytes: Int?
    public let stderrBytes: Int?
    public let result: ResultEnvelope?
    public let reason: String?
    public let preVector: RunResourceVector
    public let postVector: RunResourceVector
}

public struct OutcomePayload: Codable, Equatable, Sendable {
    public let version: Int
    public let outcome: WorkloadOutcome
    public let packetBasename: String
    public let actionTableDigest: String
    public let runLedgerDigest: String
    public let sliceLaunchSnapshotDigest: String
    public let earliestStopOrdinal: Int?
    public let publicResults: [String: [String: TypedValue]]
    public let claimBoundaryDigest: String

    public init(version: Int, outcome: WorkloadOutcome, packetBasename: String,
                actionTableDigest: String, runLedgerDigest: String, sliceLaunchSnapshotDigest: String,
                earliestStopOrdinal: Int?, publicResults: [String: [String: TypedValue]], claimBoundaryDigest: String) {
        self.version = version; self.outcome = outcome; self.packetBasename = packetBasename
        self.actionTableDigest = actionTableDigest; self.runLedgerDigest = runLedgerDigest
        self.sliceLaunchSnapshotDigest = sliceLaunchSnapshotDigest; self.earliestStopOrdinal = earliestStopOrdinal
        self.publicResults = publicResults; self.claimBoundaryDigest = claimBoundaryDigest
    }
}

public struct RunReceipt: Codable, Equatable, Sendable {
    public let version: Int
    public let path: String
    public let packetRootDigest: String
    public let outcomeDigest: String
    public let outcome: OutcomePayload
}

public struct VerificationReceipt: Codable, Equatable, Sendable {
    public let version: Int
    public let path: String
    public let packetRootDigest: String
    public let outcomeDigest: String
    public init(version: Int, path: String, packetRootDigest: String, outcomeDigest: String) {
        self.version = version; self.path = path; self.packetRootDigest = packetRootDigest; self.outcomeDigest = outcomeDigest
    }
}

public enum CanonicalJSON {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }

    public static func decode<T: Codable>(
        _ type: T.Type,
        from data: Data,
        allowedTopLevelKeys: Set<String>? = nil
    ) throws -> T {
        guard data.count <= 256 * 1024 else { throw ControllerError.input("json-too-large") }
        guard String(data: data, encoding: .utf8) != nil else { throw ControllerError.input("invalid-utf8") }
        var scanner = JSONDuplicateKeyScanner(data: data)
        try scanner.validate()
        let object = try JSONSerialization.jsonObject(with: data)
        if let allowedTopLevelKeys {
            guard let dictionary = object as? [String: Any] else { throw ControllerError.input("object-required") }
            guard Set(dictionary.keys).isSubset(of: allowedTopLevelKeys) else { throw ControllerError.input("unknown-field") }
        }
        let decoded = try JSONDecoder().decode(T.self, from: data)
        guard try encode(decoded) == data else { throw ControllerError.input("noncanonical-json") }
        return decoded
    }
}

private struct JSONDuplicateKeyScanner {
    private let bytes: [UInt8]
    private var index = 0

    init(data: Data) { bytes = Array(data) }

    mutating func validate() throws {
        try parseValue()
        skipWhitespace()
        guard index == bytes.count else { throw ControllerError.input("trailing-json") }
    }

    private mutating func parseValue() throws {
        skipWhitespace()
        guard index < bytes.count else { throw ControllerError.input("unexpected-eof") }
        switch bytes[index] {
        case 0x7B: try parseObject()
        case 0x5B: try parseArray()
        case 0x22: _ = try parseString()
        case 0x74: try consume("true")
        case 0x66: try consume("false")
        case 0x6E: try consume("null")
        case 0x2D, 0x30...0x39: try parseNumber()
        default: throw ControllerError.input("invalid-json-token")
        }
    }

    private mutating func parseObject() throws {
        index += 1
        skipWhitespace()
        var keys = Set<String>()
        if consumeIf(0x7D) { return }
        while true {
            let key = try parseString()
            guard keys.insert(key).inserted else { throw ControllerError.input("duplicate-json-key") }
            skipWhitespace()
            guard consumeIf(0x3A) else { throw ControllerError.input("missing-colon") }
            try parseValue()
            skipWhitespace()
            if consumeIf(0x7D) { return }
            guard consumeIf(0x2C) else { throw ControllerError.input("missing-comma") }
            skipWhitespace()
        }
    }

    private mutating func parseArray() throws {
        index += 1
        skipWhitespace()
        if consumeIf(0x5D) { return }
        while true {
            try parseValue()
            skipWhitespace()
            if consumeIf(0x5D) { return }
            guard consumeIf(0x2C) else { throw ControllerError.input("missing-comma") }
        }
    }

    private mutating func parseString() throws -> String {
        skipWhitespace()
        guard consumeIf(0x22) else { throw ControllerError.input("string-required") }
        let start = index - 1
        var escaped = false
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            if escaped {
                if byte == 0x75 {
                    guard index + 4 <= bytes.count else { throw ControllerError.input("invalid-unicode-escape") }
                    for value in bytes[index..<(index + 4)] where !((0x30...0x39).contains(value) || (0x41...0x46).contains(value) || (0x61...0x66).contains(value)) {
                        throw ControllerError.input("invalid-unicode-escape")
                    }
                    index += 4
                } else if ![0x22, 0x5C, 0x2F, 0x62, 0x66, 0x6E, 0x72, 0x74].contains(byte) {
                    throw ControllerError.input("invalid-escape")
                }
                escaped = false
            } else if byte == 0x5C {
                escaped = true
            } else if byte == 0x22 {
                let token = Data(bytes[start..<index])
                return try JSONDecoder().decode(String.self, from: token)
            } else if byte < 0x20 {
                throw ControllerError.input("control-in-string")
            }
        }
        throw ControllerError.input("unterminated-string")
    }

    private mutating func parseNumber() throws {
        let start = index
        if consumeIf(0x2D), index == bytes.count { throw ControllerError.input("invalid-number") }
        if consumeIf(0x30) {
            if index < bytes.count, (0x30...0x39).contains(bytes[index]) { throw ControllerError.input("leading-zero") }
        } else {
            guard index < bytes.count, (0x31...0x39).contains(bytes[index]) else { throw ControllerError.input("invalid-number") }
            while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
        }
        if index < bytes.count, bytes[index] == 0x2E || bytes[index] == 0x65 || bytes[index] == 0x45 {
            throw ControllerError.input("nonintegral-number")
        }
        guard index > start else { throw ControllerError.input("invalid-number") }
    }

    private mutating func consume(_ literal: String) throws {
        let target = Array(literal.utf8)
        guard index + target.count <= bytes.count, Array(bytes[index..<(index + target.count)]) == target else {
            throw ControllerError.input("invalid-literal")
        }
        index += target.count
    }

    private mutating func skipWhitespace() {
        while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
    }

    private mutating func consumeIf(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }
}

public enum ResultDecoder {
    private static let keys: Set<String> = ["actionID", "fields", "kind", "ordinal", "reasonCode", "version"]
    private static let fieldName = try! NSRegularExpression(pattern: "^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
    private static let digest = try! NSRegularExpression(pattern: "^[0-9a-f]{64}$")
    private static let forbidden = ["authorization", "bearer ", "private key", "cookie", ".env.local", "/users/", "\\users\\"]

    public static func decode(_ data: Data, action: ActionSpec) throws -> ResultEnvelope {
        guard data.count <= 256 * 1024 else { throw ControllerError.result("logical-result-limit") }
        let value = try CanonicalJSON.decode(ResultEnvelope.self, from: data, allowedTopLevelKeys: keys)
        guard value.version == 1, value.actionID == action.id, value.ordinal == action.ordinal else {
            throw ControllerError.result("result-identity")
        }
        guard value.fields.count <= 128 else { throw ControllerError.result("field-count") }
        for (name, typed) in value.fields {
            let range = NSRange(name.startIndex..<name.endIndex, in: name)
            guard fieldName.firstMatch(in: name, range: range)?.range == range else { throw ControllerError.result("field-name") }
            let text = typed.publicString
            guard text.utf8.count <= 64 * 1024 else { throw ControllerError.result("field-value-limit") }
            let lowered = "\(name)\n\(text)".lowercased()
            guard !forbidden.contains(where: lowered.contains) else { throw ControllerError.result("secret-material") }
            if case .digest(let string) = typed {
                let digestRange = NSRange(string.startIndex..<string.endIndex, in: string)
                guard digest.firstMatch(in: string, range: digestRange)?.range == digestRange else {
                    throw ControllerError.result("invalid-digest")
                }
            }
        }
        if let reason = value.reasonCode {
            guard action.allowedReasonCodes.contains(reason) else { throw ControllerError.result("reason-code") }
        } else if value.kind != .ok {
            throw ControllerError.result("missing-reason-code")
        }
        return value
    }
}

public enum RawClock {
    public static func now() -> UInt64 {
        var value = timespec()
        clock_gettime(CLOCK_MONOTONIC_RAW, &value)
        return UInt64(value.tv_sec) * 1_000_000_000 + UInt64(value.tv_nsec)
    }
}
