import Foundation
import Glibc
import ReachHost
import ReachLinuxTransport
import ReachWire

public enum LinuxServiceConfigurationError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    case invalid(String)
    case unsafeFile(String)
    case system(String, Int32)

    public var description: String {
        switch self {
        case .invalid(let detail):
            "invalid reachd configuration: \(detail)"
        case .unsafeFile(let detail):
            "unsafe reachd file: \(detail)"
        case .system(let operation, let code):
            "\(operation) failed with errno \(code)"
        }
    }

    public var errorDescription: String? { description }
}

public struct LinuxServiceConfiguration: Sendable, Equatable {
    public static let productionPath = "/etc/reach/reachd.json"
    public static let maximumDocumentBytes = 65_536

    public struct Endpoint: Sendable, Equatable, Hashable, Codable {
        public var address: String
        public var port: UInt16

        public init(address: String, port: UInt16) {
            self.address = address
            self.port = port
        }

        public var road: RoadEndpoint { RoadEndpoint(host: address, port: port) }
    }

    public struct TLS: Sendable, Equatable {
        public var clusterCACertificatePath: String
        public var serverCertificateChainPath: String
        public var serverPrivateKeyPath: String
    }

    public var schemaVersion: Int
    public var clusterDisplayName: String
    public var listen: Endpoint
    public var advertisedRoads: [Endpoint]
    public var tls: TLS
    public var modelID: String
    public var exoEndpoint: String

    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= maximumDocumentBytes else {
            throw LinuxServiceConfigurationError.invalid("document exceeds 65536 bytes")
        }
        guard String(data: data, encoding: .utf8) != nil else {
            throw LinuxServiceConfigurationError.invalid("document is not UTF-8")
        }
        var parser = StrictJSONParser(bytes: Array(data))
        let root = try parser.parseDocument()
        let object = try root.exactObject(
            keys: [
                "schemaVersion", "clusterDisplayName", "listen", "advertisedRoads",
                "tls", "modelID", "exoEndpoint",
            ],
            at: "top level"
        )

        guard try object.requiredNumber("schemaVersion") == "1" else {
            throw LinuxServiceConfigurationError.invalid("schemaVersion must be the JSON integer 1")
        }
        let clusterDisplayName = try boundedNFCString(
            object.requiredString("clusterDisplayName"),
            name: "clusterDisplayName",
            maximumBytes: 128
        )
        let modelID = try boundedNFCString(
            object.requiredString("modelID"),
            name: "modelID",
            maximumBytes: 256
        )
        let exoEndpoint = try boundedASCIIString(
            object.requiredString("exoEndpoint"),
            name: "exoEndpoint",
            maximumBytes: 256
        )
        do {
            _ = try EXOConfiguration(endpoint: exoEndpoint)
        } catch {
            throw LinuxServiceConfigurationError.invalid(
                "exoEndpoint must be canonical numeric-loopback HTTP"
            )
        }

        let listenObject = try object.required("listen").exactObject(
            keys: ["address", "port"],
            at: "listen"
        )
        let listen = try endpoint(from: listenObject, name: "listen", allowWildcard: true)

        let roadValues = try object.required("advertisedRoads").array(at: "advertisedRoads")
        guard (1 ... 16).contains(roadValues.count) else {
            throw LinuxServiceConfigurationError.invalid("advertisedRoads must contain 1 through 16 roads")
        }
        var roads: [Endpoint] = []
        var identities: Set<Endpoint> = []
        for (index, value) in roadValues.enumerated() {
            let roadObject = try value.exactObject(
                keys: ["address", "port"],
                at: "advertisedRoads[\(index)]"
            )
            let road = try endpoint(
                from: roadObject,
                name: "advertisedRoads[\(index)]",
                allowWildcard: false
            )
            guard identities.insert(road).inserted else {
                throw LinuxServiceConfigurationError.invalid("advertisedRoads contains a duplicate endpoint")
            }
            roads.append(road)
        }

        let tlsObject = try object.required("tls").exactObject(
            keys: [
                "clusterCACertificatePath", "serverCertificateChainPath", "serverPrivateKeyPath",
            ],
            at: "tls"
        )
        let tls = TLS(
            clusterCACertificatePath: try tlsPath(
                tlsObject.requiredString("clusterCACertificatePath"),
                name: "clusterCACertificatePath"
            ),
            serverCertificateChainPath: try tlsPath(
                tlsObject.requiredString("serverCertificateChainPath"),
                name: "serverCertificateChainPath"
            ),
            serverPrivateKeyPath: try tlsPath(
                tlsObject.requiredString("serverPrivateKeyPath"),
                name: "serverPrivateKeyPath"
            )
        )
        let tlsPaths = [
            tls.clusterCACertificatePath,
            tls.serverCertificateChainPath,
            tls.serverPrivateKeyPath,
        ]
        guard Set(tlsPaths).count == tlsPaths.count else {
            throw LinuxServiceConfigurationError.invalid("TLS paths must be distinct")
        }

        return Self(
            schemaVersion: 1,
            clusterDisplayName: clusterDisplayName,
            listen: listen,
            advertisedRoads: roads,
            tls: tls,
            modelID: modelID,
            exoEndpoint: exoEndpoint
        )
    }

    public static func loadProduction() throws -> Self {
        let group = getgid()
        let data = try LinuxSecureFile.read(
            path: productionPath,
            authority: .init(owner: 0, group: group, mode: 0o640),
            maximumBytes: maximumDocumentBytes,
            allowedRoot: "/etc/reach"
        )
        let decoded = try decode(data)
        try decoded.validateTLSFiles(serviceGroup: group)
        return decoded
    }

    public func validateTLSFiles(serviceGroup: gid_t) throws {
        let authority = LinuxSecureFile.Authority(owner: 0, group: serviceGroup, mode: 0o640)
        for path in [
            tls.clusterCACertificatePath,
            tls.serverCertificateChainPath,
            tls.serverPrivateKeyPath,
        ] {
            try LinuxSecureFile.validate(
                path: path,
                authority: authority,
                allowedRoot: "/etc/reach"
            )
        }
    }

    public var listenerConfiguration: LinuxListenerConfiguration {
        LinuxListenerConfiguration(
            address: listen.address,
            port: listen.port,
            clusterCACertificatePath: tls.clusterCACertificatePath,
            serverCertificateChainPath: tls.serverCertificateChainPath,
            serverPrivateKeyPath: tls.serverPrivateKeyPath
        )
    }

    public func helloAck(version: UInt8, capabilities: [String]) -> HelloAck {
        HelloAck(
            version: version,
            cluster: clusterDisplayName,
            models: [ModelDescriptor(
                id: modelID,
                displayName: "\(modelID) (EXO)",
                capabilities: capabilities
            )],
            roads: advertisedRoads.map(\.road)
        )
    }

    private static func endpoint(
        from object: [String: StrictJSONValue],
        name: String,
        allowWildcard: Bool
    ) throws -> Endpoint {
        let source = try boundedASCIIString(
            object.requiredString("address"),
            name: "\(name).address",
            maximumBytes: 45
        )
        let canonical = try NumericAddress.canonical(source)
        guard canonical == source else {
            throw LinuxServiceConfigurationError.invalid("\(name).address is not canonical")
        }
        if !allowWildcard && NumericAddress.isWildcard(canonical) {
            throw LinuxServiceConfigurationError.invalid("\(name).address may not be wildcard")
        }
        let number = try object.requiredNumber("port")
        guard number.allSatisfy(\.isNumber),
              let value = UInt16(number),
              (1024 ... 65535).contains(value)
        else {
            throw LinuxServiceConfigurationError.invalid("\(name).port must be an integer from 1024 through 65535")
        }
        return Endpoint(address: canonical, port: value)
    }

    private static func boundedNFCString(
        _ value: String,
        name: String,
        maximumBytes: Int
    ) throws -> String {
        try rejectControls(value, name: name)
        let count = value.utf8.count
        guard (1 ... maximumBytes).contains(count) else {
            throw LinuxServiceConfigurationError.invalid("\(name) has an invalid byte length")
        }
        let normalized = value.precomposedStringWithCanonicalMapping
        guard value.utf8.elementsEqual(normalized.utf8) else {
            throw LinuxServiceConfigurationError.invalid("\(name) must already be NFC")
        }
        return value
    }

    private static func boundedASCIIString(
        _ value: String,
        name: String,
        maximumBytes: Int
    ) throws -> String {
        let bytes = Array(value.utf8)
        guard (1 ... maximumBytes).contains(bytes.count),
              bytes.allSatisfy({ (0x20 ... 0x7e).contains($0) })
        else {
            throw LinuxServiceConfigurationError.invalid("\(name) must be bounded printable ASCII")
        }
        return value
    }

    private static func rejectControls(_ value: String, name: String) throws {
        guard !value.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }) else {
            throw LinuxServiceConfigurationError.invalid("\(name) contains a control character")
        }
    }

    private static func tlsPath(_ value: String, name: String) throws -> String {
        guard value.utf8.count <= 4_096 else {
            throw LinuxServiceConfigurationError.invalid("\(name) exceeds 4096 bytes")
        }
        try rejectControls(value, name: name)
        guard value.hasPrefix("/etc/reach/"),
              value != "/etc/reach/",
              !value.split(separator: "/", omittingEmptySubsequences: false).contains("."),
              !value.split(separator: "/", omittingEmptySubsequences: false).contains(".."),
              URL(fileURLWithPath: value).standardizedFileURL.path == value
        else {
            throw LinuxServiceConfigurationError.invalid("\(name) must be a canonical path below /etc/reach")
        }
        return value
    }
}

enum NumericAddress {
    static func canonical(_ source: String) throws -> String {
        var ipv4 = in_addr()
        if source.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            var output = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &ipv4, &output, socklen_t(output.count)) != nil else {
                throw LinuxServiceConfigurationError.system("inet_ntop", errno)
            }
            return String(
                decoding: output.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
                as: UTF8.self
            )
        }
        var ipv6 = in6_addr()
        if source.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &ipv6, &output, socklen_t(output.count)) != nil else {
                throw LinuxServiceConfigurationError.system("inet_ntop", errno)
            }
            return String(
                decoding: output.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
                as: UTF8.self
            )
        }
        throw LinuxServiceConfigurationError.invalid("address must be numeric IPv4 or IPv6")
    }

    static func isWildcard(_ address: String) -> Bool {
        address == "0.0.0.0" || address == "::"
    }
}

enum LinuxSecureFile {
    struct Authority: Sendable, Equatable {
        var owner: uid_t
        var group: gid_t
        var mode: mode_t
    }

    static func validate(path: String, authority: Authority, allowedRoot: String) throws {
        let descriptor = try openValidated(path: path, authority: authority, allowedRoot: allowedRoot)
        guard close(descriptor) == 0 else {
            throw LinuxServiceConfigurationError.system("close", errno)
        }
    }

    static func read(
        path: String,
        authority: Authority,
        maximumBytes: Int,
        allowedRoot: String
    ) throws -> Data {
        let descriptor = try openValidated(path: path, authority: authority, allowedRoot: allowedRoot)
        defer { _ = close(descriptor) }
        var result = Data()
        result.reserveCapacity(min(maximumBytes, 16 * 1024))
        var buffer = [UInt8](repeating: 0, count: 8 * 1024)
        while true {
            let amount = Glibc.read(descriptor, &buffer, buffer.count)
            if amount == 0 { break }
            if amount < 0 {
                if errno == EINTR { continue }
                throw LinuxServiceConfigurationError.system("read", errno)
            }
            guard result.count + amount <= maximumBytes else {
                throw LinuxServiceConfigurationError.invalid("document exceeds 65536 bytes")
            }
            result.append(contentsOf: buffer.prefix(amount))
        }
        return result
    }

    private static func openValidated(
        path: String,
        authority: Authority,
        allowedRoot: String
    ) throws -> Int32 {
        let canonicalRoot = URL(fileURLWithPath: allowedRoot).standardizedFileURL.path
        let canonicalPath = URL(fileURLWithPath: path).standardizedFileURL.path
        guard path == canonicalPath,
              canonicalPath.hasPrefix(canonicalRoot + "/")
        else {
            throw LinuxServiceConfigurationError.unsafeFile("path escapes its declared root")
        }
        let relative = String(canonicalPath.dropFirst(canonicalRoot.count + 1))
        let components = relative.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty, components.allSatisfy({ !$0.isEmpty }) else {
            throw LinuxServiceConfigurationError.unsafeFile("path has an empty component")
        }

        var directory = allowedRoot.withCString {
            open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        }
        guard directory >= 0 else {
            throw LinuxServiceConfigurationError.system("open(root)", errno)
        }
        defer { _ = close(directory) }

        for component in components.dropLast() {
            let next = component.withCString {
                openat(directory, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
            }
            guard next >= 0 else {
                throw LinuxServiceConfigurationError.system("openat(directory)", errno)
            }
            _ = close(directory)
            directory = next
        }

        let descriptor = components.last!.withCString {
            openat(directory, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw LinuxServiceConfigurationError.system("openat(file)", errno)
        }
        do {
            var metadata = stat()
            guard fstat(descriptor, &metadata) == 0 else {
                throw LinuxServiceConfigurationError.system("fstat", errno)
            }
            guard metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else {
                throw LinuxServiceConfigurationError.unsafeFile("not a regular file")
            }
            guard metadata.st_nlink == 1 else {
                throw LinuxServiceConfigurationError.unsafeFile("hard-linked file")
            }
            guard metadata.st_uid == authority.owner, metadata.st_gid == authority.group else {
                throw LinuxServiceConfigurationError.unsafeFile("unexpected owner or group")
            }
            guard metadata.st_mode & 0o7777 == authority.mode else {
                throw LinuxServiceConfigurationError.unsafeFile("unexpected mode")
            }
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }
}

private indirect enum StrictJSONValue: Sendable, Equatable {
    case object([String: StrictJSONValue])
    case array([StrictJSONValue])
    case string(String)
    case number(String)
    case bool(Bool)
    case null

    func exactObject(keys: Set<String>, at location: String) throws -> [String: Self] {
        guard case .object(let object) = self else {
            throw LinuxServiceConfigurationError.invalid("\(location) must be an object")
        }
        guard Set(object.keys) == keys else {
            throw LinuxServiceConfigurationError.invalid("\(location) has missing or unknown members")
        }
        return object
    }

    func array(at location: String) throws -> [Self] {
        guard case .array(let values) = self else {
            throw LinuxServiceConfigurationError.invalid("\(location) must be an array")
        }
        return values
    }
}

private extension Dictionary where Key == String, Value == StrictJSONValue {
    func required(_ key: String) throws -> Value {
        guard let value = self[key] else {
            throw LinuxServiceConfigurationError.invalid("missing \(key)")
        }
        return value
    }

    func requiredString(_ key: String) throws -> String {
        guard case .string(let value) = try required(key) else {
            throw LinuxServiceConfigurationError.invalid("\(key) must be a string")
        }
        return value
    }

    func requiredNumber(_ key: String) throws -> String {
        guard case .number(let value) = try required(key) else {
            throw LinuxServiceConfigurationError.invalid("\(key) must be a number")
        }
        return value
    }
}

private struct StrictJSONParser {
    let bytes: [UInt8]
    var index = 0

    mutating func parseDocument() throws -> StrictJSONValue {
        skipWhitespace()
        let value = try parseValue()
        skipWhitespace()
        guard index == bytes.count else {
            throw LinuxServiceConfigurationError.invalid("trailing JSON value")
        }
        return value
    }

    private mutating func parseValue() throws -> StrictJSONValue {
        guard index < bytes.count else { return try malformed() }
        switch bytes[index] {
        case 0x7b: return try parseObject()
        case 0x5b: return try parseArray()
        case 0x22: return .string(try parseString())
        case 0x74: try consume("true"); return .bool(true)
        case 0x66: try consume("false"); return .bool(false)
        case 0x6e: try consume("null"); return .null
        case 0x2d, 0x30 ... 0x39: return .number(try parseNumber())
        default: return try malformed()
        }
    }

    private mutating func parseObject() throws -> StrictJSONValue {
        index += 1
        skipWhitespace()
        var result: [String: StrictJSONValue] = [:]
        if take(0x7d) { return .object(result) }
        while true {
            guard index < bytes.count, bytes[index] == 0x22 else { return try malformed() }
            let key = try parseString()
            guard result[key] == nil else {
                throw LinuxServiceConfigurationError.invalid("duplicate JSON member")
            }
            skipWhitespace()
            guard take(0x3a) else { return try malformed() }
            skipWhitespace()
            result[key] = try parseValue()
            skipWhitespace()
            if take(0x7d) { break }
            guard take(0x2c) else { return try malformed() }
            skipWhitespace()
        }
        return .object(result)
    }

    private mutating func parseArray() throws -> StrictJSONValue {
        index += 1
        skipWhitespace()
        var result: [StrictJSONValue] = []
        if take(0x5d) { return .array(result) }
        while true {
            result.append(try parseValue())
            skipWhitespace()
            if take(0x5d) { break }
            guard take(0x2c) else { return try malformed() }
            skipWhitespace()
        }
        return .array(result)
    }

    private mutating func parseString() throws -> String {
        let start = index
        index += 1
        var escaped = false
        while index < bytes.count {
            let byte = bytes[index]
            if !escaped && byte == 0x22 {
                index += 1
                let data = Data(bytes[start ..< index])
                do {
                    return try JSONDecoder().decode(String.self, from: data)
                } catch {
                    throw LinuxServiceConfigurationError.invalid("malformed JSON string")
                }
            }
            if !escaped && byte < 0x20 { return try malformed() }
            if escaped {
                escaped = false
            } else if byte == 0x5c {
                escaped = true
            }
            index += 1
        }
        return try malformed()
    }

    private mutating func parseNumber() throws -> String {
        let start = index
        _ = take(0x2d)
        guard index < bytes.count else { return try malformed() }
        if take(0x30) {
            if index < bytes.count, (0x30 ... 0x39).contains(bytes[index]) {
                return try malformed()
            }
        } else {
            guard (0x31 ... 0x39).contains(bytes[index]) else { return try malformed() }
            index += 1
            while index < bytes.count, (0x30 ... 0x39).contains(bytes[index]) { index += 1 }
        }
        if take(0x2e) {
            guard index < bytes.count, (0x30 ... 0x39).contains(bytes[index]) else {
                return try malformed()
            }
            while index < bytes.count, (0x30 ... 0x39).contains(bytes[index]) { index += 1 }
        }
        if index < bytes.count, (bytes[index] == 0x65 || bytes[index] == 0x45) {
            index += 1
            if index < bytes.count, (bytes[index] == 0x2b || bytes[index] == 0x2d) { index += 1 }
            guard index < bytes.count, (0x30 ... 0x39).contains(bytes[index]) else {
                return try malformed()
            }
            while index < bytes.count, (0x30 ... 0x39).contains(bytes[index]) { index += 1 }
        }
        return String(decoding: bytes[start ..< index], as: UTF8.self)
    }

    private mutating func consume(_ literal: StaticString) throws {
        let expected = Array(String(describing: literal).utf8)
        guard index + expected.count <= bytes.count,
              bytes[index ..< index + expected.count].elementsEqual(expected)
        else { return try malformed() }
        index += expected.count
    }

    private mutating func skipWhitespace() {
        while index < bytes.count, [0x20, 0x09, 0x0a, 0x0d].contains(bytes[index]) {
            index += 1
        }
    }

    private mutating func take(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }

    private func malformed<T>() throws -> T {
        throw LinuxServiceConfigurationError.invalid("malformed JSON")
    }
}
