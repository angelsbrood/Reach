import Foundation
import CryptoKit
import Security
import Darwin

public enum RootKeyError: Error, Equatable { case invalid, unavailable, duplicate, os(String, Int32) }
public enum RootKeyRole: String, Codable, CaseIterable { case hostCatalog = "host-catalog", hostTicket = "host-ticket", clientMetadata = "client-metadata" }
public struct RootKeyReference: Codable, Equatable {
    public var bootstrap: String, identifier: String, role: RootKeyRole
    public init(bootstrap: String, identifier: String = UUID().uuidString.lowercased(), role: RootKeyRole) {
        self.bootstrap = bootstrap; self.identifier = identifier; self.role = role
    }
    public var service: String { "reach-s85:"+bootstrap }
    public var account: String { role.rawValue+":"+identifier }
    public func validate() throws { try RootKeyCodec.require(RootKeyCodec.uuid(bootstrap) && RootKeyCodec.uuid(identifier)) }
}
/// Storage keys have no Codable or message representation outside the protected record.
public struct RootKeyMaterial {
    private let bytes: Data
    public init(_ bytes: Data) throws { try RootKeyCodec.require(bytes.count == 32); self.bytes = bytes }
    public func use<T>(_ body: (Data) throws -> T) rethrows -> T { try body(bytes) }
    private func domain(_ reference: RootKeyReference, binding: String) throws -> Data {
        try reference.validate(); try RootKeyCodec.require(RootKeyCodec.digest(binding))
        return Data("S85/root-key-confirmation/v1\0".utf8)+Data(binding.utf8)+Data([0])+Data(try RootKeyCodec.encode(reference))
    }
    public func confirmation(_ reference: RootKeyReference, binding: String) throws -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: try domain(reference, binding: binding), using: SymmetricKey(data: bytes)))
    }
    public func confirm(_ expected: Data, reference: RootKeyReference, binding: String) throws {
        try RootKeyCodec.require(expected.count == 32 && HMAC<SHA256>.isValidAuthenticationCode(expected,
            authenticating: domain(reference, binding: binding), using: SymmetricKey(data: bytes)))
    }
}
public protocol RootKeyProvider: AnyObject {
    func create(_ reference: RootKeyReference, binding: String) throws -> RootKeyMaterial
    func load(_ reference: RootKeyReference, binding: String) throws -> RootKeyMaterial
}
public enum RootKeyCodec {
    public static func require(_ condition: Bool) throws { if !condition { throw RootKeyError.invalid } }
    public static func check(_ code: OSStatus, _ operation: String) throws {
        if code == errSecDuplicateItem { throw RootKeyError.duplicate }
        if code != errSecSuccess { throw RootKeyError.os(operation, code) }
    }
    public static func uuid(_ value: String) -> Bool { value.utf8.count == 36 && UUID(uuidString: value)?.uuidString.lowercased() == value }
    public static func digest(_ value: String) -> Bool { value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    public static func hash(_ value: Data) -> String { SHA256.hash(data: value).map { String(format: "%02x", $0) }.joined() }
    public static func encode<T: Encodable>(_ value: T, limit: Int = 4096) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value); try require(data.count <= limit); return data
    }
    public static func decode<T: Codable>(_ type: T.Type, _ bytes: Data, limit: Int = 4096) throws -> T {
        try require(bytes.count <= limit); let value = try JSONDecoder().decode(type, from: bytes)
        try require(encode(value, limit: limit) == bytes); return value
    }
    public static func random() throws -> Data {
        var bytes = Data(count: 32)
        try check(bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }, "new-storage-key")
        return bytes
    }
    public static func boot() throws -> String {
        var size = 0
        try require(sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0 && (2...256).contains(size))
        var data = [CChar](repeating: 0, count: size)
        try require(sysctlbyname("kern.bootsessionuuid", &data, &size, nil, 0) == 0 && data.last == 0)
        let result = String(cString: data).lowercased(); try require(uuid(result)); return result
    }
    public static func canonicalExisting(_ path: String) throws -> String {
        guard let pointer = realpath(path, nil) else { throw RootKeyError.unavailable }
        defer { free(pointer) }; return String(cString: pointer)
    }
    public static func parent(_ path: String) throws -> String {
        guard path.first == "/", !path.hasSuffix("/"), let slash = path.lastIndex(of: "/") else { throw RootKeyError.invalid }
        let parent = String(path[..<slash]), leaf = String(path[path.index(after: slash)...])
        try require(!["", ".", ".."].contains(leaf) && canonicalExisting(parent) == parent)
        try directory(parent); return parent
    }
    public static func directory(_ path: String) throws {
        var s = stat()
        try require(lstat(path, &s) == 0 && s.st_mode&S_IFMT == S_IFDIR && s.st_uid == getuid() && s.st_mode&0o7777 == 0o700)
    }
    public static func regular(_ path: String, maximum: Int, mode: mode_t? = nil) throws -> stat {
        var s = stat()
        try require(lstat(path, &s) == 0 && s.st_mode&S_IFMT == S_IFREG && s.st_uid == getuid() && s.st_nlink == 1 &&
            s.st_size >= 0 && s.st_size <= maximum && (mode == nil || s.st_mode&0o7777 == mode!))
        return s
    }
}
public struct FrozenWorker: Codable, Equatable {
    public let path: String, sha256: String
    public init(path: String, sha256: String) { self.path = path; self.sha256 = sha256 }
    public func validate() throws {
        _ = try RootKeyCodec.parent(path); try RootKeyCodec.require(RootKeyCodec.canonicalExisting(path) == path && RootKeyCodec.digest(sha256))
        _ = try RootKeyCodec.regular(path, maximum: 192<<20, mode: 0o700)
        try RootKeyCodec.require(RootKeyCodec.hash(Data(contentsOf: URL(fileURLWithPath: path))) == sha256)
    }
}
