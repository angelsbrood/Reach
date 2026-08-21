import CryptoKit
import Foundation

public enum ReleasePackageError: Error, CustomStringConvertible, Equatable {
  case invalidArgument(String)
  case invalidConfiguration(String)
  case sourceAuthority(String)
  case unsafePath(String)
  case processFailure(String)
  case verification(String)

  public var description: String {
    switch self {
    case .invalidArgument(let value): "invalid argument: \(value)"
    case .invalidConfiguration(let value): "invalid release configuration: \(value)"
    case .sourceAuthority(let value): "release source refused: \(value)"
    case .unsafePath(let value): "unsafe release path: \(value)"
    case .processFailure(let value): "release command failed: \(value)"
    case .verification(let value): "release verification failed: \(value)"
    }
  }
}

public struct DottedVersion: Codable, Hashable, Comparable, Sendable, CustomStringConvertible {
  public let components: [UInt64]

  public init(_ raw: String) throws {
    let pieces = raw.split(separator: ".", omittingEmptySubsequences: false)
    guard !pieces.isEmpty else {
      throw ReleasePackageError.invalidConfiguration("version is empty")
    }
    var parsed: [UInt64] = []
    for piece in pieces {
      guard !piece.isEmpty,
        piece.allSatisfy({ $0.isNumber }),
        piece == "0" || piece.first != "0",
        let value = UInt64(piece)
      else {
        throw ReleasePackageError.invalidConfiguration(
          "version \"\(raw)\" is not canonical dotted integers")
      }
      parsed.append(value)
    }
    guard parsed.count == 3 else {
      throw ReleasePackageError.invalidConfiguration(
        "version \"\(raw)\" must contain exactly three components")
    }
    components = parsed
  }

  public var description: String { components.map(String.init).joined(separator: ".") }

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    try self.init(container.decode(String.self))
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(description)
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.components.lexicographicallyPrecedes(rhs.components)
  }
}

public struct ReleaseConfiguration: Codable, Equatable, Sendable {
  public struct Product: Codable, Equatable, Sendable {
    public let name: String
    public let version: DottedVersion
    public let architecture: String
    public let minimumMacOS: DottedVersion
  }

  public struct Component: Codable, Equatable, Sendable {
    public let identifier: String
    public let version: DottedVersion
  }

  public struct Components: Codable, Equatable, Sendable {
    public let host: Component
    public let helper: Component
  }

  public struct Compatibility: Codable, Equatable, Sendable {
    public let wireDialects: [Int]
    public let helperStatusVersions: [Int]
    public let helperSpecificationVersions: [Int]
    public let hostMinimum: DottedVersion
    public let hostMaximum: DottedVersion
    public let helperMinimum: DottedVersion
    public let helperMaximum: DottedVersion
  }

  public let schemaVersion: Int
  public let product: Product
  public let components: Components
  public let compatibility: Compatibility
  public let consumedVersions: [String: [DottedVersion]]
  public let hostBundles: [String]
  public let untrackedAllowlist: [String]

  public static func load(from url: URL) throws -> Self {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let object = try requireObjectKeys(
      data,
      expected: [
        "schemaVersion", "product", "components", "compatibility", "consumedVersions",
        "hostBundles", "untrackedAllowlist",
      ], label: "release configuration")
    try requireObjectKeys(
      object["product"],
      expected: ["name", "version", "architecture", "minimumMacOS"],
      label: "release product")
    let components = try requireObjectKeys(
      object["components"], expected: ["host", "helper"], label: "release components")
    for name in ["host", "helper"] {
      try requireObjectKeys(
        components[name], expected: ["identifier", "version"], label: "release \(name) component")
    }
    try requireObjectKeys(
      object["compatibility"],
      expected: [
        "wireDialects", "helperStatusVersions", "helperSpecificationVersions", "hostMinimum",
        "hostMaximum", "helperMinimum", "helperMaximum",
      ],
      label: "release compatibility")
    try requireObjectKeys(
      object["consumedVersions"],
      expected: ["systems.reach.host", "systems.reach.meshd"],
      label: "consumed versions")
    let decoded = try JSONDecoder().decode(Self.self, from: data)
    try decoded.validate()
    return decoded
  }

  public func validate() throws {
    guard schemaVersion == 1 else {
      throw ReleasePackageError.invalidConfiguration("unsupported schema version \(schemaVersion)")
    }
    guard product.name == "Reach",
      product.version.description == "0.0.1",
      product.architecture == "arm64",
      product.minimumMacOS.description == "27.0.0"
    else {
      throw ReleasePackageError.invalidConfiguration(
        "the first product authority must remain Reach 0.0.1 arm64 for macOS 27.0.0")
    }
    guard components.host.identifier == "systems.reach.host",
      components.host.version.description == "0.0.1",
      components.helper.identifier == "systems.reach.meshd",
      components.helper.version.description == "1.0.1"
    else {
      throw ReleasePackageError.invalidConfiguration(
        "component identifiers or frozen first versions changed")
    }
    guard compatibility.wireDialects == [1, 0],
      compatibility.helperStatusVersions == [1, 2],
      compatibility.helperSpecificationVersions == [1, 2],
      compatibility.hostMinimum == components.host.version,
      compatibility.hostMaximum == components.host.version,
      compatibility.helperMinimum == components.helper.version,
      compatibility.helperMaximum == components.helper.version
    else {
      throw ReleasePackageError.invalidConfiguration(
        "compatibility must bind the exact first component pair and the existing protocol ranges")
    }
    let expectedBundles = [
      "mlx-swift_Cmlx.bundle",
      "swift-crypto_CCryptoBoringSSL.bundle",
      "swift-crypto_CCryptoBoringSSLShims.bundle",
      "swift-crypto_Crypto.bundle",
      "swift-crypto_CryptoBoringWrapper.bundle",
      "swift-crypto_CryptoExtras.bundle",
      "swift-transformers_Hub.bundle",
    ]
    guard hostBundles == expectedBundles else {
      throw ReleasePackageError.invalidConfiguration("the seven-item bundle allowlist changed")
    }
    guard untrackedAllowlist == ["tasks/"] else {
      throw ReleasePackageError.invalidConfiguration(
        "only tasks/ may be an untracked release-source exclusion")
    }
    let consumedHelper = try DottedVersion("1.0.0")
    guard
      Set(consumedVersions.keys)
        == Set([components.host.identifier, components.helper.identifier]),
      consumedVersions[components.host.identifier] == [],
      consumedVersions[components.helper.identifier] == [consumedHelper],
      consumedHelper < components.helper.version,
      consumedVersions[components.helper.identifier]?.contains(components.helper.version) != true,
      consumedVersions[components.host.identifier]?.contains(components.host.version) != true
    else {
      throw ReleasePackageError.invalidConfiguration(
        "consumed-version authority is inconsistent with the first package")
    }
  }
}

public struct NoticeAuthority: Codable, Equatable, Sendable {
  public struct Pin: Codable, Equatable, Sendable {
    public let identity: String
    public let revision: String
  }

  public struct Module: Codable, Equatable, Sendable {
    public let path: String
    public let revision: String
  }

  public struct Family: Codable, Equatable, Sendable {
    public let id: String
    public let scope: String
    public let sourceRoot: String
    public let licensePaths: [String]
    public let noticePaths: [String]
  }

  public let schemaVersion: Int
  public let expectedSwiftPins: [Pin]
  public let expectedGoModules: [Module]
  public let families: [Family]

  public static func load(from url: URL) throws -> Self {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let object = try requireObjectKeys(
      data,
      expected: ["schemaVersion", "expectedSwiftPins", "expectedGoModules", "families"],
      label: "notice authority"
    )
    guard let pins = object["expectedSwiftPins"] as? [Any],
      let modules = object["expectedGoModules"] as? [Any],
      let families = object["families"] as? [Any]
    else {
      throw ReleasePackageError.invalidConfiguration("notice authority arrays are malformed")
    }
    for (index, pin) in pins.enumerated() {
      try requireObjectKeys(
        pin, expected: ["identity", "revision"], label: "notice Swift pin \(index)")
    }
    for (index, module) in modules.enumerated() {
      try requireObjectKeys(
        module, expected: ["path", "revision"], label: "notice Go module \(index)")
    }
    for (index, family) in families.enumerated() {
      try requireObjectKeys(
        family,
        expected: ["id", "scope", "sourceRoot", "licensePaths", "noticePaths"],
        label: "notice family \(index)")
    }
    let decoded = try JSONDecoder().decode(Self.self, from: data)
    guard decoded.schemaVersion == 1 else {
      throw ReleasePackageError.invalidConfiguration("unsupported notice schema version")
    }
    guard
      decoded.expectedSwiftPins.map(\.identity)
        == decoded.expectedSwiftPins.map(\.identity).sorted(),
      Set(decoded.expectedSwiftPins.map(\.identity)).count == decoded.expectedSwiftPins.count,
      decoded.expectedGoModules.map(\.path) == decoded.expectedGoModules.map(\.path).sorted(),
      Set(decoded.expectedGoModules.map(\.path)).count == decoded.expectedGoModules.count
    else {
      throw ReleasePackageError.invalidConfiguration(
        "notice dependency authorities must be unique and sorted")
    }
    guard Set(decoded.families.map(\.id)).count == decoded.families.count,
      decoded.families.allSatisfy({ family in
        family.licensePaths == family.licensePaths.sorted()
          && Set(family.licensePaths).count == family.licensePaths.count
          && family.noticePaths == family.noticePaths.sorted()
          && Set(family.noticePaths).count == family.noticePaths.count
      })
    else {
      throw ReleasePackageError.invalidConfiguration(
        "notice families and their input paths must be unique and sorted")
    }
    return decoded
  }

  public var swiftPins: [String] { expectedSwiftPins.map(\.identity) }
  public var goModules: [String] { expectedGoModules.map(\.path) }
}

@discardableResult
private func requireObjectKeys(_ data: Data, expected: Set<String>, label: String) throws
  -> [String: Any]
{
  try requireObjectKeys(
    try JSONSerialization.jsonObject(with: data), expected: expected, label: label)
}

@discardableResult
private func requireObjectKeys(_ value: Any?, expected: Set<String>, label: String) throws
  -> [String: Any]
{
  guard let object = value as? [String: Any], Set(object.keys) == expected else {
    throw ReleasePackageError.invalidConfiguration(
      "\(label) contains unknown or missing fields")
  }
  return object
}

public enum CanonicalJSON {
  public static func encode<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    var data = try encoder.encode(value)
    data.append(0x0A)
    return data
  }
}

public enum Digests {
  public static func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  public static func sha256(file url: URL) throws -> String {
    guard let stream = InputStream(url: url) else {
      throw ReleasePackageError.verification("cannot open \(url.path) for hashing")
    }
    stream.open()
    defer { stream.close() }
    var hasher = SHA256()
    let capacity = 1024 * 1024
    var buffer = [UInt8](repeating: 0, count: capacity)
    while stream.hasBytesAvailable {
      let count = stream.read(&buffer, maxLength: capacity)
      if count < 0 {
        throw stream.streamError
          ?? ReleasePackageError.verification("hash read failed for \(url.path)")
      }
      if count == 0 { break }
      hasher.update(data: Data(buffer[0..<count]))
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
  }
}
