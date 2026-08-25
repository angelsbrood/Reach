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
  public let lineage: ReleaseLineage?
  public let consumedProductVersions: [DottedVersion]?
  public let consumedVersions: [String: [DottedVersion]]
  public let hostBundles: [String]
  public let untrackedAllowlist: [String]

  public static func load(from url: URL) throws -> Self {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      let schemaVersion = raw["schemaVersion"] as? Int
    else {
      throw ReleasePackageError.invalidConfiguration(
        "release configuration schema version is missing")
    }
    let expectedTopLevel: Set<String>
    switch schemaVersion {
    case 1:
      expectedTopLevel = [
        "schemaVersion", "product", "components", "compatibility", "consumedVersions",
        "hostBundles", "untrackedAllowlist",
      ]
    case 2:
      expectedTopLevel = [
        "schemaVersion", "product", "components", "compatibility", "lineage",
        "consumedProductVersions", "consumedVersions", "hostBundles", "untrackedAllowlist",
      ]
    default:
      throw ReleasePackageError.invalidConfiguration(
        "unsupported schema version \(schemaVersion)")
    }
    let object = try requireObjectKeys(
      raw, expected: expectedTopLevel, label: "release configuration")
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
    if schemaVersion == 2 {
      try validateLineageObject(object["lineage"])
    }
    let decoded = try JSONDecoder().decode(Self.self, from: data)
    try decoded.validate()
    return decoded
  }

  public func validate() throws {
    guard product.name == "Reach",
      product.architecture == "arm64",
      product.minimumMacOS.description == "27.0.0"
    else {
      throw ReleasePackageError.invalidConfiguration(
        "product authority must remain Reach arm64 for macOS 27.0.0")
    }
    guard components.host.identifier == "systems.reach.host",
      components.helper.identifier == "systems.reach.meshd"
    else {
      throw ReleasePackageError.invalidConfiguration(
        "component identifiers changed")
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
        "compatibility must bind the exact component pair and the existing protocol ranges")
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
    guard
      Set(consumedVersions.keys)
        == Set([components.host.identifier, components.helper.identifier])
    else {
      throw ReleasePackageError.invalidConfiguration("consumed-version component set changed")
    }
    switch schemaVersion {
    case 1: try validateHistoricalFirstRelease()
    case 2: try validateMultiRelease()
    default:
      throw ReleasePackageError.invalidConfiguration("unsupported schema version \(schemaVersion)")
    }
  }

  private func validateHistoricalFirstRelease() throws {
    let consumedHelper = try DottedVersion("1.0.0")
    guard product.version.description == "0.0.1",
      components.host.version.description == "0.0.1",
      components.helper.version.description == "1.0.1",
      lineage == nil,
      consumedProductVersions == nil,
      consumedVersions[components.host.identifier] == [],
      consumedVersions[components.helper.identifier] == [consumedHelper]
    else {
      throw ReleasePackageError.invalidConfiguration(
        "historical schema-1 first-release authority changed")
    }
  }

  private func validateMultiRelease() throws {
    guard let lineage, let consumedProductVersions else {
      throw ReleasePackageError.invalidConfiguration(
        "schema-2 releases require explicit lineage and consumed product versions")
    }
    try requireCanonicalConsumedVersions(consumedProductVersions, current: product.version)
    guard consumedProductVersions.contains(lineage.predecessor.product) else {
      throw ReleasePackageError.invalidConfiguration(
        "the predecessor product version is absent from consumed authority")
    }
    try validateComponentLineage(
      current: components.host.version,
      predecessor: lineage.predecessor.host,
      disposition: lineage.components.host,
      consumed: consumedVersions[components.host.identifier] ?? [],
      label: "host")
    try validateComponentLineage(
      current: components.helper.version,
      predecessor: lineage.predecessor.helper,
      disposition: lineage.components.helper,
      consumed: consumedVersions[components.helper.identifier] ?? [],
      label: "helper")

    switch lineage {
    case .replacement(let replacement):
      let historical = ReleaseVersionMap(
        product: try DottedVersion("0.0.1"),
        host: try DottedVersion("0.0.1"),
        helper: try DottedVersion("1.0.1"))
      guard product.version.description == "0.0.2",
        components.host.version.description == "0.0.2",
        components.helper.version.description == "1.0.2",
        replacement.predecessor == historical,
        replacement.historicalP5Reference
          == "sha256-abbrev:97397473…6389f;size:13741205",
        replacement.components
          == .init(host: .changed, helper: .changed)
      else {
        throw ReleasePackageError.invalidConfiguration(
          "replacement authority does not match the founder-selected S35 successor")
      }
    case .successor(let successor):
      let replacement = ReleaseVersionMap(
        product: try DottedVersion("0.0.2"),
        host: try DottedVersion("0.0.2"),
        helper: try DottedVersion("1.0.2"))
      guard product.version.description == "0.0.3",
        components.host.version.description == "0.0.3",
        components.helper.version.description == "1.0.2",
        successor.parent == replacement,
        successor.components == .init(host: .changed, helper: .unchanged),
        validSHA256(successor.parentP5SHA256),
        validSHA256(successor.parentProvenanceSHA256)
      else {
        throw ReleasePackageError.invalidConfiguration(
          "successor authority does not match the founder-selected replacement update")
      }
    }
  }

  private func validateComponentLineage(
    current: DottedVersion,
    predecessor: DottedVersion,
    disposition: ReleaseComponentDisposition,
    consumed: [DottedVersion],
    label: String
  ) throws {
    try requireCanonicalConsumedVersions(
      consumed, current: current, allowCurrent: disposition == .unchanged)
    guard consumed.contains(predecessor) else {
      throw ReleasePackageError.invalidConfiguration(
        "the predecessor \(label) version is absent from consumed authority")
    }
    switch disposition {
    case .changed:
      guard predecessor < current else {
        throw ReleasePackageError.invalidConfiguration(
          "changed \(label) bytes require a higher component version")
      }
    case .unchanged:
      guard predecessor == current else {
        throw ReleasePackageError.invalidConfiguration(
          "unchanged \(label) bytes must retain the parent component version")
      }
    }
  }

  private func requireCanonicalConsumedVersions(
    _ versions: [DottedVersion], current: DottedVersion, allowCurrent: Bool = false
  ) throws {
    guard versions == versions.sorted(), Set(versions).count == versions.count,
      versions.allSatisfy({ $0 < current || (allowCurrent && $0 == current) }),
      !versions.isEmpty
    else {
      throw ReleasePackageError.invalidConfiguration(
        "consumed versions must be unique, ordered, and precede the selected version")
    }
  }

  private func validSHA256(_ value: String) -> Bool {
    value.count == 64 && value.allSatisfy(\.isHexDigit)
  }

  private static func validateLineageObject(_ value: Any?) throws {
    let lineage = try requireObjectKeys(
      value,
      allowed: [
        "kind", "predecessor", "historicalP5Reference", "parent", "parentP5SHA256",
        "parentProvenanceSHA256", "components",
      ],
      required: ["kind", "components"],
      label: "release lineage")
    guard let kind = lineage["kind"] as? String else {
      throw ReleasePackageError.invalidConfiguration("release lineage kind is malformed")
    }
    switch kind {
    case "replacement":
      guard
        Set(lineage.keys)
          == Set([
            "kind", "predecessor", "historicalP5Reference", "components",
          ])
      else {
        throw ReleasePackageError.invalidConfiguration(
          "replacement lineage fields are incomplete or unknown")
      }
      try requireObjectKeys(
        lineage["predecessor"], expected: ["product", "host", "helper"],
        label: "replacement predecessor")
    case "successor":
      guard
        Set(lineage.keys)
          == Set([
            "kind", "parent", "parentP5SHA256", "parentProvenanceSHA256", "components",
          ])
      else {
        throw ReleasePackageError.invalidConfiguration(
          "successor lineage fields are incomplete or unknown")
      }
      try requireObjectKeys(
        lineage["parent"], expected: ["product", "host", "helper"],
        label: "successor parent")
    default:
      throw ReleasePackageError.invalidConfiguration("unknown release lineage kind")
    }
    try requireObjectKeys(
      lineage["components"], expected: ["host", "helper"],
      label: "release component dispositions")
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

@discardableResult
private func requireObjectKeys(
  _ value: Any?, allowed: Set<String>, required: Set<String>, label: String
) throws -> [String: Any] {
  guard let object = value as? [String: Any],
    Set(object.keys).isSubset(of: allowed),
    required.isSubset(of: Set(object.keys))
  else {
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
