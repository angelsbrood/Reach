import Foundation

public enum ReleaseComponentDisposition: String, Codable, Equatable, Sendable {
  case changed
  case unchanged
}

public struct ReleaseVersionMap: Codable, Equatable, Sendable {
  public let product: DottedVersion
  public let host: DottedVersion
  public let helper: DottedVersion

  public init(product: DottedVersion, host: DottedVersion, helper: DottedVersion) {
    self.product = product
    self.host = host
    self.helper = helper
  }
}

public struct ReleaseComponentDispositions: Codable, Equatable, Sendable {
  public let host: ReleaseComponentDisposition
  public let helper: ReleaseComponentDisposition

  public init(host: ReleaseComponentDisposition, helper: ReleaseComponentDisposition) {
    self.host = host
    self.helper = helper
  }
}

/// Release lineage is intentionally a closed sum type. A replacement records
/// the exact unavailable historical lineage it supersedes; it is not a parent
/// and cannot authorize rollback. A successor names a complete, retained P5
/// parent and its signed provenance. Callers cannot substitute loose hashes.
public enum ReleaseLineage: Equatable, Sendable {
  public struct Replacement: Codable, Equatable, Sendable {
    public let predecessor: ReleaseVersionMap
    public let historicalP5Reference: String
    public let components: ReleaseComponentDispositions

    public init(
      predecessor: ReleaseVersionMap,
      historicalP5Reference: String,
      components: ReleaseComponentDispositions
    ) {
      self.predecessor = predecessor
      self.historicalP5Reference = historicalP5Reference
      self.components = components
    }
  }

  public struct Successor: Codable, Equatable, Sendable {
    public let parent: ReleaseVersionMap
    public let parentP5SHA256: String
    public let parentProvenanceSHA256: String
    public let components: ReleaseComponentDispositions

    public init(
      parent: ReleaseVersionMap,
      parentP5SHA256: String,
      parentProvenanceSHA256: String,
      components: ReleaseComponentDispositions
    ) {
      self.parent = parent
      self.parentP5SHA256 = parentP5SHA256
      self.parentProvenanceSHA256 = parentProvenanceSHA256
      self.components = components
    }
  }

  case replacement(Replacement)
  case successor(Successor)

  public var predecessor: ReleaseVersionMap {
    switch self {
    case .replacement(let value): value.predecessor
    case .successor(let value): value.parent
    }
  }

  public var components: ReleaseComponentDispositions {
    switch self {
    case .replacement(let value): value.components
    case .successor(let value): value.components
    }
  }
}

extension ReleaseLineage: Codable {
  private enum CodingKeys: String, CodingKey {
    case kind, predecessor, historicalP5Reference, parent, parentP5SHA256
    case parentProvenanceSHA256, components
  }

  private enum Kind: String, Codable {
    case replacement
    case successor
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    switch try container.decode(Kind.self, forKey: .kind) {
    case .replacement:
      self = .replacement(
        .init(
          predecessor: try container.decode(ReleaseVersionMap.self, forKey: .predecessor),
          historicalP5Reference: try container.decode(
            String.self, forKey: .historicalP5Reference),
          components: try container.decode(
            ReleaseComponentDispositions.self, forKey: .components)))
    case .successor:
      self = .successor(
        .init(
          parent: try container.decode(ReleaseVersionMap.self, forKey: .parent),
          parentP5SHA256: try container.decode(String.self, forKey: .parentP5SHA256),
          parentProvenanceSHA256: try container.decode(
            String.self, forKey: .parentProvenanceSHA256),
          components: try container.decode(
            ReleaseComponentDispositions.self, forKey: .components)))
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .replacement(let value):
      try container.encode(Kind.replacement, forKey: .kind)
      try container.encode(value.predecessor, forKey: .predecessor)
      try container.encode(value.historicalP5Reference, forKey: .historicalP5Reference)
      try container.encode(value.components, forKey: .components)
    case .successor(let value):
      try container.encode(Kind.successor, forKey: .kind)
      try container.encode(value.parent, forKey: .parent)
      try container.encode(value.parentP5SHA256, forKey: .parentP5SHA256)
      try container.encode(value.parentProvenanceSHA256, forKey: .parentProvenanceSHA256)
      try container.encode(value.components, forKey: .components)
    }
  }
}
