import Darwin
import Foundation

public struct ReleaseLineageAuthority: Codable, Equatable, Sendable {
  public struct Component: Codable, Equatable, Sendable {
    public let identifier: String
    public let version: DottedVersion
    public let disposition: ReleaseComponentDisposition
    public let unsignedComponent: ReleaseProvenance.Artifact

    public init(
      identifier: String,
      version: DottedVersion,
      disposition: ReleaseComponentDisposition,
      unsignedComponent: ReleaseProvenance.Artifact
    ) {
      self.identifier = identifier
      self.version = version
      self.disposition = disposition
      self.unsignedComponent = unsignedComponent
    }
  }

  public struct HistoricalPredecessor: Codable, Equatable, Sendable {
    public let versions: ReleaseVersionMap
    public let p5Reference: String
    public let availability: String

    public init(versions: ReleaseVersionMap, p5Reference: String, availability: String) {
      self.versions = versions
      self.p5Reference = p5Reference
      self.availability = availability
    }
  }

  public struct RetainedParent: Codable, Equatable, Sendable {
    public let versions: ReleaseVersionMap
    public let p5: ReleaseProvenance.Artifact
    public let provenance: ReleaseProvenance.Artifact
    public let hostLeaf: ReleaseProvenance.Artifact
    public let helperLeaf: ReleaseProvenance.Artifact
    public let hostComponent: ReleaseProvenance.Artifact
    public let helperComponent: ReleaseProvenance.Artifact

    public init(
      versions: ReleaseVersionMap,
      p5: ReleaseProvenance.Artifact,
      provenance: ReleaseProvenance.Artifact,
      hostLeaf: ReleaseProvenance.Artifact,
      helperLeaf: ReleaseProvenance.Artifact,
      hostComponent: ReleaseProvenance.Artifact,
      helperComponent: ReleaseProvenance.Artifact
    ) {
      self.versions = versions
      self.p5 = p5
      self.provenance = provenance
      self.hostLeaf = hostLeaf
      self.helperLeaf = helperLeaf
      self.hostComponent = hostComponent
      self.helperComponent = helperComponent
    }
  }

  public enum Predecessor: Equatable, Sendable {
    case unavailableHistorical(HistoricalPredecessor)
    case retained(RetainedParent)
  }

  public let schemaVersion: Int
  public let release: ReleaseVersionMap
  public let declaration: ReleaseLineage
  public let releaseConfigurationSHA256: String
  public let unsignedProvenanceSHA256: String
  public let sourceCommit: String
  public let unsignedToolSourceSHA256: String
  public let unsignedContainer: ReleaseProvenance.Artifact
  public let normalizedSemanticSHA256: String
  public let components: [Component]
  public let predecessor: Predecessor

  public init(
    schemaVersion: Int,
    release: ReleaseVersionMap,
    declaration: ReleaseLineage,
    releaseConfigurationSHA256: String,
    unsignedProvenanceSHA256: String,
    sourceCommit: String,
    unsignedToolSourceSHA256: String,
    unsignedContainer: ReleaseProvenance.Artifact,
    normalizedSemanticSHA256: String,
    components: [Component],
    predecessor: Predecessor
  ) {
    self.schemaVersion = schemaVersion
    self.release = release
    self.declaration = declaration
    self.releaseConfigurationSHA256 = releaseConfigurationSHA256
    self.unsignedProvenanceSHA256 = unsignedProvenanceSHA256
    self.sourceCommit = sourceCommit
    self.unsignedToolSourceSHA256 = unsignedToolSourceSHA256
    self.unsignedContainer = unsignedContainer
    self.normalizedSemanticSHA256 = normalizedSemanticSHA256
    self.components = components
    self.predecessor = predecessor
  }

  public static func load(from url: URL) throws -> Self {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let decoded = try JSONDecoder().decode(Self.self, from: data)
    guard data == (try CanonicalJSON.encode(decoded)) else {
      throw ReleasePackageError.verification("release lineage authority is not canonical JSON")
    }
    try decoded.validateStructure()
    return decoded
  }

  public func validate(configuration: ReleaseConfiguration, configurationURL: URL) throws {
    try validateStructure()
    guard configuration.schemaVersion == 2,
      release
        == .init(
          product: configuration.product.version,
          host: configuration.components.host.version,
          helper: configuration.components.helper.version),
      declaration == configuration.lineage,
      releaseConfigurationSHA256 == (try Digests.sha256(file: configurationURL)),
      components
        == [
          .init(
            identifier: configuration.components.host.identifier,
            version: configuration.components.host.version,
            disposition: declaration.components.host,
            unsignedComponent: components[0].unsignedComponent),
          .init(
            identifier: configuration.components.helper.identifier,
            version: configuration.components.helper.version,
            disposition: declaration.components.helper,
            unsignedComponent: components[1].unsignedComponent),
        ]
    else {
      throw ReleasePackageError.verification(
        "release lineage does not match the selected configuration")
    }
    switch (declaration, predecessor) {
    case (.replacement(let declared), .unavailableHistorical(let actual)):
      guard actual.versions == declared.predecessor,
        actual.p5Reference == declared.historicalP5Reference,
        actual.availability == "unavailable-no-rollback-authority"
      else {
        throw ReleasePackageError.verification(
          "replacement lineage predecessor authority changed")
      }
    case (.successor(let declared), .retained(let actual)):
      guard actual.versions == declared.parent,
        actual.p5.sha256 == declared.parentP5SHA256,
        actual.provenance.sha256 == declared.parentProvenanceSHA256
      else {
        throw ReleasePackageError.verification("successor parent authority changed")
      }
    default:
      throw ReleasePackageError.verification(
        "release lineage predecessor kind does not match its declaration")
    }
  }

  public func validateStructure() throws {
    let expectedIdentifiers = ["systems.reach.host", "systems.reach.meshd"]
    guard schemaVersion == 1,
      sourceCommit.count == 40 && sourceCommit.allSatisfy(\.isHexDigit),
      validSHA256(releaseConfigurationSHA256),
      validSHA256(unsignedProvenanceSHA256),
      validSHA256(unsignedToolSourceSHA256),
      validSHA256(normalizedSemanticSHA256),
      validArtifact(unsignedContainer),
      components.map(\.identifier) == expectedIdentifiers,
      components.allSatisfy({ validArtifact($0.unsignedComponent) })
    else {
      throw ReleasePackageError.verification("release lineage authority is malformed")
    }
    switch predecessor {
    case .unavailableHistorical(let value):
      guard value.availability == "unavailable-no-rollback-authority",
        value.p5Reference == "sha256-abbrev:97397473…6389f;size:13741205"
      else {
        throw ReleasePackageError.verification(
          "historical predecessor authority is malformed")
      }
    case .retained(let value):
      guard
        [
          value.p5, value.provenance, value.hostLeaf, value.helperLeaf,
          value.hostComponent, value.helperComponent,
        ].allSatisfy(validArtifact)
      else {
        throw ReleasePackageError.verification("retained parent authority is malformed")
      }
    }
  }

  private func validSHA256(_ value: String) -> Bool {
    value.count == 64 && value.allSatisfy(\.isHexDigit)
  }

  private func validArtifact(_ artifact: ReleaseProvenance.Artifact) -> Bool {
    !artifact.path.isEmpty && artifact.size > 0 && validSHA256(artifact.sha256)
  }
}

extension ReleaseLineageAuthority.Predecessor: Codable {
  private enum CodingKeys: String, CodingKey {
    case kind, historical, retained
  }

  private enum Kind: String, Codable {
    case unavailableHistorical
    case retained
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    switch try container.decode(Kind.self, forKey: .kind) {
    case .unavailableHistorical:
      self = .unavailableHistorical(
        try container.decode(
          ReleaseLineageAuthority.HistoricalPredecessor.self, forKey: .historical))
    case .retained:
      self = .retained(
        try container.decode(ReleaseLineageAuthority.RetainedParent.self, forKey: .retained))
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .unavailableHistorical(let value):
      try container.encode(Kind.unavailableHistorical, forKey: .kind)
      try container.encode(value, forKey: .historical)
    case .retained(let value):
      try container.encode(Kind.retained, forKey: .kind)
      try container.encode(value, forKey: .retained)
    }
  }
}

public struct MultiReleaseSignedProvenance: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let lineage: ReleaseLineageAuthority
  public let p0: ReleaseProvenance.SourceStage
  public let p1: ReleaseProvenance.PayloadStage
  public let u1: ReleaseProvenance.UnsignedStage
  public let p2: SignedReleaseProvenance.SignedPayloadStage
  public let p3: SignedReleaseProvenance.SignedContainerStage
  public let p4: SignedReleaseProvenance.NotarizationStage?
  public let p5: SignedReleaseProvenance.StapledStage?

  public init(
    schemaVersion: Int,
    lineage: ReleaseLineageAuthority,
    p0: ReleaseProvenance.SourceStage,
    p1: ReleaseProvenance.PayloadStage,
    u1: ReleaseProvenance.UnsignedStage,
    p2: SignedReleaseProvenance.SignedPayloadStage,
    p3: SignedReleaseProvenance.SignedContainerStage,
    p4: SignedReleaseProvenance.NotarizationStage? = nil,
    p5: SignedReleaseProvenance.StapledStage? = nil
  ) {
    self.schemaVersion = schemaVersion
    self.lineage = lineage
    self.p0 = p0
    self.p1 = p1
    self.u1 = u1
    self.p2 = p2
    self.p3 = p3
    self.p4 = p4
    self.p5 = p5
  }

  public static func load(from url: URL) throws -> Self {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(object.keys).isSubset(of: [
        "schemaVersion", "lineage", "p0", "p1", "u1", "p2", "p3", "p4", "p5",
      ]),
      Set(["schemaVersion", "lineage", "p0", "p1", "u1", "p2", "p3"])
        .isSubset(of: Set(object.keys)),
      !containsNull(object)
    else {
      throw ReleasePackageError.verification(
        "multi-release provenance has unknown, missing, or null stages")
    }
    let decoded = try JSONDecoder().decode(Self.self, from: data)
    guard data == (try CanonicalJSON.encode(decoded)) else {
      throw ReleasePackageError.verification(
        "multi-release provenance is not canonical JSON")
    }
    try decoded.validateStructure()
    return decoded
  }

  public func validateStructure() throws {
    try lineage.validateStructure()
    let expectedIdentifiers = [
      "/Library/Application Support/Reach/Host/reachd": "reachd",
      "/Library/PrivilegedHelperTools/systems.reach.meshd": "systems.reach.meshd",
    ]
    guard schemaVersion == 3,
      p0.name == "P0-source",
      p1.name == "P1-payload",
      u1.name == "U1-unsigned-container-semantics",
      p2.name == "P2-signed-payload",
      p3.name == "P3-signed-installer",
      p0.authority.commit == lineage.sourceCommit,
      p0.releaseToolSourceSHA256 == lineage.unsignedToolSourceSHA256,
      u1.selectedContainer == lineage.unsignedContainer,
      u1.normalizedSemanticSHA256 == lineage.normalizedSemanticSHA256,
      p2.unsignedParent == lineage.unsignedContainer,
      p2.unsignedToolSourceSHA256 == lineage.unsignedToolSourceSHA256,
      validSHA256(p2.finalizerToolSourceSHA256),
      p2.finalizerToolSourceSHA256 != p2.unsignedToolSourceSHA256,
      p2.signedLeaves.count == 2,
      p2.signedLeaves.map(\.path).sorted() == expectedIdentifiers.keys.sorted(),
      p2.applicationCertificate.certificateClass == .application,
      p2.signedLeaves.allSatisfy({ leaf in
        leaf.artifact.path == leaf.path
          && leaf.artifact.size > 0 && validSHA256(leaf.artifact.sha256)
          && expectedIdentifiers[leaf.path] == leaf.identifier
          && leaf.cdHash.count == 40 && leaf.cdHash.allSatisfy(\.isHexDigit)
          && CodeSignatureInspector.designatedRequirementIsBound(
            leaf.designatedRequirement, identifier: leaf.identifier,
            teamID: leaf.teamID, policyOID: SignedReleaseContract.applicationPolicyOID)
          && p2.applicationCertificate.isValid(atTimestamp: leaf.secureTimestampUTC)
          && leaf.architecture == "arm64" && leaf.runtime
          && leaf.entitlementsSHA256 == SignedReleaseContract.emptyEntitlementsSHA256
          && leaf.teamID == p2.applicationCertificate.teamID
          && leaf.certificateSHA1 == p2.applicationCertificate.certificateSHA1
      }),
      validSHA256(p2.normalizedSemanticSHA256),
      [
        p2.unsignedParent, p2.embeddedManifest, p2.hostComponent, p2.helperComponent,
        p2.hostBOM, p2.helperBOM, p2.unsignedContainer,
      ].allSatisfy(validArtifact),
      lineage.components[0].unsignedComponent
        == p1.hostComponents.first(where: {
          $0 == lineage.components[0].unsignedComponent
        }),
      lineage.components[1].unsignedComponent
        == p1.helperComponents.first(where: {
          $0 == lineage.components[1].unsignedComponent
        }),
      p3.installerCertificate.certificateClass == .installer,
      p3.installerCertificate.teamID == p2.applicationCertificate.teamID,
      p3.installerCertificate.isValid(atTimestamp: p3.secureTimestampUTC),
      p3.p2ContainerSHA256 == p2.unsignedContainer.sha256,
      validArtifact(p3.signedContainer), validArtifact(p3.payloadVerification),
      validSHA256(p3.preNotaryAssessment.stdoutSHA256),
      validSHA256(p3.preNotaryAssessment.stderrSHA256),
      p3.packageIdentifiers == ["systems.reach.host", "systems.reach.meshd"]
    else {
      throw ReleasePackageError.verification("multi-release stage authority changed")
    }
    try p2.applicationCertificate.validate()
    try p3.installerCertificate.validate()
    if let p4 {
      guard p4.name == "P4-notary-accepted",
        p4.signedContainerSHA256 == p3.signedContainer.sha256,
        p4.status == "Accepted", p4.issueCount == 0,
        UUID(uuidString: p4.submissionID) != nil,
        validArtifact(p4.submissionEvidence), validArtifact(p4.waitResponse),
        validArtifact(p4.notaryLog), !p4.acceptedAtUTC.isEmpty
      else {
        throw ReleasePackageError.verification("multi-release P4 authority changed")
      }
    }
    if let p5 {
      guard p4 != nil,
        p5.name == "P5-stapled-candidate",
        p5.p3ParentSHA256 == p3.signedContainer.sha256,
        validArtifact(p5.stapledContainer), validArtifact(p5.stapleValidation),
        validArtifact(p5.nestedVerification), p5.localAssessment.exitStatus == 0,
        validSHA256(p5.localAssessment.stdoutSHA256),
        validSHA256(p5.localAssessment.stderrSHA256)
      else {
        throw ReleasePackageError.verification("multi-release P5 authority changed")
      }
    }
  }

  private func validSHA256(_ value: String) -> Bool {
    value.count == 64 && value.allSatisfy(\.isHexDigit)
  }

  private func validArtifact(_ artifact: ReleaseProvenance.Artifact) -> Bool {
    artifact.size > 0 && validSHA256(artifact.sha256)
      && (try? SecureFiles.validateRelativePath(artifact.path)) != nil
  }

  private static func containsNull(_ value: Any) -> Bool {
    if value is NSNull { return true }
    if let array = value as? [Any] { return array.contains(where: containsNull) }
    if let dictionary = value as? [String: Any] {
      return dictionary.values.contains(where: containsNull)
    }
    return false
  }
}

struct SignedProvenanceView: Equatable {
  let schemaVersion: Int
  let lineage: ReleaseLineageAuthority?
  let p0: ReleaseProvenance.SourceStage
  let p1: ReleaseProvenance.PayloadStage
  let u1: ReleaseProvenance.UnsignedStage
  let p2: SignedReleaseProvenance.SignedPayloadStage
  let p3: SignedReleaseProvenance.SignedContainerStage
  let p4: SignedReleaseProvenance.NotarizationStage?
  let p5: SignedReleaseProvenance.StapledStage?
}

enum AnySignedReleaseProvenance {
  case historical(SignedReleaseProvenance)
  case multiRelease(MultiReleaseSignedProvenance)

  static func load(from url: URL) throws -> Self {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      let schema = object["schemaVersion"] as? Int
    else {
      throw ReleasePackageError.verification("signed provenance schema is missing")
    }
    switch schema {
    case 2: return .historical(try SignedReleaseProvenance.load(from: url))
    case 3: return .multiRelease(try MultiReleaseSignedProvenance.load(from: url))
    default:
      throw ReleasePackageError.verification(
        "unsupported signed provenance schema \(schema)")
    }
  }

  var view: SignedProvenanceView {
    switch self {
    case .historical(let value):
      return .init(
        schemaVersion: value.schemaVersion, lineage: nil,
        p0: value.p0, p1: value.p1, u1: value.u1,
        p2: value.p2, p3: value.p3, p4: value.p4, p5: value.p5)
    case .multiRelease(let value):
      return .init(
        schemaVersion: value.schemaVersion, lineage: value.lineage,
        p0: value.p0, p1: value.p1, u1: value.u1,
        p2: value.p2, p3: value.p3, p4: value.p4, p5: value.p5)
    }
  }

  func adding(p4: SignedReleaseProvenance.NotarizationStage) throws -> Self {
    let current = view
    guard current.p4 == nil, current.p5 == nil else {
      throw ReleasePackageError.verification("P4 authority already exists")
    }
    switch self {
    case .historical(let value):
      let updated = SignedReleaseProvenance(
        schemaVersion: value.schemaVersion,
        p0: value.p0, p1: value.p1, u1: value.u1,
        p2: value.p2, p3: value.p3, p4: p4)
      try updated.validate()
      return .historical(updated)
    case .multiRelease(let value):
      let updated = MultiReleaseSignedProvenance(
        schemaVersion: value.schemaVersion, lineage: value.lineage,
        p0: value.p0, p1: value.p1, u1: value.u1,
        p2: value.p2, p3: value.p3, p4: p4)
      try updated.validateStructure()
      return .multiRelease(updated)
    }
  }

  func adding(p5: SignedReleaseProvenance.StapledStage) throws -> Self {
    let current = view
    guard current.p4 != nil, current.p5 == nil else {
      throw ReleasePackageError.verification("P5 authority requires one earned P4")
    }
    switch self {
    case .historical(let value):
      let updated = SignedReleaseProvenance(
        schemaVersion: value.schemaVersion,
        p0: value.p0, p1: value.p1, u1: value.u1,
        p2: value.p2, p3: value.p3, p4: value.p4, p5: p5)
      try updated.validate()
      return .historical(updated)
    case .multiRelease(let value):
      let updated = MultiReleaseSignedProvenance(
        schemaVersion: value.schemaVersion, lineage: value.lineage,
        p0: value.p0, p1: value.p1, u1: value.u1,
        p2: value.p2, p3: value.p3, p4: value.p4, p5: p5)
      try updated.validateStructure()
      return .multiRelease(updated)
    }
  }

  func canonicalData() throws -> Data {
    switch self {
    case .historical(let value): try CanonicalJSON.encode(value)
    case .multiRelease(let value): try CanonicalJSON.encode(value)
    }
  }
}
