import Foundation

public enum SignedReleaseContract {
  public static let unsignedSourceCommit =
    "92b233e9c8c0ebfee57d0aceb182130d0bd7fa0b"
  public static let unsignedToolSourceSHA256 =
    "7b215b2bd6a953add3ffcbe566d2f22a6aacc5b0d0467bceec9586a8038f7c8a"
  public static let unsignedPackageSHA256 =
    "a8ff82e0411df6e9980adac32a04edcc20e9956f05d25406ad2721b4f4e14a88"
  public static let unsignedSemanticSHA256 =
    "3b7324a9d35a139fc3e0a0fd136f40fd504c2a767dccf377e26e45d2c120305d"
  public static let applicationPolicyOID = "1.2.840.113635.100.6.1.13"
  public static let installerPolicyOID = "1.2.840.113635.100.6.1.14"
  public static let emptyEntitlementsSHA256 = Digests.sha256(Data())
}

public enum DeveloperIDClass: String, Codable, Sendable, CaseIterable {
  case application = "Developer ID Application"
  case installer = "Developer ID Installer"

  public var policyOID: String {
    switch self {
    case .application: SignedReleaseContract.applicationPolicyOID
    case .installer: SignedReleaseContract.installerPolicyOID
    }
  }
}

public struct SigningCertificateAuthority: Codable, Equatable, Sendable {
  public let certificateClass: DeveloperIDClass
  public let policyOID: String
  public let certificateSHA1: String
  public let teamID: String
  public let notBeforeUTC: String
  public let notAfterUTC: String
  public let chainSHA256: [String]

  public init(
    certificateClass: DeveloperIDClass,
    policyOID: String,
    certificateSHA1: String,
    teamID: String,
    notBeforeUTC: String,
    notAfterUTC: String,
    chainSHA256: [String]
  ) {
    self.certificateClass = certificateClass
    self.policyOID = policyOID
    self.certificateSHA1 = certificateSHA1
    self.teamID = teamID
    self.notBeforeUTC = notBeforeUTC
    self.notAfterUTC = notAfterUTC
    self.chainSHA256 = chainSHA256
  }

  public func validate() throws {
    guard policyOID == certificateClass.policyOID,
      certificateSHA1.count == 40,
      certificateSHA1.allSatisfy(\.isHexDigit),
      teamID.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
      !notBeforeUTC.isEmpty,
      !notAfterUTC.isEmpty,
      chainSHA256.count >= 2,
      chainSHA256.allSatisfy({ $0.count == 64 && $0.allSatisfy(\.isHexDigit) })
    else {
      throw ReleasePackageError.verification("Developer ID certificate authority is malformed")
    }
  }

  public func isValid(at date: Date) -> Bool {
    guard let notBefore = Self.parseTimestamp(notBeforeUTC),
      let notAfter = Self.parseTimestamp(notAfterUTC)
    else { return false }
    return notBefore <= date && date <= notAfter
  }

  func isValid(atTimestamp value: String) -> Bool {
    guard let date = Self.parseTimestamp(value) else { return false }
    return isValid(at: date)
  }

  private static func parseTimestamp(_ value: String) -> Date? {
    let fractional = ISO8601DateFormatter()
    fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value)
  }
}

public struct SignedLeafAuthority: Codable, Equatable, Sendable {
  public let path: String
  public let artifact: ReleaseProvenance.Artifact
  public let identifier: String
  public let architecture: String
  public let cdHash: String
  public let designatedRequirement: String
  public let teamID: String
  public let certificateSHA1: String
  public let secureTimestampUTC: String
  public let runtime: Bool
  public let entitlementsSHA256: String

  public init(
    path: String,
    artifact: ReleaseProvenance.Artifact,
    identifier: String,
    architecture: String,
    cdHash: String,
    designatedRequirement: String,
    teamID: String,
    certificateSHA1: String,
    secureTimestampUTC: String,
    runtime: Bool,
    entitlementsSHA256: String
  ) {
    self.path = path
    self.artifact = artifact
    self.identifier = identifier
    self.architecture = architecture
    self.cdHash = cdHash
    self.designatedRequirement = designatedRequirement
    self.teamID = teamID
    self.certificateSHA1 = certificateSHA1
    self.secureTimestampUTC = secureTimestampUTC
    self.runtime = runtime
    self.entitlementsSHA256 = entitlementsSHA256
  }
}

public struct AssessmentAuthority: Codable, Equatable, Sendable {
  public let exitStatus: Int32
  public let stdoutSHA256: String
  public let stderrSHA256: String

  public init(exitStatus: Int32, stdoutSHA256: String, stderrSHA256: String) {
    self.exitStatus = exitStatus
    self.stdoutSHA256 = stdoutSHA256
    self.stderrSHA256 = stderrSHA256
  }
}

public struct SignedReleaseProvenance: Codable, Equatable, Sendable {
  public struct SignedPayloadStage: Codable, Equatable, Sendable {
    public let name: String
    public let unsignedParent: ReleaseProvenance.Artifact
    public let unsignedToolSourceSHA256: String
    public let finalizerToolSourceSHA256: String
    public let applicationCertificate: SigningCertificateAuthority
    public let signedLeaves: [SignedLeafAuthority]
    public let embeddedManifest: ReleaseProvenance.Artifact
    public let hostComponent: ReleaseProvenance.Artifact
    public let helperComponent: ReleaseProvenance.Artifact
    public let hostBOM: ReleaseProvenance.Artifact
    public let helperBOM: ReleaseProvenance.Artifact
    public let unsignedContainer: ReleaseProvenance.Artifact
    public let normalizedSemanticSHA256: String
  }

  public struct SignedContainerStage: Codable, Equatable, Sendable {
    public let name: String
    public let p2ContainerSHA256: String
    public let signedContainer: ReleaseProvenance.Artifact
    public let payloadVerification: ReleaseProvenance.Artifact
    public let installerCertificate: SigningCertificateAuthority
    public let secureTimestampUTC: String
    public let packageIdentifiers: [String]
    public let preNotaryAssessment: AssessmentAuthority
  }

  public struct NotarizationStage: Codable, Equatable, Sendable {
    public let name: String
    public let signedContainerSHA256: String
    public let submissionID: String
    public let status: String
    public let submissionEvidence: ReleaseProvenance.Artifact
    public let waitResponse: ReleaseProvenance.Artifact
    public let notaryLog: ReleaseProvenance.Artifact
    public let acceptedAtUTC: String
    public let issueCount: Int
  }

  public struct StapledStage: Codable, Equatable, Sendable {
    public let name: String
    public let p3ParentSHA256: String
    public let stapledContainer: ReleaseProvenance.Artifact
    public let stapleValidation: ReleaseProvenance.Artifact
    public let nestedVerification: ReleaseProvenance.Artifact
    public let localAssessment: AssessmentAuthority
  }

  public let schemaVersion: Int
  public let p0: ReleaseProvenance.SourceStage
  public let p1: ReleaseProvenance.PayloadStage
  public let u1: ReleaseProvenance.UnsignedStage
  public let p2: SignedPayloadStage
  public let p3: SignedContainerStage
  public let p4: NotarizationStage?
  public let p5: StapledStage?

  public init(
    schemaVersion: Int,
    p0: ReleaseProvenance.SourceStage,
    p1: ReleaseProvenance.PayloadStage,
    u1: ReleaseProvenance.UnsignedStage,
    p2: SignedPayloadStage,
    p3: SignedContainerStage,
    p4: NotarizationStage? = nil,
    p5: StapledStage? = nil
  ) {
    self.schemaVersion = schemaVersion
    self.p0 = p0
    self.p1 = p1
    self.u1 = u1
    self.p2 = p2
    self.p3 = p3
    self.p4 = p4
    self.p5 = p5
  }

  enum CodingKeys: String, CodingKey {
    case schemaVersion, p0, p1, u1, p2, p3, p4, p5
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
    p0 = try container.decode(ReleaseProvenance.SourceStage.self, forKey: .p0)
    p1 = try container.decode(ReleaseProvenance.PayloadStage.self, forKey: .p1)
    u1 = try container.decode(ReleaseProvenance.UnsignedStage.self, forKey: .u1)
    p2 = try container.decode(SignedPayloadStage.self, forKey: .p2)
    p3 = try container.decode(SignedContainerStage.self, forKey: .p3)
    p4 = try container.decodeIfPresent(NotarizationStage.self, forKey: .p4)
    p5 = try container.decodeIfPresent(StapledStage.self, forKey: .p5)
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(schemaVersion, forKey: .schemaVersion)
    try container.encode(p0, forKey: .p0)
    try container.encode(p1, forKey: .p1)
    try container.encode(u1, forKey: .u1)
    try container.encode(p2, forKey: .p2)
    try container.encode(p3, forKey: .p3)
    try container.encodeIfPresent(p4, forKey: .p4)
    try container.encodeIfPresent(p5, forKey: .p5)
  }

  public static func load(from url: URL) throws -> Self {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw ReleasePackageError.verification("signed provenance is not a JSON object")
    }
    let allowed = Set(["schemaVersion", "p0", "p1", "u1", "p2", "p3", "p4", "p5"])
    let required = Set(["schemaVersion", "p0", "p1", "u1", "p2", "p3"])
    guard Set(object.keys).isSubset(of: allowed), required.isSubset(of: Set(object.keys)),
      !containsNull(object)
    else {
      throw ReleasePackageError.verification(
        "signed provenance has unknown, missing, or null stages")
    }
    let decoded = try JSONDecoder().decode(Self.self, from: data)
    guard data == (try CanonicalJSON.encode(decoded)) else {
      throw ReleasePackageError.verification("signed provenance is not canonical JSON")
    }
    try decoded.validate()
    return decoded
  }

  public func validate() throws {
    let expectedIdentifiers = [
      "/Library/Application Support/Reach/Host/reachd": "reachd",
      "/Library/PrivilegedHelperTools/systems.reach.meshd": "systems.reach.meshd",
    ]
    guard schemaVersion == 2,
      p0.name == "P0-source",
      p1.name == "P1-payload",
      u1.name == "U1-unsigned-container-semantics",
      p2.name == "P2-signed-payload",
      p3.name == "P3-signed-installer",
      p0.authority.commit == SignedReleaseContract.unsignedSourceCommit,
      p0.releaseToolSourceSHA256 == SignedReleaseContract.unsignedToolSourceSHA256,
      u1.selectedContainer.sha256 == SignedReleaseContract.unsignedPackageSHA256,
      u1.normalizedSemanticSHA256 == SignedReleaseContract.unsignedSemanticSHA256,
      p2.unsignedParent.sha256 == SignedReleaseContract.unsignedPackageSHA256,
      p2.unsignedToolSourceSHA256 == SignedReleaseContract.unsignedToolSourceSHA256,
      validSHA256(p2.finalizerToolSourceSHA256),
      p2.finalizerToolSourceSHA256 != p2.unsignedToolSourceSHA256,
      p2.applicationCertificate.certificateClass == .application,
      p2.signedLeaves.count == 2,
      p2.signedLeaves.map(\.path).sorted()
        == [
          "/Library/Application Support/Reach/Host/reachd",
          "/Library/PrivilegedHelperTools/systems.reach.meshd",
        ],
      p2.signedLeaves.allSatisfy({ leaf in
        leaf.artifact.path == leaf.path
          && leaf.artifact.size > 0
          && validSHA256(leaf.artifact.sha256)
          && expectedIdentifiers[leaf.path] == leaf.identifier
          && leaf.cdHash.count == 40
          && leaf.cdHash.allSatisfy(\.isHexDigit)
          && CodeSignatureInspector.designatedRequirementIsBound(
            leaf.designatedRequirement,
            identifier: leaf.identifier,
            teamID: leaf.teamID,
            policyOID: SignedReleaseContract.applicationPolicyOID)
          && p2.applicationCertificate.isValid(atTimestamp: leaf.secureTimestampUTC)
          && leaf.architecture == "arm64" && leaf.runtime
          && leaf.entitlementsSHA256 == SignedReleaseContract.emptyEntitlementsSHA256
          && leaf.teamID == p2.applicationCertificate.teamID
          && leaf.certificateSHA1 == p2.applicationCertificate.certificateSHA1
      }),
      validSHA256(p2.normalizedSemanticSHA256),
      validArtifact(p2.unsignedParent),
      validArtifact(p2.embeddedManifest),
      validArtifact(p2.hostComponent),
      validArtifact(p2.helperComponent),
      validArtifact(p2.hostBOM),
      validArtifact(p2.helperBOM),
      validArtifact(p2.unsignedContainer),
      p3.name == "P3-signed-installer",
      p3.p2ContainerSHA256 == p2.unsignedContainer.sha256,
      validArtifact(p3.signedContainer),
      validArtifact(p3.payloadVerification),
      p3.installerCertificate.certificateClass == .installer,
      p3.installerCertificate.teamID == p2.applicationCertificate.teamID,
      p3.installerCertificate.isValid(atTimestamp: p3.secureTimestampUTC),
      validSHA256(p3.preNotaryAssessment.stdoutSHA256),
      validSHA256(p3.preNotaryAssessment.stderrSHA256),
      p3.packageIdentifiers == ["systems.reach.host", "systems.reach.meshd"]
    else {
      throw ReleasePackageError.verification("signed provenance stage authority changed")
    }
    try p2.applicationCertificate.validate()
    try p3.installerCertificate.validate()
    if let p4 {
      guard p4.name == "P4-notary-accepted",
        p4.signedContainerSHA256 == p3.signedContainer.sha256,
        UUID(uuidString: p4.submissionID) != nil,
        p4.status == "Accepted",
        p4.issueCount == 0,
        validArtifact(p4.submissionEvidence),
        validArtifact(p4.waitResponse),
        validArtifact(p4.notaryLog),
        !p4.acceptedAtUTC.isEmpty
      else {
        throw ReleasePackageError.verification("P4 notarization authority changed")
      }
    }
    if let p5 {
      guard let p4,
        p5.name == "P5-stapled-candidate",
        p5.p3ParentSHA256 == p3.signedContainer.sha256,
        validArtifact(p5.stapledContainer),
        validArtifact(p5.stapleValidation),
        validArtifact(p5.nestedVerification),
        p5.localAssessment.exitStatus == 0,
        validSHA256(p5.localAssessment.stdoutSHA256),
        validSHA256(p5.localAssessment.stderrSHA256),
        p4.signedContainerSHA256 == p3.signedContainer.sha256
      else {
        throw ReleasePackageError.verification("P5 staple authority changed")
      }
    }
  }

  private static func containsNull(_ value: Any) -> Bool {
    if value is NSNull { return true }
    if let array = value as? [Any] { return array.contains(where: containsNull) }
    if let dictionary = value as? [String: Any] {
      return dictionary.values.contains(where: containsNull)
    }
    return false
  }

  private func validSHA256(_ value: String) -> Bool {
    value.count == 64 && value.allSatisfy(\.isHexDigit)
  }

  private func validArtifact(_ artifact: ReleaseProvenance.Artifact) -> Bool {
    guard artifact.size > 0, validSHA256(artifact.sha256) else { return false }
    return (try? SecureFiles.validateRelativePath(artifact.path)) != nil
  }
}

public enum NotarizationPhase: String, Codable, Sendable {
  case prepared
  case submitting
  case submitted
  case accepted
  case stapled
}

public struct NotarizationJournal: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let phase: NotarizationPhase
  public let p3SHA256: String
  public let p3VerificationSHA256: String?
  public let archiveName: String
  public let profileBindingSHA256: String
  public let preparedAtUTC: String
  public let submissionStartedAtUTC: String?
  public let submissionID: String?
  public let submissionEvidenceSHA256: String?
  public let acceptedAtUTC: String?
  public let waitResponseSHA256: String?
  public let notaryLogSHA256: String?
  public let p5SHA256: String?

  public init(
    schemaVersion: Int = 2,
    phase: NotarizationPhase,
    p3SHA256: String,
    p3VerificationSHA256: String? = nil,
    archiveName: String,
    profileBindingSHA256: String,
    preparedAtUTC: String,
    submissionStartedAtUTC: String? = nil,
    submissionID: String? = nil,
    submissionEvidenceSHA256: String? = nil,
    acceptedAtUTC: String? = nil,
    waitResponseSHA256: String? = nil,
    notaryLogSHA256: String? = nil,
    p5SHA256: String? = nil
  ) {
    self.schemaVersion = schemaVersion
    self.phase = phase
    self.p3SHA256 = p3SHA256
    self.p3VerificationSHA256 = p3VerificationSHA256
    self.archiveName = archiveName
    self.profileBindingSHA256 = profileBindingSHA256
    self.preparedAtUTC = preparedAtUTC
    self.submissionStartedAtUTC = submissionStartedAtUTC
    self.submissionID = submissionID
    self.submissionEvidenceSHA256 = submissionEvidenceSHA256
    self.acceptedAtUTC = acceptedAtUTC
    self.waitResponseSHA256 = waitResponseSHA256
    self.notaryLogSHA256 = notaryLogSHA256
    self.p5SHA256 = p5SHA256
  }

  enum CodingKeys: String, CodingKey {
    case schemaVersion, phase, p3SHA256, p3VerificationSHA256, archiveName
    case profileBindingSHA256, preparedAtUTC
    case submissionStartedAtUTC, submissionID, submissionEvidenceSHA256, acceptedAtUTC
    case waitResponseSHA256, notaryLogSHA256, p5SHA256
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
    phase = try container.decode(NotarizationPhase.self, forKey: .phase)
    p3SHA256 = try container.decode(String.self, forKey: .p3SHA256)
    p3VerificationSHA256 = try container.decodeIfPresent(
      String.self, forKey: .p3VerificationSHA256)
    archiveName = try container.decode(String.self, forKey: .archiveName)
    profileBindingSHA256 = try container.decode(String.self, forKey: .profileBindingSHA256)
    preparedAtUTC = try container.decode(String.self, forKey: .preparedAtUTC)
    submissionStartedAtUTC = try container.decodeIfPresent(
      String.self, forKey: .submissionStartedAtUTC)
    submissionID = try container.decodeIfPresent(String.self, forKey: .submissionID)
    submissionEvidenceSHA256 = try container.decodeIfPresent(
      String.self, forKey: .submissionEvidenceSHA256)
    acceptedAtUTC = try container.decodeIfPresent(String.self, forKey: .acceptedAtUTC)
    waitResponseSHA256 = try container.decodeIfPresent(String.self, forKey: .waitResponseSHA256)
    notaryLogSHA256 = try container.decodeIfPresent(String.self, forKey: .notaryLogSHA256)
    p5SHA256 = try container.decodeIfPresent(String.self, forKey: .p5SHA256)
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(schemaVersion, forKey: .schemaVersion)
    try container.encode(phase, forKey: .phase)
    try container.encode(p3SHA256, forKey: .p3SHA256)
    try container.encodeIfPresent(p3VerificationSHA256, forKey: .p3VerificationSHA256)
    try container.encode(archiveName, forKey: .archiveName)
    try container.encode(profileBindingSHA256, forKey: .profileBindingSHA256)
    try container.encode(preparedAtUTC, forKey: .preparedAtUTC)
    try container.encodeIfPresent(submissionStartedAtUTC, forKey: .submissionStartedAtUTC)
    try container.encodeIfPresent(submissionID, forKey: .submissionID)
    try container.encodeIfPresent(submissionEvidenceSHA256, forKey: .submissionEvidenceSHA256)
    try container.encodeIfPresent(acceptedAtUTC, forKey: .acceptedAtUTC)
    try container.encodeIfPresent(waitResponseSHA256, forKey: .waitResponseSHA256)
    try container.encodeIfPresent(notaryLogSHA256, forKey: .notaryLogSHA256)
    try container.encodeIfPresent(p5SHA256, forKey: .p5SHA256)
  }

  public func validate() throws {
    guard schemaVersion == 1 || schemaVersion == 2,
      p3SHA256.count == 64,
      profileBindingSHA256.count == 64,
      !archiveName.isEmpty,
      !archiveName.contains("/")
    else {
      throw ReleasePackageError.verification("notarization journal authority is malformed")
    }
    if schemaVersion == 1 {
      guard p3VerificationSHA256 == nil else {
        throw ReleasePackageError.verification(
          "legacy notarization journal contains unknown preflight authority")
      }
    } else {
      guard validSHA256(p3VerificationSHA256) else {
        throw ReleasePackageError.verification(
          "notarization journal lacks complete P3 verification authority")
      }
    }
    switch phase {
    case .prepared:
      guard submissionStartedAtUTC == nil, submissionID == nil else {
        throw ReleasePackageError.verification("prepared journal contains submission authority")
      }
    case .submitting:
      guard submissionStartedAtUTC != nil, submissionID == nil else {
        throw ReleasePackageError.verification("submitting journal authority is malformed")
      }
    case .submitted:
      guard submissionStartedAtUTC != nil, UUID(uuidString: submissionID ?? "") != nil,
        validSHA256(submissionEvidenceSHA256), acceptedAtUTC == nil
      else {
        throw ReleasePackageError.verification("submitted journal authority is malformed")
      }
    case .accepted:
      guard UUID(uuidString: submissionID ?? "") != nil, acceptedAtUTC != nil,
        validSHA256(submissionEvidenceSHA256), validSHA256(waitResponseSHA256),
        validSHA256(notaryLogSHA256), p5SHA256 == nil
      else {
        throw ReleasePackageError.verification("accepted journal authority is malformed")
      }
    case .stapled:
      guard UUID(uuidString: submissionID ?? "") != nil, acceptedAtUTC != nil,
        validSHA256(submissionEvidenceSHA256), validSHA256(waitResponseSHA256),
        validSHA256(notaryLogSHA256), validSHA256(p5SHA256)
      else {
        throw ReleasePackageError.verification("stapled journal authority is malformed")
      }
    }
  }

  private func validSHA256(_ value: String?) -> Bool {
    value?.count == 64 && value?.allSatisfy(\.isHexDigit) == true
  }
}

extension Character {
  fileprivate var isHexDigit: Bool {
    isNumber || ("a"..."f").contains(lowercased())
  }
}
