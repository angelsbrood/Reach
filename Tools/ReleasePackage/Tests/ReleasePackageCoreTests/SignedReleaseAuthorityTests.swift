import Foundation
import Testing

@testable import ReleasePackageCore

private let authorityTimestamp = "2026-08-22T00:00:00.000Z"

func releaseArtifact(_ path: String, hash: Character = "a")
  -> ReleaseProvenance.Artifact
{
  .init(path: path, size: 1, sha256: String(repeating: hash, count: 64))
}

func signingAuthority(
  _ certificateClass: DeveloperIDClass,
  teamID: String = "ABCDEFGHIJ",
  validFrom: String = "2025-01-01T00:00:00.000Z",
  validThrough: String = "2030-01-01T00:00:00.000Z"
) -> SigningCertificateAuthority {
  .init(
    certificateClass: certificateClass,
    policyOID: certificateClass.policyOID,
    certificateSHA1: String(
      repeating: certificateClass == .application ? "a" : "b", count: 40),
    teamID: teamID,
    notBeforeUTC: validFrom,
    notAfterUTC: validThrough,
    chainSHA256: [String(repeating: "c", count: 64), String(repeating: "d", count: 64)])
}

func signedLeaf(
  path: String,
  identifier: String,
  authority: SigningCertificateAuthority,
  runtime: Bool = true,
  entitlementsSHA256: String = SignedReleaseContract.emptyEntitlementsSHA256,
  timestamp: String = authorityTimestamp
) -> SignedLeafAuthority {
  .init(
    path: path,
    artifact: .init(path: path, size: 1, sha256: String(repeating: "e", count: 64)),
    identifier: identifier,
    architecture: "arm64",
    cdHash: String(repeating: "f", count: 40),
    designatedRequirement:
      "identifier \(identifier) and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.\(SignedReleaseContract.applicationPolicyOID)] exists and certificate leaf[subject.OU] = \"\(authority.teamID)\"",
    teamID: authority.teamID,
    certificateSHA1: authority.certificateSHA1,
    secureTimestampUTC: timestamp,
    runtime: runtime,
    entitlementsSHA256: entitlementsSHA256)
}

func signedProvenanceFixture(
  application: SigningCertificateAuthority = signingAuthority(.application),
  installer: SigningCertificateAuthority = signingAuthority(.installer),
  runtime: Bool = true,
  entitlementsSHA256: String = SignedReleaseContract.emptyEntitlementsSHA256,
  leafTimestamp: String = authorityTimestamp,
  finalizerDigest: String = String(repeating: "9", count: 64)
) -> SignedReleaseProvenance {
  let source = SourceAuthority(
    commit: SignedReleaseContract.unsignedSourceCommit,
    commitTimestamp: 1_777_000_000,
    main: SignedReleaseContract.unsignedSourceCommit,
    originMain: SignedReleaseContract.unsignedSourceCommit,
    submodules: [],
    exportedTreeSHA256: String(repeating: "1", count: 64),
    packageResolvedSHA256: String(repeating: "2", count: 64),
    goModSHA256: String(repeating: "3", count: 64),
    goSumSHA256: String(repeating: "4", count: 64))
  let selected = ReleaseProvenance.Artifact(
    path: "artifacts/build-a/Reach-0.0.1-unsigned.pkg",
    size: 1,
    sha256: SignedReleaseContract.unsignedPackageSHA256)
  let p2Container = releaseArtifact("p2/Reach-0.0.1-p2-unsigned.pkg", hash: "2")
  return SignedReleaseProvenance(
    schemaVersion: 2,
    p0: .init(
      name: "P0-source",
      authority: source,
      releaseConfigurationSHA256: String(repeating: "5", count: 64),
      releaseToolSourceSHA256: SignedReleaseContract.unsignedToolSourceSHA256,
      noticeAuthoritySHA256: String(repeating: "6", count: 64),
      dependencyDepotSHA256: String(repeating: "7", count: 64)),
    p1: .init(
      name: "P1-payload",
      embeddedManifest: releaseArtifact("artifacts/payload-manifest.json"),
      notices: releaseArtifact("artifacts/THIRD-PARTY-NOTICES.md"),
      hostComponents: [releaseArtifact("artifacts/host.pkg")],
      helperComponents: [releaseArtifact("artifacts/helper.pkg")],
      hostBOMs: [releaseArtifact("artifacts/host.Bom")],
      helperBOMs: [releaseArtifact("artifacts/helper.Bom")]),
    u1: .init(
      name: "U1-unsigned-container-semantics",
      containers: [selected],
      selectedContainer: selected,
      normalizedSemanticSHA256: SignedReleaseContract.unsignedSemanticSHA256,
      distributionSHA256: String(repeating: "8", count: 64)),
    p2: .init(
      name: "P2-signed-payload",
      unsignedParent: selected,
      unsignedToolSourceSHA256: SignedReleaseContract.unsignedToolSourceSHA256,
      finalizerToolSourceSHA256: finalizerDigest,
      applicationCertificate: application,
      signedLeaves: [
        signedLeaf(
          path: "/Library/Application Support/Reach/Host/reachd",
          identifier: "reachd",
          authority: application,
          runtime: runtime,
          entitlementsSHA256: entitlementsSHA256,
          timestamp: leafTimestamp),
        signedLeaf(
          path: "/Library/PrivilegedHelperTools/systems.reach.meshd",
          identifier: "systems.reach.meshd",
          authority: application,
          runtime: runtime,
          entitlementsSHA256: entitlementsSHA256,
          timestamp: leafTimestamp),
      ],
      embeddedManifest: releaseArtifact("p2/payload-manifest.json"),
      hostComponent: releaseArtifact("p2/systems.reach.host.pkg"),
      helperComponent: releaseArtifact("p2/systems.reach.meshd.pkg"),
      hostBOM: releaseArtifact("p2/systems.reach.host.Bom"),
      helperBOM: releaseArtifact("p2/systems.reach.meshd.Bom"),
      unsignedContainer: p2Container,
      normalizedSemanticSHA256: String(repeating: "5", count: 64)),
    p3: .init(
      name: "P3-signed-installer",
      p2ContainerSHA256: p2Container.sha256,
      signedContainer: releaseArtifact("Reach-0.0.1-signed.pkg", hash: "3"),
      payloadVerification: releaseArtifact("p3-payload-verification.json", hash: "4"),
      installerCertificate: installer,
      secureTimestampUTC: authorityTimestamp,
      packageIdentifiers: ["systems.reach.host", "systems.reach.meshd"],
      preNotaryAssessment: .init(
        exitStatus: 1,
        stdoutSHA256: String(repeating: "6", count: 64),
        stderrSHA256: String(repeating: "7", count: 64))))
}

@Test func signedProvenanceOmitsUnearnedStagesAndRefusesNulls() throws {
  let value = signedProvenanceFixture()
  try value.validate()
  let encoded = try CanonicalJSON.encode(value)
  let object = try #require(
    JSONSerialization.jsonObject(with: encoded) as? [String: Any])
  #expect(object["p4"] == nil)
  #expect(object["p5"] == nil)

  let root = try makeTemporaryDirectory("signed-provenance-null")
  defer { removeTemporaryDirectory(root) }
  var changed = object
  var p2 = try #require(changed["p2"] as? [String: Any])
  var leaves = try #require(p2["signedLeaves"] as? [[String: Any]])
  leaves[0]["runtime"] = NSNull()
  p2["signedLeaves"] = leaves
  changed["p2"] = p2
  let url = root.appendingPathComponent("release-provenance.json")
  try SecureFiles.atomicWrite(
    try JSONSerialization.data(withJSONObject: changed, options: [.prettyPrinted, .sortedKeys]),
    to: url)
  #expect(throws: ReleasePackageError.self) {
    try SignedReleaseProvenance.load(from: url)
  }
}

@Test func signedProvenanceBindsEveryP4AndP5ArtifactAndRefusesUnknownStages() throws {
  let base = signedProvenanceFixture()
  let p4 = SignedReleaseProvenance.NotarizationStage(
    name: "P4-notary-accepted",
    signedContainerSHA256: base.p3.signedContainer.sha256,
    submissionID: "12345678-1234-1234-1234-123456789abc",
    status: "Accepted",
    submissionEvidence: releaseArtifact("p4/submission-evidence.json"),
    waitResponse: releaseArtifact("p4/wait-response.json"),
    notaryLog: releaseArtifact("p4/notary-log.json"),
    acceptedAtUTC: authorityTimestamp,
    issueCount: 0)
  let p5 = SignedReleaseProvenance.StapledStage(
    name: "P5-stapled-candidate",
    p3ParentSHA256: base.p3.signedContainer.sha256,
    stapledContainer: releaseArtifact("Reach-0.0.1.pkg"),
    stapleValidation: releaseArtifact("p5/staple-validation.json"),
    nestedVerification: releaseArtifact("p5/nested-verification.json"),
    localAssessment: .init(
      exitStatus: 0,
      stdoutSHA256: String(repeating: "1", count: 64),
      stderrSHA256: String(repeating: "2", count: 64)))
  let complete = SignedReleaseProvenance(
    schemaVersion: 2,
    p0: base.p0,
    p1: base.p1,
    u1: base.u1,
    p2: base.p2,
    p3: base.p3,
    p4: p4,
    p5: p5)
  try complete.validate()

  let root = try makeTemporaryDirectory("signed-provenance-unknown")
  defer { removeTemporaryDirectory(root) }
  var object = try #require(
    JSONSerialization.jsonObject(with: try CanonicalJSON.encode(complete)) as? [String: Any])
  object["p6"] = [:]
  let url = root.appendingPathComponent("release-provenance.json")
  try SecureFiles.atomicWrite(
    try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
    to: url)
  #expect(throws: ReleasePackageError.self) {
    try SignedReleaseProvenance.load(from: url)
  }

  let invalidP5 = SignedReleaseProvenance.StapledStage(
    name: p5.name,
    p3ParentSHA256: p5.p3ParentSHA256,
    stapledContainer: p5.stapledContainer,
    stapleValidation: .init(
      path: p5.stapleValidation.path,
      size: p5.stapleValidation.size,
      sha256: "bad"),
    nestedVerification: p5.nestedVerification,
    localAssessment: p5.localAssessment)
  #expect(throws: ReleasePackageError.self) {
    try SignedReleaseProvenance(
      schemaVersion: 2,
      p0: base.p0,
      p1: base.p1,
      u1: base.u1,
      p2: base.p2,
      p3: base.p3,
      p4: p4,
      p5: invalidP5
    ).validate()
  }
}

@Test func signedProvenanceRefusesWrongClassTeamRuntimeEntitlementsAndTimestamp() throws {
  #expect(throws: ReleasePackageError.self) {
    try signedProvenanceFixture(
      installer: signingAuthority(.installer, teamID: "KLMNOPQRST")
    ).validate()
  }
  #expect(throws: ReleasePackageError.self) {
    try signedProvenanceFixture(runtime: false).validate()
  }
  #expect(throws: ReleasePackageError.self) {
    try signedProvenanceFixture(entitlementsSHA256: String(repeating: "0", count: 64))
      .validate()
  }
  #expect(throws: ReleasePackageError.self) {
    try signedProvenanceFixture(leafTimestamp: "2031-01-01T00:00:00.000Z").validate()
  }
  #expect(throws: ReleasePackageError.self) {
    try signedProvenanceFixture(
      finalizerDigest: SignedReleaseContract.unsignedToolSourceSHA256
    ).validate()
  }
}

private func identityCandidate(
  _ certificateClass: DeveloperIDClass,
  teamID: String = "ABCDEFGHIJ",
  trusted: Bool = true,
  privateKey: Bool = true,
  expectedChain: Bool = true,
  validThrough: String = "2030-01-01T00:00:00.000Z"
) -> DeveloperIDIdentityCandidate {
  .init(
    authority: signingAuthority(
      certificateClass, teamID: teamID, validThrough: validThrough),
    trusted: trusted,
    hasPrivateKey: privateKey,
    expectedG2Chain: expectedChain)
}

@Test func identitySelectionRequiresOneTrustedCurrentPrivateKeyPerClassAndOneTeam() throws {
  let date = try #require(ISO8601DateFormatter().date(from: "2026-08-22T00:00:00Z"))
  let expected = try DeveloperIDIdentityResolver.select(
    [identityCandidate(.application), identityCandidate(.installer)], at: date)
  #expect(expected.application.certificateClass == .application)
  #expect(expected.installer.certificateClass == .installer)

  for unusable in [
    identityCandidate(.application, trusted: false),
    identityCandidate(.application, privateKey: false),
    identityCandidate(.application, expectedChain: false),
    identityCandidate(.application, validThrough: "2026-01-01T00:00:00.000Z"),
  ] {
    #expect(throws: ReleasePackageError.self) {
      try DeveloperIDIdentityResolver.select(
        [unusable, identityCandidate(.installer)], at: date)
    }
  }
  #expect(throws: ReleasePackageError.self) {
    try DeveloperIDIdentityResolver.select(
      [
        identityCandidate(.application), identityCandidate(.application),
        identityCandidate(.installer),
      ],
      at: date)
  }
  #expect(throws: ReleasePackageError.self) {
    try DeveloperIDIdentityResolver.select(
      [identityCandidate(.application), identityCandidate(.installer, teamID: "KLMNOPQRST")],
      at: date)
  }
}

@Test func developerIDPolicyClassesComeFromExactDERObjectIdentifiers() throws {
  let application = try DERObjectIdentifiers.encode(
    SignedReleaseContract.applicationPolicyOID)
  let installer = try DERObjectIdentifiers.encode(
    SignedReleaseContract.installerPolicyOID)
  #expect(application == Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0d]))
  #expect(installer == Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0e]))
  let body =
    Data([0x06, UInt8(application.count)]) + application
    + Data([0x06, UInt8(installer.count)]) + installer
  let certificate = Data([0x30, UInt8(body.count)]) + body
  #expect(try DERObjectIdentifiers.values(in: certificate) == Set([application, installer]))
  #expect(throws: ReleasePackageError.self) {
    try DERObjectIdentifiers.values(in: Data([0x30, 0x82, 0x01]))
  }
}

@Test func developerIDClassesUseTheirCorrectPublicTrustPolicies() {
  #expect(DeveloperIDClass.application.trustPolicy == .appleCodeSigning)
  #expect(DeveloperIDClass.installer.trustPolicy == .basicX509)
}

@Test func developerIDG2ChainRequiresTheExactIntermediateAndRootAuthority() {
  let subjects = [
    "Developer ID Application: Example", "Developer ID Certification Authority", "Apple Root CA",
  ]
  let units = [["ABCDEFGHIJ"], ["G2"], ["Apple Certification Authority"]]
  #expect(
    SecurityDeveloperIDIdentityProvider.hasExactDeveloperIDG2Chain(
      subjectSummaries: subjects, organizationalUnits: units))
  #expect(
    !SecurityDeveloperIDIdentityProvider.hasExactDeveloperIDG2Chain(
      subjectSummaries: subjects,
      organizationalUnits: [["ABCDEFGHIJ"], ["G1"], ["Apple Certification Authority"]]))
  #expect(
    !SecurityDeveloperIDIdentityProvider.hasExactDeveloperIDG2Chain(
      subjectSummaries: [subjects[0], "Developer ID Certification Authority Legacy", subjects[2]],
      organizationalUnits: units))
  #expect(
    !SecurityDeveloperIDIdentityProvider.hasExactDeveloperIDG2Chain(
      subjectSummaries: Array(subjects.dropLast()),
      organizationalUnits: Array(units.dropLast())))
}

@Test func designatedRequirementAcceptsEquivalentQuotedAndUnquotedIdentifiers() {
  let unquoted =
    "identifier reachd and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"ABCDEFGHIJ\""
  let quoted = unquoted.replacingOccurrences(of: "identifier reachd", with: "identifier \"reachd\"")
  for value in [unquoted, quoted] {
    #expect(
      CodeSignatureInspector.designatedRequirementIsBound(
        value,
        identifier: "reachd",
        teamID: "ABCDEFGHIJ",
        policyOID: SignedReleaseContract.applicationPolicyOID))
  }
  #expect(
    !CodeSignatureInspector.designatedRequirementIsBound(
      unquoted,
      identifier: "wrong",
      teamID: "ABCDEFGHIJ",
      policyOID: SignedReleaseContract.applicationPolicyOID))
  #expect(
    !CodeSignatureInspector.designatedRequirementIsBound(
      unquoted,
      identifier: "reachd",
      teamID: "ZZZZZZZZZZ",
      policyOID: SignedReleaseContract.applicationPolicyOID))
  #expect(
    !CodeSignatureInspector.designatedRequirementIsBound(
      unquoted,
      identifier: "reachd",
      teamID: "ABCDEFGHIJ",
      policyOID: SignedReleaseContract.installerPolicyOID))
}

@Test func installerTrustAcceptsOnlyKnownSuccessfulPkgutilStatuses() {
  #expect(
    CodeSignatureInspector.hasTrustedInstallerStatus(
      "Status: signed by a certificate trusted by macOS\n"))
  #expect(
    CodeSignatureInspector.hasTrustedInstallerStatus(
      "   Status: signed by a developer certificate issued by Apple for distribution\n"))
  #expect(!CodeSignatureInspector.hasTrustedInstallerStatus("Status: signed but not trusted\n"))
  #expect(!CodeSignatureInspector.hasTrustedInstallerStatus("Status: unsigned\n"))
  #expect(!CodeSignatureInspector.hasTrustedInstallerStatus("no status\n"))
}

@Test func installerTimestampIsCanonicalAndStrict() throws {
  let output = """
       Signed with a trusted timestamp on: 2026-08-22 11:47:04 +0000
    """
  #expect(
    try CodeSignatureInspector.trustedInstallerTimestampUTC(from: output)
      == "2026-08-22T11:47:04.000Z")
  #expect(throws: ReleasePackageError.self) {
    try CodeSignatureInspector.trustedInstallerTimestampUTC(
      from: "Signed with a trusted timestamp on: yesterday")
  }
  #expect(throws: ReleasePackageError.self) {
    try CodeSignatureInspector.trustedInstallerTimestampUTC(
      from: "Timestamp: 2026-08-22 11:47:04 +0000")
  }
}

@Test func xarCertificateParserAcceptsOnlyWhitespaceWrappedBase64() throws {
  let certificate = Data([0x30, 0x03, 0x02, 0x01, 0x01])
  let encoded = certificate.base64EncodedString()
  let split = encoded.index(encoded.startIndex, offsetBy: 4)
  let wrapped = """
    <xar><toc><signature><KeyInfo><X509Data>
    <X509Certificate>\n\t\(encoded[..<split])\r\n \(encoded[split...])\n</X509Certificate>
    </X509Data></KeyInfo></signature></toc></xar>
    """
  #expect(try CodeSignatureInspector.certificateDER(fromXARTOC: wrapped) == [certificate])

  let corrupted = wrapped.replacingOccurrences(of: "AQE=", with: "AQ!=")
  #expect(throws: ReleasePackageError.self) {
    try CodeSignatureInspector.certificateDER(fromXARTOC: corrupted)
  }
  #expect(throws: ReleasePackageError.self) {
    try CodeSignatureInspector.certificateDER(fromXARTOC: "<xar><toc/></xar>")
  }
}

@Test func embeddedCertificateChainComparisonBindsEveryCertificateInOrder() {
  let chain = [Data("leaf".utf8), Data("intermediate".utf8), Data("root".utf8)]
  let hashes = chain.map(Digests.sha256)
  #expect(CodeSignatureInspector.certificateChainMatches(chain, expectedSHA256: hashes))
  #expect(
    CodeSignatureInspector.embeddedCertificateChainsMatch(
      chain + chain, expectedSHA256: hashes))
  #expect(
    !CodeSignatureInspector.certificateChainMatches(
      Array(chain.dropLast()), expectedSHA256: hashes))
  #expect(
    !CodeSignatureInspector.certificateChainMatches(
      [chain[0], chain[2], chain[1]], expectedSHA256: hashes))
  var changed = chain
  changed[1] = Data("other".utf8)
  #expect(!CodeSignatureInspector.certificateChainMatches(changed, expectedSHA256: hashes))
  #expect(
    !CodeSignatureInspector.embeddedCertificateChainsMatch(
      chain + changed, expectedSHA256: hashes))
}

@Test func signedSmokeKeepsFilesPrivateWithoutLosingTheLoginKeychain() {
  let root = URL(fileURLWithPath: "/private/tmp/reach-signed-smoke-fixture")
  let environment = SignedReleaseFinalizer.signedSmokeEnvironment(workRoot: root)
  #expect(environment.keys.sorted() == ["HF_HUB_CACHE", "HOME", "TMPDIR"])
  #expect(environment["HOME"] == FileManager.default.homeDirectoryForCurrentUser.path)
  #expect(environment["TMPDIR"] == root.path)
  #expect(environment["HF_HUB_CACHE"]?.hasPrefix(environment["HOME"]! + "/") == true)
}

@Test func finalizationMetalMismatchLeavesOutputEmptyAndIdentityUnconsulted() throws {
  let root = try makeTemporaryDirectory("finalization-metal-order")
  defer { removeTemporaryDirectory(root) }
  let output = root.appendingPathComponent("output")
  try SecureFiles.createPrivateDirectory(output)
  var identityConsulted = false
  var retainCalled = false
  let metal = testMetalToolchainAuthority()

  #expect(throws: ReleasePackageError.self) {
    _ = try SignedReleaseFinalizer.establishFinalizationAuthority(
      declaredMetal: metal,
      metalLog: root.appendingPathComponent("metal.log"),
      requireLiveMetalAuthority: { _, _ in
        throw ReleasePackageError.verification("installed Metal authority changed")
      },
      retainUnsignedAuthority: {
        retainCalled = true
        try SecureFiles.atomicWrite(
          Data("should-not-exist".utf8), to: output.appendingPathComponent("authority"))
      },
      resolveSigningContext: {
        identityConsulted = true
        throw ReleasePackageError.verification("identity boundary was reached")
      })
  }
  #expect(!retainCalled)
  #expect(!identityConsulted)
  #expect(try FileManager.default.contentsOfDirectory(atPath: output.path).isEmpty)

  let context = try SignedReleaseFinalizer.establishFinalizationAuthority(
    declaredMetal: metal,
    metalLog: root.appendingPathComponent("metal-retry.log"),
    requireLiveMetalAuthority: { _, _ in },
    retainUnsignedAuthority: {
      try SecureFiles.atomicWrite(
        Data("retained".utf8), to: output.appendingPathComponent("authority"))
    },
    resolveSigningContext: {
      identityConsulted = true
      return .init(
        identities: .init(
          application: signingAuthority(.application),
          installer: signingAuthority(.installer)),
        loginKeychainPath: "/Users/fixture/Library/Keychains/login.keychain-db")
    })
  #expect(identityConsulted)
  #expect(context.identities.application.certificateClass == .application)
  #expect(FileManager.default.fileExists(atPath: output.appendingPathComponent("authority").path))
}

@Test func p5StaticReportJoinRequiresExactMetalAuthority() throws {
  let metal = testMetalToolchainAuthority()
  let exact = VerificationReport(
    schemaVersion: 2,
    packageSHA256: String(repeating: "1", count: 64),
    normalizedSemanticSHA256: String(repeating: "2", count: 64),
    embeddedManifestSHA256: String(repeating: "3", count: 64),
    noticeSetSHA256: String(repeating: "4", count: 64),
    hostFiles: 50,
    helperFiles: 6,
    scriptsPresent: false,
    resourcesPresent: false,
    metalToolchain: metal)
  try SignedPackageStaticPreflight.requireRetainedReportAuthority(
    exact, exact, requireP3Hash: false)

  let changedMetal = MetalToolchainAuthority(
    componentIdentifier: metal.componentIdentifier,
    componentBuild: metal.componentBuild,
    metadata: metal.metadata,
    tools: metal.tools.enumerated().map { index, tool in
      index == 0
        ? .init(
          path: tool.path, resolvedPath: tool.resolvedPath,
          sha256: String(repeating: "0", count: 64), version: tool.version)
        : tool
    })
  let decomposedVersion = "Apple metal cafe\u{301}\nAIR tools"
  let composedVersion = decomposedVersion.precomposedStringWithCanonicalMapping
  #expect(decomposedVersion == composedVersion)
  #expect(!decomposedVersion.utf8.elementsEqual(composedVersion.utf8))
  let versionMetal = MetalToolchainAuthority(
    componentIdentifier: metal.componentIdentifier,
    componentBuild: metal.componentBuild,
    metadata: metal.metadata,
    tools: metal.tools.enumerated().map { index, tool in
      index == 0
        ? .init(
          path: tool.path, resolvedPath: tool.resolvedPath,
          sha256: tool.sha256, version: composedVersion)
        : tool
    })
  let exactVersionMetal = MetalToolchainAuthority(
    componentIdentifier: metal.componentIdentifier,
    componentBuild: metal.componentBuild,
    metadata: metal.metadata,
    tools: metal.tools.enumerated().map { index, tool in
      index == 0
        ? .init(
          path: tool.path, resolvedPath: tool.resolvedPath,
          sha256: tool.sha256, version: decomposedVersion)
        : tool
    })
  #expect(exactVersionMetal != versionMetal)
  for mutation in [
    VerificationReport(
      schemaVersion: exact.schemaVersion,
      packageSHA256: exact.packageSHA256,
      normalizedSemanticSHA256: exact.normalizedSemanticSHA256,
      embeddedManifestSHA256: exact.embeddedManifestSHA256,
      noticeSetSHA256: exact.noticeSetSHA256,
      hostFiles: exact.hostFiles,
      helperFiles: exact.helperFiles,
      scriptsPresent: exact.scriptsPresent,
      resourcesPresent: exact.resourcesPresent,
      metalToolchain: nil),
    VerificationReport(
      schemaVersion: exact.schemaVersion,
      packageSHA256: exact.packageSHA256,
      normalizedSemanticSHA256: exact.normalizedSemanticSHA256,
      embeddedManifestSHA256: exact.embeddedManifestSHA256,
      noticeSetSHA256: exact.noticeSetSHA256,
      hostFiles: exact.hostFiles,
      helperFiles: exact.helperFiles,
      scriptsPresent: exact.scriptsPresent,
      resourcesPresent: exact.resourcesPresent,
      metalToolchain: changedMetal),
  ] {
    #expect(throws: ReleasePackageError.self) {
      try SignedPackageStaticPreflight.requireRetainedReportAuthority(
        exact, mutation, requireP3Hash: false)
    }
  }

  let exactVersionReport = VerificationReport(
    schemaVersion: exact.schemaVersion,
    packageSHA256: exact.packageSHA256,
    normalizedSemanticSHA256: exact.normalizedSemanticSHA256,
    embeddedManifestSHA256: exact.embeddedManifestSHA256,
    noticeSetSHA256: exact.noticeSetSHA256,
    hostFiles: exact.hostFiles,
    helperFiles: exact.helperFiles,
    scriptsPresent: exact.scriptsPresent,
    resourcesPresent: exact.resourcesPresent,
    metalToolchain: exactVersionMetal)
  let substitutedVersionReport = VerificationReport(
    schemaVersion: exact.schemaVersion,
    packageSHA256: exact.packageSHA256,
    normalizedSemanticSHA256: exact.normalizedSemanticSHA256,
    embeddedManifestSHA256: exact.embeddedManifestSHA256,
    noticeSetSHA256: exact.noticeSetSHA256,
    hostFiles: exact.hostFiles,
    helperFiles: exact.helperFiles,
    scriptsPresent: exact.scriptsPresent,
    resourcesPresent: exact.resourcesPresent,
    metalToolchain: versionMetal)
  try SignedPackageStaticPreflight.requireRetainedReportAuthority(
    exactVersionReport, exactVersionReport, requireP3Hash: false)
  #expect(throws: ReleasePackageError.self) {
    try SignedPackageStaticPreflight.requireRetainedReportAuthority(
      exactVersionReport, substitutedVersionReport, requireP3Hash: false)
  }
}

@Test func realIdentityBoundaryResolvesExactlyOnePairOnlyWhenExplicitlyEnabled() throws {
  guard ProcessInfo.processInfo.environment["REACH_RELEASE_REAL_IDENTITIES"] == "1" else {
    return
  }
  let context = try DeveloperIDIdentityResolver().resolveSigningContext()
  let pair = context.identities
  #expect(pair.application.certificateClass == .application)
  #expect(pair.installer.certificateClass == .installer)
  #expect(pair.application.teamID == pair.installer.teamID)
  #expect(context.loginKeychainPath.hasPrefix("/"))
}
