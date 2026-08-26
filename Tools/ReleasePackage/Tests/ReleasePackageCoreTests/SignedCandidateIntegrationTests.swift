import Foundation
import Testing

@testable import ReleasePackageCore

private struct SignedCandidateInputs {
  let authority: URL
  let unsignedToolSource: URL
  let finalizerToolSource: URL
  let configuration: URL
  let notices: URL
  let depot: URL

  private static let environmentKeys = [
    "REACH_RELEASE_SIGNED_AUTHORITY", "REACH_RELEASE_UNSIGNED_TOOL_SOURCE",
    "REACH_RELEASE_FINALIZER_TOOL_SOURCE", "REACH_RELEASE_CONFIGURATION",
    "REACH_RELEASE_NOTICES", "REACH_RELEASE_DEPOT",
  ]

  static var environmentIsPresent: Bool {
    environmentKeys.contains { ProcessInfo.processInfo.environment[$0] != nil }
  }

  static func current() -> Self? {
    let environment = ProcessInfo.processInfo.environment
    guard environmentKeys.allSatisfy({ environment[$0]?.hasPrefix("/") == true }) else {
      return nil
    }
    return Self(
      authority: URL(fileURLWithPath: environment["REACH_RELEASE_SIGNED_AUTHORITY"]!),
      unsignedToolSource: URL(
        fileURLWithPath: environment["REACH_RELEASE_UNSIGNED_TOOL_SOURCE"]!),
      finalizerToolSource: URL(
        fileURLWithPath: environment["REACH_RELEASE_FINALIZER_TOOL_SOURCE"]!),
      configuration: URL(fileURLWithPath: environment["REACH_RELEASE_CONFIGURATION"]!),
      notices: URL(fileURLWithPath: environment["REACH_RELEASE_NOTICES"]!),
      depot: URL(fileURLWithPath: environment["REACH_RELEASE_DEPOT"]!)
    )
  }

  static func required() throws -> Self {
    guard let value = current() else {
      throw ReleasePackageError.invalidArgument(
        "signed-candidate authority environment is incomplete or malformed")
    }
    return value
  }

  var provenance: URL { authority.appendingPathComponent("release-provenance.json") }
  var p3: URL { authority.appendingPathComponent("Reach-0.0.1-signed.pkg") }
  var p5: URL { authority.appendingPathComponent("Reach-0.0.1.pkg") }

  func verify(
    package: URL,
    provenance: URL? = nil,
    scratch: URL,
    report: URL? = nil
  ) throws
    -> SignedReleaseVerificationReport
  {
    try SignedReleaseVerifier().verify(
      package: package,
      provenanceURL: provenance ?? self.provenance,
      unsignedToolSource: unsignedToolSource,
      finalizerToolSource: finalizerToolSource,
      configurationURL: configuration,
      noticeAuthorityURL: notices,
      dependencyDepot: depot,
      scratch: scratch,
      reportURL: report)
  }
}

private func cloneSignedAuthority(_ inputs: SignedCandidateInputs, below root: URL) throws -> URL {
  let destination = root.appendingPathComponent("authority")
  try SecureFiles.copyTree(
    from: inputs.authority, to: destination, directoryMode: 0o700, fileMode: 0o600)
  return destination
}

private func writeMutatedSignedProvenance(
  source: URL,
  destination: URL,
  mutation: (inout [String: Any]) throws -> Void
) throws {
  var object = try #require(
    JSONSerialization.jsonObject(with: Data(contentsOf: source)) as? [String: Any])
  try mutation(&object)
  let intermediate = try JSONSerialization.data(
    withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
  let decoded = try JSONDecoder().decode(SignedReleaseProvenance.self, from: intermediate)
  try SecureFiles.atomicWrite(try CanonicalJSON.encode(decoded), to: destination)
}

private func expectSignedRefusal(
  containing expected: String,
  _ operation: () throws -> Void
) {
  do {
    try operation()
    Issue.record("expected signed-candidate refusal containing: \(expected)")
  } catch let error as ReleasePackageError {
    #expect(String(describing: error).contains(expected))
  } catch {
    Issue.record("unexpected signed-candidate refusal type: \(error)")
  }
}

@Test(
  .enabled(
    if: SignedCandidateInputs.environmentIsPresent,
    "signed-candidate authority environment is absent"))
func signedCandidatePassesCompleteIndependentP3AndP5Verification() throws {
  let inputs = try SignedCandidateInputs.required()
  let root = try makeTemporaryDirectory("signed-candidate-good")
  defer { removeTemporaryDirectory(root) }
  let provenance = try SignedReleaseProvenance.load(from: inputs.provenance)
  let p3Report = try SignedPackageStaticPreflight(runner: .init()).verifyP3BeforeSubmission(
    package: inputs.p3,
    provenance: provenance,
    authorityRoot: inputs.authority,
    configurationURL: inputs.configuration,
    noticeAuthorityURL: inputs.notices,
    dependencyDepot: inputs.depot,
    scratch: root.appendingPathComponent("p3-preflight"))
  let retained = try JSONDecoder().decode(
    SignedReleaseVerificationReport.self,
    from: Data(
      contentsOf: inputs.authority.appendingPathComponent("p3-independent-verification.json")))
  #expect(p3Report == retained)

  let p3 = try inputs.verify(package: inputs.p3, scratch: root.appendingPathComponent("p3"))
  #expect(p3.stage == "P3")
  #expect(!p3.stapleValidated)
  let copiedAuthority = try cloneSignedAuthority(inputs, below: root)
  let p5Report = copiedAuthority.appendingPathComponent("p5-independent-verification.json")
  let p5 = try inputs.verify(
    package: copiedAuthority.appendingPathComponent("Reach-0.0.1.pkg"),
    provenance: copiedAuthority.appendingPathComponent("release-provenance.json"),
    scratch: root.appendingPathComponent("p5"),
    report: p5Report)
  #expect(p5.stage == "P5")
  #expect(p5.stapleValidated)
  #expect(p5.localAssessmentPassed)
  let sums = try String(
    contentsOf: copiedAuthority.appendingPathComponent("SHA256SUMS"), encoding: .utf8)
  #expect(
    sums.contains(
      "\(try Digests.sha256(file: p5Report))  ./p5-independent-verification.json\n"))

}

@Test(
  .enabled(
    if: SignedCandidateInputs.environmentIsPresent,
    "signed-candidate authority environment is absent"))
func signedCandidateBindsEveryRetainedP0P1AndU1StageBeforeUploadAndFinalVerification() throws {
  let inputs = try SignedCandidateInputs.required()
  let root = try makeTemporaryDirectory("signed-candidate-u1-binding")
  defer { removeTemporaryDirectory(root) }
  let authority = try cloneSignedAuthority(inputs, below: root)
  let canonical = authority.appendingPathComponent("release-provenance.json")
  let original = try Data(contentsOf: canonical)
  let variants: [(String, (inout [String: Any]) throws -> Void)] = [
    (
      "signed P0 does not match retained U1 provenance",
      { object in
        var p0 = try #require(object["p0"] as? [String: Any])
        p0["releaseConfigurationSHA256"] = String(repeating: "0", count: 64)
        object["p0"] = p0
      }
    ),
    (
      "signed P1 does not match retained U1 provenance",
      { object in
        var p1 = try #require(object["p1"] as? [String: Any])
        var manifest = try #require(p1["embeddedManifest"] as? [String: Any])
        manifest["sha256"] = String(repeating: "0", count: 64)
        p1["embeddedManifest"] = manifest
        object["p1"] = p1
      }
    ),
    (
      "signed U1 does not match retained U1 provenance",
      { object in
        var u1 = try #require(object["u1"] as? [String: Any])
        u1["distributionSHA256"] = String(repeating: "0", count: 64)
        object["u1"] = u1
      }
    ),
  ]
  for (index, variant) in variants.enumerated() {
    try SecureFiles.atomicWrite(original, to: canonical)
    try writeMutatedSignedProvenance(
      source: canonical, destination: canonical, mutation: variant.1)
    expectSignedRefusal(containing: variant.0) {
      _ = try inputs.verify(
        package: authority.appendingPathComponent("Reach-0.0.1.pkg"),
        provenance: canonical,
        scratch: root.appendingPathComponent("verification-\(index)"))
    }
    expectSignedRefusal(containing: variant.0) {
      let changed = try SignedReleaseProvenance.load(from: canonical)
      _ = try SignedPackageStaticPreflight(runner: .init()).verifyP3BeforeSubmission(
        package: authority.appendingPathComponent("Reach-0.0.1-signed.pkg"),
        provenance: changed,
        authorityRoot: authority,
        configurationURL: inputs.configuration,
        noticeAuthorityURL: inputs.notices,
        dependencyDepot: inputs.depot,
        scratch: root.appendingPathComponent("pre-upload-\(index)"))
    }
  }
}

@Test(
  .enabled(
    if: SignedCandidateInputs.environmentIsPresent,
    "signed-candidate authority environment is absent"))
func signedCandidateRefusesP2AdHocRuntimeTimestampEntitlementAndChainMutations() throws {
  let inputs = try SignedCandidateInputs.required()
  let root = try makeTemporaryDirectory("signed-candidate-p2-refusals")
  defer { removeTemporaryDirectory(root) }
  let authority = try cloneSignedAuthority(inputs, below: root)
  let canonical = authority.appendingPathComponent("release-provenance.json")
  let original = try Data(contentsOf: canonical)
  let invalidMutations: [(inout [String: Any]) throws -> Void] = [
    { object in
      var p2 = try #require(object["p2"] as? [String: Any])
      var leaves = try #require(p2["signedLeaves"] as? [[String: Any]])
      leaves[0]["runtime"] = false
      p2["signedLeaves"] = leaves
      object["p2"] = p2
    },
    { object in
      var p2 = try #require(object["p2"] as? [String: Any])
      var leaves = try #require(p2["signedLeaves"] as? [[String: Any]])
      leaves[0]["secureTimestampUTC"] = "2035-01-01T00:00:00.000Z"
      p2["signedLeaves"] = leaves
      object["p2"] = p2
    },
    { object in
      var p2 = try #require(object["p2"] as? [String: Any])
      var leaves = try #require(p2["signedLeaves"] as? [[String: Any]])
      leaves[0]["entitlementsSHA256"] = String(repeating: "0", count: 64)
      p2["signedLeaves"] = leaves
      object["p2"] = p2
    },
  ]
  for (index, mutation) in invalidMutations.enumerated() {
    try SecureFiles.atomicWrite(original, to: canonical)
    try writeMutatedSignedProvenance(source: canonical, destination: canonical, mutation: mutation)
    expectSignedRefusal(containing: "signed provenance stage authority changed") {
      _ = try inputs.verify(
        package: authority.appendingPathComponent("Reach-0.0.1.pkg"),
        provenance: canonical,
        scratch: root.appendingPathComponent("invalid-p2-\(index)"))
    }
  }

  try SecureFiles.atomicWrite(original, to: canonical)
  try writeMutatedSignedProvenance(source: canonical, destination: canonical) { object in
    var p2 = try #require(object["p2"] as? [String: Any])
    var certificate = try #require(p2["applicationCertificate"] as? [String: Any])
    var chain = try #require(certificate["chainSHA256"] as? [String])
    chain[1] = String(repeating: "0", count: 64)
    certificate["chainSHA256"] = chain
    p2["applicationCertificate"] = certificate
    object["p2"] = p2
  }
  expectSignedRefusal(containing: "certificate chain") {
    _ = try inputs.verify(
      package: authority.appendingPathComponent("Reach-0.0.1.pkg"),
      provenance: canonical,
      scratch: root.appendingPathComponent("wrong-chain"))
  }

  let originalProvenance = try SignedReleaseProvenance.load(from: inputs.provenance)
  let u1 = inputs.authority.appendingPathComponent(originalProvenance.u1.selectedContainer.path)
  let extractionRoot = root.appendingPathComponent("adhoc-u1")
  try SecureFiles.createPrivateDirectory(extractionRoot)
  let logs = extractionRoot.appendingPathComponent("logs")
  try SecureFiles.createPrivateDirectory(logs)
  let leaves = try SignedPackageLeafExtractor(runner: .init()).extract(
    from: u1, scratch: extractionRoot.appendingPathComponent("leaves"), logs: logs)
  expectSignedRefusal(containing: "signed") {
    _ = try CodeSignatureInspector(runner: .init()).inspectLeaf(
      leaves.host,
      relativePath: "/Library/Application Support/Reach/Host/reachd",
      expectedIdentifier: "reachd",
      expectedCertificate: originalProvenance.p2.applicationCertificate,
      logDirectory: logs)
  }
}

@Test(
  .enabled(
    if: SignedCandidateInputs.environmentIsPresent,
    "signed-candidate authority environment is absent"))
func signedCandidateRefusesP3WrongPayloadAndCertificateClass() throws {
  let inputs = try SignedCandidateInputs.required()
  let root = try makeTemporaryDirectory("signed-candidate-p3-refusals")
  defer { removeTemporaryDirectory(root) }
  let provenance = try SignedReleaseProvenance.load(from: inputs.provenance)
  let u1 = inputs.authority.appendingPathComponent(provenance.u1.selectedContainer.path)
  expectSignedRefusal(containing: "signed container") {
    _ = try PackageVerifier().verifySignedPayload(
      package: u1,
      configurationURL: inputs.configuration,
      noticeAuthorityURL: inputs.notices,
      dependencyDepot: inputs.depot,
      expectedFinalizerToolSourceSHA256: provenance.p2.finalizerToolSourceSHA256,
      noticeManifestURL: inputs.authority.appendingPathComponent("notice-manifest.json"),
      scratch: root.appendingPathComponent("wrong-payload"),
      logDirectory: root.appendingPathComponent("wrong-payload/logs"),
      outerSigned: true)
  }
  let logs = root.appendingPathComponent("wrong-class")
  try SecureFiles.createPrivateDirectory(logs)
  expectSignedRefusal(containing: "wrong certificate chain") {
    _ = try CodeSignatureInspector(runner: .init()).inspectInstallerPackage(
      inputs.p3,
      expectedCertificate: provenance.p2.applicationCertificate,
      logDirectory: logs)
  }
}

@Test(
  .enabled(
    if: SignedCandidateInputs.environmentIsPresent,
    "signed-candidate authority environment is absent"))
func signedCandidateRefusesP5ParentStapleAndTicketSubstitution() throws {
  let inputs = try SignedCandidateInputs.required()
  let root = try makeTemporaryDirectory("signed-candidate-p5-refusals")
  defer { removeTemporaryDirectory(root) }
  let authority = try cloneSignedAuthority(inputs, below: root)
  let canonical = authority.appendingPathComponent("release-provenance.json")
  let original = try Data(contentsOf: canonical)
  try writeMutatedSignedProvenance(source: canonical, destination: canonical) { object in
    var p5 = try #require(object["p5"] as? [String: Any])
    p5["p3ParentSHA256"] = String(repeating: "0", count: 64)
    object["p5"] = p5
  }
  expectSignedRefusal(containing: "P5 staple authority changed") {
    _ = try inputs.verify(
      package: authority.appendingPathComponent("Reach-0.0.1.pkg"),
      provenance: canonical,
      scratch: root.appendingPathComponent("wrong-parent"))
  }

  try SecureFiles.atomicWrite(original, to: canonical)
  try writeMutatedSignedProvenance(source: canonical, destination: canonical) { object in
    var p5 = try #require(object["p5"] as? [String: Any])
    var staple = try #require(p5["stapleValidation"] as? [String: Any])
    staple["sha256"] = String(repeating: "0", count: 64)
    p5["stapleValidation"] = staple
    object["p5"] = p5
  }
  expectSignedRefusal(containing: "signed authority artifact changed") {
    _ = try inputs.verify(
      package: authority.appendingPathComponent("Reach-0.0.1.pkg"),
      provenance: canonical,
      scratch: root.appendingPathComponent("wrong-staple"))
  }

  let missingTicket = try ProcessRunner().run(
    "/usr/bin/xcrun", ["stapler", "validate", inputs.p3.path],
    logURL: root.appendingPathComponent("missing-ticket.log"), requireSuccess: false)
  #expect(missingTicket.exitStatus != 0)

  let tamperedP5 = root.appendingPathComponent("tampered-ticket.pkg")
  try SecureFiles.copyRegularFile(from: inputs.p5, to: tamperedP5, mode: 0o600)
  var bytes = try Data(contentsOf: tamperedP5)
  bytes[bytes.index(before: bytes.endIndex)] ^= 0x01
  try SecureFiles.atomicWrite(bytes, to: tamperedP5)
  expectSignedRefusal(containing: "package is not the P3 or P5 provenance artifact") {
    _ = try inputs.verify(
      package: tamperedP5,
      scratch: root.appendingPathComponent("tampered-ticket-verification"))
  }
}

@Test(
  .enabled(
    if: SignedCandidateInputs.environmentIsPresent,
    "signed-candidate authority environment is absent"))
func signedCandidateReusesTheExactAcceptedNotaryArtifactsWithoutResubmission() throws {
  let inputs = try SignedCandidateInputs.required()
  let provenance = try SignedReleaseProvenance.load(from: inputs.provenance)
  let p4 = try #require(provenance.p4)
  let waitURL = inputs.authority.appendingPathComponent(p4.waitResponse.path)
  let logURL = inputs.authority.appendingPathComponent(p4.notaryLog.path)
  let first = try ReleaseNotarizer.validateAcceptedArtifacts(
    waitURL: waitURL,
    logURL: logURL,
    submissionID: p4.submissionID,
    p3SHA256: provenance.p3.signedContainer.sha256,
    archiveName: URL(fileURLWithPath: provenance.p3.signedContainer.path).lastPathComponent,
    startedAtUTC: nil)
  let second = try ReleaseNotarizer.validateAcceptedArtifacts(
    waitURL: waitURL,
    logURL: logURL,
    submissionID: p4.submissionID,
    p3SHA256: provenance.p3.signedContainer.sha256,
    archiveName: URL(fileURLWithPath: provenance.p3.signedContainer.path).lastPathComponent,
    startedAtUTC: nil)
  #expect(first.waitResponseSHA256 == p4.waitResponse.sha256)
  #expect(first.notaryLogSHA256 == p4.notaryLog.sha256)
  #expect(first.waitResponseSHA256 == second.waitResponseSHA256)
  #expect(first.notaryLogSHA256 == second.notaryLogSHA256)
}
