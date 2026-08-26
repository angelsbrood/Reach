import Foundation

struct SignedPackageStaticPreflight {
  private let runner: ProcessRunner

  init(runner: ProcessRunner) {
    self.runner = runner
  }

  func verifyP3BeforeSubmission(
    package: URL,
    provenance: SignedReleaseProvenance,
    authorityRoot: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    scratch: URL
  ) throws -> SignedReleaseVerificationReport {
    try verifyP3BeforeSubmission(
      package: package,
      provenance: .init(
        schemaVersion: provenance.schemaVersion, lineage: nil,
        p0: provenance.p0, p1: provenance.p1, u1: provenance.u1,
        p2: provenance.p2, p3: provenance.p3, p4: provenance.p4, p5: provenance.p5),
      authorityRoot: authorityRoot,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      scratch: scratch)
  }

  func verifyP3BeforeSubmission(
    package: URL,
    provenance: SignedProvenanceView,
    authorityRoot: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    scratch: URL
  ) throws -> SignedReleaseVerificationReport {
    _ = try RetainedU1AuthorityBinder.verify(
      signed: provenance, authorityRoot: authorityRoot)
    let payload = try verify(
      package: package,
      provenance: provenance,
      authorityRoot: authorityRoot,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      scratch: scratch)
    let reportURL = authorityRoot.appendingPathComponent("p3-independent-verification.json")
    let reportData = try Data(contentsOf: reportURL, options: [.mappedIfSafe])
    let report = try JSONDecoder().decode(
      SignedReleaseVerificationReport.self, from: reportData)
    let expected = SignedReleaseVerificationReport(
      schemaVersion: 1,
      stage: "P3",
      packageSHA256: provenance.p3.signedContainer.sha256,
      p3ParentSHA256: provenance.p3.signedContainer.sha256,
      normalizedSemanticSHA256: payload.normalizedSemanticSHA256,
      teamID: provenance.p2.applicationCertificate.teamID,
      hostFiles: payload.hostFiles,
      helperFiles: payload.helperFiles,
      scriptsPresent: payload.scriptsPresent,
      resourcesPresent: payload.resourcesPresent,
      stapleValidated: false,
      localAssessmentPassed: false)
    guard reportData == (try CanonicalJSON.encode(report)), report == expected else {
      throw ReleasePackageError.verification(
        "independent P3 verification authority changed before notarization")
    }
    return report
  }

  func verify(
    package: URL,
    provenance: SignedReleaseProvenance,
    authorityRoot: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    scratch: URL,
    requireP3Hash: Bool = true
  ) throws -> VerificationReport {
    try verify(
      package: package,
      provenance: .init(
        schemaVersion: provenance.schemaVersion, lineage: nil,
        p0: provenance.p0, p1: provenance.p1, u1: provenance.u1,
        p2: provenance.p2, p3: provenance.p3, p4: provenance.p4, p5: provenance.p5),
      authorityRoot: authorityRoot,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      scratch: scratch,
      requireP3Hash: requireP3Hash)
  }

  func verify(
    package: URL,
    provenance: SignedProvenanceView,
    authorityRoot: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    scratch: URL,
    requireP3Hash: Bool = true
  ) throws -> VerificationReport {
    try SecureFiles.createPrivateDirectory(scratch)
    let logs = scratch.appendingPathComponent("logs")
    try SecureFiles.createPrivateDirectory(logs)
    let packageSHA256 = try Digests.sha256(file: package)
    guard !requireP3Hash || packageSHA256 == provenance.p3.signedContainer.sha256 else {
      throw ReleasePackageError.verification("P3 package hash changed before notarization")
    }
    let independentlyVerified = try PackageVerifier(runner: runner).verifySignedPayload(
      package: package,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      expectedFinalizerToolSourceSHA256: provenance.p2.finalizerToolSourceSHA256,
      noticeManifestURL: authorityRoot.appendingPathComponent("notice-manifest.json"),
      scratch: scratch.appendingPathComponent("payload"),
      logDirectory: logs.appendingPathComponent("payload"),
      outerSigned: true)
    let reportURL = authorityRoot.appendingPathComponent(provenance.p3.payloadVerification.path)
    let reportData = try Data(contentsOf: reportURL, options: [.mappedIfSafe])
    let report = try JSONDecoder().decode(VerificationReport.self, from: reportData)
    guard reportData == (try CanonicalJSON.encode(report)),
      report.packageSHA256 == provenance.p3.signedContainer.sha256,
      report.normalizedSemanticSHA256 == provenance.p2.normalizedSemanticSHA256,
      report.hostFiles == 50,
      report.helperFiles == 6,
      !report.scriptsPresent,
      !report.resourcesPresent
    else {
      throw ReleasePackageError.verification("P3 payload verification authority changed")
    }
    try Self.requireRetainedReportAuthority(
      independentlyVerified, report, requireP3Hash: requireP3Hash)
    let inspector = CodeSignatureInspector(runner: runner)
    _ = try inspector.inspectInstallerPackage(
      package,
      expectedCertificate: provenance.p3.installerCertificate,
      logDirectory: logs)
    let leaves = try SignedPackageLeafExtractor(runner: runner).extract(
      from: package, scratch: scratch.appendingPathComponent("leaves"), logs: logs)
    let actual = try [
      inspector.inspectLeaf(
        leaves.host,
        relativePath: "/Library/Application Support/Reach/Host/reachd",
        expectedIdentifier: "reachd",
        expectedCertificate: provenance.p2.applicationCertificate,
        logDirectory: logs),
      inspector.inspectLeaf(
        leaves.helper,
        relativePath: "/Library/PrivilegedHelperTools/systems.reach.meshd",
        expectedIdentifier: "systems.reach.meshd",
        expectedCertificate: provenance.p2.applicationCertificate,
        logDirectory: logs),
    ]
    guard actual == provenance.p2.signedLeaves else {
      throw ReleasePackageError.verification("P3 nested signatures changed")
    }
    return independentlyVerified
  }

  static func requireRetainedReportAuthority(
    _ independentlyVerified: VerificationReport,
    _ retained: VerificationReport,
    requireP3Hash: Bool
  ) throws {
    guard samePayloadAuthority(independentlyVerified, retained) else {
      throw ReleasePackageError.verification(
        "independent signed-package verification does not match retained P3 authority")
    }
    if requireP3Hash, independentlyVerified != retained {
      throw ReleasePackageError.verification(
        "independent P3 verification does not match the retained report")
    }
  }

  private static func samePayloadAuthority(
    _ lhs: VerificationReport,
    _ rhs: VerificationReport
  ) -> Bool {
    lhs.schemaVersion == rhs.schemaVersion
      && lhs.normalizedSemanticSHA256 == rhs.normalizedSemanticSHA256
      && lhs.embeddedManifestSHA256 == rhs.embeddedManifestSHA256
      && lhs.noticeSetSHA256 == rhs.noticeSetSHA256
      && lhs.hostFiles == rhs.hostFiles
      && lhs.helperFiles == rhs.helperFiles
      && lhs.scriptsPresent == rhs.scriptsPresent
      && lhs.resourcesPresent == rhs.resourcesPresent
      && lhs.metalToolchain == rhs.metalToolchain
  }
}

struct SignedPackageLeafExtractor {
  private let runner: ProcessRunner

  init(runner: ProcessRunner) {
    self.runner = runner
  }

  func extract(from package: URL, scratch: URL, logs: URL) throws
    -> (host: URL, helper: URL)
  {
    try SecureFiles.createPrivateDirectory(scratch)
    let expanded = scratch.appendingPathComponent("expanded")
    try SecureFiles.createPrivateDirectory(expanded)
    _ = try runner.run(
      "/usr/bin/xar", ["-xf", package.path], currentDirectory: expanded,
      logURL: logs.appendingPathComponent("leaf-outer-expand.log"))
    let host = try extractLeaf(
      component: expanded.appendingPathComponent("systems.reach.host.pkg"),
      memberPath: "./Library/Application Support/Reach/Host/reachd",
      destination: scratch.appendingPathComponent("signed-reachd"),
      scratch: scratch.appendingPathComponent("host"), logs: logs)
    let helper = try extractLeaf(
      component: expanded.appendingPathComponent("systems.reach.meshd.pkg"),
      memberPath: "./Library/PrivilegedHelperTools/systems.reach.meshd",
      destination: scratch.appendingPathComponent("signed-meshd"),
      scratch: scratch.appendingPathComponent("helper"), logs: logs)
    return (host, helper)
  }

  private func extractLeaf(
    component: URL,
    memberPath: String,
    destination: URL,
    scratch: URL,
    logs: URL
  ) throws -> URL {
    try SecureFiles.createPrivateDirectory(scratch)
    let compressed = scratch.appendingPathComponent("Payload.gz")
    try SecureFiles.copyRegularFile(
      from: component.appendingPathComponent("Payload"), to: compressed, mode: 0o600)
    _ = try runner.run(
      "/usr/bin/gzip", ["-d", "-k", compressed.path],
      logURL: logs.appendingPathComponent("leaf-gzip-\(destination.lastPathComponent).log"))
    let members = try ODCArchive.parseMembers(
      Data(contentsOf: scratch.appendingPathComponent("Payload"), options: [.mappedIfSafe]))
    guard let member = members.first(where: { $0.record.path == memberPath }),
      member.record.kind == .file
    else {
      throw ReleasePackageError.verification("signed package leaf is missing")
    }
    try SecureFiles.atomicWrite(member.data, to: destination, mode: 0o700)
    return destination
  }
}
