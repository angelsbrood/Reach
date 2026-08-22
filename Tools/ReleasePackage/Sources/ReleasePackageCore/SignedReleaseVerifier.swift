import Darwin
import Foundation

public struct SignedReleaseVerificationReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let stage: String
  public let packageSHA256: String
  public let p3ParentSHA256: String
  public let normalizedSemanticSHA256: String
  public let teamID: String
  public let hostFiles: Int
  public let helperFiles: Int
  public let scriptsPresent: Bool
  public let resourcesPresent: Bool
  public let stapleValidated: Bool
  public let localAssessmentPassed: Bool
}

enum RetainedU1AuthorityBinder {
  static func verify(
    signed provenance: SignedReleaseProvenance,
    authorityRoot: URL
  ) throws -> ReleaseProvenance {
    let url = authorityRoot.appendingPathComponent("u1-release-provenance.json")
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let retained = try JSONDecoder().decode(ReleaseProvenance.self, from: data)
    guard data == (try CanonicalJSON.encode(retained)) else {
      throw ReleasePackageError.verification("retained U1 provenance is not canonical JSON")
    }
    guard provenance.p0 == retained.p0 else {
      throw ReleasePackageError.verification(
        "signed P0 does not match retained U1 provenance")
    }
    guard provenance.p1 == retained.p1 else {
      throw ReleasePackageError.verification(
        "signed P1 does not match retained U1 provenance")
    }
    guard provenance.u1 == retained.u1 else {
      throw ReleasePackageError.verification(
        "signed U1 does not match retained U1 provenance")
    }
    return retained
  }
}

public struct SignedReleaseVerifier {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
  }

  public func verify(
    package: URL,
    provenanceURL: URL,
    unsignedToolSource: URL,
    finalizerToolSource: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    scratch: URL,
    reportURL: URL? = nil
  ) throws -> SignedReleaseVerificationReport {
    try SecureFiles.createPrivateDirectory(scratch)
    let logs = scratch.appendingPathComponent("logs")
    try SecureFiles.createPrivateDirectory(logs)
    let provenance = try SignedReleaseProvenance.load(from: provenanceURL)
    let authorityRoot = provenanceURL.deletingLastPathComponent()
    _ = try RetainedU1AuthorityBinder.verify(
      signed: provenance, authorityRoot: authorityRoot)
    guard
      try SourceInspector().canonicalTreeDigest(unsignedToolSource)
        == SignedReleaseContract.unsignedToolSourceSHA256,
      try SourceInspector().canonicalTreeDigest(finalizerToolSource)
        == provenance.p2.finalizerToolSourceSHA256
    else {
      throw ReleasePackageError.verification("release-tool source authority changed")
    }
    try verifyRetainedArtifacts(provenance, root: authorityRoot)

    let u1 = authorityRoot.appendingPathComponent(provenance.u1.selectedContainer.path)
    let u1Report = try PackageVerifier(runner: runner).verify(
      package: u1,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      expectedReleaseToolSourceSHA256: SignedReleaseContract.unsignedToolSourceSHA256,
      provenanceURL: authorityRoot.appendingPathComponent("u1-release-provenance.json"),
      noticeManifestURL: authorityRoot.appendingPathComponent("notice-manifest.json"),
      scratch: scratch.appendingPathComponent("u1"),
      logDirectory: scratch.appendingPathComponent("u1/logs")
    )
    guard u1Report.normalizedSemanticSHA256 == SignedReleaseContract.unsignedSemanticSHA256 else {
      throw ReleasePackageError.verification("retained U1 semantic authority changed")
    }

    let packageHash = try Digests.sha256(file: package)
    let isP5: Bool
    if packageHash == provenance.p3.signedContainer.sha256 {
      isP5 = false
    } else if let p5 = provenance.p5, packageHash == p5.stapledContainer.sha256 {
      isP5 = true
    } else {
      throw ReleasePackageError.verification("package is not the P3 or P5 provenance artifact")
    }
    let packageReport = try PackageVerifier(runner: runner).verifySignedPayload(
      package: package,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      expectedFinalizerToolSourceSHA256: provenance.p2.finalizerToolSourceSHA256,
      noticeManifestURL: authorityRoot.appendingPathComponent("notice-manifest.json"),
      scratch: scratch.appendingPathComponent("signed-package"),
      logDirectory: scratch.appendingPathComponent("signed-package/logs"),
      outerSigned: true
    )
    guard packageReport.normalizedSemanticSHA256 == provenance.p2.normalizedSemanticSHA256 else {
      throw ReleasePackageError.verification("signed payload semantics changed")
    }
    let extractedLeaves = try SignedPackageLeafExtractor(runner: runner).extract(
      from: package, scratch: scratch.appendingPathComponent("leaf-extraction"), logs: logs)
    let inspector = CodeSignatureInspector(runner: runner)
    let actualLeaves = try [
      inspector.inspectLeaf(
        extractedLeaves.host,
        relativePath: "/Library/Application Support/Reach/Host/reachd",
        expectedIdentifier: "reachd",
        expectedCertificate: provenance.p2.applicationCertificate,
        logDirectory: logs),
      inspector.inspectLeaf(
        extractedLeaves.helper,
        relativePath: "/Library/PrivilegedHelperTools/systems.reach.meshd",
        expectedIdentifier: "systems.reach.meshd",
        expectedCertificate: provenance.p2.applicationCertificate,
        logDirectory: logs),
    ]
    guard actualLeaves == provenance.p2.signedLeaves else {
      throw ReleasePackageError.verification("signed leaf provenance changed")
    }
    _ = try inspector.inspectInstallerPackage(
      package,
      expectedCertificate: provenance.p3.installerCertificate,
      logDirectory: logs)

    var stapleValidated = false
    var assessmentPassed = false
    if isP5 {
      guard let p4 = provenance.p4, let p5 = provenance.p5,
        p4.signedContainerSHA256 == provenance.p3.signedContainer.sha256,
        p5.p3ParentSHA256 == provenance.p3.signedContainer.sha256
      else {
        throw ReleasePackageError.verification("P5 lacks its exact accepted P3 parent")
      }
      _ = try runner.run(
        "/usr/bin/xcrun", ["stapler", "validate", package.path],
        logURL: logs.appendingPathComponent("stapler-validate.log"))
      stapleValidated = true
      let assessment = try runner.run(
        "/usr/sbin/spctl", ["--assess", "--type", "install", "--verbose=4", package.path],
        logURL: logs.appendingPathComponent("spctl-p5.log"))
      assessmentPassed = assessment.exitStatus == 0
      let logURL = authorityRoot.appendingPathComponent(p4.notaryLog.path)
      try verifyNotaryLog(
        logURL, p3SHA256: provenance.p3.signedContainer.sha256,
        submissionID: p4.submissionID, archiveName: packageName(provenance.p3.signedContainer.path))
    }
    let report = SignedReleaseVerificationReport(
      schemaVersion: 1,
      stage: isP5 ? "P5" : "P3",
      packageSHA256: packageHash,
      p3ParentSHA256: provenance.p3.signedContainer.sha256,
      normalizedSemanticSHA256: packageReport.normalizedSemanticSHA256,
      teamID: provenance.p2.applicationCertificate.teamID,
      hostFiles: packageReport.hostFiles,
      helperFiles: packageReport.helperFiles,
      scriptsPresent: packageReport.scriptsPresent,
      resourcesPresent: packageReport.resourcesPresent,
      stapleValidated: stapleValidated,
      localAssessmentPassed: assessmentPassed
    )
    if let reportURL {
      try SecureFiles.atomicWrite(try CanonicalJSON.encode(report), to: reportURL)
      try refreshAuthorityManifestIfOwned(reportURL: reportURL, authorityRoot: authorityRoot)
    }
    return report
  }

  private func verifyRetainedArtifacts(_ value: SignedReleaseProvenance, root: URL) throws {
    var artifacts = [value.p1.embeddedManifest, value.p1.notices]
    artifacts.append(contentsOf: value.p1.hostComponents)
    artifacts.append(contentsOf: value.p1.helperComponents)
    artifacts.append(contentsOf: value.p1.hostBOMs)
    artifacts.append(contentsOf: value.p1.helperBOMs)
    artifacts.append(contentsOf: value.u1.containers)
    artifacts.append(value.u1.selectedContainer)
    artifacts.append(contentsOf: [
      value.p2.unsignedParent, value.p2.embeddedManifest, value.p2.hostComponent,
      value.p2.helperComponent, value.p2.hostBOM, value.p2.helperBOM,
      value.p2.unsignedContainer, value.p3.signedContainer, value.p3.payloadVerification,
    ])
    if let p4 = value.p4 {
      artifacts.append(contentsOf: [p4.submissionEvidence, p4.waitResponse, p4.notaryLog])
    }
    if let p5 = value.p5 {
      artifacts.append(contentsOf: [
        p5.stapledContainer, p5.stapleValidation, p5.nestedVerification,
      ])
    }
    for artifact in artifacts {
      try SecureFiles.validateRelativePath(artifact.path)
      let file = root.appendingPathComponent(artifact.path)
      var info = stat()
      guard lstat(file.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
        info.st_nlink == 1,
        UInt64(info.st_size) == artifact.size,
        try Digests.sha256(file: file) == artifact.sha256
      else {
        throw ReleasePackageError.verification(
          "signed authority artifact changed: \(artifact.path)")
      }
    }
  }

  private func refreshAuthorityManifestIfOwned(reportURL: URL, authorityRoot: URL) throws {
    guard reportURL.deletingLastPathComponent().path.utf8.elementsEqual(authorityRoot.path.utf8),
      FileManager.default.fileExists(
        atPath: authorityRoot.appendingPathComponent("SHA256SUMS").path)
    else { return }
    let entries = try SecureFiles.enumerateTree(authorityRoot).filter { url in
      var info = stat()
      return lstat(url.path, &info) == 0
        && (info.st_mode & S_IFMT) == S_IFREG
        && url.lastPathComponent != "SHA256SUMS"
    }.sorted { $0.path < $1.path }
    let lines =
      try entries.map { url in
        let relative = String(url.path.dropFirst(authorityRoot.path.count + 1))
        return "\(try Digests.sha256(file: url))  ./\(relative)"
      }.joined(separator: "\n") + "\n"
    try SecureFiles.atomicWrite(
      Data(lines.utf8), to: authorityRoot.appendingPathComponent("SHA256SUMS"))
  }

  private func verifyNotaryLog(
    _ url: URL,
    p3SHA256: String,
    submissionID: String,
    archiveName: String
  ) throws {
    _ = try NotarizationResponseValidator().requireAcceptedLog(
      Data(contentsOf: url),
      submissionID: submissionID,
      p3SHA256: p3SHA256,
      archiveName: archiveName,
      startedAtUTC: nil,
      requireUploadWindow: false)
  }

  private func packageName(_ path: String) -> String {
    URL(fileURLWithPath: path).lastPathComponent
  }
}
