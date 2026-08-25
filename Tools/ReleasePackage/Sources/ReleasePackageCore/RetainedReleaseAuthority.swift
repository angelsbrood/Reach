import Darwin
import Foundation

public struct RetainedReleaseAuthorityManifest: Codable, Equatable, Sendable {
  public struct File: Codable, Equatable, Sendable {
    public let path: String
    public let size: UInt64
    public let sha256: String

    public init(path: String, size: UInt64, sha256: String) {
      self.path = path
      self.size = size
      self.sha256 = sha256
    }
  }

  public let schemaVersion: Int
  public let release: ReleaseVersionMap
  public let p5SHA256: String
  public let provenanceSHA256: String
  public let verificationReportSHA256: String
  public let files: [File]

  public init(
    schemaVersion: Int,
    release: ReleaseVersionMap,
    p5SHA256: String,
    provenanceSHA256: String,
    verificationReportSHA256: String,
    files: [File]
  ) {
    self.schemaVersion = schemaVersion
    self.release = release
    self.p5SHA256 = p5SHA256
    self.provenanceSHA256 = provenanceSHA256
    self.verificationReportSHA256 = verificationReportSHA256
    self.files = files
  }
}

public struct RetainedReleaseAuthorityResult: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let authorityRoot: String
  public let manifestSHA256: String
  public let p5SHA256: String
  public let provenanceSHA256: String
  public let fileCount: Int
}

/// Promotes a verified P5 into durable, self-contained authority. The source
/// signing work root is deliberately not copied wholesale: only artifacts
/// named by provenance plus the exact verifier inputs cross this boundary.
public struct RetainedReleaseAuthoritySealer {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
  }

  public func seal(
    signedAuthority: URL,
    unsignedToolSource: URL,
    finalizerToolSource: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    scratch: URL,
    output: URL
  ) throws -> RetainedReleaseAuthorityResult {
    guard !FileManager.default.fileExists(atPath: output.path) else {
      throw ReleasePackageError.unsafePath("retained authority output already exists")
    }
    try SecureFiles.createPrivateDirectory(scratch)
    let provenanceURL = signedAuthority.appendingPathComponent("release-provenance.json")
    let envelope = try AnySignedReleaseProvenance.load(from: provenanceURL)
    let view = envelope.view
    guard let lineage = view.lineage, let p5 = view.p5 else {
      throw ReleasePackageError.verification(
        "durable multi-release authority requires complete schema-3 P5 provenance")
    }
    let package = try verifiedArtifact(p5.stapledContainer, below: signedAuthority)
    let sourceReport = scratch.appendingPathComponent("source-verification.json")
    let report = try SignedReleaseVerifier(runner: runner).verify(
      package: package,
      provenanceURL: provenanceURL,
      unsignedToolSource: unsignedToolSource,
      finalizerToolSource: finalizerToolSource,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      scratch: scratch.appendingPathComponent("source-verification"),
      reportURL: sourceReport)
    guard report.stage == "P5", report.packageSHA256 == p5.stapledContainer.sha256,
      report.hostFiles == 50, report.helperFiles == 6,
      !report.scriptsPresent, !report.resourcesPresent,
      report.stapleValidated, report.localAssessmentPassed
    else {
      throw ReleasePackageError.verification(
        "signed release did not pass the complete retained-authority gate")
    }

    try SecureFiles.createPrivateDirectory(output)
    do {
      try copyInput(configurationURL, to: output.appendingPathComponent("release.json"))
      try copyInput(noticeAuthorityURL, to: output.appendingPathComponent("notices.json"))
      try copyTree(unsignedToolSource, to: output.appendingPathComponent("unsigned-tool-source"))
      try copyTree(finalizerToolSource, to: output.appendingPathComponent("finalizer-tool-source"))
      try copyTree(dependencyDepot, to: output.appendingPathComponent("dependency-depot"))
      try copyInput(provenanceURL, to: output.appendingPathComponent("release-provenance.json"))
      try copyInput(
        signedAuthority.appendingPathComponent("u1-release-provenance.json"),
        to: output.appendingPathComponent("u1-release-provenance.json"))
      let lineageURL = signedAuthority.appendingPathComponent("release-lineage.json")
      let retainedLineage = try ReleaseLineageAuthority.load(from: lineageURL)
      guard retainedLineage == lineage else {
        throw ReleasePackageError.verification(
          "retained lineage file does not match schema-3 provenance")
      }
      try copyInput(lineageURL, to: output.appendingPathComponent("release-lineage.json"))

      let noticeManifest = signedAuthority.appendingPathComponent("notice-manifest.json")
      try copyInput(noticeManifest, to: output.appendingPathComponent("notice-manifest.json"))
      var artifacts = [view.p1.embeddedManifest, view.p1.notices]
      artifacts.append(contentsOf: view.p1.hostComponents)
      artifacts.append(contentsOf: view.p1.helperComponents)
      artifacts.append(contentsOf: view.p1.hostBOMs)
      artifacts.append(contentsOf: view.p1.helperBOMs)
      artifacts.append(contentsOf: view.u1.containers)
      artifacts.append(view.u1.selectedContainer)
      artifacts.append(contentsOf: [
        view.p2.embeddedManifest, view.p2.hostComponent, view.p2.helperComponent,
        view.p2.hostBOM, view.p2.helperBOM, view.p2.unsignedContainer,
        view.p3.signedContainer, view.p3.payloadVerification,
        p5.stapledContainer, p5.stapleValidation, p5.nestedVerification,
      ])
      if let p4 = view.p4 {
        artifacts += [p4.submissionEvidence, p4.waitResponse, p4.notaryLog]
      }
      for artifact in try Self.uniqueArtifacts(artifacts) {
        let source = try verifiedArtifact(artifact, below: signedAuthority)
        let destination = output.appendingPathComponent(artifact.path)
        try createPrivateAncestors(for: destination, below: output)
        try copyInput(source, to: destination)
      }

      let destinationReport = output.appendingPathComponent("retained-verification.json")
      let retainedReport = try SignedReleaseVerifier(runner: runner).verify(
        package: output.appendingPathComponent(p5.stapledContainer.path),
        provenanceURL: output.appendingPathComponent("release-provenance.json"),
        unsignedToolSource: output.appendingPathComponent("unsigned-tool-source"),
        finalizerToolSource: output.appendingPathComponent("finalizer-tool-source"),
        configurationURL: output.appendingPathComponent("release.json"),
        noticeAuthorityURL: output.appendingPathComponent("notices.json"),
        dependencyDepot: output.appendingPathComponent("dependency-depot"),
        scratch: scratch.appendingPathComponent("retained-verification"),
        reportURL: destinationReport)
      guard retainedReport == report else {
        throw ReleasePackageError.verification(
          "retained release authority does not reproduce its source verification")
      }

      let manifestURL = output.appendingPathComponent("retained-authority.json")
      let files = try fileRecords(below: output, excluding: [manifestURL.lastPathComponent])
      let manifest = RetainedReleaseAuthorityManifest(
        schemaVersion: 1,
        release: lineage.release,
        p5SHA256: p5.stapledContainer.sha256,
        provenanceSHA256: try Digests.sha256(
          file: output.appendingPathComponent("release-provenance.json")),
        verificationReportSHA256: try Digests.sha256(file: destinationReport),
        files: files)
      try SecureFiles.atomicWrite(try CanonicalJSON.encode(manifest), to: manifestURL)
      try verify(manifestURL: manifestURL, authorityRoot: output)
      return .init(
        schemaVersion: 1,
        authorityRoot: output.path,
        manifestSHA256: try Digests.sha256(file: manifestURL),
        p5SHA256: manifest.p5SHA256,
        provenanceSHA256: manifest.provenanceSHA256,
        fileCount: manifest.files.count)
    } catch {
      try? FileManager.default.removeItem(at: output)
      throw error
    }
  }

  public func verify(manifestURL: URL, authorityRoot: URL) throws {
    let expectedManifest = authorityRoot.appendingPathComponent("retained-authority.json")
    guard manifestURL.path.utf8.elementsEqual(expectedManifest.path.utf8) else {
      throw ReleasePackageError.unsafePath("retained manifest is outside its authority root")
    }
    var rootInfo = stat()
    guard lstat(authorityRoot.path, &rootInfo) == 0,
      (rootInfo.st_mode & S_IFMT) == S_IFDIR,
      rootInfo.st_uid == getuid(),
      (rootInfo.st_mode & 0o7777) == 0o700
    else {
      throw ReleasePackageError.unsafePath("retained authority root must be mode 0700")
    }
    let data = try Data(contentsOf: manifestURL, options: [.mappedIfSafe])
    let manifest = try JSONDecoder().decode(RetainedReleaseAuthorityManifest.self, from: data)
    let shaPattern = #"^[0-9a-f]{64}$"#
    guard data == (try CanonicalJSON.encode(manifest)), manifest.schemaVersion == 1,
      manifest.p5SHA256.range(of: shaPattern, options: .regularExpression) != nil,
      manifest.provenanceSHA256.range(of: shaPattern, options: .regularExpression) != nil,
      manifest.verificationReportSHA256.range(
        of: shaPattern, options: .regularExpression) != nil,
      manifest.files.map(\.path).count == Set(manifest.files.map(\.path)).count,
      manifest.files.allSatisfy({ file in
        (try? SecureFiles.validateRelativePath(file.path)) != nil
          && file.path != "retained-authority.json" && file.size > 0
          && file.sha256.range(of: shaPattern, options: .regularExpression) != nil
      }),
      manifest.files
        == (try fileRecords(
          below: authorityRoot, excluding: [manifestURL.lastPathComponent])),
      manifest.files.filter({ $0.sha256 == manifest.p5SHA256 }).count == 1
    else {
      throw ReleasePackageError.verification("retained release manifest changed")
    }
    guard
      manifest.files.contains(where: {
        $0.path == "release-provenance.json" && $0.sha256 == manifest.provenanceSHA256
      }),
      manifest.files.contains(where: {
        $0.path == "retained-verification.json"
          && $0.sha256 == manifest.verificationReportSHA256
      }), manifest.files.contains(where: { $0.sha256 == manifest.p5SHA256 })
    else {
      throw ReleasePackageError.verification("retained release authority is incomplete")
    }
  }

  private func copyTree(_ source: URL, to destination: URL) throws {
    try SecureFiles.copyTree(
      from: source, to: destination, directoryMode: 0o700, fileMode: 0o600)
  }

  private func copyInput(_ source: URL, to destination: URL) throws {
    try SecureFiles.copyInputFile(from: source, to: destination, mode: 0o600)
  }

  static func uniqueArtifacts(
    _ artifacts: [ReleaseProvenance.Artifact]
  ) throws -> [ReleaseProvenance.Artifact] {
    let grouped = Dictionary(grouping: artifacts, by: \.path)
    var result: [ReleaseProvenance.Artifact] = []
    for path in grouped.keys.sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }) {
      guard let values = grouped[path], let first = values.first,
        values.dropFirst().allSatisfy({ $0 == first })
      else {
        throw ReleasePackageError.verification(
          "retained release names conflicting artifacts at " + path)
      }
      result.append(first)
    }
    return result
  }

  private func verifiedArtifact(
    _ artifact: ReleaseProvenance.Artifact, below root: URL
  ) throws -> URL {
    try SecureFiles.validateRelativePath(artifact.path)
    let url = root.appendingPathComponent(artifact.path)
    var info = stat()
    guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, UInt64(info.st_size) == artifact.size,
      try Digests.sha256(file: url) == artifact.sha256
    else {
      throw ReleasePackageError.verification(
        "signed authority artifact changed: \(artifact.path)")
    }
    return url
  }

  private func createPrivateAncestors(for file: URL, below root: URL) throws {
    let relative = String(file.deletingLastPathComponent().path.dropFirst(root.path.count + 1))
    if relative.isEmpty { return }
    var current = root
    for component in relative.split(separator: "/") {
      current.appendPathComponent(String(component))
      try SecureFiles.createDirectory(current, mode: 0o700)
    }
  }

  private func fileRecords(below root: URL, excluding: Set<String>) throws
    -> [RetainedReleaseAuthorityManifest.File]
  {
    try SecureFiles.enumerateTree(root).compactMap { url in
      let relative = String(url.path.dropFirst(root.path.count + 1))
      guard !excluding.contains(relative) else { return nil }
      var info = stat()
      guard lstat(url.path, &info) == 0 else {
        throw ReleasePackageError.verification("cannot inspect retained authority member")
      }
      if (info.st_mode & S_IFMT) == S_IFDIR {
        guard (info.st_mode & 0o7777) == 0o700 else {
          throw ReleasePackageError.unsafePath(
            "retained authority directory must be mode 0700: \(relative)")
        }
        return nil
      }
      guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
        info.st_uid == getuid(), (info.st_mode & 0o7777) == 0o600
      else {
        throw ReleasePackageError.unsafePath(
          "retained authority file must be a mode-0600 single-link file: \(relative)")
      }
      return .init(
        path: relative, size: UInt64(info.st_size), sha256: try Digests.sha256(file: url))
    }.sorted { lhs, rhs in
      lhs.path.utf8.lexicographicallyPrecedes(rhs.path.utf8)
    }
  }
}
