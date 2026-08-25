import Darwin
import Foundation

public struct ReleaseLineageFreezeResult: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let lineageAuthority: String
  public let lineageAuthoritySHA256: String
  public let release: ReleaseVersionMap
  public let unsignedContainerSHA256: String
  public let normalizedSemanticSHA256: String
}

public struct ReleaseLineageFreezer {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
  }

  public func freeze(
    unsignedAuthority: URL,
    unsignedToolSource: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    scratch: URL,
    output: URL,
    parentAuthority: URL? = nil
  ) throws -> ReleaseLineageFreezeResult {
    let configuration = try ReleaseConfiguration.load(from: configurationURL)
    guard configuration.schemaVersion == 2, let declaration = configuration.lineage else {
      throw ReleasePackageError.verification(
        "lineage freeze requires a selected schema-2 release configuration")
    }
    try SecureFiles.createPrivateDirectory(scratch)
    let provenanceURL = unsignedAuthority.appendingPathComponent("release-provenance.json")
    let provenance = try loadUnsignedProvenance(provenanceURL)
    let unsignedToolDigest = try SourceInspector().canonicalTreeDigest(unsignedToolSource)
    let configurationDigest = try Digests.sha256(file: configurationURL)
    guard provenance.p0.releaseConfigurationSHA256 == configurationDigest,
      provenance.p0.releaseToolSourceSHA256 == unsignedToolDigest,
      provenance.u1.selectedContainer.path
        == "Reach-\(configuration.product.version)-unsigned.pkg"
    else {
      throw ReleasePackageError.verification(
        "unsigned authority does not belong to the selected replacement configuration")
    }
    let selectedPackage = try verifiedArtifact(
      provenance.u1.selectedContainer, below: unsignedAuthority)
    let report = try PackageVerifier(runner: runner).verify(
      package: selectedPackage,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      expectedReleaseToolSourceSHA256: unsignedToolDigest,
      provenanceURL: provenanceURL,
      noticeManifestURL: unsignedAuthority.appendingPathComponent("notice-manifest.json"),
      scratch: scratch.appendingPathComponent("u1-verification"),
      logDirectory: scratch.appendingPathComponent("u1-verification/logs"))
    guard report.normalizedSemanticSHA256 == provenance.u1.normalizedSemanticSHA256,
      report.hostFiles == 50, report.helperFiles == 6,
      !report.scriptsPresent, !report.resourcesPresent
    else {
      throw ReleasePackageError.verification(
        "replacement U1 did not retain the selected package semantics")
    }
    let host = try exactBuildAComponent(
      provenance.p1.hostComponents, name: "systems.reach.host.pkg",
      below: unsignedAuthority)
    let helper = try exactBuildAComponent(
      provenance.p1.helperComponents, name: "systems.reach.meshd.pkg",
      below: unsignedAuthority)
    let release = ReleaseVersionMap(
      product: configuration.product.version,
      host: configuration.components.host.version,
      helper: configuration.components.helper.version)
    let predecessor: ReleaseLineageAuthority.Predecessor
    switch declaration {
    case .replacement(let replacement):
      guard parentAuthority == nil else {
        throw ReleasePackageError.verification(
          "replacement lineage cannot acquire rollback authority from a substitute parent")
      }
      predecessor = .unavailableHistorical(
        .init(
          versions: replacement.predecessor,
          p5Reference: replacement.historicalP5Reference,
          availability: "unavailable-no-rollback-authority"))
    case .successor(let successor):
      guard let parentAuthority else {
        throw ReleasePackageError.verification(
          "successor lineage requires a complete retained parent authority")
      }
      predecessor = .retained(
        try verifyRetainedParent(
          parentAuthority,
          declared: successor,
          scratch: scratch.appendingPathComponent("parent-verification")))
    }
    let authority = ReleaseLineageAuthority(
      schemaVersion: 1,
      release: release,
      declaration: declaration,
      releaseConfigurationSHA256: configurationDigest,
      unsignedProvenanceSHA256: try Digests.sha256(file: provenanceURL),
      sourceCommit: provenance.p0.authority.commit,
      unsignedToolSourceSHA256: unsignedToolDigest,
      unsignedContainer: provenance.u1.selectedContainer,
      normalizedSemanticSHA256: provenance.u1.normalizedSemanticSHA256,
      components: [
        .init(
          identifier: configuration.components.host.identifier,
          version: configuration.components.host.version,
          disposition: declaration.components.host,
          unsignedComponent: host),
        .init(
          identifier: configuration.components.helper.identifier,
          version: configuration.components.helper.version,
          disposition: declaration.components.helper,
          unsignedComponent: helper),
      ],
      predecessor: predecessor)
    try authority.validate(configuration: configuration, configurationURL: configurationURL)
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(authority), to: output)
    return .init(
      schemaVersion: 1,
      lineageAuthority: output.path,
      lineageAuthoritySHA256: try Digests.sha256(file: output),
      release: release,
      unsignedContainerSHA256: authority.unsignedContainer.sha256,
      normalizedSemanticSHA256: authority.normalizedSemanticSHA256)
  }

  private func verifyRetainedParent(
    _ root: URL,
    declared: ReleaseLineage.Successor,
    scratch: URL
  ) throws -> ReleaseLineageAuthority.RetainedParent {
    let provenanceURL = root.appendingPathComponent("release-provenance.json")
    let provenance = try MultiReleaseSignedProvenance.load(from: provenanceURL)
    guard let p5 = provenance.p5,
      provenance.lineage.release == declared.parent,
      try Digests.sha256(file: provenanceURL) == declared.parentProvenanceSHA256,
      p5.stapledContainer.sha256 == declared.parentP5SHA256
    else {
      throw ReleasePackageError.verification(
        "retained parent does not match the declared successor authority")
    }
    let p5URL = try verifiedArtifact(p5.stapledContainer, below: root)
    let report = try SignedReleaseVerifier(runner: runner).verify(
      package: p5URL,
      provenanceURL: provenanceURL,
      unsignedToolSource: root.appendingPathComponent("unsigned-tool-source"),
      finalizerToolSource: root.appendingPathComponent("finalizer-tool-source"),
      configurationURL: root.appendingPathComponent("release.json"),
      noticeAuthorityURL: root.appendingPathComponent("notices.json"),
      dependencyDepot: root.appendingPathComponent("dependency-depot"),
      scratch: scratch)
    guard report.stage == "P5", report.stapleValidated, report.localAssessmentPassed,
      report.packageSHA256 == declared.parentP5SHA256,
      report.hostFiles == 50, report.helperFiles == 6,
      !report.scriptsPresent, !report.resourcesPresent
    else {
      throw ReleasePackageError.verification(
        "retained parent did not pass complete P5 verification")
    }
    guard
      let hostLeaf = provenance.p2.signedLeaves.first(where: {
        $0.path == "/Library/Application Support/Reach/Host/reachd"
      }),
      let helperLeaf = provenance.p2.signedLeaves.first(where: {
        $0.path == "/Library/PrivilegedHelperTools/systems.reach.meshd"
      })
    else {
      throw ReleasePackageError.verification("retained parent leaf authority is incomplete")
    }
    return .init(
      versions: provenance.lineage.release,
      p5: p5.stapledContainer,
      provenance: try localArtifact(path: "release-provenance.json", url: provenanceURL),
      hostLeaf: hostLeaf.artifact,
      helperLeaf: helperLeaf.artifact,
      hostComponent: provenance.p2.hostComponent,
      helperComponent: provenance.p2.helperComponent)
  }

  private func localArtifact(path: String, url: URL) throws -> ReleaseProvenance.Artifact {
    var info = stat()
    guard lstat(url.path, &info) == 0,
      (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1
    else {
      throw ReleasePackageError.unsafePath("lineage artifact is not a regular file")
    }
    return .init(
      path: path, size: UInt64(info.st_size), sha256: try Digests.sha256(file: url))
  }

  private func loadUnsignedProvenance(_ url: URL) throws -> ReleaseProvenance {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let provenance = try JSONDecoder().decode(ReleaseProvenance.self, from: data)
    guard provenance.schemaVersion == 1,
      data == (try CanonicalJSON.encode(provenance))
    else {
      throw ReleasePackageError.verification("unsigned provenance is not canonical schema 1")
    }
    return provenance
  }

  private func exactBuildAComponent(
    _ artifacts: [ReleaseProvenance.Artifact], name: String, below root: URL
  ) throws -> ReleaseProvenance.Artifact {
    let path = "artifacts/build-a/\(name)"
    guard let artifact = artifacts.first(where: { $0.path == path }),
      artifacts.filter({ $0.path == path }).count == 1
    else {
      throw ReleasePackageError.verification("build-A component authority is ambiguous")
    }
    _ = try verifiedArtifact(artifact, below: root)
    return artifact
  }

  private func verifiedArtifact(
    _ artifact: ReleaseProvenance.Artifact, below root: URL
  ) throws -> URL {
    try SecureFiles.validateRelativePath(artifact.path)
    let url = root.appendingPathComponent(artifact.path)
    var info = stat()
    guard lstat(url.path, &info) == 0,
      (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1,
      UInt64(info.st_size) == artifact.size,
      try Digests.sha256(file: url) == artifact.sha256
    else {
      throw ReleasePackageError.verification(
        "unsigned lineage artifact changed: \(artifact.path)")
    }
    return url
  }
}
