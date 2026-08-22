import Darwin
import Foundation

struct MaterializedUnsignedAuthority {
  let provenance: ReleaseProvenance
  let verification: VerificationReport
  let package: URL
  let manifest: PayloadManifest
  let hostRoot: URL
  let helperRoot: URL
}

struct SignedPayloadMaterializer {
  private let runner: ProcessRunner

  init(runner: ProcessRunner) {
    self.runner = runner
  }

  func materialize(
    unsignedAuthority: URL,
    unsignedToolSource: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    workRoot: URL
  ) throws -> MaterializedUnsignedAuthority {
    let provenanceURL = unsignedAuthority.appendingPathComponent("release-provenance.json")
    let provenanceData = try Data(contentsOf: provenanceURL, options: [.mappedIfSafe])
    let provenance = try JSONDecoder().decode(ReleaseProvenance.self, from: provenanceData)
    guard provenanceData == (try CanonicalJSON.encode(provenance)),
      provenance.schemaVersion == 1,
      provenance.p0.authority.commit == SignedReleaseContract.unsignedSourceCommit,
      provenance.p0.releaseToolSourceSHA256 == SignedReleaseContract.unsignedToolSourceSHA256,
      provenance.u1.selectedContainer.sha256 == SignedReleaseContract.unsignedPackageSHA256,
      provenance.u1.normalizedSemanticSHA256 == SignedReleaseContract.unsignedSemanticSHA256
    else {
      throw ReleasePackageError.verification("unsigned S34 authority is not the selected U1")
    }
    let unsignedToolDigest = try SourceInspector().canonicalTreeDigest(unsignedToolSource)
    guard unsignedToolDigest == SignedReleaseContract.unsignedToolSourceSHA256 else {
      throw ReleasePackageError.verification("unsigned-tool source does not match final U1")
    }
    try SecureFiles.validateRelativePath(provenance.u1.selectedContainer.path)
    let package = unsignedAuthority.appendingPathComponent(
      provenance.u1.selectedContainer.path)
    guard try Digests.sha256(file: package) == SignedReleaseContract.unsignedPackageSHA256 else {
      throw ReleasePackageError.verification("selected U1 package bytes changed")
    }
    let verification = try PackageVerifier(runner: runner).verify(
      package: package,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      expectedReleaseToolSourceSHA256: unsignedToolDigest,
      provenanceURL: provenanceURL,
      noticeManifestURL: unsignedAuthority.appendingPathComponent("notice-manifest.json"),
      scratch: workRoot.appendingPathComponent("u1-verification"),
      logDirectory: workRoot.appendingPathComponent("u1-verification/logs")
    )
    guard verification.normalizedSemanticSHA256 == SignedReleaseContract.unsignedSemanticSHA256,
      verification.hostFiles == 50,
      verification.helperFiles == 6,
      !verification.scriptsPresent,
      !verification.resourcesPresent
    else {
      throw ReleasePackageError.verification("selected U1 package semantics changed")
    }

    let expanded = workRoot.appendingPathComponent("u1-expanded")
    try SecureFiles.createPrivateDirectory(expanded)
    _ = try runner.run(
      "/usr/bin/xar", ["-xf", package.path], currentDirectory: expanded,
      logURL: workRoot.appendingPathComponent("u1-expand.log"))
    let payloads = workRoot.appendingPathComponent("p2-payloads")
    try SecureFiles.createPrivateDirectory(payloads)
    let hostRoot = try materializeComponent(
      expanded.appendingPathComponent("systems.reach.host.pkg"),
      destination: payloads.appendingPathComponent("host"),
      scratch: workRoot.appendingPathComponent("host-materialization"),
      label: "host"
    )
    let helperRoot = try materializeComponent(
      expanded.appendingPathComponent("systems.reach.meshd.pkg"),
      destination: payloads.appendingPathComponent("helper"),
      scratch: workRoot.appendingPathComponent("helper-materialization"),
      label: "helper"
    )
    let manifestURL = hostRoot.appendingPathComponent(
      "Library/Application Support/Reach/Release/payload-manifest.json")
    let manifest = try JSONDecoder().decode(
      PayloadManifest.self, from: Data(contentsOf: manifestURL, options: [.mappedIfSafe]))
    guard manifest.releaseToolSourceSHA256 == SignedReleaseContract.unsignedToolSourceSHA256,
      manifest.source.commit == SignedReleaseContract.unsignedSourceCommit
    else {
      throw ReleasePackageError.verification("embedded U1 manifest authority changed")
    }
    return MaterializedUnsignedAuthority(
      provenance: provenance,
      verification: verification,
      package: package,
      manifest: manifest,
      hostRoot: hostRoot,
      helperRoot: helperRoot
    )
  }

  private func materializeComponent(
    _ component: URL,
    destination: URL,
    scratch: URL,
    label: String
  ) throws -> URL {
    let expectedMembers = Set(["Bom", "Payload", "PackageInfo"])
    guard
      Set(try FileManager.default.contentsOfDirectory(atPath: component.path))
        == expectedMembers
    else {
      throw ReleasePackageError.verification("\(label) component member authority changed")
    }
    try SecureFiles.createPrivateDirectory(scratch)
    let compressed = scratch.appendingPathComponent("Payload.gz")
    try SecureFiles.copyRegularFile(
      from: component.appendingPathComponent("Payload"), to: compressed, mode: 0o600)
    _ = try runner.run(
      "/usr/bin/gzip", ["-d", "-k", compressed.path],
      logURL: scratch.appendingPathComponent("gzip.log"))
    let raw = scratch.appendingPathComponent("Payload")
    let members = try ODCArchive.parseMembers(Data(contentsOf: raw, options: [.mappedIfSafe]))
    try SecureFiles.createPrivateDirectory(destination)
    for member in members {
      let record = member.record
      let target: URL
      if record.path == "." {
        target = destination
      } else {
        target = destination.appendingPathComponent(String(record.path.dropFirst(2)))
      }
      switch record.kind {
      case .directory:
        try SecureFiles.createDirectory(target, mode: mode_t(record.mode & 0o7777))
      case .file:
        try SecureFiles.atomicWrite(
          member.data, to: target, mode: mode_t(record.mode & 0o7777))
      case .symlink:
        guard record.path == "./usr/local/bin/reachd",
          record.linkTarget == "/Library/Application Support/Reach/Host/reachd"
        else {
          throw ReleasePackageError.unsafePath("unexpected payload symlink \(record.path)")
        }
        try SecureFiles.createSymlink(at: target, target: record.linkTarget!)
      }
    }
    let roundTrip = try PayloadTree.inspect(root: destination).records
    guard roundTrip == members.map(\.record) else {
      throw ReleasePackageError.verification(
        "\(label) payload changed while materializing U1")
    }
    return destination
  }
}
