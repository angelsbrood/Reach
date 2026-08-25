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

enum UnsignedReleaseSelection {
  case historicalS35
  case lineage(ReleaseLineageAuthority)
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
    workRoot: URL,
    selection: UnsignedReleaseSelection = .historicalS35
  ) throws -> MaterializedUnsignedAuthority {
    let provenanceURL = unsignedAuthority.appendingPathComponent("release-provenance.json")
    let provenanceData = try Data(contentsOf: provenanceURL, options: [.mappedIfSafe])
    let provenance = try JSONDecoder().decode(ReleaseProvenance.self, from: provenanceData)
    guard provenanceData == (try CanonicalJSON.encode(provenance)),
      provenance.schemaVersion == 1
    else {
      throw ReleasePackageError.verification("unsigned authority is not canonical schema 1")
    }
    let configuration = try ReleaseConfiguration.load(from: configurationURL)
    let unsignedToolDigest = try SourceInspector().canonicalTreeDigest(unsignedToolSource)
    let expectedCommit: String
    let expectedToolDigest: String
    let expectedPackageDigest: String
    let expectedSemanticDigest: String
    switch selection {
    case .historicalS35:
      guard configuration.schemaVersion == 1 else {
        throw ReleasePackageError.verification(
          "historical S35 selection requires the frozen schema-1 configuration")
      }
      expectedCommit = SignedReleaseContract.unsignedSourceCommit
      expectedToolDigest = SignedReleaseContract.unsignedToolSourceSHA256
      expectedPackageDigest = SignedReleaseContract.unsignedPackageSHA256
      expectedSemanticDigest = SignedReleaseContract.unsignedSemanticSHA256
    case .lineage(let lineage):
      try lineage.validate(configuration: configuration, configurationURL: configurationURL)
      guard lineage.unsignedProvenanceSHA256 == (try Digests.sha256(file: provenanceURL)),
        lineage.unsignedContainer == provenance.u1.selectedContainer,
        lineage.normalizedSemanticSHA256 == provenance.u1.normalizedSemanticSHA256
      else {
        throw ReleasePackageError.verification(
          "frozen lineage does not bind the supplied unsigned provenance")
      }
      expectedCommit = lineage.sourceCommit
      expectedToolDigest = lineage.unsignedToolSourceSHA256
      expectedPackageDigest = lineage.unsignedContainer.sha256
      expectedSemanticDigest = lineage.normalizedSemanticSHA256
      try verifyLineageComponents(lineage, provenance: provenance, root: unsignedAuthority)
    }
    guard provenance.p0.authority.commit == expectedCommit,
      provenance.p0.releaseToolSourceSHA256 == expectedToolDigest,
      provenance.u1.selectedContainer.sha256 == expectedPackageDigest,
      provenance.u1.normalizedSemanticSHA256 == expectedSemanticDigest,
      unsignedToolDigest == expectedToolDigest
    else {
      throw ReleasePackageError.verification("unsigned source or U1 lineage changed")
    }
    try SecureFiles.validateRelativePath(provenance.u1.selectedContainer.path)
    let package = unsignedAuthority.appendingPathComponent(
      provenance.u1.selectedContainer.path)
    guard try Digests.sha256(file: package) == expectedPackageDigest else {
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
    guard verification.normalizedSemanticSHA256 == expectedSemanticDigest,
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
    guard manifest.releaseToolSourceSHA256 == expectedToolDigest,
      manifest.source.commit == expectedCommit
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

  private func verifyLineageComponents(
    _ lineage: ReleaseLineageAuthority,
    provenance: ReleaseProvenance,
    root: URL
  ) throws {
    let expected = provenance.p1.hostComponents + provenance.p1.helperComponents
    for component in lineage.components {
      guard expected.contains(component.unsignedComponent) else {
        throw ReleasePackageError.verification(
          "frozen lineage component is absent from unsigned provenance")
      }
      try SecureFiles.validateRelativePath(component.unsignedComponent.path)
      let url = root.appendingPathComponent(component.unsignedComponent.path)
      var info = stat()
      guard lstat(url.path, &info) == 0,
        (info.st_mode & S_IFMT) == S_IFREG,
        info.st_nlink == 1,
        UInt64(info.st_size) == component.unsignedComponent.size,
        try Digests.sha256(file: url) == component.unsignedComponent.sha256
      else {
        throw ReleasePackageError.verification(
          "frozen lineage component bytes changed: \(component.identifier)")
      }
    }
  }

  func materializeComponent(
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

  func materializeStandaloneComponent(
    _ component: URL,
    destination: URL,
    scratch: URL,
    label: String
  ) throws -> URL {
    try SecureFiles.createPrivateDirectory(scratch)
    let expanded = scratch.appendingPathComponent("expanded")
    try SecureFiles.createPrivateDirectory(expanded)
    _ = try runner.run(
      "/usr/bin/xar", ["-xf", component.path], currentDirectory: expanded,
      logURL: scratch.appendingPathComponent("expand.log"))
    return try materializeComponent(
      expanded, destination: destination,
      scratch: scratch.appendingPathComponent("payload"), label: label)
  }

  func materializeComponent(
    named name: String,
    fromOuterPackage package: URL,
    destination: URL,
    scratch: URL,
    label: String
  ) throws -> URL {
    try SecureFiles.createPrivateDirectory(scratch)
    let expanded = scratch.appendingPathComponent("outer-expanded")
    try SecureFiles.createPrivateDirectory(expanded)
    _ = try runner.run(
      "/usr/bin/xar", ["-xf", package.path], currentDirectory: expanded,
      logURL: scratch.appendingPathComponent("outer-expand.log"))
    return try materializeComponent(
      expanded.appendingPathComponent(name), destination: destination,
      scratch: scratch.appendingPathComponent("payload"), label: label)
  }
}
