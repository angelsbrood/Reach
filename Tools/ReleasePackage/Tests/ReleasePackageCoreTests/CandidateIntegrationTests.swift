import Foundation
import Testing

@testable import ReleasePackageCore

private struct CandidateInputs {
  let package: URL
  let configuration: URL
  let notices: URL
  let depot: URL
  let toolSource: URL
  let provenance: URL
  let noticeManifest: URL

  static func current() -> Self? {
    let environment = ProcessInfo.processInfo.environment
    let keys = [
      "REACH_RELEASE_CANDIDATE", "REACH_RELEASE_CONFIGURATION", "REACH_RELEASE_NOTICES",
      "REACH_RELEASE_DEPOT", "REACH_RELEASE_TOOL_SOURCE", "REACH_RELEASE_PROVENANCE",
      "REACH_RELEASE_NOTICE_MANIFEST",
    ]
    guard keys.allSatisfy({ environment[$0]?.hasPrefix("/") == true }) else { return nil }
    return Self(
      package: URL(fileURLWithPath: environment["REACH_RELEASE_CANDIDATE"]!),
      configuration: URL(fileURLWithPath: environment["REACH_RELEASE_CONFIGURATION"]!),
      notices: URL(fileURLWithPath: environment["REACH_RELEASE_NOTICES"]!),
      depot: URL(fileURLWithPath: environment["REACH_RELEASE_DEPOT"]!),
      toolSource: URL(fileURLWithPath: environment["REACH_RELEASE_TOOL_SOURCE"]!),
      provenance: URL(fileURLWithPath: environment["REACH_RELEASE_PROVENANCE"]!),
      noticeManifest: URL(fileURLWithPath: environment["REACH_RELEASE_NOTICE_MANIFEST"]!)
    )
  }

  func verify(
    package override: URL? = nil,
    provenance overrideProvenance: URL? = nil,
    noticeManifest overrideNoticeManifest: URL? = nil,
    root: URL
  )
    throws -> VerificationReport
  {
    try SecureFiles.createPrivateDirectory(root)
    return try PackageVerifier().verify(
      package: override ?? package,
      configurationURL: configuration,
      noticeAuthorityURL: notices,
      dependencyDepot: depot,
      expectedReleaseToolSourceSHA256: try SourceInspector().canonicalTreeDigest(toolSource),
      provenanceURL: overrideProvenance ?? provenance,
      noticeManifestURL: overrideNoticeManifest ?? noticeManifest,
      scratch: root.appendingPathComponent("scratch"),
      logDirectory: root.appendingPathComponent("scratch/logs")
    )
  }
}

private func copyProvenanceAuthority(
  _ provenance: ReleaseProvenance,
  from inputs: CandidateInputs,
  to root: URL
) throws -> URL {
  try SecureFiles.createPrivateDirectory(root)
  let sourceRoot = inputs.provenance.deletingLastPathComponent()
  let artifacts =
    [provenance.p1.embeddedManifest, provenance.p1.notices]
    + provenance.p1.hostComponents
    + provenance.p1.helperComponents
    + provenance.p1.hostBOMs
    + provenance.p1.helperBOMs
    + provenance.u1.containers
    + [provenance.u1.selectedContainer]
  for artifact in Dictionary(grouping: artifacts, by: \.path).values.compactMap(\.first) {
    try SecureFiles.validateRelativePath(artifact.path)
    let destination = root.appendingPathComponent(artifact.path)
    var parent = root
    for component in artifact.path.split(separator: "/").dropLast() {
      parent.appendPathComponent(String(component))
      if !FileManager.default.fileExists(atPath: parent.path) {
        try SecureFiles.createDirectory(parent, mode: 0o700)
      }
    }
    try SecureFiles.copyRegularFile(
      from: sourceRoot.appendingPathComponent(artifact.path),
      to: destination,
      mode: 0o600
    )
  }
  return root.appendingPathComponent("release-provenance.json")
}

private func expectReleaseError(
  _ expected: ReleasePackageError,
  performing operation: () throws -> Void
) {
  do {
    try operation()
    Issue.record("expected refusal: \(expected)")
  } catch let actual as ReleasePackageError {
    #expect(actual == expected)
  } catch {
    Issue.record("unexpected refusal type: \(error)")
  }
}

@Test func candidateRejectsChangedNoticeFamilyAuthority() throws {
  guard let inputs = CandidateInputs.current() else { return }
  let root = try makeTemporaryDirectory("candidate-notice-authority")
  defer { removeTemporaryDirectory(root) }
  let original = try JSONDecoder().decode(
    NoticeManifest.self, from: Data(contentsOf: inputs.noticeManifest))
  var families = original.families
  let first = try #require(families.first)
  families[0] = .init(
    id: first.id,
    scope: first.scope + " changed",
    sourceRoot: first.sourceRoot,
    inputs: first.inputs)
  let changed = NoticeManifest(
    schemaVersion: original.schemaVersion,
    noticeSetSHA256: original.noticeSetSHA256,
    noticesPath: original.noticesPath,
    noticesSHA256: original.noticesSHA256,
    families: families)
  let changedURL = root.appendingPathComponent("changed-notice-manifest.json")
  try SecureFiles.atomicWrite(try CanonicalJSON.encode(changed), to: changedURL)
  #expect(throws: ReleasePackageError.self) {
    try inputs.verify(
      noticeManifest: changedURL, root: root.appendingPathComponent("verification"))
  }
}

@Test func selectedCandidatePassesIndependentVerification() throws {
  guard let inputs = CandidateInputs.current() else { return }
  let root = try makeTemporaryDirectory("candidate-verify")
  defer { removeTemporaryDirectory(root) }
  let report = try inputs.verify(root: root)
  #expect(report.hostFiles == 50)
  #expect(report.helperFiles == 6)
  #expect(!report.scriptsPresent)
  #expect(!report.resourcesPresent)
}

@Test func candidateRejectsDistributionPayloadAndMemberTampering() throws {
  guard let inputs = CandidateInputs.current() else { return }
  for kind in ["distribution", "payload", "missing-helper", "extra-scripts"] {
    let root = try makeTemporaryDirectory("candidate-tamper-\(kind)")
    defer { removeTemporaryDirectory(root) }
    let expanded = root.appendingPathComponent("expanded")
    try SecureFiles.createPrivateDirectory(expanded)
    try ProcessRunner().run(
      "/usr/bin/xar", ["-xf", inputs.package.path], currentDirectory: expanded)
    var members = ["systems.reach.host.pkg", "systems.reach.meshd.pkg", "Distribution"]
    switch kind {
    case "distribution":
      let file = expanded.appendingPathComponent("Distribution")
      try SecureFiles.atomicWrite(try Data(contentsOf: file) + Data("\n".utf8), to: file)
    case "payload":
      let file = expanded.appendingPathComponent("systems.reach.host.pkg/Payload")
      var data = try Data(contentsOf: file)
      data[data.index(data.startIndex, offsetBy: 20)] ^= 0x01
      try SecureFiles.atomicWrite(data, to: file)
    case "missing-helper":
      members.remove(at: 1)
    case "extra-scripts":
      try SecureFiles.createDirectory(expanded.appendingPathComponent("Scripts"), mode: 0o755)
      members.append("Scripts")
    default:
      Issue.record("unknown tamper fixture")
    }
    let tampered = root.appendingPathComponent("tampered.pkg")
    try ProcessRunner().run(
      "/usr/bin/xar", ["-cf", tampered.path] + members, currentDirectory: expanded)
    #expect(throws: ReleasePackageError.self) {
      try inputs.verify(package: tampered, root: root.appendingPathComponent("verification"))
    }
  }
}

@Test func candidateRejectsStaleExternalProvenance() throws {
  guard let inputs = CandidateInputs.current() else { return }
  let root = try makeTemporaryDirectory("candidate-provenance")
  defer { removeTemporaryDirectory(root) }
  let original = try JSONDecoder().decode(
    ReleaseProvenance.self, from: Data(contentsOf: inputs.provenance))
  let selected = original.u1.selectedContainer
  let staleProvenance = ReleaseProvenance(
    schemaVersion: original.schemaVersion,
    p0: original.p0,
    p1: original.p1,
    u1: .init(
      name: original.u1.name,
      containers: original.u1.containers,
      selectedContainer: .init(
        path: selected.path,
        size: selected.size,
        sha256: String(repeating: "0", count: 64)),
      normalizedSemanticSHA256: original.u1.normalizedSemanticSHA256,
      distributionSHA256: original.u1.distributionSHA256)
  )
  let authority = root.appendingPathComponent("authority")
  let stale = try copyProvenanceAuthority(original, from: inputs, to: authority)
  try SecureFiles.atomicWrite(try CanonicalJSON.encode(staleProvenance), to: stale)
  expectReleaseError(.verification("external U1 container provenance changed")) {
    _ = try inputs.verify(provenance: stale, root: root.appendingPathComponent("verification"))
  }
}

@Test func candidateRejectsEveryChangedProvenanceAuthorityClass() throws {
  guard let inputs = CandidateInputs.current() else { return }
  let root = try makeTemporaryDirectory("candidate-provenance-authority")
  defer { removeTemporaryDirectory(root) }
  let original = try JSONDecoder().decode(
    ReleaseProvenance.self, from: Data(contentsOf: inputs.provenance))
  let zero = String(repeating: "0", count: 64)
  let firstHost = try #require(original.p1.hostComponents.first)
  let firstContainer = try #require(original.u1.containers.first)
  let variants: [(ReleaseProvenance, ReleasePackageError)] = [
    (
      .init(
        schemaVersion: original.schemaVersion,
        p0: .init(
          name: original.p0.name,
          authority: original.p0.authority,
          releaseConfigurationSHA256: zero,
          releaseToolSourceSHA256: original.p0.releaseToolSourceSHA256,
          noticeAuthoritySHA256: original.p0.noticeAuthoritySHA256,
          dependencyDepotSHA256: original.p0.dependencyDepotSHA256),
        p1: original.p1,
        u1: original.u1),
      .verification("external P0 source provenance changed")
    ),
    (
      .init(
        schemaVersion: original.schemaVersion,
        p0: original.p0,
        p1: .init(
          name: original.p1.name,
          embeddedManifest: original.p1.embeddedManifest,
          notices: original.p1.notices,
          hostComponents: [
            .init(
              path: "artifacts/build-a/wrong.pkg", size: firstHost.size, sha256: firstHost.sha256)
          ] + original.p1.hostComponents.dropFirst(),
          helperComponents: original.p1.helperComponents,
          hostBOMs: original.p1.hostBOMs,
          helperBOMs: original.p1.helperBOMs),
        u1: original.u1),
      .verification("external P1 payload provenance changed")
    ),
    (
      .init(
        schemaVersion: original.schemaVersion,
        p0: original.p0,
        p1: .init(
          name: original.p1.name,
          embeddedManifest: original.p1.embeddedManifest,
          notices: original.p1.notices,
          hostComponents: [
            .init(path: firstHost.path, size: firstHost.size + 1, sha256: firstHost.sha256)
          ] + original.p1.hostComponents.dropFirst(),
          helperComponents: original.p1.helperComponents,
          hostBOMs: original.p1.hostBOMs,
          helperBOMs: original.p1.helperBOMs),
        u1: original.u1),
      .verification("external P1 payload provenance changed")
    ),
    (
      .init(
        schemaVersion: original.schemaVersion,
        p0: original.p0,
        p1: original.p1,
        u1: .init(
          name: original.u1.name,
          containers: [
            .init(path: firstContainer.path, size: firstContainer.size, sha256: zero)
          ] + original.u1.containers.dropFirst(),
          selectedContainer: original.u1.selectedContainer,
          normalizedSemanticSHA256: original.u1.normalizedSemanticSHA256,
          distributionSHA256: original.u1.distributionSHA256)),
      .verification("external U1 container provenance changed")
    ),
  ]
  for (index, entry) in variants.enumerated() {
    let authority = root.appendingPathComponent("authority-\(index)")
    let url = try copyProvenanceAuthority(original, from: inputs, to: authority)
    let (variant, expectedError) = entry
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(variant), to: url)
    expectReleaseError(expectedError) {
      _ = try inputs.verify(
        provenance: url, root: root.appendingPathComponent("verification-\(index)"))
    }
  }
}
