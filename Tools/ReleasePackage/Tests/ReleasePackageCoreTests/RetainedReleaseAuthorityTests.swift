import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

private func retainedFixture() throws -> (
  root: URL, manifest: URL, package: URL, provenance: URL, report: URL
) {
  let root = try makeTemporaryDirectory("retained-authority")
  let package = root.appendingPathComponent("Reach-0.0.2.pkg")
  let provenance = root.appendingPathComponent("release-provenance.json")
  let report = root.appendingPathComponent("retained-verification.json")
  try SecureFiles.atomicWrite(Data("package".utf8), to: package)
  try SecureFiles.atomicWrite(Data("provenance".utf8), to: provenance)
  try SecureFiles.atomicWrite(Data("report".utf8), to: report)
  let files = try [package, provenance, report].map { url in
    let info = try FileManager.default.attributesOfItem(atPath: url.path)
    return RetainedReleaseAuthorityManifest.File(
      path: url.lastPathComponent,
      size: (info[.size] as? NSNumber)?.uint64Value ?? 0,
      sha256: try Digests.sha256(file: url))
  }.sorted {
    $0.path.utf8.lexicographicallyPrecedes($1.path.utf8)
  }
  let manifest = RetainedReleaseAuthorityManifest(
    schemaVersion: 1,
    release: .init(
      product: try DottedVersion("0.0.2"), host: try DottedVersion("0.0.2"),
      helper: try DottedVersion("1.0.2")),
    p5SHA256: try Digests.sha256(file: package),
    provenanceSHA256: try Digests.sha256(file: provenance),
    verificationReportSHA256: try Digests.sha256(file: report),
    files: files)
  let manifestURL = root.appendingPathComponent("retained-authority.json")
  try SecureFiles.atomicWrite(try CanonicalJSON.encode(manifest), to: manifestURL)
  return (root, manifestURL, package, provenance, report)
}

@Test func retainedAuthorityManifestIsAcyclicModeBoundAndExact() throws {
  let fixture = try retainedFixture()
  defer { removeTemporaryDirectory(fixture.root) }
  try RetainedReleaseAuthoritySealer().verify(
    manifestURL: fixture.manifest, authorityRoot: fixture.root)

  try SecureFiles.atomicWrite(Data("changed".utf8), to: fixture.report)
  #expect(throws: ReleasePackageError.self) {
    try RetainedReleaseAuthoritySealer().verify(
      manifestURL: fixture.manifest, authorityRoot: fixture.root)
  }
}

@Test func retainedAuthorityRefusesAliasesModesAndDuplicateP5Binders() throws {
  let fixture = try retainedFixture()
  defer { removeTemporaryDirectory(fixture.root) }
  let alias = fixture.root.appendingPathComponent("nested/retained-authority.json")
  #expect(throws: ReleasePackageError.self) {
    try RetainedReleaseAuthoritySealer().verify(
      manifestURL: alias, authorityRoot: fixture.root)
  }

  #expect(chmod(fixture.provenance.path, 0o644) == 0)
  #expect(throws: ReleasePackageError.self) {
    try RetainedReleaseAuthoritySealer().verify(
      manifestURL: fixture.manifest, authorityRoot: fixture.root)
  }
  #expect(chmod(fixture.provenance.path, 0o600) == 0)

  let duplicate = fixture.root.appendingPathComponent("duplicate.pkg")
  try SecureFiles.copyInputFile(from: fixture.package, to: duplicate, mode: 0o600)
  let data = try Data(contentsOf: fixture.manifest)
  let original = try JSONDecoder().decode(RetainedReleaseAuthorityManifest.self, from: data)
  let duplicateRecord = RetainedReleaseAuthorityManifest.File(
    path: duplicate.lastPathComponent,
    size: UInt64(try Data(contentsOf: duplicate).count),
    sha256: original.p5SHA256)
  let changed = RetainedReleaseAuthorityManifest(
    schemaVersion: original.schemaVersion, release: original.release,
    p5SHA256: original.p5SHA256,
    provenanceSHA256: original.provenanceSHA256,
    verificationReportSHA256: original.verificationReportSHA256,
    files: (original.files + [duplicateRecord]).sorted {
      $0.path.utf8.lexicographicallyPrecedes($1.path.utf8)
    })
  try SecureFiles.atomicWrite(try CanonicalJSON.encode(changed), to: fixture.manifest)
  #expect(throws: ReleasePackageError.self) {
    try RetainedReleaseAuthoritySealer().verify(
      manifestURL: fixture.manifest, authorityRoot: fixture.root)
  }
}

@Test func retainedAuthorityDeduplicatesOnlyIdenticalNamedArtifacts() throws {
  let first = ReleaseProvenance.Artifact(
    path: "artifacts/build-a/systems.reach.host.pkg",
    size: 10,
    sha256: String(repeating: "1", count: 64))
  let second = ReleaseProvenance.Artifact(
    path: "artifacts/build-a/systems.reach.meshd.pkg",
    size: 20,
    sha256: String(repeating: "2", count: 64))
  let values = try RetainedReleaseAuthoritySealer.uniqueArtifacts([
    second, first, first,
  ])
  #expect(values == [first, second])

  let conflicting = ReleaseProvenance.Artifact(
    path: first.path,
    size: first.size + 1,
    sha256: String(repeating: "3", count: 64))
  #expect(throws: ReleasePackageError.self) {
    try RetainedReleaseAuthoritySealer.uniqueArtifacts([first, conflicting])
  }
}

@Test func retainedAuthorityPreservesSafeBoundInputModesExactly() throws {
  let root = try makeTemporaryDirectory("retained-input-modes")
  defer { removeTemporaryDirectory(root) }
  let source = root.appendingPathComponent("source")
  let nested = source.appendingPathComponent("Sources")
  try SecureFiles.createDirectory(source, mode: 0o755)
  try SecureFiles.createDirectory(nested, mode: 0o755)
  let file = nested.appendingPathComponent("Authority.swift")
  try SecureFiles.atomicWrite(Data("authority\n".utf8), to: file, mode: 0o644)

  let copy = root.appendingPathComponent("copy")
  try SecureFiles.copyTree(from: source, to: copy, preserveSourceModes: true)
  var sourceInfo = stat()
  var copyInfo = stat()
  #expect(lstat(file.path, &sourceInfo) == 0)
  #expect(lstat(copy.appendingPathComponent("Sources/Authority.swift").path, &copyInfo) == 0)
  #expect(sourceInfo.st_mode & 0o7777 == copyInfo.st_mode & 0o7777)
  #expect(
    try SourceInspector().canonicalTreeDigest(source)
      == SourceInspector().canonicalTreeDigest(copy))

  #expect(chmod(file.path, 0o666) == 0)
  #expect(throws: ReleasePackageError.self) {
    try SecureFiles.copyTree(
      from: source, to: root.appendingPathComponent("unsafe"), preserveSourceModes: true)
  }
}
