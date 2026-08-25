import Foundation
import Testing

@testable import ReleasePackageCore

private func lineageArtifact(_ path: String, _ character: Character = "a")
  -> ReleaseProvenance.Artifact
{
  .init(path: path, size: 1, sha256: String(repeating: character, count: 64))
}

@Test func unchangedHelperComponentIsCopiedAsTheExactRetainedArtifact() throws {
  let root = try makeTemporaryDirectory("retained-helper-component")
  defer { removeTemporaryDirectory(root) }
  let source = root.appendingPathComponent("parent-helper.pkg")
  let destination = root.appendingPathComponent("successor-helper.pkg")
  let bytes = Data("synthetic retained component\n".utf8)
  try SecureFiles.atomicWrite(bytes, to: source)
  let artifact = ReleaseProvenance.Artifact(
    path: "p2/systems.reach.meshd.pkg", size: UInt64(bytes.count),
    sha256: Digests.sha256(bytes))
  try SignedReleaseFinalizer.copyExactRetainedComponent(
    source: source, artifact: artifact, destination: destination)
  #expect(try Data(contentsOf: destination) == bytes)
  #expect(try Digests.sha256(file: destination) == artifact.sha256)

  let changed = root.appendingPathComponent("changed-helper.pkg")
  try SecureFiles.atomicWrite(Data("changed component\n".utf8), to: changed)
  #expect(throws: ReleasePackageError.self) {
    try SignedReleaseFinalizer.copyExactRetainedComponent(
      source: changed, artifact: artifact,
      destination: root.appendingPathComponent("refused.pkg"))
  }
}

private func replacementLineageAuthority(
  configuration: ReleaseConfiguration,
  configurationURL: URL
) throws -> ReleaseLineageAuthority {
  let declaration = try #require(configuration.lineage)
  guard case .replacement(let replacement) = declaration else {
    Issue.record("checked-in authority is not a replacement")
    throw ReleasePackageError.verification("replacement fixture unavailable")
  }
  return .init(
    schemaVersion: 1,
    release: .init(
      product: configuration.product.version,
      host: configuration.components.host.version,
      helper: configuration.components.helper.version),
    declaration: declaration,
    releaseConfigurationSHA256: try Digests.sha256(file: configurationURL),
    unsignedProvenanceSHA256: String(repeating: "1", count: 64),
    sourceCommit: String(repeating: "2", count: 40),
    unsignedToolSourceSHA256: String(repeating: "3", count: 64),
    unsignedContainer: lineageArtifact("Reach-0.0.2-unsigned.pkg", "4"),
    normalizedSemanticSHA256: String(repeating: "5", count: 64),
    components: [
      .init(
        identifier: configuration.components.host.identifier,
        version: configuration.components.host.version,
        disposition: .changed,
        unsignedComponent: lineageArtifact(
          "artifacts/build-a/systems.reach.host.pkg", "6")),
      .init(
        identifier: configuration.components.helper.identifier,
        version: configuration.components.helper.version,
        disposition: .changed,
        unsignedComponent: lineageArtifact(
          "artifacts/build-a/systems.reach.meshd.pkg", "7")),
    ],
    predecessor: .unavailableHistorical(
      .init(
        versions: replacement.predecessor,
        p5Reference: replacement.historicalP5Reference,
        availability: "unavailable-no-rollback-authority")))
}

private func multiReleaseFixture(
  runtime: Bool = true,
  entitlementsSHA256: String = SignedReleaseContract.emptyEntitlementsSHA256
) throws -> MultiReleaseSignedProvenance {
  let configurationURL = repositoryRoot().appendingPathComponent("release/release.json")
  let configuration = try ReleaseConfiguration.load(from: configurationURL)
  let base = signedProvenanceFixture(
    runtime: runtime, entitlementsSHA256: entitlementsSHA256)
  let original = try replacementLineageAuthority(
    configuration: configuration, configurationURL: configurationURL)
  let lineage = ReleaseLineageAuthority(
    schemaVersion: original.schemaVersion,
    release: original.release,
    declaration: original.declaration,
    releaseConfigurationSHA256: original.releaseConfigurationSHA256,
    unsignedProvenanceSHA256: original.unsignedProvenanceSHA256,
    sourceCommit: base.p0.authority.commit,
    unsignedToolSourceSHA256: base.p0.releaseToolSourceSHA256,
    unsignedContainer: base.u1.selectedContainer,
    normalizedSemanticSHA256: base.u1.normalizedSemanticSHA256,
    components: [
      .init(
        identifier: "systems.reach.host", version: original.release.host,
        disposition: .changed,
        unsignedComponent: try #require(base.p1.hostComponents.first)),
      .init(
        identifier: "systems.reach.meshd", version: original.release.helper,
        disposition: .changed,
        unsignedComponent: try #require(base.p1.helperComponents.first)),
    ],
    predecessor: original.predecessor)
  return .init(
    schemaVersion: 3, lineage: lineage,
    p0: base.p0, p1: base.p1, u1: base.u1, p2: base.p2, p3: base.p3)
}

@Test func replacementLineageIsCanonicalAndCannotAuthorizeRollback() throws {
  let configurationURL = repositoryRoot().appendingPathComponent("release/release.json")
  let configuration = try ReleaseConfiguration.load(from: configurationURL)
  let authority = try replacementLineageAuthority(
    configuration: configuration, configurationURL: configurationURL)
  try authority.validate(configuration: configuration, configurationURL: configurationURL)

  let root = try makeTemporaryDirectory("replacement-lineage")
  defer { removeTemporaryDirectory(root) }
  let url = root.appendingPathComponent("lineage.json")
  try SecureFiles.atomicWrite(try CanonicalJSON.encode(authority), to: url)
  let loaded = try ReleaseLineageAuthority.load(from: url)
  #expect(loaded == authority)
  guard case .unavailableHistorical(let predecessor) = loaded.predecessor else {
    Issue.record("replacement predecessor became rollback authority")
    return
  }
  #expect(predecessor.availability == "unavailable-no-rollback-authority")
}

@Test func lineageRefusesConfigurationAndPredecessorSubstitution() throws {
  let configurationURL = repositoryRoot().appendingPathComponent("release/release.json")
  let configuration = try ReleaseConfiguration.load(from: configurationURL)
  let authority = try replacementLineageAuthority(
    configuration: configuration, configurationURL: configurationURL)
  let wrongConfiguration = ReleaseLineageAuthority(
    schemaVersion: authority.schemaVersion,
    release: authority.release,
    declaration: authority.declaration,
    releaseConfigurationSHA256: String(repeating: "f", count: 64),
    unsignedProvenanceSHA256: authority.unsignedProvenanceSHA256,
    sourceCommit: authority.sourceCommit,
    unsignedToolSourceSHA256: authority.unsignedToolSourceSHA256,
    unsignedContainer: authority.unsignedContainer,
    normalizedSemanticSHA256: authority.normalizedSemanticSHA256,
    components: authority.components,
    predecessor: authority.predecessor)
  #expect(throws: ReleasePackageError.self) {
    try wrongConfiguration.validate(
      configuration: configuration, configurationURL: configurationURL)
  }

  let retainedForgery = ReleaseLineageAuthority(
    schemaVersion: authority.schemaVersion,
    release: authority.release,
    declaration: authority.declaration,
    releaseConfigurationSHA256: authority.releaseConfigurationSHA256,
    unsignedProvenanceSHA256: authority.unsignedProvenanceSHA256,
    sourceCommit: authority.sourceCommit,
    unsignedToolSourceSHA256: authority.unsignedToolSourceSHA256,
    unsignedContainer: authority.unsignedContainer,
    normalizedSemanticSHA256: authority.normalizedSemanticSHA256,
    components: authority.components,
    predecessor: .retained(
      .init(
        versions: authority.declaration.predecessor,
        p5: lineageArtifact("Reach-0.0.1.pkg"),
        provenance: lineageArtifact("release-provenance.json"),
        hostLeaf: lineageArtifact("reachd"),
        helperLeaf: lineageArtifact("meshd"),
        hostComponent: lineageArtifact("host.pkg"),
        helperComponent: lineageArtifact("helper.pkg"))))
  #expect(throws: ReleasePackageError.self) {
    try retainedForgery.validate(
      configuration: configuration, configurationURL: configurationURL)
  }
}

@Test func schemaThreeProvenanceIsCanonicalStrictAndOmitsUnearnedStages() throws {
  let value = try multiReleaseFixture()
  try value.validateStructure()
  let encoded = try CanonicalJSON.encode(value)
  let object = try #require(
    JSONSerialization.jsonObject(with: encoded) as? [String: Any])
  #expect(object["p4"] == nil)
  #expect(object["p5"] == nil)

  let root = try makeTemporaryDirectory("multi-release-provenance")
  defer { removeTemporaryDirectory(root) }
  let canonical = root.appendingPathComponent("canonical.json")
  try SecureFiles.atomicWrite(encoded, to: canonical)
  #expect(try MultiReleaseSignedProvenance.load(from: canonical) == value)

  var unknown = object
  unknown["p6"] = [:]
  let unknownURL = root.appendingPathComponent("unknown.json")
  try SecureFiles.atomicWrite(
    try JSONSerialization.data(withJSONObject: unknown, options: [.sortedKeys]),
    to: unknownURL)
  #expect(throws: ReleasePackageError.self) {
    try MultiReleaseSignedProvenance.load(from: unknownURL)
  }

  var null = object
  null["p4"] = NSNull()
  let nullURL = root.appendingPathComponent("null.json")
  try SecureFiles.atomicWrite(
    try JSONSerialization.data(withJSONObject: null, options: [.sortedKeys]),
    to: nullURL)
  #expect(throws: ReleasePackageError.self) {
    try MultiReleaseSignedProvenance.load(from: nullURL)
  }
}

@Test func schemaThreeRetainsRuntimeEntitlementAndComponentBinders() throws {
  #expect(throws: ReleasePackageError.self) {
    try multiReleaseFixture(runtime: false).validateStructure()
  }
  #expect(throws: ReleasePackageError.self) {
    try multiReleaseFixture(entitlementsSHA256: String(repeating: "0", count: 64))
      .validateStructure()
  }
  let original = try multiReleaseFixture()
  let wrongComponents = ReleaseLineageAuthority(
    schemaVersion: original.lineage.schemaVersion,
    release: original.lineage.release,
    declaration: original.lineage.declaration,
    releaseConfigurationSHA256: original.lineage.releaseConfigurationSHA256,
    unsignedProvenanceSHA256: original.lineage.unsignedProvenanceSHA256,
    sourceCommit: original.lineage.sourceCommit,
    unsignedToolSourceSHA256: original.lineage.unsignedToolSourceSHA256,
    unsignedContainer: original.lineage.unsignedContainer,
    normalizedSemanticSHA256: original.lineage.normalizedSemanticSHA256,
    components: [
      .init(
        identifier: "systems.reach.host", version: original.lineage.release.host,
        disposition: .changed,
        unsignedComponent: lineageArtifact("wrong-host.pkg", "8")),
      original.lineage.components[1],
    ],
    predecessor: original.lineage.predecessor)
  let changed = MultiReleaseSignedProvenance(
    schemaVersion: 3, lineage: wrongComponents,
    p0: original.p0, p1: original.p1, u1: original.u1,
    p2: original.p2, p3: original.p3)
  #expect(throws: ReleasePackageError.self) { try changed.validateStructure() }
}

private func putLineageU32(_ value: UInt32, at offset: Int, in data: inout Data) {
  for index in 0..<4 { data[offset + index] = UInt8((value >> UInt32(index * 8)) & 0xff) }
}

private func putLineageU64(_ value: UInt64, at offset: Int, in data: inout Data) {
  for index in 0..<8 { data[offset + index] = UInt8((value >> UInt64(index * 8)) & 0xff) }
}

private func putLineageName(_ value: String, at offset: Int, in data: inout Data) {
  for (index, byte) in value.utf8.prefix(16).enumerated() { data[offset + index] = byte }
}

private func lineageMachO(uuid: UInt8, signature: UInt8, runtime: UInt8) -> Data {
  var data = Data(repeating: 0, count: 0x300)
  putLineageU32(0xfeed_facf, at: 0, in: &data)
  putLineageU32(0x0100_000c, at: 4, in: &data)
  putLineageU32(2, at: 12, in: &data)
  putLineageU32(3, at: 16, in: &data)
  putLineageU32(192, at: 20, in: &data)
  let segment = 32
  putLineageU32(0x19, at: segment, in: &data)
  putLineageU32(152, at: segment + 4, in: &data)
  putLineageName("__TEXT", at: segment + 8, in: &data)
  putLineageU64(0x300, at: segment + 32, in: &data)
  putLineageU32(1, at: segment + 64, in: &data)
  let section = segment + 72
  putLineageName("__text", at: section, in: &data)
  putLineageName("__TEXT", at: section + 16, in: &data)
  putLineageU64(4, at: section + 40, in: &data)
  putLineageU32(0x200, at: section + 48, in: &data)
  putLineageU32(2, at: section + 52, in: &data)
  putLineageU32(0x8000_0400, at: section + 64, in: &data)
  let uuidOffset = segment + 152
  putLineageU32(0x1b, at: uuidOffset, in: &data)
  putLineageU32(24, at: uuidOffset + 4, in: &data)
  for index in 0..<16 { data[uuidOffset + 8 + index] = uuid &+ UInt8(index) }
  let signatureOffset = uuidOffset + 24
  putLineageU32(0x1d, at: signatureOffset, in: &data)
  putLineageU32(16, at: signatureOffset + 4, in: &data)
  putLineageU32(0x240, at: signatureOffset + 8, in: &data)
  putLineageU32(16, at: signatureOffset + 12, in: &data)
  for index in 0..<16 { data[0x240 + index] = signature &+ UInt8(index) }
  for index in 0..<4 { data[0x200 + index] = runtime &+ UInt8(index) }
  return data
}

private func unchangedHelperTree(
  _ root: URL, uuid: UInt8, signature: UInt8, runtime: UInt8,
  notice: String = "same\n"
) throws {
  let executable = root.appendingPathComponent(
    "Library/PrivilegedHelperTools/systems.reach.meshd")
  try FileManager.default.createDirectory(
    at: executable.deletingLastPathComponent(),
    withIntermediateDirectories: true,
    attributes: [.posixPermissions: 0o700])
  try SecureFiles.atomicWrite(
    lineageMachO(uuid: uuid, signature: signature, runtime: runtime),
    to: executable, mode: 0o555)
  let noticeURL = root.appendingPathComponent(
    "Library/Application Support/Reach/Helper/NOTICE.md")
  try FileManager.default.createDirectory(
    at: noticeURL.deletingLastPathComponent(),
    withIntermediateDirectories: true,
    attributes: [.posixPermissions: 0o700])
  try SecureFiles.atomicWrite(Data(notice.utf8), to: noticeURL, mode: 0o644)
  for entry in try SecureFiles.enumerateTree(root) {
    var info = stat()
    guard lstat(entry.path, &info) == 0 else { continue }
    if (info.st_mode & S_IFMT) == S_IFDIR {
      #expect(chmod(entry.path, 0o755) == 0)
    }
  }
}

@Test func unchangedHelperIgnoresOnlySignatureMetadataAndRefusesRuntimeOrPayloadDrift() throws {
  let root = try makeTemporaryDirectory("unchanged-helper")
  defer { removeTemporaryDirectory(root) }
  let current = root.appendingPathComponent("current")
  let parent = root.appendingPathComponent("parent")
  try SecureFiles.createPrivateDirectory(current)
  try SecureFiles.createPrivateDirectory(parent)
  #expect(chmod(current.path, 0o755) == 0)
  #expect(chmod(parent.path, 0o755) == 0)
  try unchangedHelperTree(current, uuid: 1, signature: 2, runtime: 3)
  try unchangedHelperTree(parent, uuid: 40, signature: 80, runtime: 3)
  try SignedReleaseFinalizer.requireUnchangedPayload(
    current: current, parent: parent,
    executablePath: "Library/PrivilegedHelperTools/systems.reach.meshd")

  let runtimeDrift = root.appendingPathComponent("runtime-drift")
  try SecureFiles.createPrivateDirectory(runtimeDrift)
  #expect(chmod(runtimeDrift.path, 0o755) == 0)
  try unchangedHelperTree(runtimeDrift, uuid: 1, signature: 2, runtime: 4)
  #expect(throws: ReleasePackageError.self) {
    try SignedReleaseFinalizer.requireUnchangedPayload(
      current: runtimeDrift, parent: parent,
      executablePath: "Library/PrivilegedHelperTools/systems.reach.meshd")
  }

  let payloadDrift = root.appendingPathComponent("payload-drift")
  try SecureFiles.createPrivateDirectory(payloadDrift)
  #expect(chmod(payloadDrift.path, 0o755) == 0)
  try unchangedHelperTree(payloadDrift, uuid: 1, signature: 2, runtime: 3, notice: "changed\n")
  #expect(throws: ReleasePackageError.self) {
    try SignedReleaseFinalizer.requireUnchangedPayload(
      current: payloadDrift, parent: parent,
      executablePath: "Library/PrivilegedHelperTools/systems.reach.meshd")
  }
}
