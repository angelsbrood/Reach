import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

private func makeHostAuthorityInputs(
  _ root: URL
) throws -> (identity: URL, knownHosts: URL, tooling: URL) {
  let identity = root.appendingPathComponent("identity")
  let knownHosts = root.appendingPathComponent("known-hosts")
  let tooling = root.appendingPathComponent("tooling")
  try SecureFiles.atomicWrite(Data("synthetic identity\n".utf8), to: identity)
  try SecureFiles.atomicWrite(Data("synthetic known host\n".utf8), to: knownHosts)
  try SecureFiles.createPrivateDirectory(tooling)
  return (identity, knownHosts, tooling)
}

@Test func hostAuthorityBindsExactPinnedSSHAndToolingVnodes() throws {
  let root = try makeTemporaryDirectory("host-authority")
  defer { removeTemporaryDirectory(root) }
  let inputs = try makeHostAuthorityInputs(root)
  let value = try AcceptanceHostAuthority.capture(
    runID: UUID().uuidString, identity: inputs.identity,
    knownHosts: inputs.knownHosts, toolingRoot: inputs.tooling)
  let url = root.appendingPathComponent("authority.json")
  let data = try CanonicalJSON.encode(value)
  try SecureFiles.atomicWrite(data, to: url)

  let loaded = try AcceptanceHostAuthority.loadWithDigest(url)
  #expect(loaded.authority == value)
  #expect(loaded.sha256 == Digests.sha256(data))
  try loaded.authority.verifyCredentials(
    identity: inputs.identity, knownHosts: inputs.knownHosts)
  try loaded.authority.verifyToolingRoot()
}

@Test func hostAuthorityRefusesCredentialAndToolingSubstitution() throws {
  let root = try makeTemporaryDirectory("host-authority-substitution")
  defer { removeTemporaryDirectory(root) }
  let inputs = try makeHostAuthorityInputs(root)
  let value = try AcceptanceHostAuthority.capture(
    runID: UUID().uuidString, identity: inputs.identity,
    knownHosts: inputs.knownHosts, toolingRoot: inputs.tooling)

  let realIdentity = root.appendingPathComponent("identity-real")
  try FileManager.default.moveItem(at: inputs.identity, to: realIdentity)
  try SecureFiles.atomicWrite(Data("substitute identity\n".utf8), to: inputs.identity)
  #expect(throws: ReleasePackageError.self) {
    try value.verifyCredentials(identity: inputs.identity, knownHosts: inputs.knownHosts)
  }

  let realTooling = root.appendingPathComponent("tooling-real")
  try FileManager.default.moveItem(at: inputs.tooling, to: realTooling)
  try SecureFiles.createPrivateDirectory(inputs.tooling)
  #expect(throws: ReleasePackageError.self) { try value.verifyToolingRoot() }
}

@Test func hostAuthorityRequiresPrivateCredentialAndToolingModes() throws {
  let root = try makeTemporaryDirectory("host-authority-modes")
  defer { removeTemporaryDirectory(root) }
  let inputs = try makeHostAuthorityInputs(root)
  #expect(chmod(inputs.identity.path, 0o644) == 0)
  #expect(throws: ReleasePackageError.self) {
    try AcceptanceHostAuthority.capture(
      runID: UUID().uuidString, identity: inputs.identity,
      knownHosts: inputs.knownHosts, toolingRoot: inputs.tooling)
  }
  #expect(chmod(inputs.identity.path, 0o600) == 0)
  #expect(chmod(inputs.tooling.path, 0o755) == 0)
  #expect(throws: ReleasePackageError.self) {
    try AcceptanceHostAuthority.capture(
      runID: UUID().uuidString, identity: inputs.identity,
      knownHosts: inputs.knownHosts, toolingRoot: inputs.tooling)
  }
}
