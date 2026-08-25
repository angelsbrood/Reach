import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

@Test func runningExecutableVnodeComesFromTheProcessTextMapping() throws {
  let path = "/Library/Application Support/Reach/Host/reachd"
  let record = "p123\0\nftxt\0D0x100000e\0i4567\0n\(path)\0\n"
  let value = try MacOSInstalledStateCollector.runningExecutableVnode(
    fromLsof: record, expectedPath: path)
  #expect(value.device == 0x100000e)
  #expect(value.inode == 4567)

  #expect(throws: ReleasePackageError.self) {
    try MacOSInstalledStateCollector.runningExecutableVnode(
      fromLsof: record,
      expectedPath: "/Library/Application Support/Reach/Host/replacement")
  }
  #expect(throws: ReleasePackageError.self) {
    try MacOSInstalledStateCollector.runningExecutableVnode(
      fromLsof: record + record, expectedPath: path)
  }
}

@Test func retainedStateBindsSecretModesAndSingleLinkAuthority() throws {
  func makeState(_ parent: URL, name: String, keyMode: mode_t) throws -> URL {
    let state = parent.appendingPathComponent(name)
    let ca = state.appendingPathComponent("ca")
    try SecureFiles.createPrivateDirectory(state)
    try SecureFiles.createPrivateDirectory(ca)
    try SecureFiles.atomicWrite(
      Data("synthetic ca\n".utf8), to: ca.appendingPathComponent("ca.der"), mode: 0o644)
    try SecureFiles.atomicWrite(
      Data("synthetic key\n".utf8), to: ca.appendingPathComponent("ca-key.raw"),
      mode: keyMode)
    return state
  }

  let root = try makeTemporaryDirectory("installed-state-metadata")
  defer { removeTemporaryDirectory(root) }
  let collector = MacOSInstalledStateCollector()
  let accepted = try makeState(root, name: "accepted", keyMode: 0o600)
  let value = try collector.observeState(accepted, expectedOwnerUID: getuid())
  #expect(value.present)
  #expect(value.caCreationCount == 1)

  let exposed = try makeState(root, name: "exposed", keyMode: 0o644)
  #expect(throws: ReleasePackageError.self) {
    try collector.observeState(exposed, expectedOwnerUID: getuid())
  }

  let linked = try makeState(root, name: "linked", keyMode: 0o600)
  try FileManager.default.linkItem(
    at: linked.appendingPathComponent("ca/ca-key.raw"),
    to: linked.appendingPathComponent("ca/ca-key-copy.raw"))
  #expect(throws: ReleasePackageError.self) {
    try collector.observeState(linked, expectedOwnerUID: getuid())
  }
}

@Test func retainedStateRequiresExactModesForEveryMutableRoot() throws {
  let mutableMembers: [(String, Bool)] = [
    ("enroll-tokens", true),
    ("enroll-tokens/token.json", false),
    ("mesh-stage", true),
    ("mesh-stage/candidate.json", false),
    ("mesh-intent.lock", false),
    ("reachability.json", false),
  ]

  func makeState(_ parent: URL, name: String) throws -> URL {
    let state = parent.appendingPathComponent(name)
    try SecureFiles.createPrivateDirectory(state)
    try SecureFiles.createPrivateDirectory(state.appendingPathComponent("enroll-tokens"))
    try SecureFiles.atomicWrite(
      Data("synthetic token\n".utf8),
      to: state.appendingPathComponent("enroll-tokens/token.json"))
    try SecureFiles.createPrivateDirectory(state.appendingPathComponent("mesh-stage"))
    try SecureFiles.atomicWrite(
      Data("synthetic candidate\n".utf8),
      to: state.appendingPathComponent("mesh-stage/candidate.json"))
    try SecureFiles.atomicWrite(
      Data("synthetic lock\n".utf8), to: state.appendingPathComponent("mesh-intent.lock"))
    try SecureFiles.atomicWrite(
      Data("synthetic reachability\n".utf8),
      to: state.appendingPathComponent("reachability.json"))
    return state
  }

  let root = try makeTemporaryDirectory("installed-state-mutable-modes")
  defer { removeTemporaryDirectory(root) }
  let collector = MacOSInstalledStateCollector()
  let accepted = try makeState(root, name: "accepted")
  #expect((try collector.observeState(accepted, expectedOwnerUID: getuid())).present)

  for (index, member) in mutableMembers.enumerated() {
    let state = try makeState(root, name: "weakened-\(index)")
    let path = state.appendingPathComponent(member.0)
    #expect(chmod(path.path, member.1 ? 0o755 : 0o644) == 0)
    #expect(throws: ReleasePackageError.self) {
      try collector.observeState(state, expectedOwnerUID: getuid())
    }
  }
}

@Test func extraPathEnumerationCoversTheCompleteReachPackageRoot() throws {
  let root = try makeTemporaryDirectory("installed-package-root")
  defer { removeTemporaryDirectory(root) }
  let host = root.appendingPathComponent("Host")
  let executable = host.appendingPathComponent("reachd")
  let foreign = root.appendingPathComponent("Unexpected")
  try SecureFiles.createPrivateDirectory(host)
  try SecureFiles.atomicWrite(Data("host\n".utf8), to: executable)
  try SecureFiles.createPrivateDirectory(foreign)

  let extra = try MacOSInstalledStateCollector.unexpectedPackagePaths(
    expected: [root.path, host.path, executable.path],
    roots: [root.path], leaves: [])
  #expect(extra == [foreign.path])
}
