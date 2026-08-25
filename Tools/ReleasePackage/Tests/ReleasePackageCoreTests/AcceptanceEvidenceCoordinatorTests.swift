import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

private func evidenceSHA(_ value: Character) -> String { String(repeating: value, count: 64) }

private func writeEvidencePack(_ root: URL, text: String = "redacted evidence\n") throws {
  try SecureFiles.createPrivateDirectory(root)
  let summary = root.appendingPathComponent("summary.txt")
  try SecureFiles.atomicWrite(Data(text.utf8), to: summary)
  let line = try Digests.sha256(file: summary) + "  summary.txt\n"
  try SecureFiles.atomicWrite(Data(line.utf8), to: root.appendingPathComponent("SHA256SUMS"))
}

private struct EvidenceFixture {
  let root: URL
  let rigStore: AcceptanceRigJournalStore
  let evidenceStore: AcceptanceEvidenceJournalStore
  let coordinator: AcceptanceEvidenceCoordinator
  let hostAuthority: URL
  let identity: URL
  let knownHosts: URL
  let toolingRoot: URL
}

private func runningRig(_ runID: String) throws -> AcceptanceRigJournal {
  var rig = AcceptanceRigJournal(
    runID: runID, tartExecutableSHA256: evidenceSHA("a"),
    createdAtUTC: "t0", updatedAtUTC: "t0")
  rig = try rig.imageVerified(
    authoritySHA256: evidenceSHA("b"), inventorySHA256: evidenceSHA("c"), at: "t1")
  rig = try rig.baseCreated(
    configurationSHA256: evidenceSHA("d"), inventorySHA256: evidenceSHA("e"), at: "t2")
  rig = try rig.baseProvisioningStarted(inventorySHA256: evidenceSHA("f"), at: "t3")
  rig = try rig.baseSealed(
    provisioningSHA256: evidenceSHA("1"), sealSHA256: evidenceSHA("2"),
    inventorySHA256: evidenceSHA("3"), at: "t4")
  rig = try rig.cloneCreated(inventorySHA256: evidenceSHA("4"), at: "t5")
  return try rig.cloneRunning(inventorySHA256: evidenceSHA("5"), at: "t6")
}

private func makeEvidenceFixture(_ name: String) throws -> EvidenceFixture {
  let root = try makeTemporaryDirectory(name)
  let identity = root.appendingPathComponent("acceptance-identity")
  let knownHosts = root.appendingPathComponent("acceptance-known-hosts")
  let toolingRoot = root.appendingPathComponent("s36-tooling")
  try SecureFiles.atomicWrite(Data("synthetic private identity\n".utf8), to: identity)
  try SecureFiles.atomicWrite(Data("synthetic pinned host\n".utf8), to: knownHosts)
  try SecureFiles.createPrivateDirectory(toolingRoot)
  let nested = toolingRoot.appendingPathComponent("bin")
  try SecureFiles.createPrivateDirectory(nested)
  try SecureFiles.atomicWrite(
    Data("synthetic executable\n".utf8),
    to: nested.appendingPathComponent("acceptance-tool"), mode: 0o700)
  try SecureFiles.atomicWrite(
    Data("synthetic tooling state\n".utf8),
    to: toolingRoot.appendingPathComponent("state.json"))

  let runID = UUID().uuidString
  var rig = try runningRig(runID)
  let host = try AcceptanceHostAuthority.capture(
    runID: runID, identity: identity, knownHosts: knownHosts,
    toolingRoot: toolingRoot)
  let hostAuthority = root.appendingPathComponent("host-authority.json")
  let hostData = try CanonicalJSON.encode(host)
  try SecureFiles.atomicWrite(hostData, to: hostAuthority)
  rig = try rig.bindingHostAuthority(sha256: Digests.sha256(hostData), at: "t7")

  let rigStore = AcceptanceRigJournalStore(url: root.appendingPathComponent("rig.json"))
  try rigStore.create(rig)
  let evidenceStore = AcceptanceEvidenceJournalStore(
    url: root.appendingPathComponent("evidence.json"))
  var tick = 7
  let coordinator = AcceptanceEvidenceCoordinator(
    evidenceStore: evidenceStore, rigStore: rigStore,
    timestamp: {
      tick += 1
      return "t\(tick)"
    })
  return .init(
    root: root, rigStore: rigStore, evidenceStore: evidenceStore,
    coordinator: coordinator, hostAuthority: hostAuthority,
    identity: identity, knownHosts: knownHosts, toolingRoot: toolingRoot)
}

private func sealMetalStop(_ fixture: EvidenceFixture) throws {
  _ = try fixture.coordinator.begin()
  let raw = fixture.root.appendingPathComponent("raw.txt")
  let summary = fixture.root.appendingPathComponent("summary.txt")
  try SecureFiles.atomicWrite(Data("synthetic stop\n".utf8), to: raw)
  try SecureFiles.atomicWrite(Data("METAL-VM\n".utf8), to: summary)
  _ = try fixture.coordinator.record(
    cell: .nativeMLX, verdict: .stop,
    privateEvidence: raw, redactedSummary: summary)
  let pack = fixture.root.appendingPathComponent("pack")
  try writeEvidencePack(pack)
  _ = try fixture.coordinator.seal(outcome: .metalVM, pack: pack)
}

private func freezeAndAdvanceToBaseDeleted(
  _ fixture: EvidenceFixture
) throws -> URL {
  let authority = fixture.root.appendingPathComponent("teardown-authority.json")
  _ = try fixture.coordinator.freezeTeardownAuthority(
    hostAuthority: fixture.hostAuthority, output: authority)
  var rig = try #require(try fixture.rigStore.load())
  rig = try rig.cloneStopped(inventorySHA256: evidenceSHA("6"), at: "stop")
  try fixture.rigStore.write(rig)
  rig = try rig.cloneDeleted(inventorySHA256: evidenceSHA("7"), at: "delete-clone")
  try fixture.rigStore.write(rig)
  _ = try fixture.coordinator.advanceRigTeardown(to: .cloneDeleted)
  rig = try rig.baseDeleted(inventorySHA256: evidenceSHA("8"), at: "delete-base")
  try fixture.rigStore.write(rig)
  _ = try fixture.coordinator.advanceRigTeardown(to: .baseDeleted)
  return authority
}

@Test func evidenceCoordinatorBindsCellsAndSealToOneRigRun() throws {
  let root = try makeTemporaryDirectory("evidence-coordinator")
  defer { removeTemporaryDirectory(root) }
  let rigStore = AcceptanceRigJournalStore(url: root.appendingPathComponent("rig.json"))
  let rig = AcceptanceRigJournal(
    runID: UUID().uuidString, tartExecutableSHA256: evidenceSHA("a"),
    createdAtUTC: "t0", updatedAtUTC: "t0")
  try rigStore.create(rig)
  let evidenceStore = AcceptanceEvidenceJournalStore(
    url: root.appendingPathComponent("evidence.json"))
  let coordinator = AcceptanceEvidenceCoordinator(
    evidenceStore: evidenceStore, rigStore: rigStore, timestamp: { "t1" })
  var journal = try coordinator.begin()
  #expect(journal.runID == rig.runID)

  let raw = root.appendingPathComponent("raw.txt")
  let summary = root.appendingPathComponent("summary.txt")
  try SecureFiles.atomicWrite(Data("private synthetic result\n".utf8), to: raw)
  try SecureFiles.atomicWrite(Data("bounded stop\n".utf8), to: summary)
  journal = try coordinator.record(
    cell: .nativeMLX, verdict: .stop,
    privateEvidence: raw, redactedSummary: summary)
  let pack = root.appendingPathComponent("pack")
  try writeEvidencePack(pack)
  journal = try coordinator.seal(outcome: .metalVM, pack: pack)
  #expect(journal.phase == .sealed)
  #expect(journal.packFileCount == 2)
}

@Test func evidenceCoordinatorRejectsPrivacyLeaksAndUnboundRigTeardown() throws {
  let root = try makeTemporaryDirectory("evidence-coordinator-refusal")
  defer { removeTemporaryDirectory(root) }
  let rigStore = AcceptanceRigJournalStore(url: root.appendingPathComponent("rig.json"))
  let rig = AcceptanceRigJournal(
    runID: UUID().uuidString, tartExecutableSHA256: evidenceSHA("a"),
    createdAtUTC: "t0", updatedAtUTC: "t0")
  try rigStore.create(rig)
  let evidenceStore = AcceptanceEvidenceJournalStore(
    url: root.appendingPathComponent("evidence.json"))
  let coordinator = AcceptanceEvidenceCoordinator(
    evidenceStore: evidenceStore, rigStore: rigStore, timestamp: { "t1" })
  _ = try coordinator.begin()
  let raw = root.appendingPathComponent("raw.txt")
  let summary = root.appendingPathComponent("summary.txt")
  try SecureFiles.atomicWrite(Data("private\n".utf8), to: raw)
  try SecureFiles.atomicWrite(Data("stop\n".utf8), to: summary)
  _ = try coordinator.record(
    cell: .nativeMLX, verdict: .stop,
    privateEvidence: raw, redactedSummary: summary)
  let pack = root.appendingPathComponent("pack")
  try writeEvidencePack(pack, text: "leaked /Users/example state\n")
  #expect(throws: ReleasePackageError.self) {
    try coordinator.seal(outcome: .metalVM, pack: pack)
  }
  #expect(throws: ReleasePackageError.self) {
    try coordinator.advanceRigTeardown(to: .cloneDeleted)
  }
}

@Test func coordinatorOwnsExactCredentialAndToolingDeletionThroughCompletion() throws {
  let fixture = try makeEvidenceFixture("evidence-owned-deletion")
  defer { removeTemporaryDirectory(fixture.root) }
  try sealMetalStop(fixture)
  let authority = try freezeAndAdvanceToBaseDeleted(fixture)

  let credentials = fixture.root.appendingPathComponent("credentials-absent.json")
  var evidence = try fixture.coordinator.destroyAuthority(
    kind: "credentials", authority: authority, inventory: credentials,
    output: fixture.root.appendingPathComponent("credentials-command.json"))
  #expect(evidence.phase == .credentialsDestroyed)
  #expect(!FileManager.default.fileExists(atPath: fixture.identity.path))
  #expect(!FileManager.default.fileExists(atPath: fixture.knownHosts.path))

  let tooling = fixture.root.appendingPathComponent("tooling-absent.json")
  evidence = try fixture.coordinator.destroyAuthority(
    kind: "tooling", authority: authority, inventory: tooling,
    output: fixture.root.appendingPathComponent("tooling-command.json"))
  #expect(evidence.phase == .toolingRemoved)
  #expect(!FileManager.default.fileExists(atPath: fixture.toolingRoot.path))

  var rig = try #require(try fixture.rigStore.load())
  rig = try rig.completed(inventorySHA256: evidenceSHA("9"), at: "complete-rig")
  try fixture.rigStore.write(rig)
  let parity = fixture.root.appendingPathComponent("runtime-parity.json")
  try SecureFiles.atomicWrite(Data("{\"verdict\":\"pass\"}\n".utf8), to: parity)
  evidence = try fixture.coordinator.complete(runtimeParity: parity)
  #expect(evidence.phase == .complete)
  #expect(evidence.outcome == .metalVM)
}

@Test func credentialSubstitutionCannotBeDeletedOrCertifiedAbsent() throws {
  let fixture = try makeEvidenceFixture("evidence-credential-substitution")
  defer { removeTemporaryDirectory(fixture.root) }
  try sealMetalStop(fixture)
  let authority = try freezeAndAdvanceToBaseDeleted(fixture)

  let original = fixture.root.appendingPathComponent("real-identity-moved")
  try FileManager.default.moveItem(at: fixture.identity, to: original)
  try SecureFiles.atomicWrite(Data("substitute identity\n".utf8), to: fixture.identity)
  let inventory = fixture.root.appendingPathComponent("credentials-refused.json")
  #expect(throws: ReleasePackageError.self) {
    try fixture.coordinator.destroyAuthority(
      kind: "credentials", authority: authority, inventory: inventory,
      output: fixture.root.appendingPathComponent("credentials-command.json"))
  }
  #expect(FileManager.default.fileExists(atPath: original.path))
  #expect(FileManager.default.fileExists(atPath: fixture.identity.path))
  #expect(FileManager.default.fileExists(atPath: fixture.knownHosts.path))
  #expect(!FileManager.default.fileExists(atPath: inventory.path))
}

@Test func replacedToolingRootCannotBeDeletedOrCertifiedAbsent() throws {
  let fixture = try makeEvidenceFixture("evidence-tooling-substitution")
  defer { removeTemporaryDirectory(fixture.root) }
  try sealMetalStop(fixture)
  let authority = try freezeAndAdvanceToBaseDeleted(fixture)
  _ = try fixture.coordinator.destroyAuthority(
    kind: "credentials", authority: authority,
    inventory: fixture.root.appendingPathComponent("credentials-absent.json"),
    output: fixture.root.appendingPathComponent("credentials-command.json"))

  let original = fixture.root.appendingPathComponent("real-tooling-moved")
  try FileManager.default.moveItem(at: fixture.toolingRoot, to: original)
  try SecureFiles.createPrivateDirectory(fixture.toolingRoot)
  try SecureFiles.atomicWrite(
    Data("substitute tooling\n".utf8),
    to: fixture.toolingRoot.appendingPathComponent("substitute"))
  let inventory = fixture.root.appendingPathComponent("tooling-refused.json")
  #expect(throws: ReleasePackageError.self) {
    try fixture.coordinator.destroyAuthority(
      kind: "tooling", authority: authority, inventory: inventory,
      output: fixture.root.appendingPathComponent("tooling-command.json"))
  }
  #expect(FileManager.default.fileExists(atPath: original.path))
  #expect(FileManager.default.fileExists(atPath: fixture.toolingRoot.path))
  #expect(!FileManager.default.fileExists(atPath: inventory.path))
}

@Test func authorityDeletionRefusesUnclaimedDisappearanceAfterDurablePhase() throws {
  let fixture = try makeEvidenceFixture("evidence-unclaimed-disappearance")
  defer { removeTemporaryDirectory(fixture.root) }
  try sealMetalStop(fixture)
  let authority = try freezeAndAdvanceToBaseDeleted(fixture)

  var evidence = try #require(try fixture.evidenceStore.load())
  evidence = try evidence.beginningAuthorityDestruction(
    to: .credentialsDestroying, at: "durable-destroying")
  try fixture.evidenceStore.write(evidence)
  let moved = fixture.root.appendingPathComponent("identity-moved-outside-claim")
  try FileManager.default.moveItem(at: fixture.identity, to: moved)

  #expect(throws: ReleasePackageError.self) {
    try fixture.coordinator.destroyAuthority(
      kind: "credentials", authority: authority,
      inventory: fixture.root.appendingPathComponent("credentials-absent.json"),
      output: fixture.root.appendingPathComponent("credentials-command.json"))
  }
  #expect(FileManager.default.fileExists(atPath: moved.path))
  #expect(FileManager.default.fileExists(atPath: fixture.knownHosts.path))
  #expect((try #require(try fixture.evidenceStore.load())).phase == .credentialsDestroying)
}

@Test func authorityDeletionRecoversOnlyFromTheExactDeterministicTombstone() throws {
  let fixture = try makeEvidenceFixture("evidence-claimed-recovery")
  defer { removeTemporaryDirectory(fixture.root) }
  try sealMetalStop(fixture)
  let authority = try freezeAndAdvanceToBaseDeleted(fixture)
  let frozen = try JSONDecoder().decode(
    AcceptanceTeardownAuthority.self, from: Data(contentsOf: authority))
  let runID = (try #require(try fixture.evidenceStore.load())).runID
  let claimed = try AcceptanceEvidenceCoordinator.claimedPaths(
    records: frozen.credentials, kind: "credentials", runID: runID)
  let pair = try #require(
    zip(frozen.credentials, claimed).first(where: { $0.0.path == fixture.identity.path }))

  var evidence = try #require(try fixture.evidenceStore.load())
  evidence = try evidence.beginningAuthorityDestruction(
    to: .credentialsDestroying, at: "durable-destroying")
  try fixture.evidenceStore.write(evidence)
  try FileManager.default.moveItem(
    at: URL(fileURLWithPath: pair.0.path), to: URL(fileURLWithPath: pair.1.path))

  evidence = try fixture.coordinator.destroyAuthority(
    kind: "credentials", authority: authority,
    inventory: fixture.root.appendingPathComponent("credentials-absent.json"),
    output: fixture.root.appendingPathComponent("credentials-command.json"))
  #expect(evidence.phase == .credentialsDestroyed)
  #expect(evidence.credentialClaimedPathCount == 2)
  #expect(evidence.credentialDeletionCount == 2)
  #expect(!FileManager.default.fileExists(atPath: fixture.identity.path))
  #expect(!FileManager.default.fileExists(atPath: pair.1.path))
}

@Test func claimedDeletionResumesOnlyBehindDurablePerVnodeProgress() throws {
  let fixture = try makeEvidenceFixture("evidence-claimed-progress")
  defer { removeTemporaryDirectory(fixture.root) }
  try sealMetalStop(fixture)
  let authority = try freezeAndAdvanceToBaseDeleted(fixture)
  let frozen = try JSONDecoder().decode(
    AcceptanceTeardownAuthority.self, from: Data(contentsOf: authority))
  let runID = (try #require(try fixture.evidenceStore.load())).runID
  let claimed = try AcceptanceEvidenceCoordinator.claimedPaths(
    records: frozen.credentials, kind: "credentials", runID: runID)
  var evidence = try #require(try fixture.evidenceStore.load())
  evidence = try evidence.beginningAuthorityDestruction(
    to: .credentialsDestroying, at: "durable-destroying")
  try fixture.evidenceStore.write(evidence)
  for (source, tombstone) in zip(frozen.credentials, claimed) {
    try FileManager.default.moveItem(
      at: URL(fileURLWithPath: source.path),
      to: URL(fileURLWithPath: tombstone.path))
  }
  evidence = try evidence.recordingAuthorityClaim(
    to: .credentialsClaimed, pathCount: claimed.count,
    at: "durable-claimed")
  let ordered = claimed.sorted {
    $1.path.utf8.lexicographicallyPrecedes($0.path.utf8)
  }
  try FileManager.default.removeItem(atPath: ordered[0].path)
  evidence = try evidence.recordingAuthorityDeletion(
    kind: "credentials", deletedCount: 1, at: "durable-first-deletion")
  try fixture.evidenceStore.write(evidence)

  evidence = try fixture.coordinator.destroyAuthority(
    kind: "credentials", authority: authority,
    inventory: fixture.root.appendingPathComponent("credentials-absent.json"),
    output: fixture.root.appendingPathComponent("credentials-command.json"))
  #expect(evidence.phase == .credentialsDestroyed)
  #expect(evidence.credentialDeletionCount == claimed.count)
}

@Test func unrecordedOrSubstitutedClaimedVnodeCannotBecomeAbsenceProof() throws {
  for substitute in [false, true] {
    let fixture = try makeEvidenceFixture(
      substitute ? "evidence-claimed-substitution" : "evidence-claimed-missing")
    defer { removeTemporaryDirectory(fixture.root) }
    try sealMetalStop(fixture)
    let authority = try freezeAndAdvanceToBaseDeleted(fixture)
    let frozen = try JSONDecoder().decode(
      AcceptanceTeardownAuthority.self, from: Data(contentsOf: authority))
    let runID = (try #require(try fixture.evidenceStore.load())).runID
    let claimed = try AcceptanceEvidenceCoordinator.claimedPaths(
      records: frozen.credentials, kind: "credentials", runID: runID)
    var evidence = try #require(try fixture.evidenceStore.load())
    evidence = try evidence.beginningAuthorityDestruction(
      to: .credentialsDestroying, at: "durable-destroying")
    for (source, tombstone) in zip(frozen.credentials, claimed) {
      try FileManager.default.moveItem(
        at: URL(fileURLWithPath: source.path),
        to: URL(fileURLWithPath: tombstone.path))
    }
    evidence = try evidence.recordingAuthorityClaim(
      to: .credentialsClaimed, pathCount: claimed.count,
      at: "durable-claimed")
    try fixture.evidenceStore.write(evidence)
    let escaped = fixture.root.appendingPathComponent("escaped-claimed-vnode")
    try FileManager.default.moveItem(
      at: URL(fileURLWithPath: claimed[0].path), to: escaped)
    if substitute {
      try SecureFiles.atomicWrite(
        Data("substitute claimed credential\n".utf8),
        to: URL(fileURLWithPath: claimed[0].path))
    }

    #expect(throws: ReleasePackageError.self) {
      try fixture.coordinator.destroyAuthority(
        kind: "credentials", authority: authority,
        inventory: fixture.root.appendingPathComponent("credentials-absent.json"),
        output: fixture.root.appendingPathComponent("credentials-command.json"))
    }
    #expect(FileManager.default.fileExists(atPath: escaped.path))
    let retained = try #require(try fixture.evidenceStore.load())
    #expect(retained.phase == .credentialsClaimed)
    #expect(
      try #require(retained.credentialDeletionCount)
        < #require(retained.credentialClaimedPathCount))
  }
}

@Test func destructiveOutputCannotOverlapCredentialsOrTooling() throws {
  for useToolingOutput in [false, true] {
    let fixture = try makeEvidenceFixture(
      useToolingOutput ? "evidence-tooling-output" : "evidence-credential-output")
    defer { removeTemporaryDirectory(fixture.root) }
    try sealMetalStop(fixture)
    let authority = try freezeAndAdvanceToBaseDeleted(fixture)
    let output =
      useToolingOutput
      ? fixture.toolingRoot.appendingPathComponent("command-output.json")
      : fixture.identity
    #expect(throws: ReleasePackageError.self) {
      try fixture.coordinator.destroyAuthority(
        kind: "credentials", authority: authority,
        inventory: fixture.root.appendingPathComponent("credentials-absent.json"),
        output: output)
    }
    #expect(FileManager.default.fileExists(atPath: fixture.identity.path))
    #expect(FileManager.default.fileExists(atPath: fixture.knownHosts.path))
    #expect(FileManager.default.fileExists(atPath: fixture.toolingRoot.path))
    #expect((try #require(try fixture.evidenceStore.load())).phase == .baseDeleted)
  }
}

@Test func teardownRejectsHostAuthorityNotBoundIntoTheRig() throws {
  let fixture = try makeEvidenceFixture("evidence-unbound-host")
  defer { removeTemporaryDirectory(fixture.root) }
  try sealMetalStop(fixture)
  let otherIdentity = fixture.root.appendingPathComponent("other-identity")
  try SecureFiles.atomicWrite(Data("other identity\n".utf8), to: otherIdentity)
  let other = try AcceptanceHostAuthority.capture(
    runID: (try #require(try fixture.rigStore.load())).runID,
    identity: otherIdentity, knownHosts: fixture.knownHosts,
    toolingRoot: fixture.toolingRoot)
  let otherURL = fixture.root.appendingPathComponent("other-host-authority.json")
  try SecureFiles.atomicWrite(try CanonicalJSON.encode(other), to: otherURL)
  #expect(throws: ReleasePackageError.self) {
    try fixture.coordinator.freezeTeardownAuthority(
      hostAuthority: otherURL,
      output: fixture.root.appendingPathComponent("refused-authority.json"))
  }
}
