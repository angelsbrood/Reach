import Foundation
import Testing

@testable import ReleasePackageCore

private final class FakeAcceptanceSystem: AcceptanceTransactionSystem {
  var calls: [String] = []
  var failAt: String?
  var interruptedAuthority: AcceptanceInstalledAuthority = .mixed

  func stopHost(ownerUID: UInt32) throws { try call("stop:\(ownerUID)") }
  func install(_ release: AcceptanceReleaseReference) throws {
    try call("install:\(release.versions.product)")
  }
  func verifyInstalled(_ release: AcceptanceReleaseReference) throws {
    try call("verify-installed:\(release.versions.product)")
  }
  func reconcileHelper(
    from prior: AcceptanceReleaseReference?, to target: AcceptanceReleaseReference
  ) throws {
    try call("helper:\(prior?.versions.helper.description ?? "none")->\(target.versions.helper)")
  }
  func startHost(ownerUID: UInt32) throws { try call("start:\(ownerUID)") }
  func verifyRuntime(_ release: AcceptanceReleaseReference) throws {
    try call("verify-runtime:\(release.versions.product)")
  }
  func verifyAccepted(_ release: AcceptanceReleaseReference) throws {
    try call("verify-accepted:\(release.versions.product)")
  }
  func finalize(
    action: AcceptanceTransactionAction,
    release: AcceptanceReleaseReference
  ) throws {
    try call("finalize:\(action.rawValue):\(release.versions.product)")
  }
  func uninstall(_ release: AcceptanceReleaseReference) throws {
    try call("uninstall:\(release.versions.product)")
  }
  func verifyUninstalled(_ release: AcceptanceReleaseReference) throws {
    try call("verify-uninstalled:\(release.versions.product)")
  }
  func interruptInstaller(
    target: AcceptanceReleaseReference
  ) throws -> AcceptanceInstalledAuthority {
    try call("interrupt-installer:\(target.versions.product)")
    return interruptedAuthority
  }

  private func call(_ value: String) throws {
    calls.append(value)
    if failAt == value {
      throw ReleasePackageError.verification("injected transaction failure")
    }
  }
}

private func transactionReference(
  _ product: String, parent: String? = nil
) throws -> AcceptanceReleaseReference {
  let version = try DottedVersion(product)
  return .init(
    versions: .init(product: version, host: version, helper: try DottedVersion("1.0.2")),
    p5SHA256: String(repeating: product == "0.0.2" ? "a" : "b", count: 64),
    provenanceSHA256: String(repeating: product == "0.0.2" ? "c" : "d", count: 64),
    parentP5SHA256: parent)
}

private func transactionJournal(_ action: AcceptanceTransactionAction) throws -> AcceptanceJournal {
  let a = try transactionReference("0.0.2")
  let b = try transactionReference("0.0.3", parent: a.p5SHA256)
  let pair: (AcceptanceReleaseReference?, AcceptanceReleaseReference?)
  switch action {
  case .install: pair = (nil, a)
  case .migrate: pair = (nil, a)
  case .update: pair = (a, b)
  case .rollback: pair = (b, a)
  case .uninstall: pair = (b, nil)
  case .verify: pair = (nil, b)
  }
  return AcceptanceJournal(
    transactionID: UUID().uuidString, action: action,
    prior: pair.0, target: pair.1, selectedOwnerUID: 501,
    createdAtUTC: "2026-08-23T00:00:00Z",
    updatedAtUTC: "2026-08-23T00:00:00Z")
}

@Test func cleanInstallAndUnmanagedMigrationRemainDistinctAuthorities() throws {
  for action in [AcceptanceTransactionAction.install, .migrate] {
    let root = try makeTemporaryDirectory("transaction-\(action.rawValue)")
    defer { removeTemporaryDirectory(root) }
    let store = AcceptanceJournalStore(url: root.appendingPathComponent("journal.json"))
    let system = FakeAcceptanceSystem()
    let result = try AcceptanceTransactionExecutor(timestamp: {
      "2026-08-23T00:00:01Z"
    }).begin(store: store, journal: transactionJournal(action), system: system)
    #expect(result.phase == .accepted)
    #expect(system.calls.first == "stop:501")
    #expect(system.calls.last == "finalize:\(action.rawValue):0.0.2")
  }
}

@Test func updateInterruptionResumesFromLastDurablePhase() throws {
  let root = try makeTemporaryDirectory("transaction-update")
  defer { removeTemporaryDirectory(root) }
  let store = AcceptanceJournalStore(url: root.appendingPathComponent("journal.json"))
  let system = FakeAcceptanceSystem()
  var tick = 0
  let executor = AcceptanceTransactionExecutor {
    tick += 1
    return "2026-08-23T00:00:\(String(format: "%02d", tick))Z"
  }
  let interrupted = try executor.begin(
    store: store, journal: transactionJournal(.update), system: system,
    stopAfter: .installerStarted)
  #expect(interrupted.phase == .installerStarted)
  #expect(system.calls == ["stop:501"])
  let accepted = try executor.recover(store: store, system: system)
  #expect(accepted.phase == .accepted)
  #expect(
    system.calls == [
      "stop:501", "install:0.0.3", "verify-installed:0.0.3",
      "helper:1.0.2->1.0.2", "start:501", "verify-runtime:0.0.3",
      "verify-accepted:0.0.3", "finalize:update:0.0.3",
    ])
}

@Test func duringInstallerInterruptionIsObservableDurableAndRecoverable() throws {
  let root = try makeTemporaryDirectory("transaction-during-installer")
  defer { removeTemporaryDirectory(root) }
  let store = AcceptanceJournalStore(url: root.appendingPathComponent("journal.json"))
  let system = FakeAcceptanceSystem()
  system.interruptedAuthority = .mixed
  var tick = 0
  let executor = AcceptanceTransactionExecutor {
    tick += 1
    return "2026-08-23T00:00:\(String(format: "%02d", tick))Z"
  }
  let landed = try executor.begin(
    store: store, journal: transactionJournal(.update), system: system,
    stopAfter: .installerStarted)
  #expect(landed.phase == .installerStarted)
  let report = try executor.interruptInstaller(store: store, system: system)
  #expect(report.observedAuthority == .mixed)
  #expect(report.transactionJournalSHA256 == (try Digests.sha256(file: store.url)))
  #expect((try store.load())?.phase == .installerStarted)
  #expect((try store.loadInstallerInterruption()) == report)
  #expect(throws: ReleasePackageError.self) {
    try executor.interruptInstaller(store: store, system: system)
  }
  let accepted = try executor.recover(store: store, system: system)
  #expect(accepted.phase == .accepted)
  #expect(
    system.calls == [
      "stop:501", "interrupt-installer:0.0.3",
      "install:0.0.3", "verify-installed:0.0.3",
      "helper:1.0.2->1.0.2", "start:501", "verify-runtime:0.0.3",
      "verify-accepted:0.0.3", "finalize:update:0.0.3",
    ])
}

@Test func explicitRollbackAndUninstallHaveDistinctTerminalAuthority() throws {
  for (action, terminal) in [
    (AcceptanceTransactionAction.rollback, AcceptanceTransactionPhase.rolledBack),
    (.uninstall, .uninstalled),
  ] {
    let root = try makeTemporaryDirectory("transaction-\(action.rawValue)")
    defer { removeTemporaryDirectory(root) }
    let store = AcceptanceJournalStore(url: root.appendingPathComponent("journal.json"))
    let system = FakeAcceptanceSystem()
    let result = try AcceptanceTransactionExecutor(timestamp: {
      "2026-08-23T00:00:01Z"
    }).begin(store: store, journal: transactionJournal(action), system: system)
    #expect(result.phase == terminal)
    if action == .rollback {
      #expect(system.calls.contains("install:0.0.2"))
    } else {
      #expect(system.calls == ["stop:501", "uninstall:0.0.3", "verify-uninstalled:0.0.3"])
    }
  }
}

@Test func transactionFailurePublishesBoundedTerminalRefusal() throws {
  let root = try makeTemporaryDirectory("transaction-failure")
  defer { removeTemporaryDirectory(root) }
  let store = AcceptanceJournalStore(url: root.appendingPathComponent("journal.json"))
  let system = FakeAcceptanceSystem()
  system.failAt = "install:0.0.3"
  #expect(throws: ReleasePackageError.self) {
    try AcceptanceTransactionExecutor(timestamp: {
      "2026-08-23T00:00:01Z"
    }).begin(store: store, journal: transactionJournal(.update), system: system)
  }
  let journal = try #require(try store.load())
  #expect(journal.phase == .failed)
  #expect(journal.failureCode == "verification-refused")
}

@Test func verifyRunsRuntimeBeforeAcceptingAndInstallCanPauseBeforeRuntime() throws {
  let verifyRoot = try makeTemporaryDirectory("transaction-verify-runtime")
  defer { removeTemporaryDirectory(verifyRoot) }
  let verifyStore = AcceptanceJournalStore(
    url: verifyRoot.appendingPathComponent("journal.json"))
  let verifySystem = FakeAcceptanceSystem()
  let verified = try AcceptanceTransactionExecutor(timestamp: {
    "2026-08-23T00:00:01Z"
  }).begin(
    store: verifyStore, journal: transactionJournal(.verify), system: verifySystem)
  #expect(verified.phase == .accepted)
  #expect(
    verifySystem.calls == [
      "verify-runtime:0.0.3", "verify-accepted:0.0.3",
    ])

  let installRoot = try makeTemporaryDirectory("transaction-prelogin-pause")
  defer { removeTemporaryDirectory(installRoot) }
  let installStore = AcceptanceJournalStore(
    url: installRoot.appendingPathComponent("journal.json"))
  let installSystem = FakeAcceptanceSystem()
  let paused = try AcceptanceTransactionExecutor(timestamp: {
    "2026-08-23T00:00:01Z"
  }).begin(
    store: installStore, journal: transactionJournal(.install),
    system: installSystem, stopAfter: .payloadVerified)
  #expect(paused.phase == .payloadVerified)
  #expect(
    installSystem.calls == [
      "stop:501", "install:0.0.2", "verify-installed:0.0.2",
    ])
  let resumed = try AcceptanceTransactionExecutor(timestamp: {
    "2026-08-23T00:00:02Z"
  }).recover(store: installStore, system: installSystem)
  #expect(resumed.phase == .accepted)
  #expect(installSystem.calls.contains("verify-runtime:0.0.2"))
}
