import Foundation
import Testing

@testable import ReleasePackageCore

private func rigDigest(_ value: Character) -> String { String(repeating: value, count: 64) }

@Test func rigJournalBindsImageBaseAndEveryCloneEpoch() throws {
  var value = AcceptanceRigJournal(
    runID: UUID().uuidString, tartExecutableSHA256: rigDigest("a"),
    createdAtUTC: "t0", updatedAtUTC: "t0")
  value = try value.imageVerified(
    authoritySHA256: rigDigest("b"), inventorySHA256: rigDigest("c"), at: "t1")
  value = try value.baseCreated(
    configurationSHA256: rigDigest("d"), inventorySHA256: rigDigest("e"), at: "t2")
  value = try value.baseProvisioningStarted(inventorySHA256: rigDigest("f"), at: "t3")
  value = try value.baseSealed(
    provisioningSHA256: rigDigest("1"), sealSHA256: rigDigest("2"),
    inventorySHA256: rigDigest("3"), at: "t4")
  #expect(throws: ReleasePackageError.self) {
    try value.bindingHostAuthority(sha256: rigDigest("a"), at: "too-early")
  }
  for epoch in 1...3 {
    value = try value.cloneCreated(inventorySHA256: rigDigest("4"), at: "c\(epoch)")
    #expect(value.cloneEpoch == epoch)
    value = try value.cloneRunning(inventorySHA256: rigDigest("5"), at: "r\(epoch)")
    #expect(value.bootEpoch == 1)
    if epoch == 1 {
      value = try value.bindingHostAuthority(
        sha256: rigDigest("a"), at: "host-authority")
    }
    #expect(value.hostAuthoritySHA256 == rigDigest("a"))
    value = try value.cloneStopped(inventorySHA256: rigDigest("6"), at: "s\(epoch)")
    value = try value.cloneRunning(inventorySHA256: rigDigest("5"), at: "rr\(epoch)")
    #expect(value.bootEpoch == 2)
    value = try value.cloneStopped(inventorySHA256: rigDigest("6"), at: "ss\(epoch)")
    value = try value.cloneDeleted(inventorySHA256: rigDigest("7"), at: "d\(epoch)")
  }
  value = try value.baseDeleted(inventorySHA256: rigDigest("8"), at: "t5")
  value = try value.completed(inventorySHA256: rigDigest("9"), at: "t6")
  #expect(value.phase == .complete)
  #expect(value.cloneEpoch == 3)
  #expect(value.hostAuthoritySHA256 == rigDigest("a"))
}

@Test func rigJournalRefusesSkippedPhasesAndIsModeBound() throws {
  let root = try makeTemporaryDirectory("rig-journal")
  defer { removeTemporaryDirectory(root) }
  let store = AcceptanceRigJournalStore(url: root.appendingPathComponent("rig.json"))
  let value = AcceptanceRigJournal(
    runID: UUID().uuidString, tartExecutableSHA256: rigDigest("a"),
    createdAtUTC: "t0", updatedAtUTC: "t0")
  try store.create(value)
  #expect(try store.load() == value)
  #expect(throws: ReleasePackageError.self) {
    try value.cloneCreated(inventorySHA256: rigDigest("b"), at: "t1")
  }
  #expect(chmod(store.url.path, 0o644) == 0)
  #expect(throws: ReleasePackageError.self) { try store.load() }
}
