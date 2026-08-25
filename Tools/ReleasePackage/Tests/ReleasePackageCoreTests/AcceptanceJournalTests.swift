import Foundation
import Testing

@testable import ReleasePackageCore

private func releaseReference(
  _ product: String, parentP5SHA256: String? = nil
) throws -> AcceptanceReleaseReference {
  let version = try DottedVersion(product)
  return .init(
    versions: .init(product: version, host: version, helper: try DottedVersion("1.0.2")),
    p5SHA256: String(repeating: product == "0.0.2" ? "a" : "b", count: 64),
    provenanceSHA256: String(repeating: product == "0.0.2" ? "c" : "d", count: 64),
    parentP5SHA256: parentP5SHA256)
}

@Test func acceptanceJournalRequiresOrderedDurableTransitions() throws {
  let root = try makeTemporaryDirectory("acceptance-journal")
  defer { removeTemporaryDirectory(root) }
  let store = AcceptanceJournalStore(url: root.appendingPathComponent("journal.json"))
  let journal = AcceptanceJournal(
    transactionID: UUID().uuidString,
    action: .update,
    prior: try releaseReference("0.0.2"),
    target: try releaseReference("0.0.3", parentP5SHA256: String(repeating: "a", count: 64)),
    selectedOwnerUID: 501,
    createdAtUTC: "2026-08-23T00:00:00Z",
    updatedAtUTC: "2026-08-23T00:00:00Z")
  try store.create(journal)
  #expect(try store.load() == journal)
  var current = journal
  for (index, phase) in AcceptanceJournal.sequence(for: .update).dropFirst().enumerated() {
    current = try store.transition(
      to: phase, at: "2026-08-23T00:00:\(String(format: "%02d", index + 1))Z")
  }
  #expect(current.phase == .accepted)
  #expect(current.transitionIndex == 7)
  #expect(throws: ReleasePackageError.self) {
    try store.transition(to: .failed, at: "2026-08-23T00:01:00Z", failureCode: "late")
  }
}

@Test func journalRefusesDowngradeAsOrdinaryUpdateAndPermitsExplicitRollback() throws {
  #expect(throws: ReleasePackageError.self) {
    try AcceptanceJournal(
      transactionID: UUID().uuidString,
      action: .update,
      prior: releaseReference("0.0.3"),
      target: releaseReference("0.0.2"),
      selectedOwnerUID: 501,
      createdAtUTC: "2026-08-23T00:00:00Z",
      updatedAtUTC: "2026-08-23T00:00:00Z"
    ).validate()
  }
  let rollback = AcceptanceJournal(
    transactionID: UUID().uuidString,
    action: .rollback,
    prior: try releaseReference("0.0.3", parentP5SHA256: String(repeating: "a", count: 64)),
    target: try releaseReference("0.0.2"),
    selectedOwnerUID: 501,
    createdAtUTC: "2026-08-23T00:00:00Z",
    updatedAtUTC: "2026-08-23T00:00:00Z")
  try rollback.validate()
}

@Test func journalFailureIsBoundedAndTerminal() throws {
  let prepared = AcceptanceJournal(
    transactionID: UUID().uuidString,
    action: .migrate,
    prior: nil,
    target: try releaseReference("0.0.2"),
    selectedOwnerUID: 501,
    createdAtUTC: "2026-08-23T00:00:00Z",
    updatedAtUTC: "2026-08-23T00:00:00Z")
  let failed = try prepared.transitioning(
    to: .failed, at: "2026-08-23T00:00:01Z", failureCode: "installer-refused")
  #expect(failed.failureCode == "installer-refused")
  #expect(throws: ReleasePackageError.self) {
    try failed.transitioning(to: .accepted, at: "2026-08-23T00:00:02Z")
  }
}
