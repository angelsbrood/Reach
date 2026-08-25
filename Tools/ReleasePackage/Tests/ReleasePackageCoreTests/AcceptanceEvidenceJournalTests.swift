import Foundation
import Testing

@testable import ReleasePackageCore

private let evidenceDigest = String(repeating: "a", count: 64)

private func cellEvidence(
  _ cell: AcceptanceCell,
  attempt: Int = 1,
  verdict: AcceptanceEvidenceVerdict = .pass
) -> AcceptanceCellEvidence {
  .init(
    cell: cell, attempt: attempt, verdict: verdict,
    privateEvidenceSHA256: evidenceDigest,
    redactedSummarySHA256: String(repeating: "b", count: 64))
}

private func completeEvidenceJournal() throws -> AcceptanceEvidenceJournal {
  var value = AcceptanceEvidenceJournal(
    runID: UUID().uuidString, rigJournalSHA256: evidenceDigest,
    createdAtUTC: "2026-08-23T00:00:00Z", updatedAtUTC: "2026-08-23T00:00:00Z")
  var tick = 0
  for cell in AcceptanceCell.allCases {
    for attempt in 1...(AcceptanceCell.completeMinimums[cell] ?? 0) {
      tick += 1
      value = try value.recording(
        cellEvidence(cell, attempt: attempt),
        at: "2026-08-23T00:00:\(String(format: "%02d", tick % 60))Z")
    }
  }
  return value
}

@Test func evidenceJournalRequiresTheCompleteMeasuredMatrixBeforeSuccess() throws {
  var value = try completeEvidenceJournal()
  value = try value.sealing(
    outcome: .complete, packManifestSHA256: String(repeating: "c", count: 64),
    packFileCount: 31, at: "2026-08-23T01:00:00Z")
  value = try value.bindingTeardownAuthority(
    sha256: String(repeating: "9", count: 64),
    at: "2026-08-23T01:00:00.5Z")
  for (phase, digest) in [
    (AcceptanceEvidencePhase.cloneDeleted, "d"),
    (.baseDeleted, "e"),
  ] {
    value = try value.advancingTeardown(
      to: phase, inventorySHA256: String(repeating: digest, count: 64),
      at: "2026-08-23T01:00:01Z")
  }
  value = try value.beginningAuthorityDestruction(
    to: .credentialsDestroying, at: "2026-08-23T01:00:01.1Z")
  value = try value.recordingAuthorityClaim(
    to: .credentialsClaimed, pathCount: 2,
    at: "2026-08-23T01:00:01.11Z")
  for count in 1...2 {
    value = try value.recordingAuthorityDeletion(
      kind: "credentials", deletedCount: count,
      at: "2026-08-23T01:00:01.1\(count + 1)Z")
  }
  value = try value.advancingTeardown(
    to: .credentialsDestroyed, inventorySHA256: String(repeating: "f", count: 64),
    at: "2026-08-23T01:00:01.2Z")
  value = try value.beginningAuthorityDestruction(
    to: .toolingRemoving, at: "2026-08-23T01:00:01.3Z")
  value = try value.recordingAuthorityClaim(
    to: .toolingClaimed, pathCount: 3,
    at: "2026-08-23T01:00:01.31Z")
  for count in 1...3 {
    value = try value.recordingAuthorityDeletion(
      kind: "tooling", deletedCount: count,
      at: "2026-08-23T01:00:01.3\(count + 1)Z")
  }
  value = try value.advancingTeardown(
    to: .toolingRemoved, inventorySHA256: String(repeating: "1", count: 64),
    at: "2026-08-23T01:00:01.4Z")
  value = try value.advancingTeardown(
    to: .complete, inventorySHA256: String(repeating: "2", count: 64),
    runtimeParitySHA256: String(repeating: "3", count: 64),
    at: "2026-08-23T01:00:02Z")
  #expect(value.phase == .complete)
  #expect(value.outcome == .complete)
}

@Test func evidenceJournalCannotHideMissingRepetitionsOrUseTheWrongStop() throws {
  var incomplete = AcceptanceEvidenceJournal(
    runID: UUID().uuidString, rigJournalSHA256: evidenceDigest,
    createdAtUTC: "now", updatedAtUTC: "now")
  incomplete = try incomplete.recording(cellEvidence(.rigReset), at: "later")
  #expect(throws: ReleasePackageError.self) {
    try incomplete.sealing(
      outcome: .complete, packManifestSHA256: evidenceDigest,
      packFileCount: 1, at: "later")
  }
  #expect(throws: ReleasePackageError.self) {
    try incomplete.sealing(
      outcome: .metalVM, packManifestSHA256: evidenceDigest,
      packFileCount: 1, at: "later")
  }

  var stopped = AcceptanceEvidenceJournal(
    runID: UUID().uuidString, rigJournalSHA256: evidenceDigest,
    createdAtUTC: "now", updatedAtUTC: "now")
  stopped = try stopped.recording(
    cellEvidence(.nativeMLX, verdict: .stop), at: "later")
  let sealed = try stopped.sealing(
    outcome: .metalVM, packManifestSHA256: evidenceDigest,
    packFileCount: 4, at: "later-still")
  #expect(sealed.outcome == .metalVM)
}

@Test func evidenceStoreIsCanonicalPrivateAndRefusesAttemptSubstitution() throws {
  let root = try makeTemporaryDirectory("evidence-journal")
  defer { removeTemporaryDirectory(root) }
  let store = AcceptanceEvidenceJournalStore(url: root.appendingPathComponent("journal.json"))
  var value = AcceptanceEvidenceJournal(
    runID: UUID().uuidString, rigJournalSHA256: evidenceDigest,
    createdAtUTC: "now", updatedAtUTC: "now")
  value = try value.recording(cellEvidence(.rigReset), at: "later")
  try store.create(value)
  #expect(try store.load() == value)
  let attributes = try FileManager.default.attributesOfItem(atPath: store.url.path)
  #expect((attributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o600)
  #expect(throws: ReleasePackageError.self) {
    try value.recording(cellEvidence(.rigReset, attempt: 3), at: "wrong")
  }
}
