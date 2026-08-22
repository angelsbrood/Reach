import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

private let notarySubmissionID = "12345678-1234-1234-1234-123456789abc"
private let notaryP3 = String(repeating: "a", count: 64)
private let notaryP3Verification = String(repeating: "9", count: 64)
private let notaryProfile = String(repeating: "b", count: 64)
private let notaryStart = "2026-08-22T00:00:00.000Z"
private let notaryNow = Date(timeIntervalSince1970: 1_787_360_400)

private func notaryJSON(_ value: Any) throws -> Data {
  try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
}

private func acceptedNotaryLog() throws -> Data {
  try notaryJSON([
    "jobId": notarySubmissionID,
    "sha256": notaryP3,
    "archiveFilename": "Reach-0.0.1-signed.pkg",
    "status": "Accepted",
    "statusCode": 0,
    "uploadDate": "2026-08-22T00:01:00.000Z",
    "issues": NSNull(),
  ])
}

private func preparedJournal() throws -> NotarizationJournal {
  try NotarizationStateMachine.prepared(
    p3SHA256: notaryP3,
    p3VerificationSHA256: notaryP3Verification,
    archiveName: "Reach-0.0.1-signed.pkg",
    profileBindingSHA256: notaryProfile,
    at: notaryStart)
}

@Test func notarytoolLocatesOnlyTheCurrentUsersLoginKeychain() {
  let environment = ReleaseNotarizer.notarytoolEnvironment()
  #expect(environment.keys.sorted() == ["HOME"])
  #expect(environment["HOME"] == FileManager.default.homeDirectoryForCurrentUser.path)
  #expect(ProcessRunner.notarytoolEnvironmentIsAllowed(environment))
}

@Test func notarizationJournalTransitionsAreExactAndNeverDuplicateSubmit() throws {
  let prepared = try preparedJournal()
  #expect(prepared.schemaVersion == 2)
  #expect(prepared.p3VerificationSHA256 == notaryP3Verification)
  #expect(try NotarizationStateMachine.nextAction(prepared, recoverSubmission: nil) == .submit)
  #expect(throws: ReleasePackageError.self) {
    try NotarizationStateMachine.nextAction(
      prepared, recoverSubmission: notarySubmissionID)
  }

  let submitting = try NotarizationStateMachine.submitting(prepared, at: notaryStart)
  #expect(throws: ReleasePackageError.self) {
    try NotarizationStateMachine.nextAction(submitting, recoverSubmission: nil)
  }
  #expect(
    try NotarizationStateMachine.nextAction(
      submitting, recoverSubmission: notarySubmissionID)
      == .recover(notarySubmissionID))

  let submitted = try NotarizationStateMachine.submitted(
    submitting,
    submissionID: notarySubmissionID,
    responseSHA256: String(repeating: "c", count: 64))
  #expect(
    try NotarizationStateMachine.nextAction(submitted, recoverSubmission: nil)
      == .wait(notarySubmissionID))
  #expect(throws: ReleasePackageError.self) {
    try NotarizationStateMachine.nextAction(
      submitted, recoverSubmission: notarySubmissionID)
  }

  let accepted = try NotarizationStateMachine.accepted(
    submitted,
    acceptedAtUTC: "2026-08-22T00:05:00.000Z",
    waitResponseSHA256: String(repeating: "d", count: 64),
    notaryLogSHA256: String(repeating: "e", count: 64))
  #expect(try NotarizationStateMachine.nextAction(accepted, recoverSubmission: nil) == .staple)
  let stapled = try NotarizationStateMachine.stapled(
    accepted, p5SHA256: String(repeating: "f", count: 64))
  #expect(try NotarizationStateMachine.nextAction(stapled, recoverSubmission: nil) == .finished)
  #expect(throws: ReleasePackageError.self) {
    try NotarizationStateMachine.submitting(submitted, at: notaryStart)
  }
  #expect(throws: ReleasePackageError.self) {
    try NotarizationStateMachine.stapled(submitted, p5SHA256: String(repeating: "f", count: 64))
  }
}

@Test func fakeNotaryResponsesBindUUIDHashArchiveWindowAndNullOrEmptyIssues() throws {
  let validator = NotarizationResponseValidator()
  let submit = try notaryJSON(["id": notarySubmissionID, "status": "In Progress"])
  #expect(try validator.submissionID(from: submit) == notarySubmissionID)
  #expect(throws: ReleasePackageError.self) {
    try validator.submissionID(from: try notaryJSON(["id": "not-a-uuid"]))
  }

  let wait = try notaryJSON(["id": notarySubmissionID, "status": "Accepted"])
  try validator.requireAcceptedWait(wait, submissionID: notarySubmissionID)
  #expect(throws: ReleasePackageError.self) {
    try validator.requireAcceptedWait(
      try notaryJSON(["id": notarySubmissionID, "status": "Invalid"]),
      submissionID: notarySubmissionID)
  }

  let base: [String: Any] = [
    "jobId": notarySubmissionID,
    "sha256": notaryP3,
    "archiveFilename": "Reach-0.0.1-signed.pkg",
    "status": "Accepted",
    "statusCode": 0,
    "uploadDate": "2026-08-22T00:01:00.000Z",
    "issues": NSNull(),
  ]
  _ = try validator.requireAcceptedLog(
    try notaryJSON(base),
    submissionID: notarySubmissionID,
    p3SHA256: notaryP3,
    archiveName: "Reach-0.0.1-signed.pkg",
    startedAtUTC: notaryStart,
    now: notaryNow)
  var missingIssues = base
  missingIssues.removeValue(forKey: "issues")
  #expect(throws: ReleasePackageError.self) {
    try validator.requireAcceptedLog(
      try notaryJSON(missingIssues),
      submissionID: notarySubmissionID,
      p3SHA256: notaryP3,
      archiveName: "Reach-0.0.1-signed.pkg",
      startedAtUTC: notaryStart,
      now: notaryNow)
  }
  var emptyIssues = base
  emptyIssues["issues"] = []
  _ = try validator.requireAcceptedLog(
    try notaryJSON(emptyIssues),
    submissionID: notarySubmissionID,
    p3SHA256: notaryP3,
    archiveName: "Reach-0.0.1-signed.pkg",
    startedAtUTC: notaryStart,
    now: notaryNow)

  let mutations: [(inout [String: Any]) -> Void] = [
    { (value: inout [String: Any]) in value["jobId"] = UUID().uuidString },
    { (value: inout [String: Any]) in value["sha256"] = String(repeating: "0", count: 64) },
    { (value: inout [String: Any]) in value["archiveFilename"] = "other.pkg" },
    { (value: inout [String: Any]) in value["status"] = "Invalid" },
    { (value: inout [String: Any]) in value["statusCode"] = 4000 },
    { (value: inout [String: Any]) in value["issues"] = [["message": "bad"]] },
    { (value: inout [String: Any]) in value["uploadDate"] = "2026-08-21T00:00:00.000Z" },
  ]
  for mutation in mutations {
    var changed = base
    mutation(&changed)
    #expect(throws: ReleasePackageError.self) {
      try validator.requireAcceptedLog(
        try notaryJSON(changed),
        submissionID: notarySubmissionID,
        p3SHA256: notaryP3,
        archiveName: "Reach-0.0.1-signed.pkg",
        startedAtUTC: notaryStart,
        now: notaryNow)
    }
  }
}

@Test func journalStoreIsCanonicalModeBoundAndExclusivelyLocked() throws {
  let root = try makeTemporaryDirectory("notary-journal")
  defer { removeTemporaryDirectory(root) }
  let url = root.appendingPathComponent("journal.json")
  let store = NotarizationJournalStore(url: url)
  let prepared = try preparedJournal()
  try store.write(prepared)
  #expect(try store.load() == prepared)
  var info = stat()
  #expect(lstat(url.path, &info) == 0)
  #expect((info.st_mode & 0o7777) == 0o600)

  _ = try store.withExclusiveLock {
    #expect(throws: ReleasePackageError.self) {
      try store.withExclusiveLock { () }
    }
  }
  #expect(chmod(url.path, 0o644) == 0)
  #expect(throws: ReleasePackageError.self) { try store.load() }
}

@Test func journalBindsTheCompleteP3VerificationBeforeSubmission() throws {
  let prepared = try preparedJournal()
  let submitting = try NotarizationStateMachine.submitting(prepared, at: notaryStart)
  let submitted = try NotarizationStateMachine.submitted(
    submitting,
    submissionID: notarySubmissionID,
    responseSHA256: String(repeating: "c", count: 64))
  for value in [prepared, submitting, submitted] {
    #expect(value.schemaVersion == 2)
    #expect(value.p3SHA256 == notaryP3)
    #expect(value.p3VerificationSHA256 == notaryP3Verification)
  }

  let legacy = NotarizationJournal(
    schemaVersion: 1,
    phase: .prepared,
    p3SHA256: notaryP3,
    archiveName: "Reach-0.0.1-signed.pkg",
    profileBindingSHA256: notaryProfile,
    preparedAtUTC: notaryStart)
  try legacy.validate()
  #expect(throws: ReleasePackageError.self) {
    try NotarizationStateMachine.nextAction(legacy, recoverSubmission: nil)
  }
}

@Test func acceptedNotaryArtifactsRecoverIdempotentlyAfterTheLogWriteCrashWindow() throws {
  let root = try makeTemporaryDirectory("accepted-notary-recovery")
  defer { removeTemporaryDirectory(root) }
  let waitURL = root.appendingPathComponent("accepted-wait-response.json")
  let logURL = root.appendingPathComponent("accepted-notary-log.json")
  try SecureFiles.atomicWrite(
    try notaryJSON(["id": notarySubmissionID, "status": "Accepted"]), to: waitURL)
  try SecureFiles.atomicWrite(try acceptedNotaryLog(), to: logURL)

  let first = try ReleaseNotarizer.validateAcceptedArtifacts(
    waitURL: waitURL,
    logURL: logURL,
    submissionID: notarySubmissionID,
    p3SHA256: notaryP3,
    archiveName: "Reach-0.0.1-signed.pkg",
    startedAtUTC: notaryStart)
  let second = try ReleaseNotarizer.validateAcceptedArtifacts(
    waitURL: waitURL,
    logURL: logURL,
    submissionID: notarySubmissionID,
    p3SHA256: notaryP3,
    archiveName: "Reach-0.0.1-signed.pkg",
    startedAtUTC: notaryStart)
  #expect(first.waitResponseSHA256 == second.waitResponseSHA256)
  #expect(first.notaryLogSHA256 == second.notaryLogSHA256)

  let submitted = try NotarizationStateMachine.submitted(
    NotarizationStateMachine.submitting(try preparedJournal(), at: notaryStart),
    submissionID: notarySubmissionID,
    responseSHA256: String(repeating: "c", count: 64))
  let accepted = try NotarizationStateMachine.accepted(
    submitted,
    acceptedAtUTC: "2026-08-22T00:05:00.000Z",
    waitResponseSHA256: first.waitResponseSHA256,
    notaryLogSHA256: first.notaryLogSHA256)
  #expect(accepted.phase == .accepted)

  var corrupted = try acceptedNotaryLog()
  corrupted[corrupted.index(before: corrupted.endIndex)] ^= 0x01
  try SecureFiles.atomicWrite(corrupted, to: logURL)
  #expect(throws: ReleasePackageError.self) {
    try ReleaseNotarizer.validateAcceptedArtifacts(
      waitURL: waitURL,
      logURL: logURL,
      submissionID: notarySubmissionID,
      p3SHA256: notaryP3,
      archiveName: "Reach-0.0.1-signed.pkg",
      startedAtUTC: notaryStart)
  }
}
