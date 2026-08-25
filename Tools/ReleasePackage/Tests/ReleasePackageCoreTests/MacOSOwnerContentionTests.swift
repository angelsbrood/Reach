import Foundation
import Testing

@testable import ReleasePackageCore

@Test func ownerContentionJournalRequiresCanonicalOrderedPhases() throws {
  let digest = String(repeating: "c", count: 64)
  let primary = OwnerContentionJournal(
    packageSHA256: digest,
    primaryUID: 501,
    contenderUID: 502,
    primaryAuthoritySHA256: digest,
    phase: .primaryRecorded)
  try primary.validate()

  for phase in OwnerContentionPhase.allCases {
    let active = phase == .contenderActive
    let resolved = phase != .primaryRecorded
    let journal = OwnerContentionJournal(
      packageSHA256: digest,
      primaryUID: 501,
      contenderUID: 502,
      primaryAuthoritySHA256: digest,
      phase: phase,
      contenderServiceLoaded: resolved ? active : nil,
      contenderStatePresent: resolved ? active : nil,
      contenderCACreationCount: resolved ? (active ? 1 : 0) : nil)
    try journal.validate()
    let encoded = try CanonicalJSON.encode(journal)
    #expect(try JSONDecoder().decode(OwnerContentionJournal.self, from: encoded) == journal)
  }
}

@Test func ownerContentionJournalRejectsForgedAuthorityAndUsers() throws {
  let digest = String(repeating: "d", count: 64)
  let invalid = [
    OwnerContentionJournal(
      packageSHA256: "short", primaryUID: 501, contenderUID: 502,
      primaryAuthoritySHA256: digest, phase: .primaryRecorded),
    OwnerContentionJournal(
      packageSHA256: digest, primaryUID: 0, contenderUID: 502,
      primaryAuthoritySHA256: digest, phase: .primaryRecorded),
    OwnerContentionJournal(
      packageSHA256: digest, primaryUID: 501, contenderUID: 501,
      primaryAuthoritySHA256: digest, phase: .primaryRecorded),
  ]
  for journal in invalid {
    #expect(throws: ReleasePackageError.self) { try journal.validate() }
  }
}

@Test func ownerContentionReportSeparatesPassFromFounderStop() throws {
  let digest = String(repeating: "a", count: 64)
  let pass = OwnerContentionReport(
    packageSHA256: digest, primaryAuthoritySHA256: digest,
    primaryAuthorityPreserved: true, contenderServiceLoaded: false,
    contenderStatePresent: false, contenderCACreationCount: 0)
  try pass.validate()
  #expect(pass.verdict == "pass")

  let active = OwnerContentionReport(
    packageSHA256: digest, primaryAuthoritySHA256: digest,
    primaryAuthorityPreserved: true, contenderServiceLoaded: true,
    contenderStatePresent: true, contenderCACreationCount: 1)
  try active.validate()
  #expect(active.verdict == "owner-contention-stop")
}

@Test func ownerContentionReportCannotHidePrimaryDriftOrSecondAuthority() throws {
  let digest = String(repeating: "b", count: 64)
  let drift = OwnerContentionReport(
    packageSHA256: digest, primaryAuthoritySHA256: digest,
    primaryAuthorityPreserved: false, contenderServiceLoaded: false,
    contenderStatePresent: false, contenderCACreationCount: 0)
  #expect(throws: ReleasePackageError.self) { try drift.validate() }

  let encoded = try CanonicalJSON.encode(
    OwnerContentionReport(
      packageSHA256: digest, primaryAuthoritySHA256: digest,
      primaryAuthorityPreserved: true, contenderServiceLoaded: false,
      contenderStatePresent: true, contenderCACreationCount: 1))
  var object = try #require(
    JSONSerialization.jsonObject(with: encoded) as? [String: Any])
  object["verdict"] = "pass"
  let forged = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  let value = try JSONDecoder().decode(OwnerContentionReport.self, from: forged)
  #expect(throws: ReleasePackageError.self) { try value.validate() }
}

@Test func unrelatedDefinitionOrBootstrapFailureCannotBecomeContentionRefusal() throws {
  let success = CommandResult(
    exitStatus: 0, output: "", errorOutput: "", elapsedMilliseconds: 1)
  let failure = CommandResult(
    exitStatus: 77, output: "", errorOutput: "synthetic failure", elapsedMilliseconds: 1)
  try MacOSOwnerContentionProbe.requireDefinitionInstalled(success)
  try MacOSOwnerContentionProbe.requireBootstrapSucceeded(success)
  #expect(throws: ReleasePackageError.self) {
    try MacOSOwnerContentionProbe.requireDefinitionInstalled(failure)
  }
  #expect(throws: ReleasePackageError.self) {
    try MacOSOwnerContentionProbe.requireBootstrapSucceeded(failure)
  }
}

@Test func attributableApplicationRefusalCompletesBeginCheckFinishStateMachine() throws {
  let digest = String(repeating: "e", count: 64)
  var journal = OwnerContentionJournal(
    packageSHA256: digest, primaryUID: 501, contenderUID: 502,
    primaryAuthoritySHA256: digest, phase: .primaryRecorded)
  let decision = try MacOSOwnerContentionProbe.classify(
    .init(
      jobLoaded: true, processRunning: false, runCount: 1,
      lastExitStatus: 78, statePresent: false, caCreationCount: 0,
      log: MacOSOwnerContentionProbe.selectedOwnerRefusalLine + "\n"))
  #expect(decision == .refused)
  journal = try journal.recording(
    decision, contenderServiceLoaded: false,
    contenderStatePresent: false, contenderCACreationCount: 0)
  #expect(journal.phase == .contenderRefused)
  journal = try journal.restoringPrimary()
  #expect(journal.phase == .primaryRestored)
  try journal.validate()
}

@Test func nonattributableApplicationFailureCannotBecomeContentionRefusal() throws {
  #expect(throws: ReleasePackageError.self) {
    try MacOSOwnerContentionProbe.classify(
      .init(
        jobLoaded: true, processRunning: false, runCount: 1,
        lastExitStatus: 78, statePresent: false, caCreationCount: 0,
        log: "synthetic unrelated failure\n"))
  }
  #expect(
    try MacOSOwnerContentionProbe.classify(
      .init(
        jobLoaded: true, processRunning: true, runCount: 1,
        lastExitStatus: nil, statePresent: false, caCreationCount: 0,
        log: "")) == .active)
}

@Test func transientRunningContenderDoesNotSettleBeforeItsFinalDecision() throws {
  #expect(
    !MacOSOwnerContentionProbe.applicationDecisionSettled(
      processRunning: true, runCount: 1, lastExitStatus: nil,
      statePresent: false))
  #expect(
    MacOSOwnerContentionProbe.applicationDecisionSettled(
      processRunning: false, runCount: 1, lastExitStatus: 78,
      statePresent: false))
  #expect(
    MacOSOwnerContentionProbe.applicationDecisionSettled(
      processRunning: true, runCount: 1, lastExitStatus: nil,
      statePresent: true))
}

@Test func contenderRefusalRequiresFreshPostBootoutAbsence() throws {
  try MacOSOwnerContentionProbe.requireSettledRefusal(
    .init(
      present: false, ownerUID: nil, itemCount: 0,
      authoritySHA256: nil, caCreationCount: 0))
  #expect(throws: ReleasePackageError.self) {
    try MacOSOwnerContentionProbe.requireSettledRefusal(
      .init(
        present: true, ownerUID: 502, itemCount: 1,
        authoritySHA256: String(repeating: "a", count: 64),
        caCreationCount: 1))
  }
}
