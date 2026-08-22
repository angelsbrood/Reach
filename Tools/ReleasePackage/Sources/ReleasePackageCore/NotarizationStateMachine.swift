import Foundation

enum NotarizationStateMachine {
  enum NextAction: Equatable {
    case submit
    case recover(String)
    case wait(String)
    case staple
    case finished
  }

  static func nextAction(
    _ current: NotarizationJournal,
    recoverSubmission: String?
  ) throws -> NextAction {
    try current.validate()
    if current.schemaVersion == 1, current.phase != .accepted, current.phase != .stapled {
      throw ReleasePackageError.verification(
        "legacy notarization journal lacks complete P3 preflight authority")
    }
    if let recoverSubmission {
      guard current.phase == .submitting, UUID(uuidString: recoverSubmission) != nil else {
        throw ReleasePackageError.invalidArgument(
          "--recover-submission is legal only for an ambiguous submitting journal")
      }
      return .recover(recoverSubmission)
    }
    switch current.phase {
    case .prepared: return .submit
    case .submitting:
      throw ReleasePackageError.verification(
        "submission lineage is ambiguous; recover its UUID explicitly and do not resubmit")
    case .submitted:
      guard let submissionID = current.submissionID else {
        throw ReleasePackageError.verification("submitted lineage has no durable UUID")
      }
      return .wait(submissionID)
    case .accepted: return .staple
    case .stapled: return .finished
    }
  }

  static func prepared(
    p3SHA256: String,
    p3VerificationSHA256: String,
    archiveName: String,
    profileBindingSHA256: String,
    at timestamp: String
  ) throws -> NotarizationJournal {
    let value = NotarizationJournal(
      schemaVersion: 2,
      phase: .prepared,
      p3SHA256: p3SHA256,
      p3VerificationSHA256: p3VerificationSHA256,
      archiveName: archiveName,
      profileBindingSHA256: profileBindingSHA256,
      preparedAtUTC: timestamp)
    try value.validate()
    return value
  }

  static func submitting(_ current: NotarizationJournal, at timestamp: String) throws
    -> NotarizationJournal
  {
    guard current.phase == .prepared else {
      throw ReleasePackageError.verification("only a prepared lineage may submit")
    }
    let value = NotarizationJournal(
      schemaVersion: current.schemaVersion,
      phase: .submitting,
      p3SHA256: current.p3SHA256,
      p3VerificationSHA256: current.p3VerificationSHA256,
      archiveName: current.archiveName,
      profileBindingSHA256: current.profileBindingSHA256,
      preparedAtUTC: current.preparedAtUTC,
      submissionStartedAtUTC: timestamp)
    try value.validate()
    return value
  }

  static func submitted(
    _ current: NotarizationJournal,
    submissionID: String,
    responseSHA256: String
  ) throws -> NotarizationJournal {
    guard current.phase == .submitting, UUID(uuidString: submissionID) != nil else {
      throw ReleasePackageError.verification("submission identity cannot bind this lineage")
    }
    let value = NotarizationJournal(
      schemaVersion: current.schemaVersion,
      phase: .submitted,
      p3SHA256: current.p3SHA256,
      p3VerificationSHA256: current.p3VerificationSHA256,
      archiveName: current.archiveName,
      profileBindingSHA256: current.profileBindingSHA256,
      preparedAtUTC: current.preparedAtUTC,
      submissionStartedAtUTC: current.submissionStartedAtUTC,
      submissionID: submissionID,
      submissionEvidenceSHA256: responseSHA256)
    try value.validate()
    return value
  }

  static func accepted(
    _ current: NotarizationJournal,
    acceptedAtUTC: String,
    waitResponseSHA256: String,
    notaryLogSHA256: String
  ) throws -> NotarizationJournal {
    guard current.phase == .submitted else {
      throw ReleasePackageError.verification("only a submitted lineage may become accepted")
    }
    let value = NotarizationJournal(
      schemaVersion: current.schemaVersion,
      phase: .accepted,
      p3SHA256: current.p3SHA256,
      p3VerificationSHA256: current.p3VerificationSHA256,
      archiveName: current.archiveName,
      profileBindingSHA256: current.profileBindingSHA256,
      preparedAtUTC: current.preparedAtUTC,
      submissionStartedAtUTC: current.submissionStartedAtUTC,
      submissionID: current.submissionID,
      submissionEvidenceSHA256: current.submissionEvidenceSHA256,
      acceptedAtUTC: acceptedAtUTC,
      waitResponseSHA256: waitResponseSHA256,
      notaryLogSHA256: notaryLogSHA256)
    try value.validate()
    return value
  }

  static func stapled(_ current: NotarizationJournal, p5SHA256: String) throws
    -> NotarizationJournal
  {
    guard current.phase == .accepted else {
      throw ReleasePackageError.verification("only an accepted lineage may be stapled")
    }
    let value = NotarizationJournal(
      schemaVersion: current.schemaVersion,
      phase: .stapled,
      p3SHA256: current.p3SHA256,
      p3VerificationSHA256: current.p3VerificationSHA256,
      archiveName: current.archiveName,
      profileBindingSHA256: current.profileBindingSHA256,
      preparedAtUTC: current.preparedAtUTC,
      submissionStartedAtUTC: current.submissionStartedAtUTC,
      submissionID: current.submissionID,
      submissionEvidenceSHA256: current.submissionEvidenceSHA256,
      acceptedAtUTC: current.acceptedAtUTC,
      waitResponseSHA256: current.waitResponseSHA256,
      notaryLogSHA256: current.notaryLogSHA256,
      p5SHA256: p5SHA256)
    try value.validate()
    return value
  }
}
