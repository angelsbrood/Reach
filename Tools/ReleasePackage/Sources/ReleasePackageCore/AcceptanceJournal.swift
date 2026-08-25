import Foundation

public enum AcceptanceTransactionAction: String, Codable, CaseIterable, Sendable {
  case install
  case migrate
  case update
  case rollback
  case uninstall
  case verify
}

public enum AcceptanceTransactionPhase: String, Codable, CaseIterable, Sendable {
  case prepared
  case priorStopped
  case installerStarted
  case payloadVerified
  case helperReconciled
  case hostStarted
  case runtimeVerified
  case accepted
  case rolledBack
  case uninstalled
  case failed
}

public struct AcceptanceReleaseReference: Codable, Equatable, Sendable {
  public let versions: ReleaseVersionMap
  public let p5SHA256: String
  public let provenanceSHA256: String
  public let parentP5SHA256: String?

  public init(
    versions: ReleaseVersionMap, p5SHA256: String, provenanceSHA256: String,
    parentP5SHA256: String? = nil
  ) {
    self.versions = versions
    self.p5SHA256 = p5SHA256
    self.provenanceSHA256 = provenanceSHA256
    self.parentP5SHA256 = parentP5SHA256
  }

  public func validate() throws {
    guard Self.validSHA256(p5SHA256), Self.validSHA256(provenanceSHA256),
      parentP5SHA256 == nil || Self.validSHA256(parentP5SHA256!)
    else {
      throw ReleasePackageError.verification("acceptance release authority is malformed")
    }
  }

  private static func validSHA256(_ value: String) -> Bool {
    value.count == 64 && value.allSatisfy(\.isHexDigit)
  }
}

public struct AcceptanceJournal: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let transactionID: String
  public let action: AcceptanceTransactionAction
  public let prior: AcceptanceReleaseReference?
  public let target: AcceptanceReleaseReference?
  public let selectedOwnerUID: UInt32
  public let phase: AcceptanceTransactionPhase
  public let transitionIndex: UInt32
  public let createdAtUTC: String
  public let updatedAtUTC: String
  public let failureCode: String?

  public init(
    schemaVersion: Int = 1,
    transactionID: String,
    action: AcceptanceTransactionAction,
    prior: AcceptanceReleaseReference?,
    target: AcceptanceReleaseReference?,
    selectedOwnerUID: UInt32,
    phase: AcceptanceTransactionPhase = .prepared,
    transitionIndex: UInt32 = 0,
    createdAtUTC: String,
    updatedAtUTC: String,
    failureCode: String? = nil
  ) {
    self.schemaVersion = schemaVersion
    self.transactionID = transactionID
    self.action = action
    self.prior = prior
    self.target = target
    self.selectedOwnerUID = selectedOwnerUID
    self.phase = phase
    self.transitionIndex = transitionIndex
    self.createdAtUTC = createdAtUTC
    self.updatedAtUTC = updatedAtUTC
    self.failureCode = failureCode
  }

  public func validate() throws {
    guard schemaVersion == 1, UUID(uuidString: transactionID) != nil,
      selectedOwnerUID != 0, !createdAtUTC.isEmpty, !updatedAtUTC.isEmpty,
      (phase == .failed) == (failureCode != nil),
      failureCode?.range(of: "^[a-z0-9-]{1,64}$", options: .regularExpression) != nil
        || failureCode == nil
    else {
      throw ReleasePackageError.verification("acceptance journal authority is malformed")
    }
    try prior?.validate()
    try target?.validate()
    switch action {
    case .install, .migrate:
      guard prior == nil, target != nil else {
        throw ReleasePackageError.verification(
          "first-install journal release authority changed")
      }
    case .update, .rollback:
      guard let prior, let target, prior != target else {
        throw ReleasePackageError.verification("update journal requires two distinct releases")
      }
      if action == .update {
        guard prior.versions.product < target.versions.product,
          target.parentP5SHA256 == prior.p5SHA256
        else {
          throw ReleasePackageError.verification("ordinary update is not monotonic")
        }
      } else {
        guard target.versions.product < prior.versions.product,
          prior.parentP5SHA256 == target.p5SHA256
        else {
          throw ReleasePackageError.verification(
            "explicit rollback does not select an older parent")
        }
      }
    case .uninstall:
      guard prior != nil, target == nil else {
        throw ReleasePackageError.verification("uninstall journal authority changed")
      }
    case .verify:
      guard prior == nil, target != nil else {
        throw ReleasePackageError.verification("verification journal authority changed")
      }
    }
    guard Self.allowedPhases(for: action).contains(phase) else {
      throw ReleasePackageError.verification("acceptance phase is invalid for its action")
    }
  }

  public func transitioning(
    to next: AcceptanceTransactionPhase,
    at timestamp: String,
    failureCode: String? = nil
  ) throws -> Self {
    try validate()
    guard !timestamp.isEmpty, !Self.terminalPhases.contains(phase) else {
      throw ReleasePackageError.verification("acceptance transaction is already terminal")
    }
    let validNext: Bool
    if next == .failed {
      validNext = failureCode != nil
    } else {
      let sequence = Self.sequence(for: action)
      guard let currentIndex = sequence.firstIndex(of: phase) else {
        throw ReleasePackageError.verification("acceptance journal phase is not resumable")
      }
      validNext =
        sequence.index(after: currentIndex) < sequence.endIndex
        && sequence[sequence.index(after: currentIndex)] == next
        && failureCode == nil
    }
    guard validNext else {
      throw ReleasePackageError.verification("acceptance journal transition is invalid")
    }
    let value = Self(
      schemaVersion: schemaVersion,
      transactionID: transactionID,
      action: action,
      prior: prior,
      target: target,
      selectedOwnerUID: selectedOwnerUID,
      phase: next,
      transitionIndex: transitionIndex + 1,
      createdAtUTC: createdAtUTC,
      updatedAtUTC: timestamp,
      failureCode: failureCode)
    try value.validate()
    return value
  }

  public static func sequence(
    for action: AcceptanceTransactionAction
  ) -> [AcceptanceTransactionPhase] {
    switch action {
    case .install, .migrate, .update:
      return [
        .prepared, .priorStopped, .installerStarted, .payloadVerified,
        .helperReconciled, .hostStarted, .runtimeVerified, .accepted,
      ]
    case .rollback:
      return [
        .prepared, .priorStopped, .installerStarted, .payloadVerified,
        .helperReconciled, .hostStarted, .runtimeVerified, .rolledBack,
      ]
    case .uninstall:
      return [.prepared, .priorStopped, .installerStarted, .payloadVerified, .uninstalled]
    case .verify:
      return [.prepared, .accepted]
    }
  }

  private static func allowedPhases(
    for action: AcceptanceTransactionAction
  ) -> Set<AcceptanceTransactionPhase> {
    Set(sequence(for: action) + [.failed])
  }

  private static let terminalPhases: Set<AcceptanceTransactionPhase> = [
    .accepted, .rolledBack, .uninstalled, .failed,
  ]
}
