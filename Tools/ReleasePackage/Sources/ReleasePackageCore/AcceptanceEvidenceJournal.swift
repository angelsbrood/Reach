import Darwin
import Foundation

public enum AcceptanceEvidenceVerdict: String, Codable, Sendable {
  case pass
  case refused
  case stop
}

public enum AcceptanceCloseoutOutcome: String, Codable, Sendable {
  case complete
  case mandatoryChoice = "mandatory-choice"
  case ownerContention = "owner-contention"
  case metalVM = "metal-vm"
  case rollbackSemantics = "rollback-semantics"
  case failed
}

public enum AcceptanceEvidencePhase: String, Codable, Sendable {
  case collecting
  case sealed
  case cloneDeleted = "clone-deleted"
  case baseDeleted = "base-deleted"
  case credentialsDestroying = "credentials-destroying"
  case credentialsClaimed = "credentials-claimed"
  case credentialsDestroyed = "credentials-destroyed"
  case toolingRemoving = "tooling-removing"
  case toolingClaimed = "tooling-claimed"
  case toolingRemoved = "tooling-removed"
  case complete
  case failed
}

public enum AcceptanceCell: String, Codable, CaseIterable, Sendable {
  case rigReset = "rig-reset"
  case staticTrust = "static-trust"
  case defaultInstall = "default-install"
  case mandatoryDeselection = "mandatory-deselection"
  case preloginReboot = "prelogin-reboot"
  case loginOwner = "login-owner"
  case ownerContention = "owner-contention"
  case nativeMLX = "native-mlx"
  case authenticatedDial = "authenticated-dial"
  case directMesh = "direct-mesh"
  case migration = "migration"
  case collisionRefusal = "collision-refusal"
  case ordinaryUpdate = "ordinary-update"
  case interruptBeforeInstaller = "interrupt-before-installer"
  case interruptDuringInstaller = "interrupt-during-installer"
  case interruptAfterPayload = "interrupt-after-payload"
  case interruptAfterHelper = "interrupt-after-helper"
  case incompatibleRefusal = "incompatible-refusal"
  case downgradeRefusal = "downgrade-refusal"
  case explicitRollback = "explicit-rollback"
  case reupdate = "reupdate"
  case logoutLogin = "logout-login"
  case daemonCrash = "daemon-crash"
  case helperCrash = "helper-crash"
  case lifecycleReboot = "lifecycle-reboot"
  case lateMesh = "late-mesh"
  case tamperRefusal = "tamper-refusal"
  case uninstall = "uninstall"
  case retainedReinstall = "retained-reinstall"
  case regressions = "regressions"

  static let completeMinimums: [Self: Int] = [
    .rigReset: 3,
    .staticTrust: 1,
    .defaultInstall: 1,
    .mandatoryDeselection: 1,
    .preloginReboot: 1,
    .loginOwner: 1,
    .ownerContention: 1,
    .nativeMLX: 1,
    .authenticatedDial: 1,
    .directMesh: 1,
    .migration: 1,
    .collisionRefusal: 1,
    .ordinaryUpdate: 1,
    .interruptBeforeInstaller: 3,
    .interruptDuringInstaller: 3,
    .interruptAfterPayload: 3,
    .interruptAfterHelper: 3,
    .incompatibleRefusal: 1,
    .downgradeRefusal: 1,
    .explicitRollback: 1,
    .reupdate: 1,
    .logoutLogin: 2,
    .daemonCrash: 3,
    .helperCrash: 3,
    .lifecycleReboot: 2,
    .lateMesh: 1,
    .tamperRefusal: 1,
    .uninstall: 1,
    .retainedReinstall: 1,
    .regressions: 1,
  ]
}

public struct AcceptanceCellEvidence: Codable, Equatable, Sendable {
  public let cell: AcceptanceCell
  public let attempt: Int
  public let verdict: AcceptanceEvidenceVerdict
  public let privateEvidenceSHA256: String
  public let redactedSummarySHA256: String
  public let guestJournalSHA256: String?

  public init(
    cell: AcceptanceCell,
    attempt: Int,
    verdict: AcceptanceEvidenceVerdict,
    privateEvidenceSHA256: String,
    redactedSummarySHA256: String,
    guestJournalSHA256: String? = nil
  ) {
    self.cell = cell
    self.attempt = attempt
    self.verdict = verdict
    self.privateEvidenceSHA256 = privateEvidenceSHA256
    self.redactedSummarySHA256 = redactedSummarySHA256
    self.guestJournalSHA256 = guestJournalSHA256
  }

  public func validate() throws {
    guard (1...32).contains(attempt), Self.validSHA256(privateEvidenceSHA256),
      Self.validSHA256(redactedSummarySHA256),
      guestJournalSHA256 == nil || Self.validSHA256(guestJournalSHA256!)
    else {
      throw ReleasePackageError.verification("acceptance cell evidence is malformed")
    }
  }

  private static func validSHA256(_ value: String) -> Bool {
    value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
  }
}

/// Privacy-safe host evidence and teardown authority. Raw logs stay in the
/// disposable private roots named by their hashes; this journal contains no
/// paths, users, endpoints, package contents, model data, or credentials.
public struct AcceptanceEvidenceJournal: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let runID: String
  public let rigJournalSHA256: String
  public let phase: AcceptanceEvidencePhase
  public let transitionIndex: UInt32
  public let records: [AcceptanceCellEvidence]
  public let outcome: AcceptanceCloseoutOutcome?
  public let packManifestSHA256: String?
  public let packFileCount: Int?
  public let teardownAuthoritySHA256: String?
  public let cloneInventorySHA256: String?
  public let baseInventorySHA256: String?
  public let credentialClaimedPathCount: Int?
  public let credentialDeletionCount: Int?
  public let credentialInventorySHA256: String?
  public let toolingClaimedPathCount: Int?
  public let toolingDeletionCount: Int?
  public let toolingInventorySHA256: String?
  public let finalInventorySHA256: String?
  public let runtimeParitySHA256: String?
  public let createdAtUTC: String
  public let updatedAtUTC: String
  public let failureCode: String?

  public init(
    runID: String,
    rigJournalSHA256: String,
    createdAtUTC: String,
    updatedAtUTC: String
  ) {
    schemaVersion = 2
    self.runID = runID
    self.rigJournalSHA256 = rigJournalSHA256
    phase = .collecting
    transitionIndex = 0
    records = []
    outcome = nil
    packManifestSHA256 = nil
    packFileCount = nil
    teardownAuthoritySHA256 = nil
    cloneInventorySHA256 = nil
    baseInventorySHA256 = nil
    credentialClaimedPathCount = nil
    credentialDeletionCount = nil
    credentialInventorySHA256 = nil
    toolingClaimedPathCount = nil
    toolingDeletionCount = nil
    toolingInventorySHA256 = nil
    finalInventorySHA256 = nil
    runtimeParitySHA256 = nil
    self.createdAtUTC = createdAtUTC
    self.updatedAtUTC = updatedAtUTC
    failureCode = nil
  }

  private init(
    copying current: Self,
    phase: AcceptanceEvidencePhase,
    records: [AcceptanceCellEvidence]? = nil,
    outcome: AcceptanceCloseoutOutcome? = nil,
    packManifestSHA256: String? = nil,
    packFileCount: Int? = nil,
    teardownAuthoritySHA256: String? = nil,
    cloneInventorySHA256: String? = nil,
    baseInventorySHA256: String? = nil,
    credentialClaimedPathCount: Int? = nil,
    credentialDeletionCount: Int? = nil,
    credentialInventorySHA256: String? = nil,
    toolingClaimedPathCount: Int? = nil,
    toolingDeletionCount: Int? = nil,
    toolingInventorySHA256: String? = nil,
    finalInventorySHA256: String? = nil,
    runtimeParitySHA256: String? = nil,
    updatedAtUTC: String,
    failureCode: String? = nil
  ) {
    schemaVersion = current.schemaVersion
    runID = current.runID
    rigJournalSHA256 = current.rigJournalSHA256
    self.phase = phase
    transitionIndex = current.transitionIndex + 1
    self.records = records ?? current.records
    self.outcome = outcome ?? current.outcome
    self.packManifestSHA256 = packManifestSHA256 ?? current.packManifestSHA256
    self.packFileCount = packFileCount ?? current.packFileCount
    self.teardownAuthoritySHA256 =
      teardownAuthoritySHA256 ?? current.teardownAuthoritySHA256
    self.cloneInventorySHA256 = cloneInventorySHA256 ?? current.cloneInventorySHA256
    self.baseInventorySHA256 = baseInventorySHA256 ?? current.baseInventorySHA256
    self.credentialClaimedPathCount =
      credentialClaimedPathCount ?? current.credentialClaimedPathCount
    self.credentialDeletionCount =
      credentialDeletionCount ?? current.credentialDeletionCount
    self.credentialInventorySHA256 =
      credentialInventorySHA256 ?? current.credentialInventorySHA256
    self.toolingClaimedPathCount =
      toolingClaimedPathCount ?? current.toolingClaimedPathCount
    self.toolingDeletionCount =
      toolingDeletionCount ?? current.toolingDeletionCount
    self.toolingInventorySHA256 = toolingInventorySHA256 ?? current.toolingInventorySHA256
    self.finalInventorySHA256 = finalInventorySHA256 ?? current.finalInventorySHA256
    self.runtimeParitySHA256 = runtimeParitySHA256 ?? current.runtimeParitySHA256
    createdAtUTC = current.createdAtUTC
    self.updatedAtUTC = updatedAtUTC
    self.failureCode = failureCode
  }

  public func validate() throws {
    guard schemaVersion == 2, UUID(uuidString: runID) != nil,
      Self.validSHA256(rigJournalSHA256), !createdAtUTC.isEmpty, !updatedAtUTC.isEmpty,
      records.count == Set(records.map { "\($0.cell.rawValue):\($0.attempt)" }).count,
      (phase == .failed) == (failureCode != nil),
      failureCode == nil
        || failureCode!.range(of: "^[a-z0-9-]{1,64}$", options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("acceptance evidence journal is malformed")
    }
    for record in records {
      try record.validate()
    }
    for cell in AcceptanceCell.allCases {
      let attempts = records.filter { $0.cell == cell }.map(\.attempt)
      let expected = attempts.isEmpty ? [] : Array(1...attempts.count)
      guard attempts == expected else {
        throw ReleasePackageError.verification("acceptance cell attempts are not contiguous")
      }
    }
    let values = [
      packManifestSHA256, teardownAuthoritySHA256, cloneInventorySHA256, baseInventorySHA256,
      credentialInventorySHA256, toolingInventorySHA256, finalInventorySHA256,
      runtimeParitySHA256,
    ]
    guard values.compactMap({ $0 }).allSatisfy(Self.validSHA256) else {
      throw ReleasePackageError.verification("acceptance evidence digest is malformed")
    }
    switch phase {
    case .collecting:
      guard outcome == nil, packManifestSHA256 == nil, packFileCount == nil else {
        throw ReleasePackageError.verification("unsealed evidence claimed a closeout")
      }
    case .sealed, .cloneDeleted, .baseDeleted, .credentialsDestroying,
      .credentialsClaimed, .credentialsDestroyed, .toolingRemoving,
      .toolingClaimed, .toolingRemoved, .complete:
      guard outcome != nil, packManifestSHA256 != nil, let packFileCount, packFileCount > 0 else {
        throw ReleasePackageError.verification("sealed evidence authority is incomplete")
      }
    case .failed:
      break
    }
    if [
      .cloneDeleted, .baseDeleted, .credentialsDestroying, .credentialsClaimed,
      .credentialsDestroyed, .toolingRemoving, .toolingClaimed, .toolingRemoved,
      .complete,
    ]
    .contains(phase) {
      guard teardownAuthoritySHA256 != nil else {
        throw ReleasePackageError.verification(
          "teardown phase lacks its frozen pre-teardown authority")
      }
    }
    let credentialClaimed = credentialClaimedPathCount != nil || credentialDeletionCount != nil
    let toolingClaimed = toolingClaimedPathCount != nil || toolingDeletionCount != nil
    if credentialClaimed {
      guard let pathCount = credentialClaimedPathCount, pathCount > 0,
        let deletionCount = credentialDeletionCount,
        (0...pathCount).contains(deletionCount)
      else {
        throw ReleasePackageError.verification(
          "credential tombstone progress is malformed")
      }
    }
    if toolingClaimed {
      guard let pathCount = toolingClaimedPathCount, pathCount > 0,
        let deletionCount = toolingDeletionCount,
        (0...pathCount).contains(deletionCount)
      else {
        throw ReleasePackageError.verification(
          "tooling tombstone progress is malformed")
      }
    }
    switch phase {
    case .collecting, .sealed, .cloneDeleted, .baseDeleted, .credentialsDestroying:
      guard !credentialClaimed, !toolingClaimed else {
        throw ReleasePackageError.verification(
          "authority deletion progress appeared before its durable claim")
      }
    case .credentialsClaimed:
      guard credentialClaimed, !toolingClaimed else {
        throw ReleasePackageError.verification(
          "credential claim progress is incomplete")
      }
    case .credentialsDestroyed, .toolingRemoving:
      guard credentialDeletionCount == credentialClaimedPathCount, !toolingClaimed else {
        throw ReleasePackageError.verification(
          "credential deletion lacks complete claimed-vnode progress")
      }
    case .toolingClaimed:
      guard credentialDeletionCount == credentialClaimedPathCount, toolingClaimed else {
        throw ReleasePackageError.verification(
          "tooling claim progress is incomplete")
      }
    case .toolingRemoved, .complete:
      guard credentialDeletionCount == credentialClaimedPathCount,
        toolingDeletionCount == toolingClaimedPathCount
      else {
        throw ReleasePackageError.verification(
          "authority deletion lacks complete claimed-vnode progress")
      }
    case .failed:
      break
    }
    if phase == .complete {
      guard teardownAuthoritySHA256 != nil,
        cloneInventorySHA256 != nil, baseInventorySHA256 != nil,
        credentialInventorySHA256 != nil, toolingInventorySHA256 != nil,
        finalInventorySHA256 != nil, runtimeParitySHA256 != nil
      else {
        throw ReleasePackageError.verification("completed teardown authority is incomplete")
      }
    }
  }

  public func recording(_ record: AcceptanceCellEvidence, at timestamp: String) throws -> Self {
    try validate()
    try record.validate()
    guard phase == .collecting, !timestamp.isEmpty else {
      throw ReleasePackageError.verification("acceptance evidence is no longer collecting")
    }
    let expectedAttempt = records.filter { $0.cell == record.cell }.count + 1
    guard record.attempt == expectedAttempt else {
      throw ReleasePackageError.verification("acceptance cell attempt is out of order")
    }
    let value = Self(
      copying: self, phase: .collecting, records: records + [record], updatedAtUTC: timestamp)
    try value.validate()
    return value
  }

  public func sealing(
    outcome: AcceptanceCloseoutOutcome,
    packManifestSHA256: String,
    packFileCount: Int,
    at timestamp: String
  ) throws -> Self {
    try validate()
    guard phase == .collecting, !timestamp.isEmpty, Self.validSHA256(packManifestSHA256),
      packFileCount > 0
    else {
      throw ReleasePackageError.verification("acceptance evidence cannot be sealed")
    }
    try requireOutcome(outcome)
    let value = Self(
      copying: self, phase: .sealed, outcome: outcome,
      packManifestSHA256: packManifestSHA256, packFileCount: packFileCount,
      updatedAtUTC: timestamp)
    try value.validate()
    return value
  }

  public func advancingTeardown(
    to next: AcceptanceEvidencePhase,
    inventorySHA256: String,
    runtimeParitySHA256: String? = nil,
    at timestamp: String
  ) throws -> Self {
    try validate()
    guard teardownAuthoritySHA256 != nil,
      Self.validSHA256(inventorySHA256), !timestamp.isEmpty
    else {
      throw ReleasePackageError.verification("teardown inventory authority is malformed")
    }
    let expected: (AcceptanceEvidencePhase, AcceptanceEvidencePhase)
    switch next {
    case .cloneDeleted: expected = (.sealed, .cloneDeleted)
    case .baseDeleted: expected = (.cloneDeleted, .baseDeleted)
    case .credentialsDestroyed: expected = (.credentialsClaimed, .credentialsDestroyed)
    case .toolingRemoved: expected = (.toolingClaimed, .toolingRemoved)
    case .complete: expected = (.toolingRemoved, .complete)
    default:
      throw ReleasePackageError.verification("invalid evidence teardown phase")
    }
    guard phase == expected.0 else {
      throw ReleasePackageError.verification("evidence teardown phase is out of order")
    }
    let value: Self
    switch next {
    case .cloneDeleted:
      value = Self(
        copying: self, phase: next, cloneInventorySHA256: inventorySHA256,
        updatedAtUTC: timestamp)
    case .baseDeleted:
      value = Self(
        copying: self, phase: next, baseInventorySHA256: inventorySHA256,
        updatedAtUTC: timestamp)
    case .credentialsDestroyed:
      value = Self(
        copying: self, phase: next, credentialInventorySHA256: inventorySHA256,
        updatedAtUTC: timestamp)
    case .toolingRemoved:
      value = Self(
        copying: self, phase: next, toolingInventorySHA256: inventorySHA256,
        updatedAtUTC: timestamp)
    case .complete:
      guard let runtimeParitySHA256, Self.validSHA256(runtimeParitySHA256) else {
        throw ReleasePackageError.verification("final runtime parity is absent")
      }
      value = Self(
        copying: self, phase: next, finalInventorySHA256: inventorySHA256,
        runtimeParitySHA256: runtimeParitySHA256, updatedAtUTC: timestamp)
    default:
      preconditionFailure("invalid teardown phase returned before construction")
    }
    try value.validate()
    return value
  }

  public func recordingAuthorityClaim(
    to next: AcceptanceEvidencePhase,
    pathCount: Int,
    at timestamp: String
  ) throws -> Self {
    try validate()
    guard teardownAuthoritySHA256 != nil, pathCount > 0, !timestamp.isEmpty else {
      throw ReleasePackageError.verification(
        "authority claim progress is malformed")
    }
    let expected: AcceptanceEvidencePhase
    switch next {
    case .credentialsClaimed: expected = .credentialsDestroying
    case .toolingClaimed: expected = .toolingRemoving
    default:
      throw ReleasePackageError.verification("invalid authority-claim phase")
    }
    guard phase == expected else {
      throw ReleasePackageError.verification("authority claim is out of order")
    }
    let value: Self
    switch next {
    case .credentialsClaimed:
      value = Self(
        copying: self, phase: next,
        credentialClaimedPathCount: pathCount, credentialDeletionCount: 0,
        updatedAtUTC: timestamp)
    case .toolingClaimed:
      value = Self(
        copying: self, phase: next,
        toolingClaimedPathCount: pathCount, toolingDeletionCount: 0,
        updatedAtUTC: timestamp)
    default:
      preconditionFailure("invalid claim phase returned before construction")
    }
    try value.validate()
    return value
  }

  public func recordingAuthorityDeletion(
    kind: String,
    deletedCount: Int,
    at timestamp: String
  ) throws -> Self {
    try validate()
    guard !timestamp.isEmpty else {
      throw ReleasePackageError.verification("authority deletion progress lacks a timestamp")
    }
    let value: Self
    switch kind {
    case "credentials":
      guard phase == .credentialsClaimed,
        let total = credentialClaimedPathCount,
        let current = credentialDeletionCount,
        deletedCount == current + 1, deletedCount <= total
      else {
        throw ReleasePackageError.verification(
          "credential deletion progress is out of order")
      }
      value = Self(
        copying: self, phase: phase, credentialDeletionCount: deletedCount,
        updatedAtUTC: timestamp)
    case "tooling":
      guard phase == .toolingClaimed,
        let total = toolingClaimedPathCount,
        let current = toolingDeletionCount,
        deletedCount == current + 1, deletedCount <= total
      else {
        throw ReleasePackageError.verification(
          "tooling deletion progress is out of order")
      }
      value = Self(
        copying: self, phase: phase, toolingDeletionCount: deletedCount,
        updatedAtUTC: timestamp)
    default:
      throw ReleasePackageError.invalidArgument("unknown teardown authority kind")
    }
    try value.validate()
    return value
  }

  public func beginningAuthorityDestruction(
    to next: AcceptanceEvidencePhase, at timestamp: String
  ) throws -> Self {
    try validate()
    guard teardownAuthoritySHA256 != nil, !timestamp.isEmpty else {
      throw ReleasePackageError.verification(
        "authority destruction lacks frozen teardown authority")
    }
    let expected: AcceptanceEvidencePhase
    switch next {
    case .credentialsDestroying: expected = .baseDeleted
    case .toolingRemoving: expected = .credentialsDestroyed
    default:
      throw ReleasePackageError.verification(
        "invalid authority-destruction phase")
    }
    guard phase == expected else {
      throw ReleasePackageError.verification(
        "authority destruction is out of order")
    }
    let value = Self(copying: self, phase: next, updatedAtUTC: timestamp)
    try value.validate()
    return value
  }

  public func bindingTeardownAuthority(
    sha256: String, at timestamp: String
  ) throws -> Self {
    try validate()
    guard phase == .sealed, teardownAuthoritySHA256 == nil,
      Self.validSHA256(sha256), !timestamp.isEmpty
    else {
      throw ReleasePackageError.verification(
        "pre-teardown authority cannot be rebound")
    }
    let value = Self(
      copying: self, phase: .sealed, teardownAuthoritySHA256: sha256,
      updatedAtUTC: timestamp)
    try value.validate()
    return value
  }

  public func failing(code: String, at timestamp: String) throws -> Self {
    try validate()
    guard phase != .complete, phase != .failed, !timestamp.isEmpty,
      code.range(of: "^[a-z0-9-]{1,64}$", options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("evidence failure is malformed")
    }
    let value = Self(
      copying: self, phase: .failed, updatedAtUTC: timestamp, failureCode: code)
    try value.validate()
    return value
  }

  private func requireOutcome(_ selected: AcceptanceCloseoutOutcome) throws {
    func hasStop(_ cell: AcceptanceCell) -> Bool {
      records.contains { $0.cell == cell && $0.verdict == .stop }
    }
    switch selected {
    case .complete:
      guard !records.contains(where: { $0.verdict == .stop }) else {
        throw ReleasePackageError.verification("complete evidence contains a stop")
      }
      for (cell, minimum) in AcceptanceCell.completeMinimums {
        guard records.filter({ $0.cell == cell && $0.verdict == .pass }).count >= minimum else {
          throw ReleasePackageError.verification(
            "complete evidence is missing required cell \(cell.rawValue)")
        }
      }
    case .mandatoryChoice:
      guard hasStop(.mandatoryDeselection) else {
        throw ReleasePackageError.verification("mandatory-choice stop lacks its decisive cell")
      }
    case .ownerContention:
      guard hasStop(.ownerContention) else {
        throw ReleasePackageError.verification("owner-contention stop lacks its decisive cell")
      }
    case .metalVM:
      guard hasStop(.nativeMLX) else {
        throw ReleasePackageError.verification("METAL-VM stop lacks its decisive cell")
      }
    case .rollbackSemantics:
      guard hasStop(.explicitRollback) else {
        throw ReleasePackageError.verification("rollback stop lacks its decisive cell")
      }
    case .failed:
      guard records.contains(where: { $0.verdict == .stop }) else {
        throw ReleasePackageError.verification("failed closeout lacks bounded stop evidence")
      }
    }
  }

  private static func validSHA256(_ value: String) -> Bool {
    value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
  }
}

public struct AcceptanceEvidenceJournalStore {
  public let url: URL

  public init(url: URL) { self.url = url }

  public func withExclusiveLock<T>(_ body: () throws -> T) throws -> T {
    try SecureFiles.createPrivateDirectory(url.deletingLastPathComponent())
    let lockURL = URL(fileURLWithPath: url.path + ".lock")
    let descriptor = open(lockURL.path, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open evidence journal lock")
    }
    defer { close(descriptor) }
    guard fchmod(descriptor, 0o600) == 0, flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
      throw ReleasePackageError.verification("evidence journal is already in use")
    }
    defer { _ = flock(descriptor, LOCK_UN) }
    return try body()
  }

  public func load() throws -> AcceptanceEvidenceJournal? {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      if errno == ENOENT { return nil }
      throw ReleasePackageError.verification("cannot inspect evidence journal")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
      (info.st_mode & 0o7777) == 0o600
    else {
      throw ReleasePackageError.unsafePath(
        "evidence journal must be a mode-0600 single-link file")
    }
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let value = try JSONDecoder().decode(AcceptanceEvidenceJournal.self, from: data)
    guard data == (try CanonicalJSON.encode(value)) else {
      throw ReleasePackageError.verification("evidence journal is not canonical JSON")
    }
    try value.validate()
    return value
  }

  public func create(_ value: AcceptanceEvidenceJournal) throws {
    try value.validate()
    guard try load() == nil else {
      throw ReleasePackageError.verification("evidence journal already exists")
    }
    try write(value)
  }

  public func write(_ value: AcceptanceEvidenceJournal) throws {
    try value.validate()
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: url)
  }
}
