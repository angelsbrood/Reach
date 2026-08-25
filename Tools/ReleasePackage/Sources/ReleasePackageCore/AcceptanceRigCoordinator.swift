import Foundation

/// Serializes the two-name Tart authority through a durable journal. Finite
/// mutations hold the journal lock for their complete command and are
/// idempotently reconciled from exact Tart inventory after interruption. The
/// long-running VM process publishes `clone-running` before it starts; every
/// independent observer must still verify Tart's live running state.
public struct AcceptanceRigCoordinator {
  public typealias Timestamp = () -> String

  private let controller: TartHostController
  private let store: AcceptanceRigJournalStore
  private let imageVerifier: any MacOSRestoreImageVerifying
  private let storage: any HostStorageChecking
  private let timestamp: Timestamp

  public init(
    controller: TartHostController,
    store: AcceptanceRigJournalStore,
    timestamp: @escaping Timestamp = Self.currentTimestamp
  ) throws {
    self.controller = controller
    self.store = store
    self.imageVerifier = MacOSRestoreImageInspector()
    self.storage = try HostStorageAuthority()
    self.timestamp = timestamp
  }

  init(
    controller: TartHostController,
    store: AcceptanceRigJournalStore,
    imageVerifier: any MacOSRestoreImageVerifying,
    storage: any HostStorageChecking,
    timestamp: @escaping Timestamp
  ) {
    self.controller = controller
    self.store = store
    self.imageVerifier = imageVerifier
    self.storage = storage
    self.timestamp = timestamp
  }

  public func prepare(runID: String, tartExecutableSHA256: String) throws
    -> AcceptanceRigJournal
  {
    try store.withExclusiveLock {
      _ = try storage.require(.preparation)
      guard try store.load() == nil else {
        throw ReleasePackageError.verification("rig journal already exists")
      }
      let inventory = try controller.inventory()
      guard !inventory.contains(where: { $0.name.hasPrefix("reach-s36-") }) else {
        throw ReleasePackageError.verification("S36 VM authority is not initially empty")
      }
      let now = timestamp()
      let value = AcceptanceRigJournal(
        runID: runID, tartExecutableSHA256: tartExecutableSHA256,
        createdAtUTC: now, updatedAtUTC: now)
      try store.create(value)
      return value
    }
  }

  public func createBase(
    ipsw: URL,
    restoreImageAuthority: URL
  ) throws -> AcceptanceRigJournal {
    try store.withExclusiveLock {
      _ = try storage.require(.preparation)
      var journal = try requireJournal(phases: [.prepared, .imageVerified])
      let imageRecord = try imageVerifier.verify(
        recordURL: restoreImageAuthority, localIPSW: ipsw)
      let authorityDigest = try Digests.sha256(file: restoreImageAuthority)
      let before = try controller.inventory()
      let beforeDigest = try digest(before)
      if journal.phase == .prepared {
        journal = try journal.imageVerified(
          authoritySHA256: authorityDigest, inventorySHA256: beforeDigest,
          at: timestamp())
        try store.write(journal)
      } else {
        guard journal.restoreImageAuthoritySHA256 == authorityDigest else {
          throw ReleasePackageError.verification("restore-image authority changed after selection")
        }
      }
      _ = imageRecord
      let configuration: TartVMConfigurationRecord
      if before.contains(where: { $0.name == TartS36VM.base.rawValue }) {
        guard !before.contains(where: { $0.name == TartS36VM.acceptance.rawValue }) else {
          throw ReleasePackageError.verification("base recovery found an acceptance clone")
        }
        configuration = try controller.configuration(of: .base, requireRunning: false)
      } else {
        configuration = try controller.createBase(
          fromIPSW: ipsw, restoreImageAuthority: restoreImageAuthority)
      }
      let after = try controller.inventory()
      guard
        after.contains(where: {
          $0.name == TartS36VM.base.rawValue && !$0.running
        }), !after.contains(where: { $0.name == TartS36VM.acceptance.rawValue })
      else {
        throw ReleasePackageError.verification("base creation did not settle exactly")
      }
      journal = try journal.baseCreated(
        configurationSHA256: try digest(configuration.authority),
        inventorySHA256: try digest(after), at: timestamp())
      try store.write(journal)
      return journal
    }
  }

  /// Records the bounded, interactive first-boot transition before Tart is
  /// invoked. If the caller exits, the durable `base-provisioning` state makes
  /// the unfinished setup explicit rather than silently sealing the base.
  public func runBaseForInteractiveProvisioning() throws {
    try store.withExclusiveLock {
      _ = try storage.require(.continuation)
      var journal = try requireJournal(phases: [.baseCreated])
      let inventory = try controller.inventory()
      journal = try journal.baseProvisioningStarted(
        inventorySHA256: try digest(inventory), at: timestamp())
      try store.write(journal)
    }
    _ = try controller.runBaseForInteractiveProvisioning()
  }

  public func sealBase(
    provisioningReport: URL,
    sealReport: URL
  ) throws -> AcceptanceRigJournal {
    try store.withExclusiveLock {
      _ = try storage.require(.continuation)
      var journal = try requireJournal(phases: [.baseProvisioning])
      let inventory = try controller.inventory()
      guard
        inventory.contains(where: {
          $0.name == TartS36VM.base.rawValue && !$0.running
        }), !inventory.contains(where: { $0.name == TartS36VM.acceptance.rawValue })
      else {
        throw ReleasePackageError.verification("base is not stopped and isolated for sealing")
      }
      let configuration = try controller.configuration(of: .base, requireRunning: false)
      guard try digest(configuration.authority) == journal.baseConfigurationSHA256 else {
        throw ReleasePackageError.verification("base configuration changed during provisioning")
      }
      journal = try journal.baseSealed(
        provisioningSHA256: try privateRegularFileDigest(
          provisioningReport, label: "base provisioning report"),
        sealSHA256: try privateRegularFileDigest(sealReport, label: "base seal report"),
        inventorySHA256: try digest(inventory), at: timestamp())
      try store.write(journal)
      return journal
    }
  }

  public func cloneAcceptance() throws -> AcceptanceRigJournal {
    try store.withExclusiveLock {
      _ = try storage.require(.continuation)
      var journal = try requireJournal(phases: [.baseSealed, .cloneDeleted])
      let before = try controller.inventory()
      let record: TartVMConfigurationRecord
      if before.contains(where: { $0.name == TartS36VM.acceptance.rawValue }) {
        guard
          before.contains(where: {
            $0.name == TartS36VM.base.rawValue && !$0.running
          })
        else {
          throw ReleasePackageError.verification("clone recovery lost its stopped base")
        }
        record = try controller.configuration(of: .acceptance, requireRunning: false)
      } else {
        record = try controller.cloneAcceptance()
      }
      guard try digest(record.authority) == journal.baseConfigurationSHA256 else {
        throw ReleasePackageError.verification("acceptance clone configuration differs from base")
      }
      let after = try controller.inventory()
      journal = try journal.cloneCreated(
        inventorySHA256: try digest(after), at: timestamp())
      try store.write(journal)
      return journal
    }
  }

  /// Publishes the exact clone epoch before entering Tart's long-running
  /// process. Other invocations must require the live clone to be running.
  public func runAcceptanceHeadless() throws {
    try store.withExclusiveLock {
      _ = try storage.require(.continuation)
      var journal = try requireJournal(phases: [.cloneCreated, .cloneStopped])
      let inventory = try controller.inventory()
      journal = try journal.cloneRunning(
        inventorySHA256: try digest(inventory), at: timestamp())
      try store.write(journal)
    }
    _ = try controller.runAcceptanceHeadless()
  }

  public func requireRunningAcceptance() throws -> AcceptanceRigJournal {
    try store.withExclusiveLock {
      _ = try storage.require(.continuation)
      let journal = try requireJournal(phases: [.cloneRunning])
      let inventory = try controller.inventory()
      guard
        inventory.contains(where: {
          $0.name == TartS36VM.acceptance.rawValue && $0.running
        })
      else {
        throw ReleasePackageError.verification("acceptance clone is not live")
      }
      return journal
    }
  }

  public func bindHostAuthority(_ authority: URL) throws -> AcceptanceRigJournal {
    try store.withExclusiveLock {
      var journal = try requireJournal(phases: [.cloneRunning])
      let loaded = try AcceptanceHostAuthority.loadWithDigest(authority)
      let value = loaded.authority
      guard value.runID == journal.runID else {
        throw ReleasePackageError.verification(
          "host authority belongs to a different rig run")
      }
      try value.verifyCredentials(
        identity: URL(fileURLWithPath: value.identity.path),
        knownHosts: URL(fileURLWithPath: value.knownHosts.path))
      try value.verifyToolingRoot()
      let digest = loaded.sha256
      if let existing = journal.hostAuthoritySHA256 {
        guard existing == digest else {
          throw ReleasePackageError.verification("rig host authority changed")
        }
        return journal
      }
      journal = try journal.bindingHostAuthority(
        sha256: digest, at: timestamp())
      try store.write(journal)
      return journal
    }
  }

  public func stopAcceptance() throws -> AcceptanceRigJournal {
    try store.withExclusiveLock {
      _ = try storage.require(.continuation)
      var journal = try requireJournal(phases: [.cloneRunning])
      try controller.stop(.acceptance)
      let inventory = try controller.inventory()
      journal = try journal.cloneStopped(
        inventorySHA256: try digest(inventory), at: timestamp())
      try store.write(journal)
      return journal
    }
  }

  public func deleteAcceptance() throws -> AcceptanceRigJournal {
    try store.withExclusiveLock {
      _ = try storage.require(.continuation)
      var journal = try requireJournal(phases: [.cloneCreated, .cloneStopped])
      let before = try controller.inventory()
      if before.contains(where: { $0.name == TartS36VM.acceptance.rawValue }) {
        try controller.delete(.acceptance)
      }
      let after = try controller.inventory()
      guard !after.contains(where: { $0.name == TartS36VM.acceptance.rawValue }) else {
        throw ReleasePackageError.verification("acceptance clone survived exact deletion")
      }
      journal = try journal.cloneDeleted(
        inventorySHA256: try digest(after), at: timestamp())
      try store.write(journal)
      return journal
    }
  }

  public func deleteBase() throws -> AcceptanceRigJournal {
    try store.withExclusiveLock {
      _ = try storage.require(.continuation)
      var journal = try requireJournal(phases: [.baseSealed, .cloneDeleted])
      let before = try controller.inventory()
      guard !before.contains(where: { $0.name == TartS36VM.acceptance.rawValue }) else {
        throw ReleasePackageError.verification("base deletion found an acceptance clone")
      }
      if before.contains(where: { $0.name == TartS36VM.base.rawValue }) {
        try controller.delete(.base)
      }
      let after = try controller.inventory()
      guard !after.contains(where: { $0.name.hasPrefix("reach-s36-") }) else {
        throw ReleasePackageError.verification("S36 VM authority survived base deletion")
      }
      journal = try journal.baseDeleted(
        inventorySHA256: try digest(after), at: timestamp())
      try store.write(journal)
      return journal
    }
  }

  public func complete() throws -> AcceptanceRigJournal {
    try store.withExclusiveLock {
      _ = try storage.require(.continuation)
      var journal = try requireJournal(phases: [.baseDeleted])
      let inventory = try controller.inventory()
      guard !inventory.contains(where: { $0.name.hasPrefix("reach-s36-") }) else {
        throw ReleasePackageError.verification("rig cannot close while an S36 VM exists")
      }
      journal = try journal.completed(
        inventorySHA256: try digest(inventory), at: timestamp())
      try store.write(journal)
      return journal
    }
  }

  private func requireJournal(phases: Set<AcceptanceRigPhase>) throws
    -> AcceptanceRigJournal
  {
    guard let journal = try store.load(), phases.contains(journal.phase) else {
      throw ReleasePackageError.verification("rig journal is absent or in the wrong phase")
    }
    return journal
  }

  private func digest<T: Encodable>(_ value: T) throws -> String {
    Digests.sha256(try CanonicalJSON.encode(value))
  }

  private func privateRegularFileDigest(_ url: URL, label: String) throws -> String {
    let physical = try ReleasePathAuthority.absoluteURL(url.path, label: label)
    var info = stat()
    guard lstat(physical.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, info.st_uid == getuid(), (info.st_mode & 0o7777) == 0o600,
      info.st_size > 0
    else {
      throw ReleasePackageError.unsafePath(label + " must be one owner-private regular file")
    }
    return try Digests.sha256(file: physical)
  }

  public static func currentTimestamp() -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: Date())
  }
}
