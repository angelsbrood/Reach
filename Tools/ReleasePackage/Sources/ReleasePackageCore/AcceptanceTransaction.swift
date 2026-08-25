import Foundation

public protocol AcceptanceTransactionSystem: AnyObject {
  func stopHost(ownerUID: UInt32) throws
  func install(_ release: AcceptanceReleaseReference) throws
  func verifyInstalled(_ release: AcceptanceReleaseReference) throws
  func reconcileHelper(
    from prior: AcceptanceReleaseReference?, to target: AcceptanceReleaseReference
  ) throws
  func startHost(ownerUID: UInt32) throws
  func verifyRuntime(_ release: AcceptanceReleaseReference) throws
  func verifyAccepted(_ release: AcceptanceReleaseReference) throws
  func finalize(
    action: AcceptanceTransactionAction,
    release: AcceptanceReleaseReference
  ) throws
  func uninstall(_ release: AcceptanceReleaseReference) throws
  func verifyUninstalled(_ release: AcceptanceReleaseReference) throws
  func interruptInstaller(
    target: AcceptanceReleaseReference
  ) throws -> AcceptanceInstalledAuthority
}

public struct AcceptanceTransactionExecutor {
  public typealias Timestamp = () -> String

  private let timestamp: Timestamp

  public init() {
    self.timestamp = Self.currentTimestamp
  }

  public init(timestamp: @escaping Timestamp) {
    self.timestamp = timestamp
  }

  @discardableResult
  public func begin(
    store: AcceptanceJournalStore,
    journal: AcceptanceJournal,
    system: AcceptanceTransactionSystem,
    stopAfter: AcceptanceTransactionPhase? = nil
  ) throws -> AcceptanceJournal {
    try store.withExclusiveLock {
      try store.create(journal)
      return try advance(store: store, system: system, stopAfter: stopAfter)
    }
  }

  @discardableResult
  public func recover(
    store: AcceptanceJournalStore,
    system: AcceptanceTransactionSystem,
    stopAfter: AcceptanceTransactionPhase? = nil
  ) throws -> AcceptanceJournal {
    try store.withExclusiveLock {
      guard let journal = try store.load() else {
        throw ReleasePackageError.verification("no acceptance transaction exists to recover")
      }
      guard ![.accepted, .rolledBack, .uninstalled, .failed].contains(journal.phase) else {
        throw ReleasePackageError.verification("acceptance transaction is already terminal")
      }
      return try advance(store: store, system: system, stopAfter: stopAfter)
    }
  }

  /// Lands the `during Installer` cell only after the guest observes a real
  /// target component receipt transition. The transaction journal remains at
  /// `installer-started`; a later `recover` must classify and repair the
  /// resulting prior/target/mixed authority before starting either service.
  @discardableResult
  public func interruptInstaller(
    store: AcceptanceJournalStore,
    system: AcceptanceTransactionSystem
  ) throws -> AcceptanceInstallerInterruptionReport {
    try store.withExclusiveLock {
      guard let journal = try store.load(), journal.action == .update,
        journal.phase == .installerStarted, let target = journal.target,
        try store.loadInstallerInterruption() == nil
      else {
        throw ReleasePackageError.verification(
          "Installer interruption requires one unobserved update at installer-started")
      }
      let journalSHA256 = try Digests.sha256(file: store.url)
      let observed = try system.interruptInstaller(target: target)
      guard let unchanged = try store.load(), unchanged == journal,
        try Digests.sha256(file: store.url) == journalSHA256
      else {
        throw ReleasePackageError.verification(
          "transaction authority changed during Installer interruption")
      }
      let report = AcceptanceInstallerInterruptionReport(
        transactionID: journal.transactionID,
        transactionJournalSHA256: journalSHA256,
        targetP5SHA256: target.p5SHA256,
        observedAuthority: observed,
        observedAtUTC: timestamp())
      try store.createInstallerInterruption(report)
      return report
    }
  }

  private func advance(
    store: AcceptanceJournalStore,
    system: AcceptanceTransactionSystem,
    stopAfter: AcceptanceTransactionPhase?
  ) throws -> AcceptanceJournal {
    guard var journal = try store.load() else {
      throw ReleasePackageError.verification("acceptance transaction disappeared")
    }
    do {
      while ![.accepted, .rolledBack, .uninstalled, .failed].contains(journal.phase) {
        let next = try performNext(journal, system: system)
        journal = try store.transition(to: next, at: timestamp())
        if next == stopAfter { return journal }
      }
      return journal
    } catch let error as ReleasePackageError {
      let failureCode = Self.failureCode(error)
      if ![.accepted, .rolledBack, .uninstalled, .failed].contains(journal.phase) {
        _ = try? store.transition(to: .failed, at: timestamp(), failureCode: failureCode)
      }
      throw error
    } catch {
      if ![.accepted, .rolledBack, .uninstalled, .failed].contains(journal.phase) {
        _ = try? store.transition(to: .failed, at: timestamp(), failureCode: "system-refused")
      }
      throw error
    }
  }

  private func performNext(
    _ journal: AcceptanceJournal,
    system: AcceptanceTransactionSystem
  ) throws -> AcceptanceTransactionPhase {
    switch journal.phase {
    case .prepared:
      if journal.action == .verify {
        guard let target = journal.target else {
          throw ReleasePackageError.verification("verification target disappeared")
        }
        try system.verifyRuntime(target)
        try system.verifyAccepted(target)
        return .accepted
      }
      try system.stopHost(ownerUID: journal.selectedOwnerUID)
      return .priorStopped
    case .priorStopped:
      // The intent to invoke Installer or begin removal is durable before the
      // first payload mutation. Recovery may safely replay only this exact
      // retained release authority.
      return .installerStarted
    case .installerStarted:
      if journal.action == .uninstall {
        guard let prior = journal.prior else {
          throw ReleasePackageError.verification("uninstall authority disappeared")
        }
        try system.uninstall(prior)
        try system.verifyUninstalled(prior)
      } else {
        guard let target = journal.target else {
          throw ReleasePackageError.verification("installation target disappeared")
        }
        try system.install(target)
        try system.verifyInstalled(target)
      }
      return .payloadVerified
    case .payloadVerified:
      if journal.action == .uninstall { return .uninstalled }
      guard let target = journal.target else {
        throw ReleasePackageError.verification("helper target disappeared")
      }
      try system.reconcileHelper(from: journal.prior, to: target)
      return .helperReconciled
    case .helperReconciled:
      try system.startHost(ownerUID: journal.selectedOwnerUID)
      return .hostStarted
    case .hostStarted:
      guard let target = journal.target else {
        throw ReleasePackageError.verification("runtime target disappeared")
      }
      try system.verifyRuntime(target)
      return .runtimeVerified
    case .runtimeVerified:
      guard let target = journal.target else {
        throw ReleasePackageError.verification("accepted target disappeared")
      }
      try system.verifyAccepted(target)
      try system.finalize(action: journal.action, release: target)
      return journal.action == .rollback ? .rolledBack : .accepted
    case .accepted, .rolledBack, .uninstalled, .failed:
      throw ReleasePackageError.verification("acceptance transaction is already terminal")
    }
  }

  private static func currentTimestamp() -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: Date())
  }

  private static func failureCode(_ error: ReleasePackageError) -> String {
    switch error {
    case .invalidArgument: "argument-refused"
    case .invalidConfiguration: "configuration-refused"
    case .sourceAuthority: "source-refused"
    case .unsafePath: "path-refused"
    case .processFailure: "process-refused"
    case .verification: "verification-refused"
    }
  }
}
