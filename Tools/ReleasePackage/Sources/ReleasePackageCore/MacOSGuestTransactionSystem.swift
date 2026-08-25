import Darwin
import Foundation

public struct RetainedReleaseCatalogEntry: Equatable, Sendable {
  public let root: URL
  public let reference: AcceptanceReleaseReference
  public let helperDisposition: ReleaseComponentDisposition
  public let helperComponentSHA256: String

  public init(root: URL) throws {
    let manifestURL = root.appendingPathComponent("retained-authority.json")
    try RetainedReleaseAuthoritySealer().verify(
      manifestURL: manifestURL, authorityRoot: root)
    let provenanceURL = root.appendingPathComponent("release-provenance.json")
    let envelope = try AnySignedReleaseProvenance.load(from: provenanceURL)
    guard let lineage = envelope.view.lineage, let p5 = envelope.view.p5 else {
      throw ReleasePackageError.verification("retained catalog entry is not complete P5")
    }
    let parent: String?
    switch lineage.declaration {
    case .replacement:
      parent = nil
    case .successor(let successor):
      parent = successor.parentP5SHA256
    }
    self.root = root
    self.reference = .init(
      versions: lineage.release,
      p5SHA256: p5.stapledContainer.sha256,
      provenanceSHA256: try Digests.sha256(file: provenanceURL),
      parentP5SHA256: parent)
    self.helperDisposition = lineage.declaration.components.helper
    self.helperComponentSHA256 = envelope.view.p2.helperComponent.sha256
  }

  func packageURL() throws -> URL {
    let envelope = try AnySignedReleaseProvenance.load(
      from: root.appendingPathComponent("release-provenance.json"))
    guard let artifact = envelope.view.p5?.stapledContainer else {
      throw ReleasePackageError.verification("retained release lost its P5 package")
    }
    try SecureFiles.validateRelativePath(artifact.path)
    let url = root.appendingPathComponent(artifact.path)
    var info = stat()
    guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, UInt64(info.st_size) == artifact.size,
      try Digests.sha256(file: url) == artifact.sha256
    else {
      throw ReleasePackageError.verification("retained P5 package changed")
    }
    return url
  }
}

/// Guest-only implementation. It accepts only retained P5 catalog entries,
/// one explicit login owner, exact launchd labels, Installer's native package
/// path, and the fixed package/runtime removal set. It is not linked into
/// Reach, reachd, or the shipping package.
public final class MacOSGuestTransactionSystem: AcceptanceTransactionSystem {
  private let runner: ProcessRunner
  private let entries: [String: RetainedReleaseCatalogEntry]
  private let ownerUID: UInt32
  private let ownerHome: URL
  private let action: AcceptanceTransactionAction
  private let prior: AcceptanceReleaseReference?
  private let target: AcceptanceReleaseReference?
  private let finalHelper: InstalledHelperRequirement
  private let finalState: RetainedStateRequirement
  private let scratch: URL
  private let transactionID: String
  private let baselineStore: AcceptanceRetainedStateBaselineStore
  private let migrationStore: UnmanagedHostMigrationStore
  private var logIndex = 0

  public init(
    entries: [RetainedReleaseCatalogEntry],
    ownerUID: UInt32,
    ownerHome: URL,
    action: AcceptanceTransactionAction,
    prior: AcceptanceReleaseReference?,
    target: AcceptanceReleaseReference?,
    finalHelper: InstalledHelperRequirement,
    finalState: RetainedStateRequirement,
    transactionID: String,
    stateBaselineURL: URL,
    migrationRecordURL: URL,
    scratch: URL,
    runner: ProcessRunner = .init()
  ) throws {
    guard ownerUID != 0, UUID(uuidString: transactionID) != nil,
      ownerHome.path.hasPrefix("/Users/"),
      ownerHome.path.split(separator: "/").count == 2,
      entries.count == Set(entries.map(\.reference.p5SHA256)).count,
      entries.allSatisfy({ $0.reference == prior || $0.reference == target })
    else {
      throw ReleasePackageError.verification("guest transaction catalog or owner is ambiguous")
    }
    let probe = AcceptanceJournal(
      transactionID: UUID().uuidString, action: action, prior: prior, target: target,
      selectedOwnerUID: ownerUID, createdAtUTC: "validation", updatedAtUTC: "validation")
    try probe.validate()
    try SecureFiles.createPrivateDirectory(scratch)
    self.runner = runner
    self.entries = Dictionary(uniqueKeysWithValues: entries.map { ($0.reference.p5SHA256, $0) })
    self.ownerUID = ownerUID
    self.ownerHome = ownerHome
    self.action = action
    self.prior = prior
    self.target = target
    self.finalHelper = finalHelper
    self.finalState = finalState
    self.transactionID = transactionID
    self.baselineStore = .init(
      url: try ReleasePathAuthority.absoluteURL(
        stateBaselineURL.path, label: "retained-state baseline"))
    self.migrationStore = .init(
      url: try ReleasePathAuthority.absoluteURL(
        migrationRecordURL.path, label: "unmanaged migration record"))
    self.scratch = scratch
  }

  public func stopHost(ownerUID: UInt32) throws {
    guard ownerUID == self.ownerUID else {
      throw ReleasePackageError.verification("guest owner changed during transaction")
    }
    if action == .migrate {
      guard let target else {
        throw ReleasePackageError.verification("migration target disappeared")
      }
      let record = try UnmanagedHostMigration(runner: runner).capture(
        release: entry(for: target), ownerUID: ownerUID, ownerHome: ownerHome,
        transactionID: transactionID,
        scratch: try nextScratch("unmanaged-migration-capture"))
      try migrationStore.createOrVerify(record)
    }
    let retainedState = try MacOSInstalledStateCollector(runner: runner).observeState(
      ownerHome.appendingPathComponent("Library/Application Support/Reach"),
      expectedOwnerUID: ownerUID)
    try baselineStore.createOrVerify(
      .init(
        transactionID: transactionID, selectedOwnerUID: ownerUID,
        observation: retainedState))
    _ = try runner.run(
      "/bin/launchctl", ["bootout", "gui/\(ownerUID)/systems.reach.reachd"],
      timeout: 15, logURL: nextLog("host-bootout"), requireSuccess: false)
    try requireUnloaded("gui/\(ownerUID)/systems.reach.reachd", label: "host")
    if try action == .uninstall || helperChangesAcrossTransaction() {
      _ = try runner.run(
        "/bin/launchctl", ["bootout", "system/systems.reach.meshd"],
        timeout: 15, logURL: nextLog("helper-bootout"), requireSuccess: false)
      try requireUnloaded("system/systems.reach.meshd", label: "helper")
    }
  }

  public func install(_ release: AcceptanceReleaseReference) throws {
    let entry = try entry(for: release)
    _ = try InstalledReleaseStateVerifier(runner: runner).expectedState(
      retainedAuthority: entry.root, scratch: try nextScratch("preinstall"))
    let package = try entry.packageURL()
    _ = try runner.run(
      "/usr/sbin/installer", ["-pkg", package.path, "-target", "/"],
      timeout: 300, logURL: nextLog("installer"))
  }

  public func interruptInstaller(
    target release: AcceptanceReleaseReference
  ) throws -> AcceptanceInstalledAuthority {
    guard action == .update, release == target, let prior else {
      throw ReleasePackageError.verification(
        "only an exact A-to-B update may interrupt Installer")
    }
    let targetEntry = try entry(for: release)
    let package = try targetEntry.packageURL()
    let priorHost = prior.versions.host
    let priorHelper = prior.versions.helper
    _ = try runner.runUntilObservation(
      "/usr/sbin/installer", ["-pkg", package.path, "-target", "/"],
      timeout: 300, logURL: nextLog("installer-interruption")
    ) {
      let host = try self.receiptVersion("systems.reach.host")
      let helper = try self.receiptVersion("systems.reach.meshd")
      let hostTransitioned = host == release.versions.host && host != priorHost
      let helperTransitioned =
        helper == release.versions.helper && helper != priorHelper
      return hostTransitioned || helperTransitioned
    }
    try requireReceiptsSettled()
    let targetExact = try installedAuthorityMatches(targetEntry)
    let priorExact = try installedAuthorityMatches(entry(for: prior))
    if targetExact && !priorExact { return .target }
    if priorExact && !targetExact { return .prior }
    return .mixed
  }

  public func verifyInstalled(_ release: AcceptanceReleaseReference) throws {
    let entry = try entry(for: release)
    let hostRequirement: InstalledHostRequirement = prior == nil ? .unbound : .stopped
    let helperRequirement: InstalledHelperRequirement
    if prior == nil {
      helperRequirement = .absent
    } else if try helperChangesAcrossTransaction() {
      helperRequirement = .stopped
    } else {
      helperRequirement = finalHelper
    }
    let stateRequirement = try currentStateRequirement()
    let snapshot = try nextScratch("installed-snapshot").appendingPathComponent("snapshot.json")
    _ = try MacOSInstalledStateCollector(runner: runner).collect(
      retainedAuthority: entry.root,
      policy: .init(
        selectedOwnerUID: ownerUID, selectedOwnerHome: ownerHome.path,
        host: hostRequirement,
        helper: helperRequirement, retainedState: stateRequirement),
      ownerHome: ownerHome,
      scratch: try nextScratch("installed-collection"), output: snapshot)
  }

  public func reconcileHelper(
    from prior: AcceptanceReleaseReference?, to target: AcceptanceReleaseReference
  ) throws {
    guard prior == self.prior, target == self.target else {
      throw ReleasePackageError.verification("helper reconciliation authority changed")
    }
    _ = try entry(for: target)
    if try helperChangesAcrossTransaction() {
      let loaded = try launchTargetLoaded("system/systems.reach.meshd", label: "helper-before")
      if !loaded {
        _ = try runner.run(
          "/bin/launchctl",
          ["bootstrap", "system", "/Library/LaunchDaemons/systems.reach.meshd.plist"],
          timeout: 30, logURL: nextLog("helper-bootstrap"))
      }
      guard try launchTargetLoaded("system/systems.reach.meshd", label: "helper-after") else {
        throw ReleasePackageError.verification("helper did not become loaded")
      }
    } else {
      guard try launchTargetLoaded("system/systems.reach.meshd", label: "helper-preserved") else {
        throw ReleasePackageError.verification("unchanged helper was not preserved")
      }
    }
  }

  public func startHost(ownerUID: UInt32) throws {
    guard ownerUID == self.ownerUID else {
      throw ReleasePackageError.verification("guest owner changed during host start")
    }
    let launchTarget = "gui/\(ownerUID)/systems.reach.reachd"
    if try launchTargetLoaded(launchTarget, label: "host-before") { return }
    _ = try runner.run(
      "/usr/bin/sudo",
      [
        "-u", "#\(ownerUID)", "-H", "--",
        "/Library/Application Support/Reach/Host/reachd",
        "service", "install", "--no-load",
      ], timeout: 30, logURL: nextLog("host-definition"))
    let plist = ownerHome.appendingPathComponent(
      "Library/LaunchAgents/systems.reach.reachd.plist")
    _ = try runner.run(
      "/bin/launchctl", ["bootstrap", "gui/\(ownerUID)", plist.path],
      timeout: 30, logURL: nextLog("host-bootstrap"))
    guard try launchTargetLoaded(launchTarget, label: "host-after") else {
      throw ReleasePackageError.verification("host did not become loaded")
    }
  }

  public func verifyRuntime(_ release: AcceptanceReleaseReference) throws {
    _ = try entry(for: release)
    try requireRootRuntimeStateAbsent()
    let prefix = ["-u", "#\(ownerUID)", "-H", "--", Self.canonicalHost]
    _ = try runner.run(
      "/usr/bin/sudo", prefix + ["selftest"], timeout: 300,
      logURL: nextLog("scripted-selftest"))
    _ = try runner.run(
      "/usr/bin/sudo", prefix + ["selftest", "--mlx", "--runs", "1"],
      timeout: 1_800, logURL: nextLog("mlx-selftest"))
    _ = try runner.run(
      "/usr/bin/sudo", prefix + ["doctor", "--dial"], timeout: 300,
      logURL: nextLog("authenticated-dial"))
    try requireRootRuntimeStateAbsent()
  }

  public func verifyAccepted(_ release: AcceptanceReleaseReference) throws {
    let entry = try entry(for: release)
    let snapshot = try nextScratch("accepted-snapshot").appendingPathComponent("snapshot.json")
    let accepted = try MacOSInstalledStateCollector(runner: runner).collect(
      retainedAuthority: entry.root,
      policy: .init(
        selectedOwnerUID: ownerUID, selectedOwnerHome: ownerHome.path,
        host: .running,
        helper: finalHelper, retainedState: finalState),
      ownerHome: ownerHome,
      scratch: try nextScratch("accepted-collection"), output: snapshot)
    if action != .verify {
      let baseline = try requireBaseline()
      guard accepted.retainedState.preservesExactAuthority(from: baseline.observation) else {
        throw ReleasePackageError.verification("accepted release changed retained login state")
      }
    }
  }

  public func finalize(
    action: AcceptanceTransactionAction,
    release: AcceptanceReleaseReference
  ) throws {
    guard action == self.action else {
      throw ReleasePackageError.verification("transaction finalization action changed")
    }
    if action == .migrate {
      guard let record = try migrationStore.load(), record.transactionID == transactionID,
        record.selectedOwnerUID == ownerUID
      else {
        throw ReleasePackageError.verification("unmanaged migration authority is absent")
      }
      try UnmanagedHostMigration(runner: runner).retire(
        record: record, release: entry(for: release), ownerHome: ownerHome,
        scratch: try nextScratch("unmanaged-migration-retirement"))
    }
  }

  public func uninstall(_ release: AcceptanceReleaseReference) throws {
    let entry = try entry(for: release)
    let expectation = try InstalledReleaseStateVerifier(runner: runner).expectedState(
      retainedAuthority: entry.root, scratch: try nextScratch("uninstall-authority"))
    let records = try InstalledReleaseStateVerifier(runner: runner).mergedPayload(
      expectation.host + expectation.helper)
    let leaves = records.filter { $0.kind != .directory }
    let present = try leaves.filter { try pathExistsNoFollow($0.path) }
    if present.isEmpty {
      try verifyUninstalled(release)
      return
    }
    if present.count != leaves.count {
      // Restore only the exact trusted release before retrying teardown. A
      // partially removed authority is never treated as a valid installed
      // state and no loose file copy is used.
      try install(release)
      try verifyInstalled(release)
    }
    for record in leaves {
      let observed = try observeExactFile(record)
      guard observed.path == record.path else {
        throw ReleasePackageError.verification("uninstall payload authority changed")
      }
    }
    try removeExactPackagePayload(expected: Set(records.map(\.path)))
    let launchAgent = ownerHome.appendingPathComponent(
      "Library/LaunchAgents/systems.reach.reachd.plist")
    try removeIfExactRegularFile(launchAgent, ownerUID: ownerUID)
    try removeHelperRuntime()
    for identifier in ["systems.reach.host", "systems.reach.meshd"] {
      _ = try runner.run(
        "/usr/sbin/pkgutil", ["--forget", identifier],
        timeout: 20, logURL: nextLog("forget-\(identifier)"))
    }
  }

  public func verifyUninstalled(_ release: AcceptanceReleaseReference) throws {
    _ = try entry(for: release)
    for path in Self.packageLeaves + [
      ownerHome.appendingPathComponent("Library/LaunchAgents/systems.reach.reachd.plist").path,
      "/Library/Application Support/Reach Mesh", "/var/run/systems.reach.meshd.sock",
    ] {
      guard try !pathExistsNoFollow(path) else {
        throw ReleasePackageError.verification("uninstall left package or helper authority")
      }
    }
    for identifier in ["systems.reach.host", "systems.reach.meshd"] {
      let result = try runner.run(
        "/usr/sbin/pkgutil", ["--pkg-info-plist", identifier],
        timeout: 10, logURL: nextLog("receipt-absent-\(identifier)"), requireSuccess: false)
      guard result.exitStatus != 0 else {
        throw ReleasePackageError.verification("uninstall left a package receipt")
      }
    }
    let before = try requireBaseline().observation
    let after = try MacOSInstalledStateCollector(runner: runner).observeState(
      ownerHome.appendingPathComponent("Library/Application Support/Reach"),
      expectedOwnerUID: ownerUID)
    guard after.preservesExactAuthority(from: before) else {
      throw ReleasePackageError.verification("uninstall changed login-owned retained state")
    }
  }

  private func helperChangesAcrossTransaction() throws -> Bool {
    guard let target else { return action == .uninstall }
    let targetValue = try entry(for: target)
    guard let prior else { return true }
    return try entry(for: prior).helperComponentSHA256 != targetValue.helperComponentSHA256
  }

  private func requireRootRuntimeStateAbsent() throws {
    let forbidden = [
      "/var/root/Library/Application Support/Reach",
      "/var/root/Library/Caches/systems.reach",
      "/var/root/.cache/huggingface",
      "/var/root/.cache/mlx",
    ]
    for path in forbidden {
      guard try !pathExistsNoFollow(path) else {
        throw ReleasePackageError.verification(
          "packaged runtime created login or model authority under root")
      }
    }
  }

  private func receiptVersion(_ identifier: String) throws -> DottedVersion? {
    let result = try runner.run(
      "/usr/sbin/pkgutil", ["--pkg-info-plist", identifier],
      timeout: 10, requireSuccess: false)
    guard result.exitStatus == 0 else { return nil }
    guard
      let object = try PropertyListSerialization.propertyList(
        from: Data(result.output.utf8), format: nil) as? [String: Any],
      object["pkgid"] as? String == identifier,
      let value = object["pkg-version"] as? String
    else {
      throw ReleasePackageError.verification(
        "Installer receipt observation is malformed")
    }
    return try DottedVersion(value)
  }

  private func requireReceiptsSettled() throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(3))
    var previous: [DottedVersion?]?
    var stableSamples = 0
    while clock.now < deadline {
      let current = try [
        receiptVersion("systems.reach.host"),
        receiptVersion("systems.reach.meshd"),
      ]
      if current == previous {
        stableSamples += 1
        if stableSamples >= 5 { return }
      } else {
        previous = current
        stableSamples = 0
      }
      usleep(50_000)
    }
    throw ReleasePackageError.verification(
      "Installer receipts did not settle after the observed interruption")
  }

  private func installedAuthorityMatches(
    _ entry: RetainedReleaseCatalogEntry
  ) throws -> Bool {
    let state = try currentStateRequirement()
    for helper in [
      InstalledHelperRequirement.stopped, .unconfigured, .directReady,
    ] {
      let attempt = try nextScratch(
        "interruption-classify-\(entry.reference.versions.product)-\(helper.rawValue)")
      do {
        _ = try MacOSInstalledStateCollector(runner: runner).collect(
          retainedAuthority: entry.root,
          policy: .init(
            selectedOwnerUID: ownerUID, selectedOwnerHome: ownerHome.path,
            host: .stopped,
            helper: helper, retainedState: state),
          ownerHome: ownerHome,
          scratch: attempt.appendingPathComponent("scratch"),
          output: attempt.appendingPathComponent("snapshot.json"))
        return true
      } catch {
        continue
      }
    }
    return false
  }

  private func entry(for release: AcceptanceReleaseReference) throws
    -> RetainedReleaseCatalogEntry
  {
    guard let entry = entries[release.p5SHA256], entry.reference == release else {
      throw ReleasePackageError.verification("transaction release is outside the retained catalog")
    }
    return entry
  }

  private func currentStateRequirement() throws -> RetainedStateRequirement {
    let state = ownerHome.appendingPathComponent("Library/Application Support/Reach")
    return try pathExistsNoFollow(state.path) ? .present : .absent
  }

  private func requireUnloaded(_ target: String, label: String) throws {
    let result = try runner.run(
      "/bin/launchctl", ["print", target], timeout: 10,
      logURL: nextLog("\(label)-unloaded"), requireSuccess: false)
    guard result.exitStatus != 0 else {
      throw ReleasePackageError.verification("\(label) remained loaded")
    }
  }

  private func launchTargetLoaded(_ target: String, label: String) throws -> Bool {
    let result = try runner.run(
      "/bin/launchctl", ["print", target], timeout: 10,
      logURL: nextLog(label), requireSuccess: false)
    return result.exitStatus == 0
  }

  private func requireBaseline() throws -> AcceptanceRetainedStateBaseline {
    guard let value = try baselineStore.load(), value.transactionID == transactionID,
      value.selectedOwnerUID == ownerUID
    else {
      throw ReleasePackageError.verification("transaction retained-state baseline is absent")
    }
    return value
  }

  private func observeExactFile(_ record: PayloadRecord) throws -> InstalledFileObservation {
    let url = URL(fileURLWithPath: record.path)
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      throw ReleasePackageError.verification("uninstall payload member is missing")
    }
    let sha: String?
    let target: String?
    let kind: PayloadKind
    if (info.st_mode & S_IFMT) == S_IFREG {
      kind = .file
      sha = try Digests.sha256(file: url)
      target = nil
    } else if (info.st_mode & S_IFMT) == S_IFLNK {
      kind = .symlink
      target = try FileManager.default.destinationOfSymbolicLink(atPath: url.path)
      sha = Digests.sha256(Data((target ?? "").utf8))
    } else {
      throw ReleasePackageError.unsafePath("uninstall leaf is not a regular file or symlink")
    }
    let value = InstalledFileObservation(
      path: record.path, kind: kind, mode: UInt32(info.st_mode & 0o7777),
      uid: info.st_uid, gid: info.st_gid, size: UInt64(info.st_size), sha256: sha,
      linkTarget: target, device: UInt64(info.st_dev), inode: UInt64(info.st_ino))
    guard value.kind == record.kind, value.mode == (record.mode & 0o7777),
      value.uid == 0, value.gid == 0, value.size == record.size,
      value.sha256 == record.sha256, value.linkTarget == record.linkTarget
    else {
      throw ReleasePackageError.verification("uninstall refused a changed package leaf")
    }
    return value
  }

  private func removeExactPackagePayload(expected: Set<String>) throws {
    let packageRoot = "/Library/Application Support/Reach"
    var actual: Set<String> = []
    if try pathExistsNoFollow(packageRoot) {
      actual.insert(packageRoot)
      for url in try SecureFiles.enumerateTree(URL(fileURLWithPath: packageRoot)) {
        actual.insert(url.path)
      }
    }
    for path in Self.packageLeaves where try pathExistsNoFollow(path) {
      actual.insert(path)
    }
    guard actual.isSubset(of: expected) else {
      throw ReleasePackageError.verification("uninstall found an unowned immutable path")
    }
    for path in Self.packageLeaves {
      if try pathExistsNoFollow(path) {
        try FileManager.default.removeItem(atPath: path)
      }
    }
  }

  private func removeIfExactRegularFile(_ url: URL, ownerUID: UInt32) throws {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      if errno == ENOENT { return }
      throw ReleasePackageError.verification("cannot inspect login launch definition")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
      info.st_uid == ownerUID, info.st_gid != 0, (info.st_mode & 0o7777) == 0o600,
      let object = try PropertyListSerialization.propertyList(
        from: Data(contentsOf: url, options: [.mappedIfSafe]), format: nil)
        as? [String: Any],
      Set(object.keys)
        == Set([
          "Label", "ProgramArguments", "EnvironmentVariables", "RunAtLoad",
          "KeepAlive", "ThrottleInterval", "StandardOutPath", "StandardErrorPath",
          "ProcessType",
        ]),
      object["Label"] as? String == "systems.reach.reachd",
      object["ProgramArguments"] as? [String]
        == ["/Library/Application Support/Reach/Host/reachd", "serve"],
      object["EnvironmentVariables"] as? [String: String]
        == [
          "REACH_STATE_DIR": ownerHome.appendingPathComponent(
            "Library/Application Support/Reach"
          ).path
        ],
      object["RunAtLoad"] as? Bool == true,
      object["KeepAlive"] as? Bool == true,
      object["ThrottleInterval"] as? Int == 10,
      object["StandardOutPath"] as? String
        == ownerHome.appendingPathComponent("Library/Logs/reachd.log").path,
      object["StandardErrorPath"] as? String
        == ownerHome.appendingPathComponent("Library/Logs/reachd.log").path,
      object["ProcessType"] as? String == "Interactive"
    else {
      throw ReleasePackageError.unsafePath("login launch definition is not transaction-owned")
    }
    try FileManager.default.removeItem(at: url)
  }

  private func removeHelperRuntime() throws {
    let root = URL(fileURLWithPath: "/Library/Application Support/Reach Mesh")
    if try pathExistsNoFollow(root.path) {
      var info = stat()
      guard lstat(root.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
        info.st_uid == 0, info.st_gid == 0
      else {
        throw ReleasePackageError.unsafePath("helper runtime root is not root-owned")
      }
      for url in try SecureFiles.enumerateTree(root) {
        guard url.path.hasPrefix(root.path + "/") else {
          throw ReleasePackageError.unsafePath("helper runtime escaped its exact root")
        }
        var child = stat()
        guard lstat(url.path, &child) == 0, child.st_uid == 0,
          (child.st_mode & S_IFMT) != S_IFLNK
        else {
          throw ReleasePackageError.unsafePath("helper runtime contains unowned authority")
        }
      }
      try FileManager.default.removeItem(at: root)
    }
    for path in ["/var/run/systems.reach.meshd.sock", "/var/log/systems.reach.meshd.log"] {
      if try pathExistsNoFollow(path) {
        var info = stat()
        guard lstat(path, &info) == 0, info.st_uid == 0,
          (info.st_mode & S_IFMT) != S_IFLNK
        else {
          throw ReleasePackageError.unsafePath("helper runtime leaf is unowned")
        }
        try FileManager.default.removeItem(atPath: path)
      }
    }
  }

  private func nextLog(_ label: String) -> URL {
    logIndex += 1
    return scratch.appendingPathComponent(String(format: "%03d-%@.log", logIndex, label))
  }

  private func pathExistsNoFollow(_ path: String) throws -> Bool {
    var info = stat()
    if lstat(path, &info) == 0 { return true }
    if errno == ENOENT { return false }
    throw ReleasePackageError.verification("cannot inspect transaction path")
  }

  private func nextScratch(_ label: String) throws -> URL {
    logIndex += 1
    let url = scratch.appendingPathComponent(String(format: "%03d-%@", logIndex, label))
    try SecureFiles.createPrivateDirectory(url)
    return url
  }

  private static let packageLeaves = [
    "/Library/Application Support/Reach/Host",
    "/Library/Application Support/Reach/Release/payload-manifest.json",
    "/Library/Application Support/Reach/Release",
    "/Library/Application Support/Reach",
    "/usr/local/bin/reachd",
    "/Library/PrivilegedHelperTools/systems.reach.meshd",
    "/Library/LaunchDaemons/systems.reach.meshd.plist",
  ]

  private static let canonicalHost = "/Library/Application Support/Reach/Host/reachd"
}
