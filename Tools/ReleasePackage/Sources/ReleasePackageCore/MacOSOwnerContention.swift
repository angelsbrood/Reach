import Darwin
import Foundation

public enum OwnerContentionPhase: String, CaseIterable, Codable, Sendable {
  case primaryRecorded = "primary-recorded"
  case contenderRefused = "contender-refused"
  case contenderActive = "contender-active"
  case primaryRestored = "primary-restored"
}

enum OwnerContentionApplicationDecision: Equatable, Sendable {
  case refused
  case active
}

struct OwnerContentionApplicationObservation: Equatable, Sendable {
  let jobLoaded: Bool
  let processRunning: Bool
  let runCount: Int
  let lastExitStatus: Int32?
  let statePresent: Bool
  let caCreationCount: Int
  let log: String
}

public struct OwnerContentionJournal: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let packageSHA256: String
  public let primaryUID: UInt32
  public let contenderUID: UInt32
  public let primaryAuthoritySHA256: String
  public let phase: OwnerContentionPhase
  public let contenderServiceLoaded: Bool?
  public let contenderStatePresent: Bool?
  public let contenderCACreationCount: Int?

  public init(
    packageSHA256: String,
    primaryUID: UInt32,
    contenderUID: UInt32,
    primaryAuthoritySHA256: String,
    phase: OwnerContentionPhase,
    contenderServiceLoaded: Bool? = nil,
    contenderStatePresent: Bool? = nil,
    contenderCACreationCount: Int? = nil
  ) {
    schemaVersion = 1
    self.packageSHA256 = packageSHA256
    self.primaryUID = primaryUID
    self.contenderUID = contenderUID
    self.primaryAuthoritySHA256 = primaryAuthoritySHA256
    self.phase = phase
    self.contenderServiceLoaded = contenderServiceLoaded
    self.contenderStatePresent = contenderStatePresent
    self.contenderCACreationCount = contenderCACreationCount
  }

  public func validate() throws {
    let sha = "^[0-9a-f]{64}$"
    guard schemaVersion == 1, primaryUID != 0, contenderUID != 0,
      primaryUID != contenderUID,
      [packageSHA256, primaryAuthoritySHA256].allSatisfy({
        $0.range(of: sha, options: .regularExpression) != nil
      })
    else {
      throw ReleasePackageError.verification("owner-contention journal is malformed")
    }
    switch phase {
    case .primaryRecorded:
      guard contenderServiceLoaded == nil, contenderStatePresent == nil,
        contenderCACreationCount == nil
      else {
        throw ReleasePackageError.verification(
          "primary contention checkpoint already claims a contender result")
      }
    case .contenderRefused, .primaryRestored:
      guard contenderServiceLoaded == false, contenderStatePresent == false,
        contenderCACreationCount == 0
      else {
        throw ReleasePackageError.verification(
          "refused contention checkpoint contains a second authority")
      }
    case .contenderActive:
      guard let contenderServiceLoaded, let contenderStatePresent,
        let contenderCACreationCount, contenderCACreationCount >= 0,
        contenderServiceLoaded || contenderStatePresent
      else {
        throw ReleasePackageError.verification(
          "active contention checkpoint lacks a second authority")
      }
    }
  }

  func recording(
    _ decision: OwnerContentionApplicationDecision,
    contenderServiceLoaded: Bool,
    contenderStatePresent: Bool,
    contenderCACreationCount: Int
  ) throws -> Self {
    try validate()
    guard phase == .primaryRecorded else {
      throw ReleasePackageError.verification(
        "contender decision is out of order")
    }
    let value = Self(
      packageSHA256: packageSHA256,
      primaryUID: primaryUID,
      contenderUID: contenderUID,
      primaryAuthoritySHA256: primaryAuthoritySHA256,
      phase: decision == .refused ? .contenderRefused : .contenderActive,
      contenderServiceLoaded: contenderServiceLoaded,
      contenderStatePresent: contenderStatePresent,
      contenderCACreationCount: contenderCACreationCount)
    try value.validate()
    return value
  }

  func restoringPrimary() throws -> Self {
    try validate()
    guard phase == .contenderRefused else {
      throw ReleasePackageError.verification(
        "primary restoration lacks an attributable contender refusal")
    }
    let value = Self(
      packageSHA256: packageSHA256,
      primaryUID: primaryUID,
      contenderUID: contenderUID,
      primaryAuthoritySHA256: primaryAuthoritySHA256,
      phase: .primaryRestored,
      contenderServiceLoaded: false,
      contenderStatePresent: false,
      contenderCACreationCount: 0)
    try value.validate()
    return value
  }
}

public struct OwnerContentionReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let packageSHA256: String
  public let primaryAuthoritySHA256: String
  public let primaryAuthorityPreserved: Bool
  public let contenderServiceLoaded: Bool
  public let contenderStatePresent: Bool
  public let contenderCACreationCount: Int
  public let verdict: String

  public init(
    packageSHA256: String,
    primaryAuthoritySHA256: String,
    primaryAuthorityPreserved: Bool,
    contenderServiceLoaded: Bool,
    contenderStatePresent: Bool,
    contenderCACreationCount: Int
  ) {
    schemaVersion = 1
    self.packageSHA256 = packageSHA256
    self.primaryAuthoritySHA256 = primaryAuthoritySHA256
    self.primaryAuthorityPreserved = primaryAuthorityPreserved
    self.contenderServiceLoaded = contenderServiceLoaded
    self.contenderStatePresent = contenderStatePresent
    self.contenderCACreationCount = contenderCACreationCount
    verdict =
      contenderServiceLoaded || contenderStatePresent
      ? "owner-contention-stop"
      : "pass"
  }

  public func validate() throws {
    guard schemaVersion == 1,
      [packageSHA256, primaryAuthoritySHA256].allSatisfy({
        $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
      }), primaryAuthorityPreserved, contenderCACreationCount >= 0,
      ["pass", "owner-contention-stop"].contains(verdict),
      (verdict == "owner-contention-stop")
        == (contenderServiceLoaded || contenderStatePresent)
    else {
      throw ReleasePackageError.verification("owner-contention report is malformed")
    }
  }
}

/// A real ownership probe spans three founder-visible console sessions. The
/// driver never calls a LaunchAgent restart a logout: `begin` requires the
/// primary console owner, `checkContender` requires the second console owner,
/// and `finish` requires the primary console owner again. The mode-0600
/// journal binds those independent invocations to one package and state hash.
public struct MacOSOwnerContentionProbe {
  static let selectedOwnerRefusalLine =
    "Error: this Mac is already bound to another Reach login owner"

  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) { self.runner = runner }

  public func begin(
    retainedAuthority: URL,
    primaryUID: UInt32,
    primaryHome: URL,
    contenderUID: UInt32,
    contenderHome: URL,
    journalURL: URL,
    scratch: URL
  ) throws -> OwnerContentionJournal {
    try validateDistinctOwners(
      primaryUID: primaryUID, primaryHome: primaryHome,
      contenderUID: contenderUID, contenderHome: contenderHome)
    guard try consoleOwnerUID() == primaryUID else {
      throw ReleasePackageError.verification(
        "owner contention must begin in the primary console login")
    }
    try SecureFiles.createPrivateDirectory(scratch)
    let entry = try RetainedReleaseCatalogEntry(root: retainedAuthority)
    let collector = MacOSInstalledStateCollector(runner: runner)
    let primary = try collector.observeState(
      stateRoot(primaryHome), expectedOwnerUID: primaryUID)
    guard primary.present, primary.caCreationCount == 1,
      let authority = primary.authoritySHA256,
      try loaded(target(primaryUID), log: scratch.appendingPathComponent("primary-live.log"))
    else {
      throw ReleasePackageError.verification(
        "primary login lacks one live accepted cluster authority")
    }
    let contender = try collector.observeState(
      stateRoot(contenderHome), expectedOwnerUID: contenderUID)
    guard !contender.present,
      try !loaded(
        target(contenderUID), log: scratch.appendingPathComponent("contender-absent.log"))
    else {
      throw ReleasePackageError.verification(
        "contender login is not service- and state-free before logout")
    }
    let journal = OwnerContentionJournal(
      packageSHA256: entry.reference.p5SHA256,
      primaryUID: primaryUID,
      contenderUID: contenderUID,
      primaryAuthoritySHA256: authority,
      phase: .primaryRecorded)
    try writeNew(journal, to: journalURL)
    return journal
  }

  public func checkContender(
    retainedAuthority: URL,
    primaryUID: UInt32,
    primaryHome: URL,
    contenderUID: UInt32,
    contenderHome: URL,
    journalURL: URL,
    scratch: URL,
    output: URL
  ) throws -> OwnerContentionReport {
    var journal = try load(journalURL)
    guard journal.primaryUID == primaryUID, journal.contenderUID == contenderUID,
      journal.phase == .primaryRecorded,
      try consoleOwnerUID() == journal.contenderUID
    else {
      throw ReleasePackageError.verification(
        "contender check requires the actual second console login")
    }
    try validateDistinctOwners(
      primaryUID: journal.primaryUID, primaryHome: primaryHome,
      contenderUID: journal.contenderUID, contenderHome: contenderHome)
    let entry = try RetainedReleaseCatalogEntry(root: retainedAuthority)
    guard entry.reference.p5SHA256 == journal.packageSHA256 else {
      throw ReleasePackageError.verification("contention package authority changed")
    }
    try SecureFiles.createPrivateDirectory(scratch)
    guard
      try !loaded(
        target(journal.primaryUID), log: scratch.appendingPathComponent("primary-logged-out.log"))
    else {
      throw ReleasePackageError.verification(
        "primary GUI service survived the founder-observed logout")
    }
    let collector = MacOSInstalledStateCollector(runner: runner)
    let primary = try collector.observeState(
      stateRoot(primaryHome), expectedOwnerUID: journal.primaryUID)
    guard primary.authoritySHA256 == journal.primaryAuthoritySHA256,
      primary.caCreationCount == 1
    else {
      throw ReleasePackageError.verification("logout changed the primary cluster authority")
    }
    let contenderBefore = try collector.observeState(
      stateRoot(contenderHome), expectedOwnerUID: journal.contenderUID)
    guard !contenderBefore.present else {
      throw ReleasePackageError.verification("contender state appeared before its attempt")
    }
    let contenderLog = contenderHome.appendingPathComponent("Library/Logs/reachd.log")
    var contenderLogInfo = stat()
    guard lstat(contenderLog.path, &contenderLogInfo) != 0, errno == ENOENT else {
      throw ReleasePackageError.verification(
        "contender log was not absent before its application attempt")
    }

    let contenderTarget = target(journal.contenderUID)
    let definition = try runner.run(
      "/usr/bin/sudo",
      [
        "-u", "#\(journal.contenderUID)", "-H", "--",
        "/Library/Application Support/Reach/Host/reachd",
        "service", "install", "--no-load",
      ], timeout: 30, logURL: scratch.appendingPathComponent("contender-definition.log"),
      requireSuccess: false)
    try Self.requireDefinitionInstalled(definition)
    let contenderDefinition = try exactContenderDefinition(
      contenderHome, uid: journal.contenderUID)
    let bootstrap = try runner.run(
      "/bin/launchctl",
      [
        "bootstrap", "gui/\(journal.contenderUID)", contenderDefinition.path,
      ], timeout: 30, logURL: scratch.appendingPathComponent("contender-bootstrap.log"),
      requireSuccess: false)
    do {
      try Self.requireBootstrapSucceeded(bootstrap)
    } catch {
      try removeExactContenderDefinition(contenderHome, uid: journal.contenderUID)
      throw error
    }

    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(5))
    var contenderJob = try launchObservation(
      contenderTarget,
      log: scratch.appendingPathComponent("contender-state-initial.log"))
    var contenderState = contenderBefore
    repeat {
      contenderJob = try launchObservation(
        contenderTarget,
        log: scratch.appendingPathComponent("contender-state-\(UUID().uuidString).log"))
      contenderState = try collector.observeState(
        stateRoot(contenderHome), expectedOwnerUID: journal.contenderUID)
      if Self.applicationDecisionSettled(
        processRunning: contenderJob.processRunning,
        runCount: contenderJob.runCount,
        lastExitStatus: contenderJob.lastExitStatus,
        statePresent: contenderState.present)
      {
        break
      }
      usleep(50_000)
    } while clock.now < deadline

    let applicationLog = try readApplicationLogIfPresent(
      contenderLog, ownerUID: journal.contenderUID)
    let decision = try Self.classify(
      .init(
        jobLoaded: contenderJob.loaded,
        processRunning: contenderJob.processRunning,
        runCount: contenderJob.runCount,
        lastExitStatus: contenderJob.lastExitStatus,
        statePresent: contenderState.present,
        caCreationCount: contenderState.caCreationCount,
        log: applicationLog))
    _ = try runner.run(
      "/bin/launchctl", ["bootout", contenderTarget], timeout: 15,
      logURL: scratch.appendingPathComponent("contender-stop.log"), requireSuccess: false)
    guard
      try !loaded(
        contenderTarget,
        log: scratch.appendingPathComponent("contender-stopped-verification.log"))
    else {
      throw ReleasePackageError.verification(
        "contender service survived its bounded application decision")
    }
    let contenderFinalState = try collector.observeState(
      stateRoot(contenderHome), expectedOwnerUID: journal.contenderUID)
    if decision == .refused {
      try Self.requireSettledRefusal(contenderFinalState)
      try removeExactContenderDefinition(contenderHome, uid: journal.contenderUID)
    }
    journal = try journal.recording(
      decision,
      contenderServiceLoaded: decision == .active && contenderJob.loaded,
      contenderStatePresent: contenderFinalState.present,
      contenderCACreationCount: contenderFinalState.caCreationCount)
    try replace(journal, at: journalURL)
    let report = OwnerContentionReport(
      packageSHA256: journal.packageSHA256,
      primaryAuthoritySHA256: journal.primaryAuthoritySHA256,
      primaryAuthorityPreserved: true,
      contenderServiceLoaded: decision == .active && contenderJob.loaded,
      contenderStatePresent: contenderFinalState.present,
      contenderCACreationCount: contenderFinalState.caCreationCount)
    try report.validate()
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(report), to: output)
    return report
  }

  static func requireDefinitionInstalled(_ result: CommandResult) throws {
    guard result.exitStatus == 0 else {
      throw ReleasePackageError.verification(
        "contender did not reach the selected-owner acquisition boundary")
    }
  }

  static func requireBootstrapSucceeded(_ result: CommandResult) throws {
    guard result.exitStatus == 0 else {
      throw ReleasePackageError.verification(
        "launchd refusal is not attributable to the selected-owner boundary")
    }
  }

  static func classify(
    _ observation: OwnerContentionApplicationObservation
  ) throws -> OwnerContentionApplicationDecision {
    guard observation.caCreationCount >= 0 else {
      throw ReleasePackageError.verification(
        "contender application observation is malformed")
    }
    if observation.processRunning || observation.statePresent {
      return .active
    }
    let lines = observation.log.split(whereSeparator: \.isNewline).map(String.init)
    guard observation.jobLoaded, observation.runCount > 0,
      let status = observation.lastExitStatus, status != 0,
      lines.contains(selectedOwnerRefusalLine),
      !lines.contains("[reachd] cluster CA created")
    else {
      throw ReleasePackageError.verification(
        "contender application ended without an attributable selected-owner refusal")
    }
    return .refused
  }

  static func applicationDecisionSettled(
    processRunning: Bool,
    runCount: Int,
    lastExitStatus: Int32?,
    statePresent: Bool
  ) -> Bool {
    if statePresent { return true }
    if processRunning { return false }
    return runCount > 0 && lastExitStatus != nil
  }

  static func requireSettledRefusal(
    _ state: RetainedStateObservation
  ) throws {
    guard !state.present, state.caCreationCount == 0 else {
      throw ReleasePackageError.verification(
        "contender created cluster authority before confirmed unload")
    }
  }

  public func finish(
    retainedAuthority: URL,
    primaryUID: UInt32,
    primaryHome: URL,
    contenderUID: UInt32,
    contenderHome: URL,
    journalURL: URL,
    scratch: URL,
    output: URL
  ) throws -> OwnerContentionReport {
    var journal = try load(journalURL)
    guard journal.primaryUID == primaryUID, journal.contenderUID == contenderUID,
      journal.phase == .contenderRefused,
      try consoleOwnerUID() == journal.primaryUID
    else {
      throw ReleasePackageError.verification(
        "contention finish requires the restored primary console login")
    }
    try validateDistinctOwners(
      primaryUID: journal.primaryUID, primaryHome: primaryHome,
      contenderUID: journal.contenderUID, contenderHome: contenderHome)
    let entry = try RetainedReleaseCatalogEntry(root: retainedAuthority)
    guard entry.reference.p5SHA256 == journal.packageSHA256 else {
      throw ReleasePackageError.verification("contention package authority changed")
    }
    try SecureFiles.createPrivateDirectory(scratch)
    guard
      try loaded(
        target(journal.primaryUID), log: scratch.appendingPathComponent("primary-restored.log")),
      try !loaded(
        target(journal.contenderUID), log: scratch.appendingPathComponent("contender-gone.log"))
    else {
      throw ReleasePackageError.verification("console ownership did not restore one service")
    }
    let collector = MacOSInstalledStateCollector(runner: runner)
    let primary = try collector.observeState(
      stateRoot(primaryHome), expectedOwnerUID: journal.primaryUID)
    let contender = try collector.observeState(
      stateRoot(contenderHome), expectedOwnerUID: journal.contenderUID)
    guard primary.authoritySHA256 == journal.primaryAuthoritySHA256,
      primary.caCreationCount == 1, !contender.present
    else {
      throw ReleasePackageError.verification(
        "restored login changed primary or contender authority")
    }
    journal = try journal.restoringPrimary()
    try replace(journal, at: journalURL)
    let report = OwnerContentionReport(
      packageSHA256: journal.packageSHA256,
      primaryAuthoritySHA256: journal.primaryAuthoritySHA256,
      primaryAuthorityPreserved: true,
      contenderServiceLoaded: false,
      contenderStatePresent: false,
      contenderCACreationCount: 0)
    try report.validate()
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(report), to: output)
    return report
  }

  private func validateDistinctOwners(
    primaryUID: UInt32,
    primaryHome: URL,
    contenderUID: UInt32,
    contenderHome: URL
  ) throws {
    guard primaryUID != 0, contenderUID != 0, primaryUID != contenderUID else {
      throw ReleasePackageError.invalidArgument(
        "owner-contention requires two distinct non-root users")
    }
    try validateHome(primaryHome, ownerUID: primaryUID, label: "primary")
    try validateHome(contenderHome, ownerUID: contenderUID, label: "contender")
  }

  private func validateHome(_ home: URL, ownerUID: UInt32, label: String) throws {
    guard home.path.hasPrefix("/Users/"), home.path.split(separator: "/").count == 2 else {
      throw ReleasePackageError.unsafePath(label + " home must be one direct /Users child")
    }
    var info = stat()
    guard lstat(home.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
      info.st_uid == ownerUID
    else {
      throw ReleasePackageError.verification(label + " home owner changed")
    }
  }

  private func consoleOwnerUID() throws -> UInt32 {
    var info = stat()
    guard lstat("/dev/console", &info) == 0, (info.st_mode & S_IFMT) == S_IFCHR,
      info.st_uid != 0
    else {
      throw ReleasePackageError.verification("no non-root console owner is active")
    }
    return info.st_uid
  }

  private func stateRoot(_ home: URL) -> URL {
    home.appendingPathComponent("Library/Application Support/Reach")
  }

  private func target(_ uid: UInt32) -> String {
    "gui/\(uid)/systems.reach.reachd"
  }

  private func loaded(_ target: String, log: URL) throws -> Bool {
    try runner.run(
      "/bin/launchctl", ["print", target], timeout: 10,
      logURL: log, requireSuccess: false
    ).exitStatus == 0
  }

  private struct LaunchObservation {
    let loaded: Bool
    let processRunning: Bool
    let runCount: Int
    let lastExitStatus: Int32?
  }

  private func launchObservation(_ target: String, log: URL) throws -> LaunchObservation {
    let result = try runner.run(
      "/bin/launchctl", ["print", target], timeout: 10,
      logURL: log, requireSuccess: false)
    guard result.exitStatus == 0 else {
      return .init(loaded: false, processRunning: false, runCount: 0, lastExitStatus: nil)
    }
    func integer(_ pattern: String) -> Int? {
      guard
        let range = result.output.range(of: pattern, options: .regularExpression),
        let digits = result.output[range].range(of: #"-?[0-9]+"#, options: .regularExpression)
      else { return nil }
      return Int(result.output[range][digits])
    }
    let pid = integer(#"(?m)^\s*pid\s*=\s*[0-9]+\s*$"#) ?? 0
    let runs = integer(#"(?m)^\s*runs\s*=\s*[0-9]+\s*$"#) ?? 0
    let status = integer(#"(?m)^\s*last exit (?:code|status)\s*=\s*-?[0-9]+\s*$"#)
      .flatMap(Int32.init)
    return .init(
      loaded: true, processRunning: pid > 0,
      runCount: runs, lastExitStatus: status)
  }

  private func readApplicationLogIfPresent(_ url: URL, ownerUID: UInt32) throws -> String {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      if errno == ENOENT { return "" }
      throw ReleasePackageError.verification("cannot inspect contender application log")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
      info.st_uid == ownerUID, [mode_t(0o600), mode_t(0o644)].contains(info.st_mode & 0o7777),
      info.st_size <= 64 * 1_024
    else {
      throw ReleasePackageError.unsafePath(
        "contender application log authority changed")
    }
    return String(
      decoding: try Data(contentsOf: url, options: [.mappedIfSafe]), as: UTF8.self)
  }

  private func writeNew(_ journal: OwnerContentionJournal, to url: URL) throws {
    try journal.validate()
    var info = stat()
    guard lstat(url.path, &info) != 0, errno == ENOENT else {
      throw ReleasePackageError.verification("owner-contention journal already exists")
    }
    try SecureFiles.createPrivateDirectory(url.deletingLastPathComponent())
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(journal), to: url)
  }

  private func replace(_ journal: OwnerContentionJournal, at url: URL) throws {
    _ = try load(url)
    try journal.validate()
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(journal), to: url)
  }

  private func load(_ url: URL) throws -> OwnerContentionJournal {
    var info = stat()
    guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, info.st_uid == 0, (info.st_mode & 0o7777) == 0o600
    else {
      throw ReleasePackageError.unsafePath(
        "owner-contention journal must be one root-owned mode-0600 file")
    }
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let journal = try JSONDecoder().decode(OwnerContentionJournal.self, from: data)
    guard data == (try CanonicalJSON.encode(journal)) else {
      throw ReleasePackageError.verification("owner-contention journal is not canonical JSON")
    }
    try journal.validate()
    return journal
  }

  private func removeExactContenderDefinition(_ home: URL, uid: UInt32) throws {
    let url = try exactContenderDefinition(home, uid: uid)
    try FileManager.default.removeItem(at: url)
  }

  private func exactContenderDefinition(_ home: URL, uid: UInt32) throws -> URL {
    let url = home.appendingPathComponent(
      "Library/LaunchAgents/systems.reach.reachd.plist")
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      throw ReleasePackageError.verification("cannot inspect contender service definition")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
      info.st_uid == uid, (info.st_mode & 0o7777) == 0o600,
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
          "REACH_STATE_DIR": home.appendingPathComponent(
            "Library/Application Support/Reach"
          ).path
        ],
      object["RunAtLoad"] as? Bool == true,
      object["KeepAlive"] as? Bool == true,
      object["ThrottleInterval"] as? Int == 10,
      object["StandardOutPath"] as? String
        == home.appendingPathComponent("Library/Logs/reachd.log").path,
      object["StandardErrorPath"] as? String
        == home.appendingPathComponent("Library/Logs/reachd.log").path,
      object["ProcessType"] as? String == "Interactive"
    else {
      throw ReleasePackageError.unsafePath("contender service definition is not probe-owned")
    }
    return url
  }
}
