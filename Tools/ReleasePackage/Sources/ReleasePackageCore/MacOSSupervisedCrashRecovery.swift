import Darwin
import Foundation

public enum SupervisedCrashTarget: String, Codable, Sendable {
  case daemon
  case helper
}

public struct SupervisedCrashRecoveryReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let release: ReleaseVersionMap
  public let packageSHA256: String
  public let target: SupervisedCrashTarget
  public let priorPID: Int32
  public let replacementPID: Int32
  public let peerPIDPreserved: Bool
  public let executableInodePreserved: Bool
  public let retainedStateAuthoritySHA256: String
  public let directHelperReady: Bool
  public let verdict: String

  public init(
    release: ReleaseVersionMap,
    packageSHA256: String,
    target: SupervisedCrashTarget,
    priorPID: Int32,
    replacementPID: Int32,
    peerPIDPreserved: Bool,
    executableInodePreserved: Bool,
    retainedStateAuthoritySHA256: String,
    directHelperReady: Bool
  ) {
    schemaVersion = 1
    self.release = release
    self.packageSHA256 = packageSHA256
    self.target = target
    self.priorPID = priorPID
    self.replacementPID = replacementPID
    self.peerPIDPreserved = peerPIDPreserved
    self.executableInodePreserved = executableInodePreserved
    self.retainedStateAuthoritySHA256 = retainedStateAuthoritySHA256
    self.directHelperReady = directHelperReady
    verdict = "pass"
  }

  public func validate() throws {
    guard schemaVersion == 1,
      packageSHA256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
      retainedStateAuthoritySHA256.range(
        of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
      priorPID > 0, replacementPID > 0, priorPID != replacementPID,
      peerPIDPreserved, executableInodePreserved, directHelperReady,
      verdict == "pass"
    else {
      throw ReleasePackageError.verification("supervised crash report is malformed")
    }
  }
}

public enum SupervisedCrashRecoveryVerifier {
  public static func verify(
    before: InstalledReleaseSnapshot,
    after: InstalledReleaseSnapshot,
    target: SupervisedCrashTarget
  ) throws -> SupervisedCrashRecoveryReport {
    guard before.schemaVersion == 1, after.schemaVersion == 1,
      before.release == after.release,
      before.packageSHA256 == after.packageSHA256,
      before.provenanceSHA256 == after.provenanceSHA256,
      before.receipts == after.receipts,
      before.files == after.files,
      before.extraPackageOwnedPaths.isEmpty,
      after.extraPackageOwnedPaths.isEmpty,
      after.retainedState.preservesExactAuthority(from: before.retainedState),
      let stateAuthority = after.retainedState.authoritySHA256,
      let beforeHost = before.hostProcess, let afterHost = after.hostProcess,
      let beforeHelper = before.helper.process, let afterHelper = after.helper.process,
      beforeHost.device == afterHost.device, beforeHost.inode == afterHost.inode,
      beforeHelper.device == afterHelper.device, beforeHelper.inode == afterHelper.inode,
      after.helper.configured, after.helper.ready, after.helper.interfacePresent,
      after.helper.directRouteCount == 1, after.helper.relayRouteCount == 0,
      after.helper.foreignRouteCount == 0, after.helper.controlSocketPresent
    else {
      throw ReleasePackageError.verification(
        "supervised recovery changed immutable, runtime, or cluster authority")
    }
    let priorPID: Int32
    let replacementPID: Int32
    let peerPreserved: Bool
    switch target {
    case .daemon:
      priorPID = beforeHost.pid
      replacementPID = afterHost.pid
      peerPreserved = beforeHelper.pid == afterHelper.pid
    case .helper:
      priorPID = beforeHelper.pid
      replacementPID = afterHelper.pid
      peerPreserved = beforeHost.pid == afterHost.pid
    }
    let report = SupervisedCrashRecoveryReport(
      release: after.release,
      packageSHA256: after.packageSHA256,
      target: target,
      priorPID: priorPID,
      replacementPID: replacementPID,
      peerPIDPreserved: peerPreserved,
      executableInodePreserved: true,
      retainedStateAuthoritySHA256: stateAuthority,
      directHelperReady: true)
    try report.validate()
    return report
  }
}

/// Guest-only crash proof. The exact already-attributed supervised process is
/// killed once. A bounded monotonic poll then requires launchd to return a
/// different PID from the same installed inode while the other owner, direct
/// route and login-owned cluster authority remain unchanged.
public struct MacOSSupervisedCrashRecovery {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) { self.runner = runner }

  public func run(
    target: SupervisedCrashTarget,
    retainedAuthority: URL,
    ownerUID: UInt32,
    ownerHome: URL,
    scratch: URL,
    output: URL
  ) throws -> SupervisedCrashRecoveryReport {
    guard ownerUID != 0, ownerHome.path.hasPrefix("/Users/"),
      ownerHome.path.split(separator: "/").count == 2
    else {
      throw ReleasePackageError.invalidArgument("crash recovery owner is invalid")
    }
    _ = try RetainedReleaseCatalogEntry(root: retainedAuthority)
    try SecureFiles.createPrivateDirectory(scratch)
    let collector = MacOSInstalledStateCollector(runner: runner)
    let policy = InstalledVerificationPolicy(
      selectedOwnerUID: ownerUID, selectedOwnerHome: ownerHome.path, host: .running,
      helper: .directReady, retainedState: .present)
    let beforeRoot = scratch.appendingPathComponent("before")
    let before = try collector.collect(
      retainedAuthority: retainedAuthority, policy: policy,
      ownerHome: ownerHome, scratch: beforeRoot.appendingPathComponent("scratch"),
      output: beforeRoot.appendingPathComponent("snapshot.json"))
    let process = try selectedProcess(from: before, target: target)
    try requireLiveProcess(process)
    guard kill(process.pid, SIGKILL) == 0 else {
      throw ReleasePackageError.verification("cannot stop the attributed supervised process")
    }

    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(60))
    var attempt = 0
    var lastError: Error?
    while clock.now < deadline {
      attempt += 1
      let root = scratch.appendingPathComponent("poll-\(attempt)")
      do {
        let after = try collector.collect(
          retainedAuthority: retainedAuthority, policy: policy,
          ownerHome: ownerHome, scratch: root.appendingPathComponent("scratch"),
          output: root.appendingPathComponent("snapshot.json"))
        let report = try SupervisedCrashRecoveryVerifier.verify(
          before: before, after: after, target: target)
        try SecureFiles.atomicWrite(try CanonicalJSON.encode(report), to: output)
        return report
      } catch {
        lastError = error
        usleep(100_000)
      }
    }
    throw ReleasePackageError.verification(
      "supervised process did not recover within 60 seconds: "
        + String(describing: lastError ?? ReleasePackageError.verification("no observation")))
  }

  private func selectedProcess(
    from snapshot: InstalledReleaseSnapshot, target: SupervisedCrashTarget
  ) throws -> InstalledProcessObservation {
    switch target {
    case .daemon:
      guard let value = snapshot.hostProcess else {
        throw ReleasePackageError.verification("accepted host process disappeared")
      }
      return value
    case .helper:
      guard let value = snapshot.helper.process else {
        throw ReleasePackageError.verification("accepted helper process disappeared")
      }
      return value
    }
  }

  private func requireLiveProcess(_ expected: InstalledProcessObservation) throws {
    var pathBuffer = [CChar](repeating: 0, count: 4_096)
    guard proc_pidpath(expected.pid, &pathBuffer, UInt32(pathBuffer.count)) > 0 else {
      throw ReleasePackageError.verification("supervised process changed before SIGKILL")
    }
    let end = pathBuffer.firstIndex(of: 0) ?? pathBuffer.endIndex
    let path = String(
      decoding: pathBuffer[..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    var processInfo = proc_bsdinfo()
    guard path.utf8.elementsEqual(expected.executablePath.utf8),
      proc_pidinfo(
        expected.pid, PROC_PIDTBSDINFO, 0, &processInfo,
        Int32(MemoryLayout.size(ofValue: processInfo)))
        == MemoryLayout.size(ofValue: processInfo),
      processInfo.pbi_uid == expected.uid
    else {
      throw ReleasePackageError.verification("supervised process identity changed before SIGKILL")
    }
    var info = stat()
    guard stat(path, &info) == 0, UInt64(info.st_dev) == expected.device,
      UInt64(info.st_ino) == expected.inode
    else {
      throw ReleasePackageError.verification("supervised executable inode changed before SIGKILL")
    }
  }
}
