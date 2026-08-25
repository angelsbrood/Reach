import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

private func crashSnapshot(
  hostPID: Int32 = 1001,
  helperPID: Int32 = 1002,
  package: String = String(repeating: "a", count: 64),
  state: String = String(repeating: "c", count: 64),
  directReady: Bool = true
) throws -> InstalledReleaseSnapshot {
  let release = ReleaseVersionMap(
    product: try DottedVersion("0.0.3"), host: try DottedVersion("0.0.3"),
    helper: try DottedVersion("1.0.2"))
  let host = InstalledFileObservation(
    path: "/Library/Application Support/Reach/Host/reachd", kind: .file,
    mode: 0o755, uid: 0, gid: 0, size: 4, sha256: String(repeating: "d", count: 64),
    linkTarget: nil, device: 9, inode: 100)
  let helper = InstalledFileObservation(
    path: "/Library/PrivilegedHelperTools/systems.reach.meshd", kind: .file,
    mode: 0o555, uid: 0, gid: 0, size: 4, sha256: String(repeating: "e", count: 64),
    linkTarget: nil, device: 9, inode: 101)
  return InstalledReleaseSnapshot(
    release: release, packageSHA256: package,
    provenanceSHA256: String(repeating: "b", count: 64),
    receipts: [
      .init(identifier: "systems.reach.host", version: release.host, payloadPaths: ["host"]),
      .init(
        identifier: "systems.reach.meshd", version: release.helper,
        payloadPaths: ["helper"]),
    ],
    files: [host, helper], extraPackageOwnedPaths: [],
    hostProcess: .init(
      pid: hostPID, uid: 501, executablePath: host.path,
      device: host.device, inode: host.inode),
    hostLaunchAgent: .init(
      label: "systems.reach.reachd", uid: 501, gid: 20, mode: 0o600,
      programArguments: [host.path, "serve"],
      environmentVariables: [
        "REACH_STATE_DIR": "/Users/cassie/Library/Application Support/Reach"
      ], runAtLoad: true, keepAlive: true, throttleInterval: 10, umask: nil,
      standardOutPath: "/Users/cassie/Library/Logs/reachd.log",
      standardErrorPath: "/Users/cassie/Library/Logs/reachd.log",
      processType: "Interactive",
      definitionKeys: [
        "EnvironmentVariables", "KeepAlive", "Label", "ProcessType", "ProgramArguments",
        "RunAtLoad", "StandardErrorPath", "StandardOutPath", "ThrottleInterval",
      ], loaded: true),
    helperLaunchDaemon: .init(
      label: "systems.reach.meshd", uid: 0, gid: 0, mode: 0o644,
      programArguments: [helper.path, "serve"], environmentVariables: [:],
      runAtLoad: true, keepAlive: true, throttleInterval: 10, umask: 0o77,
      standardOutPath: "/var/log/systems.reach.meshd.log",
      standardErrorPath: "/var/log/systems.reach.meshd.log",
      processType: "Background",
      definitionKeys: [
        "KeepAlive", "Label", "ProcessType", "ProgramArguments", "RunAtLoad",
        "StandardErrorPath", "StandardOutPath", "ThrottleInterval", "Umask",
      ], loaded: true),
    helper: .init(
      process: .init(
        pid: helperPID, uid: 0, executablePath: helper.path,
        device: helper.device, inode: helper.inode),
      statusVersion: 2, configured: true, ready: directReady,
      interfacePresent: directReady, directRouteCount: directReady ? 1 : 0,
      relayRouteCount: 0, foreignRouteCount: 0, controlSocketPresent: true),
    retainedState: .init(
      present: true, ownerUID: 501, itemCount: 12,
      authoritySHA256: state, caCreationCount: 1))
}

@Test func supervisedCrashVerifierAcceptsOnlyOneRestartedOwner() throws {
  let before = try crashSnapshot()
  let daemonAfter = try crashSnapshot(hostPID: 2001)
  let daemon = try SupervisedCrashRecoveryVerifier.verify(
    before: before, after: daemonAfter, target: .daemon)
  #expect(daemon.priorPID == 1001)
  #expect(daemon.replacementPID == 2001)
  #expect(daemon.peerPIDPreserved)

  let helperAfter = try crashSnapshot(helperPID: 2002)
  let helper = try SupervisedCrashRecoveryVerifier.verify(
    before: before, after: helperAfter, target: .helper)
  #expect(helper.priorPID == 1002)
  #expect(helper.replacementPID == 2002)
  #expect(helper.directHelperReady)
}

@Test func supervisedCrashVerifierRejectsPeerStateAndRouteDrift() throws {
  let before = try crashSnapshot()
  let candidates = [
    try crashSnapshot(hostPID: 2001, helperPID: 2002),
    try crashSnapshot(hostPID: 2001, state: String(repeating: "f", count: 64)),
    try crashSnapshot(hostPID: 2001, directReady: false),
    try crashSnapshot(hostPID: 1001),
  ]
  for after in candidates {
    #expect(throws: ReleasePackageError.self) {
      try SupervisedCrashRecoveryVerifier.verify(
        before: before, after: after, target: .daemon)
    }
  }
}
