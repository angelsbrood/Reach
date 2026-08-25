import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

private let hostPath = "/Library/Application Support/Reach/Host/reachd"
private let helperPath = "/Library/PrivilegedHelperTools/systems.reach.meshd"

private func payloadFile(_ path: String, data: String, mode: UInt32) -> PayloadRecord {
  let bytes = Data(data.utf8)
  return .init(
    path: ".\(path)", kind: .file, mode: UInt32(S_IFREG) | mode,
    uid: 0, gid: 0, size: UInt64(bytes.count),
    posixChecksum: POSIXChecksum.checksum(bytes), sha256: Digests.sha256(bytes), linkTarget: nil)
}

private func payloadLink(_ path: String, target: String) -> PayloadRecord {
  let bytes = Data(target.utf8)
  return .init(
    path: ".\(path)", kind: .symlink, mode: UInt32(S_IFLNK) | 0o777,
    uid: 0, gid: 0, size: UInt64(bytes.count),
    posixChecksum: POSIXChecksum.checksum(bytes), sha256: Digests.sha256(bytes),
    linkTarget: target)
}

private func installedFixture() throws -> (
  InstalledReleaseExpectation, InstalledReleaseSnapshot, InstalledVerificationPolicy
) {
  let release = ReleaseVersionMap(
    product: try DottedVersion("0.0.3"), host: try DottedVersion("0.0.3"),
    helper: try DottedVersion("1.0.2"))
  let host = [
    payloadFile(hostPath, data: "host", mode: 0o755),
    payloadLink("/usr/local/bin/reachd", target: hostPath),
  ]
  let helper = [
    payloadFile(helperPath, data: "helper", mode: 0o555),
    payloadFile(
      "/Library/LaunchDaemons/systems.reach.meshd.plist", data: "plist", mode: 0o644),
  ]
  let expectation = InstalledReleaseExpectation(
    release: release,
    packageSHA256: String(repeating: "a", count: 64),
    provenanceSHA256: String(repeating: "b", count: 64),
    host: host, helper: helper)
  let observations = (host + helper).sorted {
    $0.path.utf8.lexicographicallyPrecedes($1.path.utf8)
  }.enumerated().map { index, record in
    InstalledFileObservation(
      path: String(record.path.dropFirst()), kind: record.kind,
      mode: record.mode & 0o7777, uid: 0, gid: 0, size: record.size,
      sha256: record.sha256, linkTarget: record.linkTarget,
      device: 9, inode: UInt64(index + 100))
  }
  let hostObservation = try #require(observations.first(where: { $0.path == hostPath }))
  let helperObservation = try #require(observations.first(where: { $0.path == helperPath }))
  let snapshot = InstalledReleaseSnapshot(
    release: release,
    packageSHA256: String(repeating: "a", count: 64),
    provenanceSHA256: String(repeating: "b", count: 64),
    receipts: [
      .init(
        identifier: "systems.reach.host", version: release.host,
        payloadPaths: [
          "Library/Application Support/Reach/Host/reachd", "usr/local/bin/reachd",
        ]),
      .init(
        identifier: "systems.reach.meshd", version: release.helper,
        payloadPaths: [
          "Library/LaunchDaemons/systems.reach.meshd.plist",
          "Library/PrivilegedHelperTools/systems.reach.meshd",
        ]),
    ],
    files: observations,
    extraPackageOwnedPaths: [],
    hostProcess: .init(
      pid: 1001, uid: 501, executablePath: hostPath,
      device: hostObservation.device, inode: hostObservation.inode),
    hostLaunchAgent: .init(
      label: "systems.reach.reachd", uid: 501, gid: 20, mode: 0o600,
      programArguments: [hostPath, "serve"],
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
      programArguments: [helperPath, "serve"], environmentVariables: [:],
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
        pid: 1002, uid: 0, executablePath: helperPath,
        device: helperObservation.device, inode: helperObservation.inode),
      statusVersion: 2, configured: true, ready: true, interfacePresent: true,
      directRouteCount: 1, relayRouteCount: 0, foreignRouteCount: 0,
      controlSocketPresent: true),
    retainedState: .init(
      present: true, ownerUID: 501, itemCount: 12,
      authoritySHA256: String(repeating: "c", count: 64), caCreationCount: 1))
  let policy = InstalledVerificationPolicy(
    selectedOwnerUID: 501, selectedOwnerHome: "/Users/cassie",
    host: .running, helper: .directReady, retainedState: .present)
  return (expectation, snapshot, policy)
}

@Test func installedVerifierJoinsReceiptsFilesInodesHelperAndState() throws {
  let (expectation, snapshot, policy) = try installedFixture()
  let report = try InstalledReleaseStateVerifier().verify(
    snapshot: snapshot, policy: policy, expectation: expectation)
  #expect(report.verdict == "pass")
  #expect(report.receiptCount == 2)
  #expect(report.immutablePathCount == 4)
  #expect(report.hostRunning)
}

@Test func installedVerifierRefusesMixedReceiptAndWrongRunningInode() throws {
  let (expectation, snapshot, policy) = try installedFixture()
  let mixedReceipts = [
    InstalledReceiptObservation(
      identifier: "systems.reach.host", version: try DottedVersion("0.0.2"),
      payloadPaths: snapshot.receipts[0].payloadPaths),
    snapshot.receipts[1],
  ]
  let mixed = InstalledReleaseSnapshot(
    release: snapshot.release,
    packageSHA256: snapshot.packageSHA256,
    provenanceSHA256: snapshot.provenanceSHA256,
    receipts: mixedReceipts, files: snapshot.files, extraPackageOwnedPaths: [],
    hostProcess: snapshot.hostProcess, hostLaunchAgent: snapshot.hostLaunchAgent,
    helperLaunchDaemon: snapshot.helperLaunchDaemon, helper: snapshot.helper,
    retainedState: snapshot.retainedState)
  #expect(throws: ReleasePackageError.self) {
    try InstalledReleaseStateVerifier().verify(
      snapshot: mixed, policy: policy, expectation: expectation)
  }

  let wrongProcess = InstalledProcessObservation(
    pid: 1001, uid: 501, executablePath: hostPath, device: 9, inode: 999)
  let wrongInode = InstalledReleaseSnapshot(
    release: snapshot.release,
    packageSHA256: snapshot.packageSHA256,
    provenanceSHA256: snapshot.provenanceSHA256,
    receipts: snapshot.receipts, files: snapshot.files, extraPackageOwnedPaths: [],
    hostProcess: wrongProcess, hostLaunchAgent: snapshot.hostLaunchAgent,
    helperLaunchDaemon: snapshot.helperLaunchDaemon, helper: snapshot.helper,
    retainedState: snapshot.retainedState)
  #expect(throws: ReleasePackageError.self) {
    try InstalledReleaseStateVerifier().verify(
      snapshot: wrongInode, policy: policy, expectation: expectation)
  }
}

@Test func installedVerifierRefusesExtraPathsStaleProvenanceAndStateOwner() throws {
  let (expectation, snapshot, policy) = try installedFixture()
  func altered(
    provenance: String = String(repeating: "b", count: 64),
    extra: [String] = [],
    state: RetainedStateObservation? = nil
  ) -> InstalledReleaseSnapshot {
    .init(
      release: snapshot.release, packageSHA256: snapshot.packageSHA256,
      provenanceSHA256: provenance, receipts: snapshot.receipts, files: snapshot.files,
      extraPackageOwnedPaths: extra, hostProcess: snapshot.hostProcess,
      hostLaunchAgent: snapshot.hostLaunchAgent,
      helperLaunchDaemon: snapshot.helperLaunchDaemon, helper: snapshot.helper,
      retainedState: state ?? snapshot.retainedState)
  }
  for candidate in [
    altered(provenance: String(repeating: "d", count: 64)),
    altered(extra: ["/Library/Application Support/Reach/Host/foreign"]),
    altered(
      state: .init(
        present: true, ownerUID: 502, itemCount: 12,
        authoritySHA256: String(repeating: "c", count: 64), caCreationCount: 1)),
  ] {
    #expect(throws: ReleasePackageError.self) {
      try InstalledReleaseStateVerifier().verify(
        snapshot: candidate, policy: policy, expectation: expectation)
    }
  }
}

@Test func installedVerifierRequiresTheExactSelectedOwnerLaunchDefinition() throws {
  let (expectation, snapshot, policy) = try installedFixture()
  let launch = try #require(snapshot.hostLaunchAgent)
  func altered(_ replacement: InstalledLaunchObservation) -> InstalledReleaseSnapshot {
    .init(
      release: snapshot.release, packageSHA256: snapshot.packageSHA256,
      provenanceSHA256: snapshot.provenanceSHA256, receipts: snapshot.receipts,
      files: snapshot.files, extraPackageOwnedPaths: snapshot.extraPackageOwnedPaths,
      hostProcess: snapshot.hostProcess, hostLaunchAgent: replacement,
      helperLaunchDaemon: snapshot.helperLaunchDaemon, helper: snapshot.helper,
      retainedState: snapshot.retainedState)
  }
  let candidates = [
    InstalledLaunchObservation(
      label: launch.label, uid: launch.uid, gid: launch.gid, mode: launch.mode,
      programArguments: launch.programArguments + ["--unexpected"],
      environmentVariables: launch.environmentVariables,
      runAtLoad: launch.runAtLoad, keepAlive: launch.keepAlive,
      throttleInterval: launch.throttleInterval, umask: launch.umask,
      standardOutPath: launch.standardOutPath, standardErrorPath: launch.standardErrorPath,
      processType: launch.processType, definitionKeys: launch.definitionKeys,
      loaded: launch.loaded),
    InstalledLaunchObservation(
      label: launch.label, uid: launch.uid, gid: launch.gid, mode: launch.mode,
      programArguments: launch.programArguments,
      environmentVariables: ["REACH_STATE_DIR": "/Users/other/Reach"],
      runAtLoad: launch.runAtLoad, keepAlive: launch.keepAlive,
      throttleInterval: launch.throttleInterval, umask: launch.umask,
      standardOutPath: launch.standardOutPath, standardErrorPath: launch.standardErrorPath,
      processType: launch.processType, definitionKeys: launch.definitionKeys,
      loaded: launch.loaded),
    InstalledLaunchObservation(
      label: launch.label, uid: launch.uid, gid: launch.gid, mode: launch.mode,
      programArguments: launch.programArguments,
      environmentVariables: launch.environmentVariables,
      runAtLoad: launch.runAtLoad, keepAlive: launch.keepAlive,
      throttleInterval: launch.throttleInterval, umask: launch.umask,
      standardOutPath: launch.standardOutPath, standardErrorPath: launch.standardErrorPath,
      processType: launch.processType,
      definitionKeys: launch.definitionKeys + ["WorkingDirectory"],
      loaded: launch.loaded),
  ]
  for candidate in candidates {
    #expect(throws: ReleasePackageError.self) {
      try InstalledReleaseStateVerifier().verify(
        snapshot: altered(candidate), policy: policy, expectation: expectation)
    }
  }
}
