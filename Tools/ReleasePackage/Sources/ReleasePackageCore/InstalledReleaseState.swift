import Darwin
import Foundation

public enum InstalledHostRequirement: String, Codable, Sendable {
  case unbound
  case stopped
  case running
}

public enum InstalledHelperRequirement: String, Codable, Sendable {
  case absent
  case stopped
  case unconfigured
  case directReady
}

public enum RetainedStateRequirement: String, Codable, Sendable {
  case absent
  case present
}

public struct InstalledVerificationPolicy: Codable, Equatable, Sendable {
  public let selectedOwnerUID: UInt32
  public let selectedOwnerHome: String
  public let host: InstalledHostRequirement
  public let helper: InstalledHelperRequirement
  public let retainedState: RetainedStateRequirement

  public init(
    selectedOwnerUID: UInt32,
    selectedOwnerHome: String,
    host: InstalledHostRequirement,
    helper: InstalledHelperRequirement,
    retainedState: RetainedStateRequirement
  ) {
    self.selectedOwnerUID = selectedOwnerUID
    self.selectedOwnerHome = selectedOwnerHome
    self.host = host
    self.helper = helper
    self.retainedState = retainedState
  }

  public func validate() throws {
    guard selectedOwnerUID != 0,
      selectedOwnerHome.hasPrefix("/Users/"),
      selectedOwnerHome.split(separator: "/").count == 2,
      !selectedOwnerHome.contains(".."), !selectedOwnerHome.contains("//")
    else {
      throw ReleasePackageError.verification("installed owner cannot be root")
    }
  }
}

public struct InstalledReceiptObservation: Codable, Equatable, Sendable {
  public let identifier: String
  public let version: DottedVersion
  public let payloadPaths: [String]

  public init(identifier: String, version: DottedVersion, payloadPaths: [String]) {
    self.identifier = identifier
    self.version = version
    self.payloadPaths = payloadPaths
  }
}

public struct InstalledFileObservation: Codable, Equatable, Sendable {
  public let path: String
  public let kind: PayloadKind
  public let mode: UInt32
  public let uid: UInt32
  public let gid: UInt32
  public let size: UInt64
  public let sha256: String?
  public let linkTarget: String?
  public let device: UInt64
  public let inode: UInt64

  public init(
    path: String,
    kind: PayloadKind,
    mode: UInt32,
    uid: UInt32,
    gid: UInt32,
    size: UInt64,
    sha256: String?,
    linkTarget: String?,
    device: UInt64,
    inode: UInt64
  ) {
    self.path = path
    self.kind = kind
    self.mode = mode
    self.uid = uid
    self.gid = gid
    self.size = size
    self.sha256 = sha256
    self.linkTarget = linkTarget
    self.device = device
    self.inode = inode
  }
}

public struct InstalledProcessObservation: Codable, Equatable, Sendable {
  public let pid: Int32
  public let uid: UInt32
  public let executablePath: String
  public let device: UInt64
  public let inode: UInt64

  public init(pid: Int32, uid: UInt32, executablePath: String, device: UInt64, inode: UInt64) {
    self.pid = pid
    self.uid = uid
    self.executablePath = executablePath
    self.device = device
    self.inode = inode
  }
}

public struct InstalledLaunchObservation: Codable, Equatable, Sendable {
  public let label: String
  public let uid: UInt32
  public let gid: UInt32
  public let mode: UInt32
  public let programArguments: [String]
  public let environmentVariables: [String: String]
  public let runAtLoad: Bool
  public let keepAlive: Bool
  public let throttleInterval: Int
  public let umask: Int?
  public let standardOutPath: String
  public let standardErrorPath: String
  public let processType: String
  public let definitionKeys: [String]
  public let loaded: Bool

  public init(
    label: String, uid: UInt32, gid: UInt32, mode: UInt32,
    programArguments: [String], environmentVariables: [String: String],
    runAtLoad: Bool, keepAlive: Bool, throttleInterval: Int,
    umask: Int?, standardOutPath: String, standardErrorPath: String,
    processType: String, definitionKeys: [String], loaded: Bool
  ) {
    self.label = label
    self.uid = uid
    self.gid = gid
    self.mode = mode
    self.programArguments = programArguments
    self.environmentVariables = environmentVariables
    self.runAtLoad = runAtLoad
    self.keepAlive = keepAlive
    self.throttleInterval = throttleInterval
    self.umask = umask
    self.standardOutPath = standardOutPath
    self.standardErrorPath = standardErrorPath
    self.processType = processType
    self.definitionKeys = definitionKeys
    self.loaded = loaded
  }
}

public struct InstalledHelperObservation: Codable, Equatable, Sendable {
  public let process: InstalledProcessObservation?
  public let statusVersion: Int?
  public let configured: Bool
  public let ready: Bool
  public let interfacePresent: Bool
  public let directRouteCount: Int
  public let relayRouteCount: Int
  public let foreignRouteCount: Int
  public let controlSocketPresent: Bool

  public init(
    process: InstalledProcessObservation?, statusVersion: Int?, configured: Bool,
    ready: Bool, interfacePresent: Bool, directRouteCount: Int,
    relayRouteCount: Int, foreignRouteCount: Int, controlSocketPresent: Bool
  ) {
    self.process = process
    self.statusVersion = statusVersion
    self.configured = configured
    self.ready = ready
    self.interfacePresent = interfacePresent
    self.directRouteCount = directRouteCount
    self.relayRouteCount = relayRouteCount
    self.foreignRouteCount = foreignRouteCount
    self.controlSocketPresent = controlSocketPresent
  }
}

public struct RetainedStateObservation: Codable, Equatable, Sendable {
  public let present: Bool
  public let ownerUID: UInt32?
  /// Count of exact, transaction-invariant filesystem members.
  public let itemCount: Int
  /// Digest of exact CA/server, registry, identity, configuration, intent,
  /// and WireGuard authority. Mutable enrollment/reachability scratch is not
  /// included in this digest.
  public let authoritySHA256: String?
  /// Count of explicitly classified mutable members. This is evidence, not a
  /// byte-equality requirement across a dial or model run.
  public let mutableItemCount: Int
  public let caCreationCount: Int

  public init(
    present: Bool, ownerUID: UInt32?, itemCount: Int,
    authoritySHA256: String?, mutableItemCount: Int = 0, caCreationCount: Int
  ) {
    self.present = present
    self.ownerUID = ownerUID
    self.itemCount = itemCount
    self.authoritySHA256 = authoritySHA256
    self.mutableItemCount = mutableItemCount
    self.caCreationCount = caCreationCount
  }

  public func preservesExactAuthority(from baseline: Self) -> Bool {
    present == baseline.present
      && ownerUID == baseline.ownerUID
      && itemCount == baseline.itemCount
      && authoritySHA256 == baseline.authoritySHA256
      && caCreationCount == baseline.caCreationCount
  }
}

public struct InstalledReleaseSnapshot: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let release: ReleaseVersionMap
  public let packageSHA256: String
  public let provenanceSHA256: String
  public let receipts: [InstalledReceiptObservation]
  public let files: [InstalledFileObservation]
  public let extraPackageOwnedPaths: [String]
  public let hostProcess: InstalledProcessObservation?
  public let hostLaunchAgent: InstalledLaunchObservation?
  public let helperLaunchDaemon: InstalledLaunchObservation?
  public let helper: InstalledHelperObservation
  public let retainedState: RetainedStateObservation

  public init(
    schemaVersion: Int = 1,
    release: ReleaseVersionMap,
    packageSHA256: String,
    provenanceSHA256: String,
    receipts: [InstalledReceiptObservation],
    files: [InstalledFileObservation],
    extraPackageOwnedPaths: [String],
    hostProcess: InstalledProcessObservation?,
    hostLaunchAgent: InstalledLaunchObservation?,
    helperLaunchDaemon: InstalledLaunchObservation?,
    helper: InstalledHelperObservation,
    retainedState: RetainedStateObservation
  ) {
    self.schemaVersion = schemaVersion
    self.release = release
    self.packageSHA256 = packageSHA256
    self.provenanceSHA256 = provenanceSHA256
    self.receipts = receipts
    self.files = files
    self.extraPackageOwnedPaths = extraPackageOwnedPaths
    self.hostProcess = hostProcess
    self.hostLaunchAgent = hostLaunchAgent
    self.helperLaunchDaemon = helperLaunchDaemon
    self.helper = helper
    self.retainedState = retainedState
  }

  public static func load(from url: URL) throws -> Self {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let value = try JSONDecoder().decode(Self.self, from: data)
    guard data == (try CanonicalJSON.encode(value)) else {
      throw ReleasePackageError.verification("installed-state snapshot is not canonical JSON")
    }
    return value
  }
}

public struct InstalledReleaseVerificationReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let release: ReleaseVersionMap
  public let packageSHA256: String
  public let provenanceSHA256: String
  public let receiptCount: Int
  public let immutablePathCount: Int
  public let hostRunning: Bool
  public let helperState: InstalledHelperRequirement
  public let retainedState: RetainedStateRequirement
  public let retainedStateItemCount: Int
  public let retainedStateAuthoritySHA256: String?
  public let verdict: String
}

struct InstalledReleaseExpectation {
  let release: ReleaseVersionMap
  let packageSHA256: String
  let provenanceSHA256: String
  let host: [PayloadRecord]
  let helper: [PayloadRecord]
}

public struct InstalledReleaseStateVerifier {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
  }

  public func verify(
    snapshotURL: URL,
    policy: InstalledVerificationPolicy,
    retainedAuthority: URL,
    scratch: URL,
    reportURL: URL? = nil
  ) throws -> InstalledReleaseVerificationReport {
    try policy.validate()
    let snapshot = try InstalledReleaseSnapshot.load(from: snapshotURL)
    let expectation = try expectedState(
      retainedAuthority: retainedAuthority, scratch: scratch)
    let report = try verify(snapshot: snapshot, policy: policy, expectation: expectation)
    if let reportURL {
      try SecureFiles.atomicWrite(try CanonicalJSON.encode(report), to: reportURL)
    }
    return report
  }

  func verify(
    snapshot: InstalledReleaseSnapshot,
    policy: InstalledVerificationPolicy,
    expectation: InstalledReleaseExpectation
  ) throws -> InstalledReleaseVerificationReport {
    try policy.validate()
    guard snapshot.schemaVersion == 1,
      snapshot.release == expectation.release,
      snapshot.packageSHA256 == expectation.packageSHA256,
      snapshot.provenanceSHA256 == expectation.provenanceSHA256,
      snapshot.extraPackageOwnedPaths.isEmpty
    else {
      throw ReleasePackageError.verification("installed release authority is mixed or stale")
    }
    let expectedReceipts = [
      InstalledReceiptObservation(
        identifier: "systems.reach.host", version: expectation.release.host,
        payloadPaths: receiptPaths(expectation.host)),
      InstalledReceiptObservation(
        identifier: "systems.reach.meshd", version: expectation.release.helper,
        payloadPaths: receiptPaths(expectation.helper)),
    ]
    guard snapshot.receipts == expectedReceipts else {
      throw ReleasePackageError.verification("installed package receipts or BOM paths changed")
    }
    let expectedFiles = try mergedPayload(expectation.host + expectation.helper)
    guard snapshot.files.count == expectedFiles.count else {
      throw ReleasePackageError.verification("installed immutable path cardinality changed")
    }
    for (record, observation) in zip(expectedFiles, snapshot.files) {
      try verify(record: record, observation: observation)
    }
    try verifyHost(snapshot, policy: policy)
    try verifyHelper(snapshot, policy: policy)
    try verifyRetainedState(snapshot.retainedState, policy: policy)
    return InstalledReleaseVerificationReport(
      schemaVersion: 1,
      release: expectation.release,
      packageSHA256: expectation.packageSHA256,
      provenanceSHA256: expectation.provenanceSHA256,
      receiptCount: snapshot.receipts.count,
      immutablePathCount: snapshot.files.count,
      hostRunning: snapshot.hostProcess != nil,
      helperState: policy.helper,
      retainedState: policy.retainedState,
      retainedStateItemCount: snapshot.retainedState.itemCount,
      retainedStateAuthoritySHA256: snapshot.retainedState.authoritySHA256,
      verdict: "pass")
  }

  func expectedState(retainedAuthority: URL, scratch: URL) throws
    -> InstalledReleaseExpectation
  {
    let manifestURL = retainedAuthority.appendingPathComponent("retained-authority.json")
    try RetainedReleaseAuthoritySealer(runner: runner).verify(
      manifestURL: manifestURL, authorityRoot: retainedAuthority)
    let provenanceURL = retainedAuthority.appendingPathComponent("release-provenance.json")
    let envelope = try AnySignedReleaseProvenance.load(from: provenanceURL)
    let view = envelope.view
    guard let lineage = view.lineage, let p5 = view.p5 else {
      throw ReleasePackageError.verification("installed-state authority requires retained P5")
    }
    let package = retainedAuthority.appendingPathComponent(p5.stapledContainer.path)
    let fullReport = try SignedReleaseVerifier(runner: runner).verify(
      package: package,
      provenanceURL: provenanceURL,
      unsignedToolSource: retainedAuthority.appendingPathComponent("unsigned-tool-source"),
      finalizerToolSource: retainedAuthority.appendingPathComponent("finalizer-tool-source"),
      configurationURL: retainedAuthority.appendingPathComponent("release.json"),
      noticeAuthorityURL: retainedAuthority.appendingPathComponent("notices.json"),
      dependencyDepot: retainedAuthority.appendingPathComponent("dependency-depot"),
      scratch: scratch.appendingPathComponent("release-verification"))
    guard fullReport.stage == "P5", fullReport.packageSHA256 == p5.stapledContainer.sha256,
      fullReport.stapleValidated, fullReport.localAssessmentPassed
    else {
      throw ReleasePackageError.verification("retained installed authority is not accepted P5")
    }
    let materializer = SignedPayloadMaterializer(runner: runner)
    let hostRoot = try materializer.materializeComponent(
      named: "systems.reach.host.pkg", fromOuterPackage: package,
      destination: scratch.appendingPathComponent("host-root"),
      scratch: scratch.appendingPathComponent("host-component"), label: "installed host")
    let helperRoot = try materializer.materializeComponent(
      named: "systems.reach.meshd.pkg", fromOuterPackage: package,
      destination: scratch.appendingPathComponent("helper-root"),
      scratch: scratch.appendingPathComponent("helper-component"), label: "installed helper")
    return .init(
      release: lineage.release,
      packageSHA256: p5.stapledContainer.sha256,
      provenanceSHA256: try Digests.sha256(file: provenanceURL),
      host: try PayloadTree.inspect(root: hostRoot).records,
      helper: try PayloadTree.inspect(root: helperRoot).records)
  }

  func receiptPaths(_ records: [PayloadRecord]) -> [String] {
    records.compactMap { record in
      guard record.path != "." else { return nil }
      return String(record.path.dropFirst(2))
    }.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
  }

  func mergedPayload(_ records: [PayloadRecord]) throws -> [PayloadRecord] {
    var merged: [String: PayloadRecord] = [:]
    for record in records where record.path != "." {
      let absolute = String(record.path.dropFirst(1))
      let value = PayloadRecord(
        path: absolute, kind: record.kind, mode: record.mode,
        uid: record.uid, gid: record.gid, size: record.size,
        posixChecksum: record.posixChecksum, sha256: record.sha256,
        linkTarget: record.linkTarget)
      if let existing = merged[absolute], existing != value {
        throw ReleasePackageError.verification(
          "component payload ownership overlaps inconsistently")
      }
      merged[absolute] = value
    }
    return merged.values.sorted {
      $0.path.utf8.lexicographicallyPrecedes($1.path.utf8)
    }
  }

  private func verify(record: PayloadRecord, observation: InstalledFileObservation) throws {
    guard observation.path == record.path,
      observation.kind == record.kind,
      observation.mode == (record.mode & 0o7777),
      observation.uid == 0, observation.gid == 0,
      observation.size == record.size,
      observation.sha256 == record.sha256,
      observation.linkTarget == record.linkTarget,
      observation.device > 0, observation.inode > 0
    else {
      throw ReleasePackageError.verification(
        "installed immutable member changed: \(record.path)")
    }
  }

  private func verifyHost(
    _ snapshot: InstalledReleaseSnapshot, policy: InstalledVerificationPolicy
  ) throws {
    let canonical = "/Library/Application Support/Reach/Host/reachd"
    if policy.host == .unbound {
      guard snapshot.hostProcess == nil, snapshot.hostLaunchAgent == nil else {
        throw ReleasePackageError.verification("host was expected to be unbound")
      }
      return
    }
    guard let launch = snapshot.hostLaunchAgent,
      launch.label == "systems.reach.reachd",
      launch.uid == policy.selectedOwnerUID,
      launch.gid != 0,
      launch.mode == 0o600,
      launch.programArguments == [canonical, "serve"],
      launch.environmentVariables
        == [
          "REACH_STATE_DIR": policy.selectedOwnerHome
            + "/Library/Application Support/Reach"
        ],
      launch.runAtLoad, launch.keepAlive, launch.throttleInterval == 10,
      launch.umask == nil,
      launch.standardOutPath == policy.selectedOwnerHome + "/Library/Logs/reachd.log",
      launch.standardErrorPath == policy.selectedOwnerHome + "/Library/Logs/reachd.log",
      launch.processType == "Interactive",
      launch.definitionKeys
        == [
          "EnvironmentVariables", "KeepAlive", "Label", "ProcessType",
          "ProgramArguments", "RunAtLoad", "StandardErrorPath",
          "StandardOutPath", "ThrottleInterval",
        ]
    else {
      throw ReleasePackageError.verification("login-owned LaunchAgent authority changed")
    }
    switch policy.host {
    case .unbound:
      preconditionFailure("unbound host returned before launch validation")
    case .stopped:
      guard snapshot.hostProcess == nil, !launch.loaded else {
        throw ReleasePackageError.verification("host was expected to be stopped")
      }
    case .running:
      guard let process = snapshot.hostProcess,
        process.pid > 0, process.uid == policy.selectedOwnerUID,
        process.executablePath == canonical, launch.loaded,
        let executable = snapshot.files.first(where: { $0.path == canonical }),
        process.device == executable.device, process.inode == executable.inode
      else {
        throw ReleasePackageError.verification("running host inode or owner changed")
      }
    }
  }

  private func verifyHelper(
    _ snapshot: InstalledReleaseSnapshot, policy: InstalledVerificationPolicy
  ) throws {
    let helperPath = "/Library/PrivilegedHelperTools/systems.reach.meshd"
    guard let launch = snapshot.helperLaunchDaemon,
      launch.label == "systems.reach.meshd", launch.uid == 0, launch.gid == 0,
      launch.mode == 0o644,
      launch.programArguments == [helperPath, "serve"],
      launch.environmentVariables.isEmpty,
      launch.runAtLoad, launch.keepAlive, launch.throttleInterval == 10,
      launch.umask == 0o77,
      launch.standardOutPath == "/var/log/systems.reach.meshd.log",
      launch.standardErrorPath == "/var/log/systems.reach.meshd.log",
      launch.processType == "Background",
      launch.definitionKeys
        == [
          "KeepAlive", "Label", "ProcessType", "ProgramArguments", "RunAtLoad",
          "StandardErrorPath", "StandardOutPath", "ThrottleInterval", "Umask",
        ]
    else {
      throw ReleasePackageError.verification("root helper LaunchDaemon authority changed")
    }
    let helper = snapshot.helper
    guard helper.directRouteCount >= 0, helper.relayRouteCount >= 0,
      helper.foreignRouteCount == 0
    else {
      throw ReleasePackageError.verification("helper route ownership changed")
    }
    switch policy.helper {
    case .absent:
      guard helper.process == nil, !launch.loaded, helper.statusVersion == nil,
        !helper.configured, !helper.ready, !helper.interfacePresent,
        helper.directRouteCount == 0, helper.relayRouteCount == 0,
        !helper.controlSocketPresent
      else {
        throw ReleasePackageError.verification("helper runtime was expected to be absent")
      }
    case .stopped:
      guard helper.process == nil, !launch.loaded,
        !helper.ready, !helper.interfacePresent,
        helper.directRouteCount == 0, helper.relayRouteCount == 0,
        !helper.controlSocketPresent
      else {
        throw ReleasePackageError.verification("helper runtime was expected to be stopped")
      }
    case .unconfigured:
      guard let process = helper.process, process.uid == 0,
        process.executablePath == helperPath, launch.loaded,
        helper.statusVersion != nil, !helper.configured, !helper.ready,
        !helper.interfacePresent, helper.directRouteCount == 0,
        helper.relayRouteCount == 0, helper.controlSocketPresent
      else {
        throw ReleasePackageError.verification("unconfigured helper boundary changed")
      }
    case .directReady:
      guard let process = helper.process, process.uid == 0,
        process.executablePath == helperPath, launch.loaded,
        helper.statusVersion != nil, helper.configured, helper.ready,
        helper.interfacePresent, helper.directRouteCount == 1,
        helper.relayRouteCount == 0, helper.controlSocketPresent
      else {
        throw ReleasePackageError.verification("direct helper authority is not ready")
      }
    }
    if let process = helper.process {
      guard let executable = snapshot.files.first(where: { $0.path == helperPath }),
        process.device == executable.device, process.inode == executable.inode
      else {
        throw ReleasePackageError.verification("running helper inode changed")
      }
    }
  }

  private func verifyRetainedState(
    _ state: RetainedStateObservation, policy: InstalledVerificationPolicy
  ) throws {
    switch policy.retainedState {
    case .absent:
      guard !state.present, state.ownerUID == nil, state.itemCount == 0,
        state.authoritySHA256 == nil, state.mutableItemCount == 0,
        state.caCreationCount == 0
      else {
        throw ReleasePackageError.verification("login-owned state was expected to be absent")
      }
    case .present:
      guard state.present, state.ownerUID == policy.selectedOwnerUID,
        state.itemCount > 0, state.caCreationCount == 1,
        state.authoritySHA256?.count == 64,
        state.authoritySHA256?.allSatisfy(\.isHexDigit) == true
      else {
        throw ReleasePackageError.verification("retained login-owned state authority changed")
      }
    }
  }
}
