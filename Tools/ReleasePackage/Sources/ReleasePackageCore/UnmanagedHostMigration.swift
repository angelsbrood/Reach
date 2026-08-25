import Darwin
import Foundation

public struct UnmanagedHostMigrationRecord: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let transactionID: String
  public let selectedOwnerUID: UInt32
  public let unitSHA256: String
  public let unitMemberCount: Int
  public let aliasTargetSHA256: String
  public let launchAgentSHA256: String
  public let runningDevice: UInt64
  public let runningInode: UInt64
  public let retainedState: RetainedStateObservation

  public init(
    transactionID: String,
    selectedOwnerUID: UInt32,
    unitSHA256: String,
    unitMemberCount: Int,
    aliasTargetSHA256: String,
    launchAgentSHA256: String,
    runningDevice: UInt64,
    runningInode: UInt64,
    retainedState: RetainedStateObservation
  ) {
    schemaVersion = 1
    self.transactionID = transactionID
    self.selectedOwnerUID = selectedOwnerUID
    self.unitSHA256 = unitSHA256
    self.unitMemberCount = unitMemberCount
    self.aliasTargetSHA256 = aliasTargetSHA256
    self.launchAgentSHA256 = launchAgentSHA256
    self.runningDevice = runningDevice
    self.runningInode = runningInode
    self.retainedState = retainedState
  }

  public func validate() throws {
    guard schemaVersion == 1, UUID(uuidString: transactionID) != nil,
      selectedOwnerUID != 0, unitMemberCount > 8,
      [unitSHA256, aliasTargetSHA256, launchAgentSHA256].allSatisfy({
        $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
      }), runningDevice > 0, runningInode > 0,
      retainedState.present, retainedState.ownerUID == selectedOwnerUID,
      retainedState.caCreationCount == 1,
      retainedState.authoritySHA256?.count == 64
    else {
      throw ReleasePackageError.verification("unmanaged migration record is malformed")
    }
  }
}

public struct UnmanagedHostMigrationStore {
  public let url: URL

  public init(url: URL) { self.url = url }

  public func load() throws -> UnmanagedHostMigrationRecord? {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      if errno == ENOENT { return nil }
      throw ReleasePackageError.verification("cannot inspect unmanaged migration record")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
      (info.st_mode & 0o7777) == 0o600
    else {
      throw ReleasePackageError.unsafePath(
        "unmanaged migration record must be a mode-0600 single-link file")
    }
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let value = try JSONDecoder().decode(UnmanagedHostMigrationRecord.self, from: data)
    guard data == (try CanonicalJSON.encode(value)) else {
      throw ReleasePackageError.verification("unmanaged migration record is not canonical JSON")
    }
    try value.validate()
    return value
  }

  public func createOrVerify(_ value: UnmanagedHostMigrationRecord) throws {
    try value.validate()
    if let existing = try load() {
      guard existing == value else {
        throw ReleasePackageError.verification("unmanaged migration authority changed")
      }
      return
    }
    try SecureFiles.createPrivateDirectory(url.deletingLastPathComponent())
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: url)
  }
}

/// Exact first-package migration authority. It accepts only the historical
/// eight-item user-owned layout whose bytes match the retained package's host
/// unit, its one historical alias, and the canonical login LaunchAgent.
public struct UnmanagedHostMigration {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) { self.runner = runner }

  public func capture(
    release: RetainedReleaseCatalogEntry,
    ownerUID: UInt32,
    ownerHome: URL,
    transactionID: String,
    scratch: URL
  ) throws -> UnmanagedHostMigrationRecord {
    let expected = try expectedUnit(release: release, scratch: scratch)
    let observation = try inspectUnit(
      expected: expected, ownerUID: ownerUID, ownerHome: ownerHome)
    let executablePath = unmanagedRoot(ownerHome).appendingPathComponent("reachd")
    guard let executableRecord = expected.first(where: { $0.path == "./reachd" }) else {
      throw ReleasePackageError.verification(
        "retained unmanaged host lacks its exact executable authority")
    }
    let exactExecutable = try exactExecutableVnode(
      executablePath, expected: executableRecord, ownerUID: ownerUID)
    try requireNoCollision(ownerHome: ownerHome)
    let launch = try inspectLaunchAgent(
      ownerUID: ownerUID, ownerHome: ownerHome,
      expectedExecutable: executablePath.path,
      requireLoaded: true,
      logURL: scratch.appendingPathComponent("migration-launchctl.log"))
    let process = try runningProcess(
      ownerUID: ownerUID,
      expectedExecutable: executablePath.path,
      expectedDevice: exactExecutable.device,
      expectedInode: exactExecutable.inode,
      logURL: scratch.appendingPathComponent("migration-process.log"))
    let state = try MacOSInstalledStateCollector(runner: runner).observeState(
      ownerHome.appendingPathComponent("Library/Application Support/Reach"),
      expectedOwnerUID: ownerUID)
    let value = UnmanagedHostMigrationRecord(
      transactionID: transactionID, selectedOwnerUID: ownerUID,
      unitSHA256: observation.digest, unitMemberCount: observation.count,
      aliasTargetSHA256: try inspectAlias(ownerUID: ownerUID, ownerHome: ownerHome),
      launchAgentSHA256: launch,
      runningDevice: process.device, runningInode: process.inode,
      retainedState: state)
    try value.validate()
    return value
  }

  public func retire(
    record: UnmanagedHostMigrationRecord,
    release: RetainedReleaseCatalogEntry,
    ownerHome: URL,
    scratch: URL
  ) throws {
    try record.validate()
    let root = unmanagedRoot(ownerHome)
    let alias = unmanagedAlias(ownerHome)
    let retired = root.deletingLastPathComponent().appendingPathComponent(
      "reach.s36-retired-" + record.transactionID)
    let rootExists = try exists(root.path)
    let retiredExists = try exists(retired.path)
    guard !(rootExists && retiredExists) else {
      throw ReleasePackageError.verification("migration has two unmanaged host authorities")
    }
    if rootExists {
      let expected = try expectedUnit(release: release, scratch: scratch)
      let observed = try inspectUnit(
        expected: expected, ownerUID: record.selectedOwnerUID, ownerHome: ownerHome)
      guard observed.digest == record.unitSHA256, observed.count == record.unitMemberCount else {
        throw ReleasePackageError.verification("unmanaged host changed before retirement")
      }
      if try exists(alias.path) {
        guard
          try inspectAlias(ownerUID: record.selectedOwnerUID, ownerHome: ownerHome)
            == record.aliasTargetSHA256
        else {
          throw ReleasePackageError.verification("unmanaged alias changed before retirement")
        }
        try FileManager.default.removeItem(at: alias)
        try SecureFiles.syncDirectory(alias.deletingLastPathComponent())
      }
      guard rename(root.path, retired.path) == 0 else {
        throw ReleasePackageError.processFailure("cannot atomically quarantine unmanaged host")
      }
      try SecureFiles.syncDirectory(root.deletingLastPathComponent())
    } else if try exists(alias.path) {
      throw ReleasePackageError.verification("unmanaged alias survived without its host unit")
    }
    if try exists(retired.path) {
      let observed = try inspectUnitAtRoot(
        retired, expected: try expectedUnit(release: release, scratch: scratch),
        ownerUID: record.selectedOwnerUID)
      guard observed.digest == record.unitSHA256, observed.count == record.unitMemberCount else {
        throw ReleasePackageError.verification("quarantined unmanaged host changed")
      }
      try FileManager.default.removeItem(at: retired)
      try SecureFiles.syncDirectory(retired.deletingLastPathComponent())
    }
    guard try !exists(root.path), try !exists(retired.path), try !exists(alias.path) else {
      throw ReleasePackageError.verification("unmanaged host retirement is incomplete")
    }
  }

  private func expectedUnit(
    release: RetainedReleaseCatalogEntry, scratch: URL
  ) throws -> [PayloadRecord] {
    let expectation = try InstalledReleaseStateVerifier(runner: runner).expectedState(
      retainedAuthority: release.root, scratch: scratch.appendingPathComponent("authority"))
    let prefix = "./Library/Application Support/Reach/Host"
    let selected = expectation.host.compactMap { record -> PayloadRecord? in
      guard record.path == prefix || record.path.hasPrefix(prefix + "/") else { return nil }
      let suffix = String(record.path.dropFirst(prefix.count))
      return PayloadRecord(
        path: suffix.isEmpty ? "." : "." + suffix,
        kind: record.kind, mode: record.mode, uid: record.uid, gid: record.gid,
        size: record.size, posixChecksum: record.posixChecksum,
        sha256: record.sha256, linkTarget: record.linkTarget)
    }.sorted { $0.path.utf8.lexicographicallyPrecedes($1.path.utf8) }
    let top = Set(
      selected.compactMap { record -> String? in
        guard record.path.hasPrefix("./") else { return nil }
        let relative = String(record.path.dropFirst(2))
        guard !relative.contains("/") else { return nil }
        return relative
      })
    guard selected.first?.path == ".", top.count == 8, top.contains("reachd") else {
      throw ReleasePackageError.verification("retained host is not one eight-item unit")
    }
    return selected
  }

  private func inspectUnit(
    expected: [PayloadRecord], ownerUID: UInt32, ownerHome: URL
  ) throws -> (digest: String, count: Int) {
    try inspectUnitAtRoot(unmanagedRoot(ownerHome), expected: expected, ownerUID: ownerUID)
  }

  private func inspectUnitAtRoot(
    _ root: URL, expected: [PayloadRecord], ownerUID: UInt32
  ) throws -> (digest: String, count: Int) {
    let actual = try PayloadTree.inspect(root: root).records
    guard actual.count == expected.count, actual.map(\.path) == expected.map(\.path) else {
      throw ReleasePackageError.verification("unmanaged host unit is incomplete or has extras")
    }
    var lines: [String] = []
    for (lhs, rhs) in zip(actual, expected) {
      guard lhs.kind == rhs.kind, lhs.mode == rhs.mode,
        lhs.size == rhs.size, lhs.sha256 == rhs.sha256,
        lhs.linkTarget == rhs.linkTarget
      else {
        throw ReleasePackageError.verification("unmanaged host bytes or metadata changed")
      }
      let url =
        lhs.path == "."
        ? root
        : root.appendingPathComponent(String(lhs.path.dropFirst(2)))
      var info = stat()
      guard lstat(url.path, &info) == 0, info.st_uid == ownerUID, info.st_gid != 0 else {
        throw ReleasePackageError.verification("unmanaged host ownership changed")
      }
      lines.append(
        "\(lhs.kind.rawValue) \(lhs.path) \(lhs.mode) \(lhs.size) \(lhs.sha256 ?? "-")")
    }
    return (
      Digests.sha256(Data((lines.joined(separator: "\n") + "\n").utf8)), actual.count
    )
  }

  private func requireNoCollision(ownerHome: URL) throws {
    let candidatePaths = [
      "/usr/local/bin/reachd", "/opt/homebrew/bin/reachd", "/usr/bin/reachd",
      "/bin/reachd", "/usr/sbin/reachd", "/sbin/reachd",
    ]
    let present = try candidatePaths.filter(exists)
    let retiredPrefix = "reach.s36-retired-"
    let parent = unmanagedRoot(ownerHome).deletingLastPathComponent()
    let names: [String]
    if try exists(parent.path) {
      names = try FileManager.default.contentsOfDirectory(atPath: parent.path)
    } else {
      names = []
    }
    try UnmanagedMigrationCollisionPolicy.requireClear(
      presentExecutablePaths: present, siblingNames: names,
      retiredPrefix: retiredPrefix)
  }

  private func inspectAlias(ownerUID: UInt32, ownerHome: URL) throws -> String {
    let alias = unmanagedAlias(ownerHome)
    var info = stat()
    guard lstat(alias.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFLNK,
      info.st_uid == ownerUID,
      try FileManager.default.destinationOfSymbolicLink(atPath: alias.path)
        == unmanagedRoot(ownerHome).appendingPathComponent("reachd").path
    else {
      throw ReleasePackageError.verification("historical unmanaged alias changed")
    }
    let target = try FileManager.default.destinationOfSymbolicLink(atPath: alias.path)
    return Digests.sha256(Data(target.utf8))
  }

  private func inspectLaunchAgent(
    ownerUID: UInt32,
    ownerHome: URL,
    expectedExecutable: String,
    requireLoaded: Bool,
    logURL: URL
  ) throws -> String {
    let url = ownerHome.appendingPathComponent(
      "Library/LaunchAgents/systems.reach.reachd.plist")
    var info = stat()
    guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, info.st_uid == ownerUID, info.st_gid != 0,
      (info.st_mode & 0o7777) == 0o600
    else {
      throw ReleasePackageError.verification("historical LaunchAgent authority changed")
    }
    let data = try readNoFollow(url, expected: info)
    guard
      let object = try PropertyListSerialization.propertyList(from: data, format: nil)
        as? [String: Any],
      Set(object.keys)
        == Set([
          "Label", "ProgramArguments", "EnvironmentVariables", "RunAtLoad",
          "KeepAlive", "ThrottleInterval", "StandardOutPath", "StandardErrorPath",
          "ProcessType",
        ]),
      object["Label"] as? String == "systems.reach.reachd",
      object["ProgramArguments"] as? [String] == [expectedExecutable, "serve"],
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
      throw ReleasePackageError.verification("historical LaunchAgent authority changed")
    }
    let launch = try runner.run(
      "/bin/launchctl", ["print", "gui/\(ownerUID)/systems.reach.reachd"],
      timeout: 10, logURL: logURL, requireSuccess: false)
    guard (launch.exitStatus == 0) == requireLoaded else {
      throw ReleasePackageError.verification("historical LaunchAgent load state changed")
    }
    return Digests.sha256(data)
  }

  private func readNoFollow(_ url: URL, expected: stat) throws -> Data {
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open historical LaunchAgent")
    }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    var observed = stat()
    guard fstat(descriptor, &observed) == 0,
      (observed.st_mode & S_IFMT) == S_IFREG, observed.st_nlink == 1,
      observed.st_dev == expected.st_dev, observed.st_ino == expected.st_ino,
      observed.st_size == expected.st_size
    else {
      try? handle.close()
      throw ReleasePackageError.verification("historical LaunchAgent changed while opening")
    }
    let data: Data
    do {
      data = try handle.readToEnd() ?? Data()
      try handle.close()
    } catch {
      try? handle.close()
      throw ReleasePackageError.verification("cannot read historical LaunchAgent")
    }
    guard data.count == Int(observed.st_size) else {
      throw ReleasePackageError.verification("historical LaunchAgent changed while reading")
    }
    return data
  }

  private func runningProcess(
    ownerUID: UInt32, expectedExecutable: String,
    expectedDevice: UInt64, expectedInode: UInt64,
    logURL: URL
  ) throws -> (device: UInt64, inode: UInt64) {
    let result = try runner.run(
      "/bin/launchctl", ["print", "gui/\(ownerUID)/systems.reach.reachd"],
      timeout: 10, logURL: logURL)
    guard
      let match = result.output.range(
        of: #"(?m)^\s*pid\s*=\s*([0-9]+)\s*$"#, options: .regularExpression),
      let digits = result.output[match].range(of: #"[0-9]+"#, options: .regularExpression),
      let pid = pid_t(result.output[match][digits]), pid > 0
    else {
      throw ReleasePackageError.verification("historical host has no attributable PID")
    }
    var buffer = [CChar](repeating: 0, count: 4_096)
    guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else {
      throw ReleasePackageError.verification("cannot resolve historical host executable")
    }
    let end = buffer.firstIndex(of: 0) ?? buffer.endIndex
    let path = String(decoding: buffer[..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    guard path.utf8.elementsEqual(expectedExecutable.utf8) else {
      throw ReleasePackageError.verification("historical host runs the wrong inode")
    }
    let textVnodes = try runner.run(
      "/usr/sbin/lsof", ["-a", "-p", String(pid), "-d", "txt", "-F0fDin"],
      timeout: 10, logURL: URL(fileURLWithPath: logURL.path + "-vnode"))
    return try Self.runningImageVnode(
      procPath: path, expectedExecutable: expectedExecutable,
      expectedDevice: expectedDevice, expectedInode: expectedInode,
      lsofOutput: textVnodes.output)
  }

  static func runningImageVnode(
    procPath: String, expectedExecutable: String,
    expectedDevice: UInt64, expectedInode: UInt64,
    lsofOutput: String
  ) throws -> (device: UInt64, inode: UInt64) {
    guard procPath.utf8.elementsEqual(expectedExecutable.utf8) else {
      throw ReleasePackageError.verification("historical host runs the wrong executable")
    }
    let vnode = try MacOSInstalledStateCollector.runningExecutableVnode(
      fromLsof: lsofOutput, expectedPath: expectedExecutable,
      allowDeletedSuffix: false)
    guard vnode.device == expectedDevice, vnode.inode == expectedInode else {
      throw ReleasePackageError.verification(
        "historical host live image is not the exact retained executable")
    }
    return (vnode.device, vnode.inode)
  }

  private func exactExecutableVnode(
    _ url: URL, expected: PayloadRecord, ownerUID: UInt32
  ) throws -> (device: UInt64, inode: UInt64) {
    guard expected.kind == .file, expected.path == "./reachd",
      let expectedSHA256 = expected.sha256
    else {
      throw ReleasePackageError.verification(
        "retained unmanaged executable authority is malformed")
    }
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification(
        "cannot open exact historical unmanaged executable")
    }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    var info = stat()
    guard fstat(descriptor, &info) == 0,
      (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
      info.st_uid == ownerUID, info.st_gid != 0,
      UInt32(info.st_mode & 0o7777) == expected.mode,
      UInt64(info.st_size) == expected.size
    else {
      try? handle.close()
      throw ReleasePackageError.verification(
        "historical unmanaged executable metadata changed")
    }
    let data: Data
    do {
      data = try handle.readToEnd() ?? Data()
      try handle.close()
    } catch {
      try? handle.close()
      throw ReleasePackageError.verification(
        "cannot read exact historical unmanaged executable")
    }
    guard data.count == Int(info.st_size), Digests.sha256(data) == expectedSHA256 else {
      throw ReleasePackageError.verification(
        "historical unmanaged executable bytes changed")
    }
    return (UInt64(info.st_dev), UInt64(info.st_ino))
  }

  private func unmanagedRoot(_ ownerHome: URL) -> URL {
    ownerHome.appendingPathComponent(".local/libexec/reach")
  }

  private func unmanagedAlias(_ ownerHome: URL) -> URL {
    ownerHome.appendingPathComponent(".local/bin/reachd")
  }

  private func exists(_ path: String) throws -> Bool {
    var info = stat()
    if lstat(path, &info) == 0 { return true }
    if errno == ENOENT { return false }
    throw ReleasePackageError.verification("cannot inspect migration path")
  }
}

enum UnmanagedMigrationCollisionPolicy {
  static func requireClear(
    presentExecutablePaths: [String], siblingNames: [String],
    retiredPrefix: String = "reach.s36-retired-"
  ) throws {
    guard presentExecutablePaths.isEmpty else {
      throw ReleasePackageError.verification(
        "first-package migration found a PATH collision")
    }
    guard !siblingNames.contains(where: { $0.hasPrefix(retiredPrefix) }) else {
      throw ReleasePackageError.verification("stale migration quarantine exists")
    }
  }
}
