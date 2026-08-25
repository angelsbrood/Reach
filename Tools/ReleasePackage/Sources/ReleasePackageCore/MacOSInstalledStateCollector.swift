import Darwin
import Foundation

public struct MacOSInstalledStateCollector {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
  }

  public func collect(
    retainedAuthority: URL,
    policy: InstalledVerificationPolicy,
    ownerHome: URL,
    scratch: URL,
    output: URL
  ) throws -> InstalledReleaseSnapshot {
    try policy.validate()
    guard ownerHome.path.hasPrefix("/Users/"),
      ownerHome.path.split(separator: "/").count == 2
    else {
      throw ReleasePackageError.unsafePath("selected owner home must be one direct /Users child")
    }
    try SecureFiles.createPrivateDirectory(scratch)
    let verifier = InstalledReleaseStateVerifier(runner: runner)
    let expectation = try verifier.expectedState(
      retainedAuthority: retainedAuthority,
      scratch: scratch.appendingPathComponent("authority"))
    let expectedFiles = try verifier.mergedPayload(expectation.host + expectation.helper)
    let files = try expectedFiles.map(observeFile)
    let receipts = try [
      observeReceipt(
        identifier: "systems.reach.host", version: expectation.release.host,
        logs: scratch.appendingPathComponent("host-receipt")),
      observeReceipt(
        identifier: "systems.reach.meshd", version: expectation.release.helper,
        logs: scratch.appendingPathComponent("helper-receipt")),
    ]
    let expectedReceiptPaths = [
      verifier.receiptPaths(expectation.host), verifier.receiptPaths(expectation.helper),
    ]
    guard zip(receipts, expectedReceiptPaths).allSatisfy({ $0.payloadPaths == $1 }) else {
      throw ReleasePackageError.verification(
        "installed receipt files differ from signed BOM authority")
    }
    let hostLaunchURL = ownerHome.appendingPathComponent(
      "Library/LaunchAgents/systems.reach.reachd.plist")
    let hostLaunch =
      try policy.host == .unbound
      ? nil
      : observeLaunch(
        plist: hostLaunchURL, expectedLabel: "systems.reach.reachd",
        domain: "gui/\(policy.selectedOwnerUID)", ownerUID: policy.selectedOwnerUID,
        logs: scratch.appendingPathComponent("host-launch"))
    let helperLaunch = try observeLaunch(
      plist: URL(fileURLWithPath: "/Library/LaunchDaemons/systems.reach.meshd.plist"),
      expectedLabel: "systems.reach.meshd", domain: "system", ownerUID: 0,
      logs: scratch.appendingPathComponent("helper-launch"))
    let hostProcess =
      try hostLaunch?.loaded == true
      ? observeProcess(
        pid: try loadedPID(
          domain: "gui/\(policy.selectedOwnerUID)", label: "systems.reach.reachd",
          logs: scratch.appendingPathComponent("host-pid")),
        expectedPath: "/Library/Application Support/Reach/Host/reachd",
        log: scratch.appendingPathComponent("host-vnode.log"))
      : nil
    let helperProcess =
      try helperLaunch.loaded
      ? observeProcess(
        pid: try loadedPID(
          domain: "system", label: "systems.reach.meshd",
          logs: scratch.appendingPathComponent("helper-pid")),
        expectedPath: "/Library/PrivilegedHelperTools/systems.reach.meshd",
        log: scratch.appendingPathComponent("helper-vnode.log"))
      : nil
    let helper = try observeHelper(
      process: helperProcess, logs: scratch.appendingPathComponent("helper-runtime"))
    let state = try observeState(
      ownerHome.appendingPathComponent("Library/Application Support/Reach"),
      expectedOwnerUID: policy.selectedOwnerUID)
    let snapshot = InstalledReleaseSnapshot(
      release: expectation.release,
      packageSHA256: expectation.packageSHA256,
      provenanceSHA256: expectation.provenanceSHA256,
      receipts: receipts,
      files: files,
      extraPackageOwnedPaths: try extraPackageOwnedPaths(expected: Set(expectedFiles.map(\.path))),
      hostProcess: hostProcess,
      hostLaunchAgent: hostLaunch,
      helperLaunchDaemon: helperLaunch,
      helper: helper,
      retainedState: state)
    let encoded = try CanonicalJSON.encode(snapshot)
    try SecureFiles.atomicWrite(encoded, to: output)
    _ = try verifier.verify(snapshot: snapshot, policy: policy, expectation: expectation)
    return snapshot
  }

  private func observeReceipt(
    identifier: String, version: DottedVersion, logs: URL
  ) throws -> InstalledReceiptObservation {
    let info = try runner.run(
      "/usr/sbin/pkgutil", ["--pkg-info-plist", identifier],
      logURL: URL(fileURLWithPath: logs.path + "-info.log"))
    guard
      let object = try PropertyListSerialization.propertyList(
        from: Data(info.output.utf8), format: nil) as? [String: Any],
      let actualIdentifier = object["pkgid"] as? String,
      let actualVersion = object["pkg-version"] as? String,
      actualIdentifier == identifier,
      try DottedVersion(actualVersion) == version
    else {
      throw ReleasePackageError.verification("installed receipt version changed: \(identifier)")
    }
    let files = try runner.run(
      "/usr/sbin/pkgutil", ["--files", identifier],
      logURL: URL(fileURLWithPath: logs.path + "-files.log"))
    let paths = files.output.split(whereSeparator: \.isNewline).map(String.init).sorted {
      $0.utf8.lexicographicallyPrecedes($1.utf8)
    }
    guard paths.allSatisfy({ !$0.hasPrefix("/") && !$0.contains("..") && !$0.isEmpty }) else {
      throw ReleasePackageError.verification("installed receipt contains an unsafe path")
    }
    return .init(identifier: identifier, version: version, payloadPaths: paths)
  }

  private func observeFile(_ record: PayloadRecord) throws -> InstalledFileObservation {
    let url = URL(fileURLWithPath: record.path)
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      throw ReleasePackageError.verification("installed payload member is missing")
    }
    let kind: PayloadKind
    let sha: String?
    let target: String?
    switch info.st_mode & S_IFMT {
    case S_IFDIR:
      kind = .directory
      sha = nil
      target = nil
    case S_IFREG:
      kind = .file
      sha = try Digests.sha256(file: url)
      target = nil
    case S_IFLNK:
      kind = .symlink
      let value = try FileManager.default.destinationOfSymbolicLink(atPath: url.path)
      target = value
      sha = Digests.sha256(Data(value.utf8))
    default:
      throw ReleasePackageError.unsafePath("installed payload member is a special file")
    }
    return .init(
      path: record.path, kind: kind, mode: UInt32(info.st_mode & 0o7777),
      uid: info.st_uid, gid: info.st_gid, size: UInt64(info.st_size),
      sha256: sha, linkTarget: target, device: UInt64(info.st_dev), inode: UInt64(info.st_ino))
  }

  private func observeLaunch(
    plist: URL, expectedLabel: String, domain: String, ownerUID: UInt32, logs: URL
  ) throws -> InstalledLaunchObservation {
    var info = stat()
    guard lstat(plist.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, info.st_uid == ownerUID
    else {
      throw ReleasePackageError.verification("launch definition ownership changed")
    }
    let data = try Data(contentsOf: plist, options: [.mappedIfSafe])
    guard
      let object = try PropertyListSerialization.propertyList(
        from: data, format: nil) as? [String: Any],
      object["Label"] as? String == expectedLabel,
      let arguments = object["ProgramArguments"] as? [String],
      let runAtLoad = object["RunAtLoad"] as? Bool,
      let keepAlive = object["KeepAlive"] as? Bool,
      let throttleInterval = object["ThrottleInterval"] as? Int,
      let standardOutPath = object["StandardOutPath"] as? String,
      let standardErrorPath = object["StandardErrorPath"] as? String,
      let processType = object["ProcessType"] as? String
    else {
      throw ReleasePackageError.verification("launch definition changed")
    }
    let environment = object["EnvironmentVariables"] as? [String: String] ?? [:]
    let umask = object["Umask"] as? Int
    let result = try runner.run(
      "/bin/launchctl", ["print", "\(domain)/\(expectedLabel)"],
      timeout: 10, logURL: logs, requireSuccess: false)
    return .init(
      label: expectedLabel, uid: info.st_uid, gid: info.st_gid,
      mode: UInt32(info.st_mode & 0o7777), programArguments: arguments,
      environmentVariables: environment,
      runAtLoad: runAtLoad, keepAlive: keepAlive,
      throttleInterval: throttleInterval, umask: umask,
      standardOutPath: standardOutPath, standardErrorPath: standardErrorPath,
      processType: processType,
      definitionKeys: object.keys.sorted {
        $0.utf8.lexicographicallyPrecedes($1.utf8)
      },
      loaded: result.exitStatus == 0)
  }

  private func loadedPID(domain: String, label: String, logs: URL) throws -> pid_t {
    let result = try runner.run(
      "/bin/launchctl", ["print", "\(domain)/\(label)"],
      timeout: 10, logURL: logs)
    guard
      let match = result.output.range(
        of: #"(?m)^\s*pid\s*=\s*([0-9]+)\s*$"#, options: .regularExpression),
      let pidRange = result.output[match].range(of: #"[0-9]+"#, options: .regularExpression),
      let pid = pid_t(result.output[match][pidRange]), pid > 0
    else {
      throw ReleasePackageError.verification("launchd job has no attributable PID")
    }
    return pid
  }

  private func observeProcess(pid: pid_t, expectedPath: String, log: URL) throws
    -> InstalledProcessObservation
  {
    // Darwin defines PROC_PIDPATHINFO_MAXSIZE as 4 * MAXPATHLEN, but the
    // macro is unavailable to Swift because it is not structurally imported.
    var buffer = [CChar](repeating: 0, count: 4_096)
    guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else {
      throw ReleasePackageError.verification("cannot resolve supervised process executable")
    }
    let terminator = buffer.firstIndex(of: 0) ?? buffer.endIndex
    let path = String(
      decoding: buffer[..<terminator].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    guard path.utf8.elementsEqual(expectedPath.utf8) else {
      throw ReleasePackageError.verification("supervised process runs the wrong executable")
    }
    let textVnodes = try runner.run(
      "/usr/sbin/lsof", ["-a", "-p", String(pid), "-d", "txt", "-F0fDin"],
      timeout: 10, logURL: log)
    let vnode = try Self.runningExecutableVnode(
      fromLsof: textVnodes.output, expectedPath: expectedPath)
    var processInfo = proc_bsdinfo()
    guard
      proc_pidinfo(
        pid, PROC_PIDTBSDINFO, 0, &processInfo, Int32(MemoryLayout.size(ofValue: processInfo)))
        == MemoryLayout.size(ofValue: processInfo)
    else {
      throw ReleasePackageError.verification("cannot inspect supervised process owner")
    }
    return .init(
      pid: pid, uid: processInfo.pbi_uid, executablePath: path,
      device: vnode.device, inode: vnode.inode)
  }

  struct RunningExecutableVnode: Equatable, Sendable {
    let device: UInt64
    let inode: UInt64
  }

  static func runningExecutableVnode(
    fromLsof output: String, expectedPath: String,
    allowDeletedSuffix: Bool = false
  ) throws -> RunningExecutableVnode {
    var matches: [RunningExecutableVnode] = []
    for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
      let fields = line.split(separator: "\0", omittingEmptySubsequences: true).map(String.init)
      guard fields.contains("ftxt"),
        let name = fields.first(where: { $0.hasPrefix("n") }).map({ String($0.dropFirst()) }),
        name.utf8.elementsEqual(expectedPath.utf8)
          || (allowDeletedSuffix
            && name.utf8.elementsEqual((expectedPath + " (deleted)").utf8)),
        let deviceText = fields.first(where: { $0.hasPrefix("D0x") })
          .map({ String($0.dropFirst(3)) }),
        let inodeText = fields.first(where: { $0.hasPrefix("i") })
          .map({ String($0.dropFirst()) }),
        let device = UInt64(deviceText, radix: 16),
        let inode = UInt64(inodeText), device > 0, inode > 0
      else { continue }
      matches.append(.init(device: device, inode: inode))
    }
    guard matches.count == 1 else {
      throw ReleasePackageError.verification(
        "running executable vnode is absent or ambiguous")
    }
    return matches[0]
  }

  private func observeHelper(
    process: InstalledProcessObservation?, logs: URL
  ) throws -> InstalledHelperObservation {
    let statusURL = URL(fileURLWithPath: "/Library/Application Support/Reach Mesh/status.json")
    guard try pathExistsNoFollow(statusURL.path) else {
      return .init(
        process: process, statusVersion: nil, configured: false, ready: false,
        interfacePresent: false, directRouteCount: 0, relayRouteCount: 0,
        foreignRouteCount: 0,
        controlSocketPresent: try observeControlSocket())
    }
    var statusInfo = stat()
    guard
      lstat(statusURL.path, &statusInfo) == 0,
      (statusInfo.st_mode & S_IFMT) == S_IFREG,
      statusInfo.st_nlink == 1, statusInfo.st_uid == 0, statusInfo.st_gid == 0,
      (statusInfo.st_mode & 0o7777) == 0o600,
      let object = try JSONSerialization.jsonObject(
        with: Data(contentsOf: statusURL)) as? [String: Any],
      let versionString = object["helperVersion"] as? String,
      let version = Int(versionString),
      let ready = object["ready"] as? Bool,
      let interfaceName = object["interfaceName"] as? String,
      let relay = object["relay"] as? [String: Any],
      let relayConfigured = relay["configured"] as? Bool,
      let relayRouteCount = relay["routeCount"] as? Int
    else {
      throw ReleasePackageError.verification("helper status is malformed")
    }
    let generation = (object["generation"] as? NSNumber)?.uint64Value ?? 0
    let route = try runner.run(
      "/sbin/route", ["-n", "get", "-net", "10.86.0.0/24"],
      timeout: 10, logURL: logs, requireSuccess: false)
    let routeInterface =
      route.output.split(whereSeparator: \.isNewline).first(where: {
        $0.trimmingCharacters(in: .whitespaces).hasPrefix("interface:")
      }).map { line in
        line.split(separator: ":", maxSplits: 1).last.map {
          $0.trimmingCharacters(in: .whitespaces)
        } ?? ""
      } ?? ""
    let directRouteCount = route.exitStatus == 0 && routeInterface == interfaceName ? 1 : 0
    let foreign =
      route.exitStatus == 0 && !routeInterface.isEmpty && routeInterface != interfaceName
      ? 1 : 0
    return .init(
      process: process, statusVersion: version, configured: generation > 0,
      ready: ready, interfacePresent: !interfaceName.isEmpty,
      directRouteCount: directRouteCount,
      relayRouteCount: relayConfigured ? relayRouteCount : 0,
      foreignRouteCount: foreign,
      controlSocketPresent: try observeControlSocket())
  }

  func observeState(_ root: URL, expectedOwnerUID: UInt32) throws
    -> RetainedStateObservation
  {
    var rootInfo = stat()
    guard lstat(root.path, &rootInfo) == 0 else {
      if errno == ENOENT {
        return .init(
          present: false, ownerUID: nil, itemCount: 0,
          authoritySHA256: nil, mutableItemCount: 0, caCreationCount: 0)
      }
      throw ReleasePackageError.verification("cannot inspect login-owned state")
    }
    guard (rootInfo.st_mode & S_IFMT) == S_IFDIR, rootInfo.st_uid == expectedOwnerUID,
      (rootInfo.st_mode & 0o7777) == 0o700
    else {
      throw ReleasePackageError.verification("login-owned state owner changed")
    }
    let exactRoots: Set<String> = [
      "ca", "config.json", "devices.json", "identities", "mesh-intent.json", "wg",
    ]
    let mutableRoots: Set<String> = [
      "enroll-tokens", "mesh-intent.lock", "mesh-stage", "reachability.json",
    ]
    var exactLines: [String] = []
    var mutableCount = 0
    for url in try SecureFiles.enumerateTree(root).sorted(by: { $0.path < $1.path }) {
      var info = stat()
      guard lstat(url.path, &info) == 0, info.st_uid == expectedOwnerUID,
        info.st_gid == rootInfo.st_gid
      else {
        throw ReleasePackageError.verification("login-owned state contains unowned authority")
      }
      let relative = String(url.path.dropFirst(root.path.count + 1))
      guard let top = relative.split(separator: "/", maxSplits: 1).first.map(String.init) else {
        throw ReleasePackageError.verification("login-owned state contains an empty path")
      }
      if exactRoots.contains(top) {
        switch info.st_mode & S_IFMT {
        case S_IFDIR:
          guard (info.st_mode & 0o7777) == 0o700 else {
            throw ReleasePackageError.unsafePath(
              "exact login-owned state directory mode changed")
          }
          exactLines.append(
            "d \(relative) \(info.st_mode & 0o7777) \(info.st_uid) \(info.st_gid) \(info.st_nlink)")
        case S_IFREG:
          let mode = info.st_mode & 0o7777
          let secret = Self.secretRetainedPath(relative)
          guard info.st_nlink == 1, [mode_t(0o600), mode_t(0o644)].contains(mode),
            !secret || mode == 0o600
          else {
            throw ReleasePackageError.unsafePath(
              "exact login-owned state file metadata changed")
          }
          exactLines.append(
            "f \(relative) \(mode) \(info.st_uid) \(info.st_gid) \(info.st_nlink) \(info.st_size) \(try Digests.sha256(file: url))"
          )
        default:
          throw ReleasePackageError.unsafePath(
            "exact login-owned state contains a link or special file")
        }
      } else if mutableRoots.contains(top) {
        switch info.st_mode & S_IFMT {
        case S_IFDIR:
          guard (info.st_mode & 0o7777) == 0o700 else {
            throw ReleasePackageError.unsafePath(
              "mutable login-owned state directory mode changed")
          }
        case S_IFREG:
          guard info.st_nlink == 1, (info.st_mode & 0o7777) == 0o600 else {
            throw ReleasePackageError.unsafePath(
              "mutable login-owned state file metadata changed")
          }
        default:
          throw ReleasePackageError.unsafePath(
            "mutable login-owned state contains a link or special file")
        }
        mutableCount += 1
      } else {
        throw ReleasePackageError.verification(
          "login-owned state contains an unclassified authority root")
      }
    }
    let ca = root.appendingPathComponent("ca/ca.der")
    let caKey = root.appendingPathComponent("ca/ca-key.raw")
    let caCount = try pathExistsNoFollow(ca.path) && pathExistsNoFollow(caKey.path) ? 1 : 0
    return .init(
      present: true, ownerUID: rootInfo.st_uid, itemCount: exactLines.count,
      authoritySHA256: Digests.sha256(
        Data((exactLines.joined(separator: "\n") + "\n").utf8)),
      mutableItemCount: mutableCount, caCreationCount: caCount)
  }

  private func extraPackageOwnedPaths(expected: Set<String>) throws -> [String] {
    try Self.unexpectedPackagePaths(
      expected: expected,
      roots: ["/Library/Application Support/Reach"],
      leaves: [
        "/usr/local/bin/reachd", "/Library/PrivilegedHelperTools/systems.reach.meshd",
        "/Library/LaunchDaemons/systems.reach.meshd.plist",
      ])
  }

  static func unexpectedPackagePaths(
    expected: Set<String>, roots: [String], leaves: [String]
  ) throws -> [String] {
    var actual: Set<String> = []
    for path in roots {
      let root = URL(fileURLWithPath: path)
      var info = stat()
      if lstat(path, &info) != 0 {
        guard errno == ENOENT else {
          throw ReleasePackageError.verification("cannot inspect installed package root")
        }
        continue
      }
      guard (info.st_mode & S_IFMT) == S_IFDIR else {
        throw ReleasePackageError.unsafePath("installed package root is not a directory")
      }
      actual.insert(path)
      for url in try SecureFiles.enumerateTree(root) { actual.insert(url.path) }
    }
    for path in leaves {
      var info = stat()
      if lstat(path, &info) == 0 {
        actual.insert(path)
      } else if errno != ENOENT {
        throw ReleasePackageError.verification("cannot inspect installed package leaf")
      }
    }
    return actual.subtracting(expected).sorted {
      $0.utf8.lexicographicallyPrecedes($1.utf8)
    }
  }

  private static func secretRetainedPath(_ relative: String) -> Bool {
    relative == "mesh-intent.json"
      || relative.hasPrefix("identities/")
      || relative.hasPrefix("wg/")
      || relative == "ca/ca-key.raw"
      || relative == "ca/server-key.raw"
  }

  private func pathExistsNoFollow(_ path: String) throws -> Bool {
    var info = stat()
    if lstat(path, &info) == 0 { return true }
    if errno == ENOENT { return false }
    throw ReleasePackageError.verification("cannot inspect retained-state path")
  }

  private func observeControlSocket() throws -> Bool {
    let path = "/var/run/systems.reach.meshd.sock"
    var info = stat()
    if lstat(path, &info) != 0 {
      if errno == ENOENT { return false }
      throw ReleasePackageError.verification("cannot inspect helper control socket")
    }
    guard (info.st_mode & S_IFMT) == S_IFSOCK, info.st_uid == 0 else {
      throw ReleasePackageError.unsafePath("helper control path is not a root-owned socket")
    }
    return true
  }
}
