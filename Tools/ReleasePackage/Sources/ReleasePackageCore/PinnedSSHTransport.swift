import Darwin
import Foundation

protocol SSHCommandExecuting {
  func execute(
    executable: String, arguments: [String], timeout: TimeInterval,
    logURL: URL, sensitiveStandardInput: Data?, requireSuccess: Bool
  ) throws -> CommandResult
}

struct ProcessSSHCommandExecutor: SSHCommandExecuting {
  private let runner = ProcessRunner(testExecutables: ["/usr/bin/ssh", "/usr/bin/scp"])

  func execute(
    executable: String, arguments: [String], timeout: TimeInterval,
    logURL: URL, sensitiveStandardInput: Data?, requireSuccess: Bool
  ) throws -> CommandResult {
    guard ["/usr/bin/ssh", "/usr/bin/scp"].contains(executable) else {
      throw ReleasePackageError.invalidArgument("SSH transport executable changed")
    }
    if let sensitiveStandardInput {
      return try runner.runWithSensitiveStandardInput(
        executable, arguments, sensitiveStandardInput: sensitiveStandardInput,
        timeout: timeout, logURL: logURL, requireSuccess: requireSuccess)
    }
    return try runner.run(
      executable, arguments, timeout: timeout, logURL: logURL,
      requireSuccess: requireSuccess)
  }
}

public struct PinnedSSHProbeReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let architecture: String
  public let systemVersionSHA256: String
  public let transport: String
  public let verdict: String
}

/// S36's host-to-guest channel. It is intentionally narrower than a general
/// SSH wrapper: one user, one IPv4 address, one mode-0600 key and host-key
/// file, one transfer/export root, and a grammar-limited guest executable.
public final class PinnedSSHTransport {
  public static let remoteUser = "reachadmin"
  public static let incomingRoot = "/private/tmp/reach-s36-incoming"
  public static let toolsRoot = "/private/tmp/reach-s36-tools"
  public static let exportRoot = "/private/tmp/reach-s36-export"
  public static let stagedGuestExecutable =
    "/private/tmp/reach-s36-tools/reach-release-acceptance"
  public static let guestExecutable =
    "/Library/PrivilegedHelperTools/reach-release-acceptance-s36"
  public static let resetSentinel = "/private/tmp/reach-s36-reset-sentinel"

  private let address: String
  private let identity: URL
  private let knownHosts: URL
  private let logRoot: URL
  private let executor: any SSHCommandExecuting

  public convenience init(
    address: String, identity: URL, knownHosts: URL, logRoot: URL
  ) throws {
    try self.init(
      address: address, identity: identity, knownHosts: knownHosts,
      logRoot: logRoot, executor: ProcessSSHCommandExecutor())
  }

  init(
    address: String, identity: URL, knownHosts: URL, logRoot: URL,
    executor: any SSHCommandExecuting
  ) throws {
    var parsed = in_addr()
    guard inet_pton(AF_INET, address, &parsed) == 1 else {
      throw ReleasePackageError.invalidArgument("SSH guest address must be one IPv4 literal")
    }
    self.address = address
    self.identity = try Self.validatePrivateInput(identity, label: "SSH identity")
    self.knownHosts = try Self.validatePrivateInput(knownHosts, label: "SSH known-hosts")
    let knownText = String(
      decoding: try Data(contentsOf: self.knownHosts, options: [.mappedIfSafe]), as: UTF8.self)
    let lines = knownText.split(whereSeparator: \.isNewline)
    guard lines.count == 1 else {
      throw ReleasePackageError.verification("SSH authority must pin exactly one host key")
    }
    let fields = lines[0].split(separator: " ")
    guard fields.count == 3,
      [address, "[" + address + "]:22"].contains(String(fields[0])),
      fields[1] == "ssh-ed25519", !fields[2].isEmpty
    else {
      throw ReleasePackageError.verification("SSH host-key authority does not match the guest")
    }
    let validatedLogs = try ReleasePathAuthority.mutableRoot(logRoot, label: "SSH log root")
    try SecureFiles.createPrivateDirectory(validatedLogs)
    self.logRoot = validatedLogs
    self.executor = executor
  }

  public func probe() throws -> PinnedSSHProbeReport {
    _ = try remote(["/usr/bin/true"], timeout: 15, label: "probe")
    let version = try remote(["/usr/bin/sw_vers"], timeout: 15, label: "system-version")
    let architecture = try remote(
      ["/usr/bin/uname", "-m"], timeout: 15, label: "architecture"
    ).output.trimmingCharacters(in: .whitespacesAndNewlines)
    guard architecture == "arm64" else {
      throw ReleasePackageError.verification("SSH guest is not native arm64")
    }
    return .init(
      schemaVersion: 1, architecture: architecture,
      systemVersionSHA256: Digests.sha256(Data(version.output.utf8)),
      transport: "pinned-ssh-public-key", verdict: "pass")
  }

  public func createResetSentinel() throws {
    let before = try remote(
      ["/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", Self.resetSentinel],
      timeout: 15, label: "reset-sentinel-before", requireSuccess: false)
    guard before.exitStatus != 0 else {
      throw ReleasePackageError.verification("reset sentinel already exists in the fresh clone")
    }
    _ = try remote(
      ["/usr/bin/touch", Self.resetSentinel], timeout: 15,
      label: "reset-sentinel-create")
    _ = try remote(
      ["/bin/chmod", "600", Self.resetSentinel], timeout: 15,
      label: "reset-sentinel-mode")
    let after = try remote(
      ["/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", Self.resetSentinel],
      timeout: 15, label: "reset-sentinel-after")
    let authority = after.output.trimmingCharacters(in: .whitespacesAndNewlines)
    guard
      authority.range(
        of: #"^reachadmin:[A-Za-z0-9_-]+:600:0$"#, options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("reset sentinel authority changed")
    }
  }

  public func requireResetSentinelAbsent() throws {
    let result = try remote(
      ["/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", Self.resetSentinel],
      timeout: 15, label: "reset-sentinel-absent", requireSuccess: false)
    guard result.exitStatus != 0 else {
      throw ReleasePackageError.verification("a prior clone reset sentinel survived")
    }
  }

  public func prepareTransferRoots() throws {
    for path in [Self.incomingRoot, Self.toolsRoot, Self.exportRoot] {
      _ = try remote(
        ["/bin/mkdir", "-m", "700", path], timeout: 15,
        label: "prepare-" + URL(fileURLWithPath: path).lastPathComponent)
    }
  }

  public func transfer(_ source: URL, remoteName: String, executable: Bool = false) throws {
    try Self.validateRemoteName(remoteName)
    let validated = try ReleasePathAuthority.absoluteURL(source.path, label: "transfer source")
    let isDirectory = try Self.validateTransferTree(validated)
    if executable {
      guard !isDirectory, remoteName == "reach-release-acceptance" else {
        throw ReleasePackageError.invalidArgument("only the guest driver may be executable")
      }
    }
    let destinationRoot = executable ? Self.toolsRoot : Self.incomingRoot
    var arguments = scpPrefix()
    if isDirectory { arguments.append("-r") }
    arguments += [
      validated.path,
      Self.remoteUser + "@" + address + ":" + destinationRoot + "/" + remoteName,
    ]
    _ = try executor.execute(
      executable: "/usr/bin/scp", arguments: arguments,
      timeout: 3_600, logURL: nextLog("transfer-" + remoteName),
      sensitiveStandardInput: nil, requireSuccess: true)
    if executable {
      _ = try remote(
        ["/bin/chmod", "700", Self.stagedGuestExecutable], timeout: 15,
        label: "driver-mode")
    }
  }

  public func installGuestDriver(
    expectedSHA256: String, administratorInput: Data
  ) throws {
    try Self.validateSHA256(expectedSHA256)
    let before = try remote(
      ["/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", Self.guestExecutable],
      timeout: 15, label: "driver-before", requireSuccess: false)
    guard before.exitStatus != 0 else {
      throw ReleasePackageError.verification("root-owned guest driver already exists")
    }
    _ = try sudoRemote(
      [
        "/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "0555",
        Self.stagedGuestExecutable, Self.guestExecutable,
      ], administratorInput: administratorInput, timeout: 30,
      label: "install-driver")
    let digest = try remote(
      ["/usr/bin/shasum", "-a", "256", Self.guestExecutable], timeout: 15,
      label: "driver-digest"
    ).output.split(whereSeparator: \.isWhitespace).first.map(String.init)
    let authority = try remote(
      ["/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", Self.guestExecutable],
      timeout: 15, label: "driver-authority"
    ).output.trimmingCharacters(in: .whitespacesAndNewlines)
    guard digest == expectedSHA256,
      authority.range(of: #"^root:wheel:555:[1-9][0-9]*$"#, options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("installed guest driver authority changed")
    }
    _ = try remote(
      ["/bin/rm", "-f", Self.stagedGuestExecutable], timeout: 15,
      label: "remove-staged-driver")
  }

  public func executeGuest(
    arguments: [String], administratorInput: Data,
    timeout: TimeInterval = 3_600
  ) throws
    -> CommandResult
  {
    try Self.validateGuestArguments(arguments)
    return try sudoRemote(
      [Self.guestExecutable] + arguments,
      administratorInput: administratorInput, timeout: timeout,
      label: "guest-" + arguments[1])
  }

  public func removeGuestDriver(administratorInput: Data) throws {
    _ = try sudoRemote(
      ["/bin/rm", "-f", Self.guestExecutable],
      administratorInput: administratorInput, timeout: 30,
      label: "remove-driver")
    let after = try remote(
      ["/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", Self.guestExecutable],
      timeout: 15, label: "driver-after", requireSuccess: false)
    guard after.exitStatus != 0 else {
      throw ReleasePackageError.verification("root-owned guest driver survived teardown")
    }
  }

  public func fetchExport(named name: String, to destination: URL) throws {
    try Self.validateRemoteName(name)
    let validated = try ReleasePathAuthority.absoluteURL(
      destination.path, label: "export destination")
    guard !FileManager.default.fileExists(atPath: validated.path) else {
      throw ReleasePackageError.unsafePath("export destination already exists")
    }
    let arguments =
      scpPrefix() + [
        Self.remoteUser + "@" + address + ":" + Self.exportRoot + "/" + name,
        validated.path,
      ]
    _ = try executor.execute(
      executable: "/usr/bin/scp", arguments: arguments,
      timeout: 600, logURL: nextLog("export-" + name),
      sensitiveStandardInput: nil, requireSuccess: true)
    _ = try Self.validateTransferTree(validated)
  }

  static func validateGuestArguments(_ arguments: [String]) throws {
    guard arguments.count >= 3, arguments[0] == "guest",
      Set([
        "inspect", "install", "migrate", "update", "rollback", "uninstall", "verify",
        "recover", "interrupt-installer", "static-trust", "mandatory-deselection",
        "owner-contention-begin", "owner-contention-check", "owner-contention-finish",
        "crash-daemon", "crash-helper",
      ]).contains(arguments[1]),
      (arguments.count - 2).isMultiple(of: 2)
    else {
      throw ReleasePackageError.invalidArgument("guest-driver arguments are outside S36")
    }
    let allowed = Set([
      "--authority", "--prior-authority", "--owner-uid", "--owner-home", "--host",
      "--helper", "--state", "--journal", "--scratch", "--stop-after", "--output",
      "--contender-uid", "--contender-home",
    ])
    var seen: Set<String> = []
    var index = 2
    while index < arguments.count {
      let key = arguments[index]
      let value = arguments[index + 1]
      guard allowed.contains(key), seen.insert(key).inserted,
        value.range(of: #"^[A-Za-z0-9_./:+-]+$"#, options: .regularExpression) != nil,
        !value.contains(".."), !value.contains("//")
      else {
        throw ReleasePackageError.invalidArgument("guest-driver option is unsafe or repeated")
      }
      if [
        "--authority", "--prior-authority", "--owner-home", "--contender-home",
        "--journal", "--scratch", "--output",
      ]
      .contains(key) {
        guard value.hasPrefix("/"), value != "/" else {
          throw ReleasePackageError.invalidArgument("guest-driver path is not absolute")
        }
      }
      index += 2
    }
  }

  private func remote(
    _ command: [String], timeout: TimeInterval, label: String,
    requireSuccess: Bool = true
  ) throws -> CommandResult {
    guard Self.remoteCommandIsAllowed(command) else {
      throw ReleasePackageError.invalidArgument("remote command is outside S36")
    }
    return try executor.execute(
      executable: "/usr/bin/ssh", arguments: sshPrefix() + ["--"] + command,
      timeout: timeout, logURL: nextLog(label), sensitiveStandardInput: nil,
      requireSuccess: requireSuccess)
  }

  private func sudoRemote(
    _ command: [String], administratorInput: Data,
    timeout: TimeInterval, label: String
  ) throws -> CommandResult {
    try Self.validateAdministratorInput(administratorInput)
    let full = ["/usr/bin/sudo", "-S", "-k", "-p", "", "--"] + command
    guard Self.remoteCommandIsAllowed(full) else {
      throw ReleasePackageError.invalidArgument("administrator command is outside S36")
    }
    return try executor.execute(
      executable: "/usr/bin/ssh", arguments: sshPrefix() + ["--"] + full,
      timeout: timeout, logURL: nextLog(label),
      sensitiveStandardInput: administratorInput, requireSuccess: true)
  }

  private static func remoteCommandIsAllowed(_ command: [String]) -> Bool {
    if command == ["/usr/bin/true"] || command == ["/usr/bin/sw_vers"]
      || command == ["/usr/bin/uname", "-m"]
    {
      return true
    }
    if command.count == 4, command[0] == "/bin/mkdir", command[1] == "-m",
      command[2] == "700",
      [incomingRoot, toolsRoot, exportRoot].contains(command[3])
    {
      return true
    }
    if command == ["/bin/chmod", "700", stagedGuestExecutable]
      || command == ["/bin/rm", "-f", stagedGuestExecutable]
    {
      return true
    }
    if command == ["/usr/bin/shasum", "-a", "256", guestExecutable]
      || command == ["/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", guestExecutable]
      || command == ["/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", resetSentinel]
    {
      return true
    }
    if command == ["/usr/bin/touch", resetSentinel]
      || command == ["/bin/chmod", "600", resetSentinel]
    {
      return true
    }
    let sudo = ["/usr/bin/sudo", "-S", "-k", "-p", "", "--"]
    guard command.starts(with: sudo) else { return false }
    let privileged = Array(command.dropFirst(sudo.count))
    if privileged == [
      "/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "0555",
      stagedGuestExecutable, guestExecutable,
    ] || privileged == ["/bin/rm", "-f", guestExecutable] {
      return true
    }
    guard privileged.first == guestExecutable else { return false }
    return (try? validateGuestArguments(Array(privileged.dropFirst()))) != nil
  }

  private func sshPrefix() -> [String] {
    commonPrefix() + ["-p", "22", Self.remoteUser + "@" + address]
  }

  private func scpPrefix() -> [String] {
    // Retained release authority is mode-bound (0700 directories, 0600
    // files). Preserve those bits across the authenticated transport; the
    // guest verifier independently rechecks every member before use.
    ["-q", "-p"] + commonPrefix() + ["-P", "22"]
  }

  private func commonPrefix() -> [String] {
    [
      "-F", "/dev/null", "-i", identity.path,
      "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
      "-o", "StrictHostKeyChecking=yes",
      "-o", "UserKnownHostsFile=" + knownHosts.path,
      "-o", "GlobalKnownHostsFile=/dev/null", "-o", "CheckHostIP=yes",
      "-o", "ConnectTimeout=10", "-o", "PasswordAuthentication=no",
      "-o", "KbdInteractiveAuthentication=no",
      "-o", "PreferredAuthentications=publickey",
    ]
  }

  private func nextLog(_ label: String) -> URL {
    logRoot.appendingPathComponent(UUID().uuidString + "-" + label + ".log")
  }

  private static func validatePrivateInput(_ url: URL, label: String) throws -> URL {
    let validated = try ReleasePathAuthority.absoluteURL(url.path, label: label)
    var info = stat()
    guard lstat(validated.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, info.st_uid == getuid(), (info.st_mode & 0o7777) == 0o600,
      info.st_size > 0
    else {
      throw ReleasePackageError.unsafePath(label + " must be one owner-private regular file")
    }
    return validated
  }

  private static func validateRemoteName(_ name: String) throws {
    guard
      name.range(of: #"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"#, options: .regularExpression)
        != nil,
      name != ".", name != ".."
    else {
      throw ReleasePackageError.invalidArgument("remote transfer name is unsafe")
    }
  }

  private static func validateSHA256(_ value: String) throws {
    guard value.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
      throw ReleasePackageError.invalidArgument("driver SHA-256 must be lowercase hexadecimal")
    }
  }

  private static func validateAdministratorInput(_ value: Data) throws {
    guard value.count >= 2, value.count <= 1_025, value.last == 0x0a,
      !value.dropLast().contains(0x00), !value.dropLast().contains(0x0a),
      !value.dropLast().contains(0x0d)
    else {
      throw ReleasePackageError.invalidArgument("administrator input is malformed")
    }
  }

  private static func validateTransferTree(_ root: URL) throws -> Bool {
    var rootInfo = stat()
    guard lstat(root.path, &rootInfo) == 0 else {
      throw ReleasePackageError.verification("transfer source is missing")
    }
    let kind = rootInfo.st_mode & S_IFMT
    if kind == S_IFREG {
      guard rootInfo.st_nlink == 1 else {
        throw ReleasePackageError.unsafePath("transfer file has multiple hard links")
      }
      return false
    }
    guard kind == S_IFDIR else {
      throw ReleasePackageError.unsafePath("transfer source is not a regular tree")
    }
    for entry in try SecureFiles.enumerateTree(root) {
      var info = stat()
      guard lstat(entry.path, &info) == 0 else {
        throw ReleasePackageError.verification("transfer tree changed during inspection")
      }
      let entryKind = info.st_mode & S_IFMT
      guard entryKind == S_IFDIR || (entryKind == S_IFREG && info.st_nlink == 1) else {
        throw ReleasePackageError.unsafePath("transfer tree contains a link or special file")
      }
    }
    return true
  }
}
