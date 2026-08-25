import Darwin
import Foundation

public enum TartS36VM: String, CaseIterable, Codable, Sendable {
  case base = "reach-s36-macos27-base"
  case acceptance = "reach-s36-macos27-acceptance"
}

public struct TartVMInventoryRecord: Codable, Equatable, Sendable {
  public let source: String
  public let name: String
  public let diskGiB: Int
  public let allocatedGiB: Int
  public let accessed: String
  public let running: Bool
  public let state: String

  enum CodingKeys: String, CodingKey {
    case source = "Source"
    case name = "Name"
    case diskGiB = "Disk"
    case allocatedGiB = "Size"
    case accessed = "Accessed"
    case running = "Running"
    case state = "State"
  }
}

public struct TartVMConfigurationRecord: Codable, Equatable, Sendable {
  public let operatingSystem: String
  public let cpuCount: Int
  public let memoryMiB: UInt64
  public let diskGiB: Int
  public let diskFormat: String
  public let allocatedSize: String
  public let display: String
  public let running: Bool
  public let state: String

  enum CodingKeys: String, CodingKey {
    case operatingSystem = "OS"
    case cpuCount = "CPU"
    case memoryMiB = "Memory"
    case diskGiB = "Disk"
    case diskFormat = "DiskFormat"
    case allocatedSize = "Size"
    case display = "Display"
    case running = "Running"
    case state = "State"
  }
}

/// Stable clone authority excludes Tart's observed allocation and lifecycle
/// fields. Provisioning necessarily changes allocated bytes; running/state are
/// verified from inventory at each transition instead of being mistaken for
/// immutable hardware configuration.
struct TartVMConfigurationAuthority: Codable, Equatable, Sendable {
  let operatingSystem: String
  let cpuCount: Int
  let memoryMiB: UInt64
  let diskGiB: Int
  let diskFormat: String
  let display: String
}

extension TartVMConfigurationRecord {
  var authority: TartVMConfigurationAuthority {
    .init(
      operatingSystem: operatingSystem, cpuCount: cpuCount,
      memoryMiB: memoryMiB, diskGiB: diskGiB,
      diskFormat: diskFormat, display: display)
  }
}

public protocol TartCommandExecuting {
  func execute(
    arguments: [String], environment: [String: String], timeout: TimeInterval,
    logURL: URL, requireSuccess: Bool
  ) throws -> CommandResult
}

public enum TartToolAuthority {
  public static let installedExecutable =
    "/opt/homebrew/opt/tart/libexec/tart.app/Contents/MacOS/tart"

  public static func resolve(expectedSHA256: String) throws -> URL {
    guard expectedSHA256.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
      throw ReleasePackageError.invalidArgument("Tart SHA-256 must be lowercase hexadecimal")
    }
    guard let pointer = realpath(installedExecutable, nil) else {
      throw ReleasePackageError.verification("the pinned Tart executable is not installed")
    }
    defer { free(pointer) }
    let physical = String(cString: pointer)
    guard
      physical.range(
        of: #"^/opt/homebrew/Cellar/tart/2\.35\.0/libexec/tart\.app/Contents/MacOS/tart$"#,
        options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("Tart did not resolve to the exact 2.35.0 Cellar")
    }
    let executable = URL(fileURLWithPath: physical)
    var info = stat()
    guard lstat(executable.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, info.st_mode & 0o111 != 0,
      try Digests.sha256(file: executable) == expectedSHA256
    else {
      throw ReleasePackageError.verification("Tart executable does not match the pinned authority")
    }
    return executable
  }
}

public struct ProcessTartCommandExecutor: TartCommandExecuting {
  private let executable: String
  private let runner: ProcessRunner

  public init(executable: URL) throws {
    guard executable.path.hasPrefix("/opt/homebrew/Cellar/tart/2.35.0/"),
      executable.path.hasSuffix("/libexec/tart.app/Contents/MacOS/tart")
    else {
      throw ReleasePackageError.invalidArgument("Tart executor lacks exact physical authority")
    }
    self.executable = executable.path
    self.runner = ProcessRunner(testExecutables: [executable.path])
  }

  public func execute(
    arguments: [String], environment: [String: String], timeout: TimeInterval,
    logURL: URL, requireSuccess: Bool = true
  ) throws -> CommandResult {
    guard ProcessRunner.tartInvocationIsAllowed(arguments),
      ProcessRunner.tartEnvironmentIsAllowed(environment)
    else {
      throw ReleasePackageError.invalidArgument(
        "Tart invocation is outside the fixed S36 VM authority")
    }
    return try runner.run(
      executable, arguments, environment: environment,
      timeout: timeout, logURL: logURL, requireSuccess: requireSuccess)
  }
}

/// Host-only Tart authority for S36. Every mutable operation names one of two
/// frozen VMs and re-enumerates local state before and after it. The controller
/// never accepts OCI names, moving image aliases, directory shares, guest
/// agents, inline provisioning credentials, or caller-selected VM names.
public final class TartHostController {
  public static let version = "2.35.0"
  public static let cpuCount = 8
  public static let memoryMiB: UInt64 = 16_384
  public static let diskGiB = 80

  private let executor: any TartCommandExecuting
  private let home: String
  private let logRoot: URL

  public init(
    logRoot: URL,
    executor: any TartCommandExecuting
  ) throws {
    let validated = try ReleasePathAuthority.mutableRoot(logRoot, label: "Tart log root")
    try SecureFiles.createPrivateDirectory(validated)
    self.logRoot = validated
    self.executor = executor
    self.home = FileManager.default.homeDirectoryForCurrentUser.path
  }

  public convenience init(logRoot: URL, tartExecutable: URL) throws {
    try self.init(
      logRoot: logRoot,
      executor: ProcessTartCommandExecutor(executable: tartExecutable))
  }

  @discardableResult
  public func verifyVersion() throws -> String {
    let result = try command(["--version"], timeout: 10, label: "version")
    let rendered = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
    guard rendered == Self.version || rendered == "tart " + Self.version else {
      throw ReleasePackageError.verification("Tart version is not exactly " + Self.version)
    }
    return rendered
  }

  public func inventory() throws -> [TartVMInventoryRecord] {
    let result = try command(
      ["list", "--source", "local", "--format", "json"],
      timeout: 30, label: "inventory")
    let values = try Self.decodeInventory(Data(result.output.utf8))
    let names = values.map(\.name)
    guard names.count == Set(names).count else {
      throw ReleasePackageError.verification("Tart returned duplicate VM names")
    }
    let owned = Set(TartS36VM.allCases.map(\.rawValue))
    guard values.filter({ $0.name.hasPrefix("reach-s36-") }).allSatisfy({ owned.contains($0.name) })
    else {
      throw ReleasePackageError.verification("an unexpected S36-named VM is present")
    }
    return values
  }

  @discardableResult
  public func createBase(
    fromIPSW ipsw: URL,
    restoreImageAuthority: URL
  ) throws -> TartVMConfigurationRecord {
    let validatedIPSW = try ReleasePathAuthority.absoluteURL(ipsw.path, label: "IPSW")
    _ = try MacOSRestoreImageInspector().verify(
      recordURL: restoreImageAuthority, localIPSW: validatedIPSW)
    let before = try inventory()
    try requireAbsent(.base, in: before)
    try requireAbsent(.acceptance, in: before)
    _ = try command(
      [
        "create", TartS36VM.base.rawValue, "--from-ipsw", validatedIPSW.path,
        "--disk-size", String(Self.diskGiB), "--disk-format", "raw",
      ], timeout: 14_400, label: "create-base")
    _ = try command(
      [
        "set", TartS36VM.base.rawValue, "--cpu", String(Self.cpuCount),
        "--memory", String(Self.memoryMiB),
      ], timeout: 30, label: "configure-base")
    return try configuration(of: .base, requireRunning: false)
  }

  /// Runs the first-boot UI without clipboard or directory sharing. This call
  /// intentionally owns the Tart process until the guest stops.
  @discardableResult
  public func runBaseForInteractiveProvisioning() throws -> CommandResult {
    let values = try inventory()
    try requirePresent(.base, running: false, in: values)
    try requireAbsent(.acceptance, in: values)
    return try command(
      ["run", TartS36VM.base.rawValue, "--no-clipboard", "--no-audio"],
      timeout: 14_400, label: "run-base")
  }

  @discardableResult
  public func cloneAcceptance() throws -> TartVMConfigurationRecord {
    let before = try inventory()
    try requirePresent(.base, running: false, in: before)
    try requireAbsent(.acceptance, in: before)
    _ = try command(
      [
        "clone", TartS36VM.base.rawValue, TartS36VM.acceptance.rawValue,
        "--prune-limit", "100",
      ], environment: tartEnvironment(noAutoPrune: true), timeout: 3_600,
      label: "clone-acceptance")
    return try configuration(of: .acceptance, requireRunning: false)
  }

  /// Runs the disposable clone headlessly with no clipboard or directory
  /// sharing. The caller keeps this invocation alive while separate bounded
  /// host commands obtain the DHCP address and execute the guest matrix.
  @discardableResult
  public func runAcceptanceHeadless() throws -> CommandResult {
    let values = try inventory()
    try requirePresent(.base, running: false, in: values)
    try requirePresent(.acceptance, running: false, in: values)
    return try command(
      [
        "run", TartS36VM.acceptance.rawValue, "--no-graphics", "--no-clipboard",
        "--no-audio",
      ], timeout: 86_400, label: "run-acceptance")
  }

  public func acceptanceAddress() throws -> String {
    let values = try inventory()
    try requirePresent(.acceptance, running: true, in: values)
    let result = try command(
      [
        "ip", TartS36VM.acceptance.rawValue, "--wait", "60", "--resolver", "dhcp",
      ], timeout: 75, label: "acceptance-address")
    let address = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
    var parsed = in_addr()
    guard inet_pton(AF_INET, address, &parsed) == 1 else {
      throw ReleasePackageError.verification("Tart returned a non-IPv4 guest address")
    }
    return address
  }

  public func stop(_ vm: TartS36VM) throws {
    let before = try inventory()
    guard let record = before.first(where: { $0.name == vm.rawValue }) else {
      throw ReleasePackageError.verification("the exact VM to stop is absent")
    }
    if record.running {
      _ = try command(
        ["stop", vm.rawValue, "--timeout", "15"], timeout: 30,
        label: "stop-\(vm.rawValue)")
    }
    try requirePresent(vm, running: false, in: inventory())
  }

  public func delete(_ vm: TartS36VM) throws {
    let before = try inventory()
    try requirePresent(vm, running: false, in: before)
    if vm == .base {
      try requireAbsent(.acceptance, in: before)
    }
    _ = try command(
      ["delete", vm.rawValue], timeout: 300, label: "delete-\(vm.rawValue)")
    try requireAbsent(vm, in: inventory())
  }

  public func configuration(
    of vm: TartS36VM, requireRunning: Bool? = nil
  ) throws -> TartVMConfigurationRecord {
    let result = try command(
      ["get", vm.rawValue, "--format", "json"], timeout: 30,
      label: "configuration-\(vm.rawValue)")
    let value = try Self.decodeConfiguration(Data(result.output.utf8))
    guard value.operatingSystem.lowercased() == "darwin",
      value.cpuCount == Self.cpuCount, value.memoryMiB == Self.memoryMiB,
      value.diskGiB == Self.diskGiB, value.diskFormat == "raw"
    else {
      throw ReleasePackageError.verification("Tart VM resources or platform changed")
    }
    if let requireRunning, value.running != requireRunning {
      throw ReleasePackageError.verification("Tart VM running state changed")
    }
    return value
  }

  static func decodeInventory(_ data: Data) throws -> [TartVMInventoryRecord] {
    let value = try JSONSerialization.jsonObject(with: data)
    guard let rows = value as? [[String: Any]],
      rows.allSatisfy({
        Set($0.keys) == ["Source", "Name", "Disk", "Size", "Accessed", "Running", "State"]
      })
    else {
      throw ReleasePackageError.verification("Tart inventory JSON shape changed")
    }
    let decoded = try JSONDecoder().decode([TartVMInventoryRecord].self, from: data)
    guard
      decoded.allSatisfy({
        $0.source.lowercased() == "local" && !$0.name.isEmpty && !$0.name.contains("/")
          && $0.diskGiB > 0 && $0.allocatedGiB >= 0 && !$0.state.isEmpty
      })
    else {
      throw ReleasePackageError.verification("Tart inventory contains unsafe values")
    }
    return decoded
  }

  static func decodeConfiguration(_ data: Data) throws -> TartVMConfigurationRecord {
    let value = try JSONSerialization.jsonObject(with: data)
    let expected = Set([
      "OS", "CPU", "Memory", "Disk", "DiskFormat", "Size", "Display", "Running", "State",
    ])
    guard let object = value as? [String: Any], Set(object.keys) == expected else {
      throw ReleasePackageError.verification("Tart configuration JSON shape changed")
    }
    return try JSONDecoder().decode(TartVMConfigurationRecord.self, from: data)
  }

  private func command(
    _ arguments: [String], environment: [String: String]? = nil,
    timeout: TimeInterval, label: String, requireSuccess: Bool = true
  ) throws -> CommandResult {
    try executor.execute(
      arguments: arguments, environment: environment ?? tartEnvironment(),
      timeout: timeout, logURL: nextLog(label), requireSuccess: requireSuccess)
  }

  private func tartEnvironment(noAutoPrune: Bool = false) -> [String: String] {
    var result = ["HOME": home]
    if noAutoPrune { result["TART_NO_AUTO_PRUNE"] = "1" }
    return result
  }

  private func nextLog(_ label: String) -> URL {
    logRoot.appendingPathComponent(UUID().uuidString + "-" + label + ".log")
  }

  private func requireAbsent(_ vm: TartS36VM, in values: [TartVMInventoryRecord]) throws {
    guard !values.contains(where: { $0.name == vm.rawValue }) else {
      throw ReleasePackageError.verification("\(vm.rawValue) already exists")
    }
  }

  private func requirePresent(
    _ vm: TartS36VM, running: Bool, in values: [TartVMInventoryRecord]
  ) throws {
    guard let record = values.first(where: { $0.name == vm.rawValue }),
      record.running == running
    else {
      throw ReleasePackageError.verification(
        "\(vm.rawValue) is absent or has the wrong running state")
    }
  }
}
