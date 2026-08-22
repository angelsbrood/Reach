import Darwin
import Foundation

public struct CommandResult: Sendable, Equatable {
  public let exitStatus: Int32
  public let output: String
  public let errorOutput: String
  public let elapsedMilliseconds: Int64
}

public struct CommandRecord: Codable, Sendable, Equatable {
  public let schemaVersion: Int
  public let executable: String
  public let arguments: [String]
  public let currentDirectory: String?
  public let startedAtUTC: String
  public let elapsedMilliseconds: Int64
  public let exitStatus: Int32
  public let timedOut: Bool
  public let stdoutSHA256: String
  public let stderrSHA256: String
}

public struct ProcessRunner: Sendable {
  public static let fixedExecutables: Set<String> = [
    "/bin/chmod", "/bin/cp", "/bin/ls", "/bin/mkdir", "/bin/mv", "/bin/sleep",
    "/opt/homebrew/bin/go", "/usr/bin/codesign", "/usr/bin/cksum", "/usr/bin/cmp",
    "/usr/bin/diff", "/usr/bin/ditto", "/usr/bin/dyld_info", "/usr/bin/file", "/usr/bin/git",
    "/usr/bin/gzip",
    "/usr/bin/lsbom", "/usr/bin/mkbom", "/usr/bin/otool", "/usr/bin/plutil",
    "/usr/bin/productbuild", "/usr/bin/productsign", "/usr/bin/shasum", "/usr/bin/stat",
    "/usr/bin/strip",
    "/usr/bin/strings", "/usr/bin/swift", "/usr/bin/tar", "/usr/bin/xar",
    "/usr/bin/xcodebuild", "/usr/bin/xcrun", "/usr/bin/sw_vers", "/usr/sbin/installer",
    "/usr/sbin/pkgutil", "/usr/sbin/spctl",
  ]

  private let testExecutables: Set<String>

  public init() { testExecutables = [] }

  init(testExecutables: Set<String>) { self.testExecutables = testExecutables }

  @discardableResult
  public func run(
    _ executable: String,
    _ arguments: [String],
    currentDirectory: URL? = nil,
    environment: [String: String] = [:],
    timeout: TimeInterval = 1_800,
    logURL: URL? = nil,
    redactedArguments: [Int: String] = [:],
    requireSuccess: Bool = true
  ) throws -> CommandResult {
    try validateExecutable(executable)
    guard timeout.isFinite, timeout > 0 else {
      throw ReleasePackageError.invalidArgument("process timeout must be positive and finite")
    }
    guard !arguments.contains(where: { $0.contains("\0") }),
      !environment.contains(where: { $0.key.contains("\0") || $0.value.contains("\0") })
    else {
      throw ReleasePackageError.invalidArgument(
        "process arguments and environment cannot contain NUL")
    }
    guard redactedArguments.keys.allSatisfy({ arguments.indices.contains($0) }),
      redactedArguments.values.allSatisfy({
        $0.hasPrefix("<redacted-") && $0.hasSuffix(">") && !$0.contains("\0")
      })
    else {
      throw ReleasePackageError.invalidArgument("sensitive argument redaction is malformed")
    }
    try validateInvocation(
      executable, arguments, environment: environment,
      redactedArguments: redactedArguments)
    let sensitiveValues = redactedArguments.keys.map { arguments[$0] }
    guard sensitiveValues.allSatisfy({ !$0.isEmpty }) else {
      throw ReleasePackageError.invalidArgument("sensitive argument values cannot be empty")
    }
    if let currentDirectory { try SecureFiles.rejectSymlink(url: currentDirectory) }

    let ownedLog: URL
    if let logURL {
      ownedLog = logURL
    } else {
      ownedLog = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("reach-release-command-\(UUID().uuidString).log")
    }
    let errorLog = URL(fileURLWithPath: ownedLog.path + ".stderr")
    let commandLog = URL(fileURLWithPath: ownedLog.path + ".command.json")
    let descriptor = open(ownedLog.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else {
      throw ReleasePackageError.processFailure("cannot create command log \(ownedLog.path)")
    }
    let errorDescriptor = open(errorLog.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard errorDescriptor >= 0 else {
      close(descriptor)
      unlink(ownedLog.path)
      throw ReleasePackageError.processFailure("cannot create command error log \(errorLog.path)")
    }

    var fileActions: posix_spawn_file_actions_t?
    var attributes: posix_spawnattr_t?
    guard posix_spawn_file_actions_init(&fileActions) == 0,
      posix_spawnattr_init(&attributes) == 0
    else {
      close(descriptor)
      close(errorDescriptor)
      unlink(ownedLog.path)
      unlink(errorLog.path)
      throw ReleasePackageError.processFailure("cannot initialize bounded process authority")
    }
    defer {
      posix_spawn_file_actions_destroy(&fileActions)
      posix_spawnattr_destroy(&attributes)
    }
    guard posix_spawn_file_actions_adddup2(&fileActions, descriptor, STDOUT_FILENO) == 0,
      posix_spawn_file_actions_adddup2(&fileActions, errorDescriptor, STDERR_FILENO) == 0,
      posix_spawn_file_actions_addclose(&fileActions, descriptor) == 0,
      posix_spawn_file_actions_addclose(&fileActions, errorDescriptor) == 0
    else {
      close(descriptor)
      close(errorDescriptor)
      unlink(ownedLog.path)
      unlink(errorLog.path)
      throw ReleasePackageError.processFailure("cannot bind bounded process output")
    }
    if let currentDirectory,
      posix_spawn_file_actions_addchdir(&fileActions, currentDirectory.path) != 0
    {
      close(descriptor)
      close(errorDescriptor)
      unlink(ownedLog.path)
      unlink(errorLog.path)
      throw ReleasePackageError.processFailure("cannot bind bounded process directory")
    }
    var defaultSignals = sigset_t()
    var emptySignalMask = sigset_t()
    sigemptyset(&defaultSignals)
    sigemptyset(&emptySignalMask)
    for signal in [SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGALRM, SIGTERM, SIGCHLD] {
      sigaddset(&defaultSignals, signal)
    }
    let spawnFlags = Int16(
      POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF
        | POSIX_SPAWN_SETSIGMASK)
    guard posix_spawnattr_setflags(&attributes, spawnFlags) == 0,
      posix_spawnattr_setsigdefault(&attributes, &defaultSignals) == 0,
      posix_spawnattr_setsigmask(&attributes, &emptySignalMask) == 0,
      posix_spawnattr_setpgroup(&attributes, 0) == 0
    else {
      close(descriptor)
      close(errorDescriptor)
      unlink(ownedLog.path)
      unlink(errorLog.path)
      throw ReleasePackageError.processFailure("cannot create a dedicated process group")
    }

    var argumentPointers = try cStrings([executable] + arguments)
    let childEnvironment = sanitizedEnvironment(overrides: environment)
    var environmentPointers = try cStrings(
      childEnvironment.keys.sorted().map { "\($0)=\(childEnvironment[$0]!)" })
    defer {
      freeCStrings(argumentPointers)
      freeCStrings(environmentPointers)
    }

    let startedAt = Date()
    let clock = ContinuousClock()
    let started = clock.now
    var processIdentifier: pid_t = 0
    let spawnResult = argumentPointers.withUnsafeMutableBufferPointer { argv in
      environmentPointers.withUnsafeMutableBufferPointer { childEnvironment in
        posix_spawn(
          &processIdentifier, argv[0]!, &fileActions, &attributes, argv.baseAddress!,
          childEnvironment.baseAddress!)
      }
    }
    if spawnResult != 0 {
      close(descriptor)
      close(errorDescriptor)
      unlink(ownedLog.path)
      unlink(errorLog.path)
      throw ReleasePackageError.processFailure(
        "could not start \(executable): \(String(cString: strerror(spawnResult)))")
    }
    close(descriptor)
    close(errorDescriptor)

    var waitStatus: Int32 = 0
    var leaderReaped = false
    let deadline = started.advanced(by: .seconds(timeout))
    while !leaderReaped, clock.now < deadline {
      let waited = waitpid(processIdentifier, &waitStatus, WNOHANG)
      if waited == processIdentifier {
        leaderReaped = true
      } else if waited < 0, errno != EINTR {
        break
      } else if waited == 0 {
        usleep(10_000)
      }
    }

    let timedOut = !leaderReaped
    var descendantLeak = false
    if timedOut {
      descendantLeak = !terminateProcessGroup(
        processIdentifier, clock: clock, leaderReaped: &leaderReaped, waitStatus: &waitStatus)
    } else {
      let graceDeadline = clock.now.advanced(by: .milliseconds(100))
      while processGroupExists(processIdentifier), clock.now < graceDeadline { usleep(10_000) }
      if processGroupExists(processIdentifier) {
        descendantLeak = true
        _ = terminateProcessGroup(
          processIdentifier, clock: clock, leaderReaped: &leaderReaped, waitStatus: &waitStatus)
      }
    }

    let elapsed = started.duration(to: clock.now)
    let components = elapsed.components
    let milliseconds =
      components.seconds * 1_000 + Int64(components.attoseconds / 1_000_000_000_000_000)
    let outputData = try Data(contentsOf: ownedLog)
    let errorData = try Data(contentsOf: errorLog)
    let output = String(decoding: outputData, as: UTF8.self)
    let errorOutput = String(decoding: errorData, as: UTF8.self)
    let exitStatus = decodedExitStatus(waitStatus, reaped: leaderReaped)
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let record = CommandRecord(
      schemaVersion: 1,
      executable: executable,
      arguments: arguments.enumerated().map { index, argument in
        redactedArguments[index] ?? argument
      },
      currentDirectory: currentDirectory?.path,
      startedAtUTC: formatter.string(from: startedAt),
      elapsedMilliseconds: milliseconds,
      exitStatus: exitStatus,
      timedOut: timedOut,
      stdoutSHA256: Digests.sha256(outputData),
      stderrSHA256: Digests.sha256(errorData)
    )
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(record), to: commandLog)
    if logURL == nil {
      try? FileManager.default.removeItem(at: ownedLog)
      try? FileManager.default.removeItem(at: errorLog)
      try? FileManager.default.removeItem(at: commandLog)
    }
    let result = CommandResult(
      exitStatus: exitStatus,
      output: output,
      errorOutput: errorOutput,
      elapsedMilliseconds: milliseconds)
    if descendantLeak {
      throw ReleasePackageError.processFailure(
        "\(executable) left a descendant process outside its bounded lifetime")
    }
    if timedOut {
      throw ReleasePackageError.processFailure("\(executable) exceeded \(Int(timeout)) seconds")
    }
    if requireSuccess, result.exitStatus != 0 {
      let bounded = redact(
        String((result.output + result.errorOutput).prefix(4_096)),
        values: sensitiveValues)
      throw ReleasePackageError.processFailure(
        "\(executable) exited \(result.exitStatus): \(bounded)")
    }
    return result
  }

  private func validateExecutable(_ executable: String) throws {
    guard executable.hasPrefix("/"), !executable.contains("\0") else {
      throw ReleasePackageError.invalidArgument("executable path must be absolute")
    }
    if Self.fixedExecutables.contains(executable) || testExecutables.contains(executable) { return }
    throw ReleasePackageError.invalidArgument(
      "executable is outside the fixed tool allowlist: \(executable)")
  }

  private func validateInvocation(
    _ executable: String,
    _ arguments: [String],
    environment: [String: String],
    redactedArguments: [Int: String]
  ) throws {
    guard executable == "/usr/bin/xcrun" else { return }
    let sdkQueries = [
      ["--sdk", "macosx", "--show-sdk-path"],
      ["--sdk", "macosx", "--show-sdk-version"],
    ]
    if sdkQueries.contains(arguments) { return }
    guard let tool = arguments.first else {
      throw ReleasePackageError.invalidArgument("xcrun requires an approved tool")
    }
    switch tool {
    case "notarytool":
      guard
        Self.notarytoolInvocationIsAllowed(
          arguments, redactedArguments: redactedArguments),
        Self.notarytoolEnvironmentIsAllowed(environment)
      else {
        throw ReleasePackageError.invalidArgument(
          "notarytool invocation must match an exact opaque-Keychain-profile operation")
      }
    case "stapler":
      guard arguments.count == 3,
        Set(["staple", "validate"]).contains(arguments[1]),
        arguments[2].hasPrefix("/")
      else {
        throw ReleasePackageError.invalidArgument("xcrun stapler operation is not approved")
      }
    default:
      throw ReleasePackageError.invalidArgument("xcrun tool is outside the fixed allowlist")
    }
  }

  static func notarytoolInvocationIsAllowed(
    _ arguments: [String],
    redactedArguments: [Int: String]
  ) -> Bool {
    if arguments == ["notarytool", "--version"] {
      return redactedArguments.isEmpty
    }
    guard arguments.first == "notarytool", arguments.count >= 2 else { return false }
    let profileIndex: Int
    switch arguments[1] {
    case "history":
      guard arguments.count == 6 else { return false }
      profileIndex = 3
      guard arguments[2] == "--keychain-profile",
        arguments[4] == "--output-format",
        arguments[5] == "json"
      else { return false }
    case "submit":
      guard arguments.count == 7, arguments[2].hasPrefix("/") else { return false }
      profileIndex = 4
      guard arguments[3] == "--keychain-profile",
        arguments[5] == "--output-format",
        arguments[6] == "json"
      else { return false }
    case "wait", "log":
      guard arguments.count == 7, UUID(uuidString: arguments[2]) != nil else { return false }
      profileIndex = 4
      guard arguments[3] == "--keychain-profile",
        arguments[5] == "--output-format",
        arguments[6] == "json"
      else { return false }
    default:
      return false
    }
    let profile = arguments[profileIndex]
    return !profile.isEmpty
      && !profile.hasPrefix("-")
      && !profile.contains("/")
      && redactedArguments == [profileIndex: "<redacted-profile>"]
  }

  static func notarytoolEnvironmentIsAllowed(_ environment: [String: String]) -> Bool {
    if environment.isEmpty { return true }
    guard environment.count == 1, let home = environment["HOME"] else { return false }
    return home.utf8.elementsEqual(FileManager.default.homeDirectoryForCurrentUser.path.utf8)
  }

  private func redact(_ text: String, values: [String]) -> String {
    values.reduce(text) { result, value in
      result.replacingOccurrences(of: value, with: "<redacted-sensitive-value>")
    }
  }

  private func sanitizedEnvironment(overrides: [String: String]) -> [String: String] {
    var result = [
      "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C",
      "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin", "TMPDIR": "/private/tmp",
      "TZ": "UTC",
    ]
    for (key, value) in overrides { result[key] = value }
    return result
  }

  private func cStrings(_ values: [String]) throws -> [UnsafeMutablePointer<CChar>?] {
    var pointers: [UnsafeMutablePointer<CChar>?] = []
    for value in values {
      guard let pointer = strdup(value) else {
        freeCStrings(pointers)
        throw ReleasePackageError.processFailure("cannot allocate bounded process arguments")
      }
      pointers.append(pointer)
    }
    pointers.append(nil)
    return pointers
  }

  private func freeCStrings(_ pointers: [UnsafeMutablePointer<CChar>?]) {
    for pointer in pointers where pointer != nil { free(pointer) }
  }

  private func processGroupExists(_ group: pid_t) -> Bool {
    if kill(-group, 0) == 0 { return true }
    return errno == EPERM
  }

  private func terminateProcessGroup(
    _ group: pid_t,
    clock: ContinuousClock,
    leaderReaped: inout Bool,
    waitStatus: inout Int32
  ) -> Bool {
    _ = kill(-group, SIGTERM)
    _ = kill(group, SIGTERM)
    var deadline = clock.now.advanced(by: .seconds(2))
    while processGroupExists(group) || !leaderReaped, clock.now < deadline {
      if !leaderReaped, waitpid(group, &waitStatus, WNOHANG) == group { leaderReaped = true }
      usleep(10_000)
    }
    if processGroupExists(group) || !leaderReaped {
      _ = kill(-group, SIGKILL)
      _ = kill(group, SIGKILL)
      deadline = clock.now.advanced(by: .seconds(2))
      while processGroupExists(group) || !leaderReaped, clock.now < deadline {
        if !leaderReaped, waitpid(group, &waitStatus, WNOHANG) == group { leaderReaped = true }
        usleep(10_000)
      }
    }
    if !leaderReaped {
      while true {
        let waited = waitpid(group, &waitStatus, WNOHANG)
        if waited == group {
          leaderReaped = true
          break
        }
        if waited == 0 { break }
        if waited < 0, errno == EINTR { continue }
        break
      }
    }
    return !processGroupExists(group)
  }

  private func decodedExitStatus(_ status: Int32, reaped: Bool) -> Int32 {
    guard reaped else { return -1 }
    let signal = status & 0x7f
    if signal == 0 { return (status >> 8) & 0xff }
    return 128 + signal
  }
}
