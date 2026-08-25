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
    "/bin/chmod", "/bin/cp", "/bin/launchctl", "/bin/ls", "/bin/mkdir", "/bin/mv",
    "/bin/sleep",
    "/opt/homebrew/bin/go", "/usr/bin/codesign", "/usr/bin/cksum", "/usr/bin/cmp",
    "/usr/bin/diff", "/usr/bin/ditto", "/usr/bin/dyld_info", "/usr/bin/file", "/usr/bin/git",
    "/usr/bin/gzip",
    "/usr/bin/lsbom", "/usr/bin/mkbom", "/usr/bin/otool", "/usr/bin/plutil",
    "/usr/bin/productbuild", "/usr/bin/productsign", "/usr/bin/shasum", "/usr/bin/stat",
    "/usr/bin/strip",
    "/usr/bin/strings", "/usr/bin/sudo", "/usr/bin/swift", "/usr/bin/tar", "/usr/bin/xar",
    "/usr/bin/xcodebuild", "/usr/bin/xcrun", "/usr/bin/sw_vers", "/sbin/route",
    "/usr/sbin/installer", "/usr/sbin/lsof", "/usr/sbin/netstat", "/usr/sbin/pkgutil",
    "/usr/sbin/spctl",
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
    try runInternal(
      executable, arguments, currentDirectory: currentDirectory,
      environment: environment, timeout: timeout, logURL: logURL,
      redactedArguments: redactedArguments, requireSuccess: requireSuccess,
      sensitiveStandardInput: nil
    ).result
  }

  @discardableResult
  func runWithSensitiveStandardInput(
    _ executable: String,
    _ arguments: [String],
    sensitiveStandardInput: Data,
    currentDirectory: URL? = nil,
    environment: [String: String] = [:],
    timeout: TimeInterval = 1_800,
    logURL: URL? = nil,
    redactedArguments: [Int: String] = [:],
    requireSuccess: Bool = true
  ) throws -> CommandResult {
    guard !sensitiveStandardInput.isEmpty, sensitiveStandardInput.count <= 4_096 else {
      throw ReleasePackageError.invalidArgument(
        "sensitive process input must contain 1...4096 transient bytes")
    }
    return try runInternal(
      executable, arguments, currentDirectory: currentDirectory,
      environment: environment, timeout: timeout, logURL: logURL,
      redactedArguments: redactedArguments, requireSuccess: requireSuccess,
      sensitiveStandardInput: sensitiveStandardInput,
      interruptionObservation: nil
    ).result
  }

  /// Runs one fixed executable until a caller-supplied, read-only observation
  /// becomes true, then terminates the complete child process group. This is
  /// intentionally package-internal: S36 uses it only to land an Installer
  /// interruption at a real component-receipt boundary rather than at a
  /// timing guess.
  @discardableResult
  func runUntilObservation(
    _ executable: String,
    _ arguments: [String],
    currentDirectory: URL? = nil,
    environment: [String: String] = [:],
    timeout: TimeInterval,
    logURL: URL,
    observation: @escaping () throws -> Bool
  ) throws -> CommandResult {
    let value = try runInternal(
      executable, arguments, currentDirectory: currentDirectory,
      environment: environment, timeout: timeout, logURL: logURL,
      redactedArguments: [:], requireSuccess: false,
      sensitiveStandardInput: nil,
      interruptionObservation: observation)
    guard value.observationReached else {
      throw ReleasePackageError.verification(
        "process exited before the required observable interruption boundary")
    }
    return value.result
  }

  private struct InternalRunResult {
    let result: CommandResult
    let observationReached: Bool
  }

  private func runInternal(
    _ executable: String,
    _ arguments: [String],
    currentDirectory: URL?,
    environment: [String: String],
    timeout: TimeInterval,
    logURL: URL?,
    redactedArguments: [Int: String],
    requireSuccess: Bool,
    sensitiveStandardInput: Data?,
    interruptionObservation: (() throws -> Bool)? = nil
  ) throws -> InternalRunResult {
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
    var inputPipe = [Int32](repeating: -1, count: 2)
    if sensitiveStandardInput != nil {
      guard pipe(&inputPipe) == 0, fcntl(inputPipe[1], F_SETNOSIGPIPE, 1) == 0 else {
        if inputPipe[0] >= 0 { close(inputPipe[0]) }
        if inputPipe[1] >= 0 { close(inputPipe[1]) }
        close(descriptor)
        close(errorDescriptor)
        unlink(ownedLog.path)
        unlink(errorLog.path)
        throw ReleasePackageError.processFailure("cannot create sensitive process input pipe")
      }
    }
    guard posix_spawn_file_actions_init(&fileActions) == 0,
      posix_spawnattr_init(&attributes) == 0
    else {
      if inputPipe[0] >= 0 { close(inputPipe[0]) }
      if inputPipe[1] >= 0 { close(inputPipe[1]) }
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
      if inputPipe[0] >= 0 { close(inputPipe[0]) }
      if inputPipe[1] >= 0 { close(inputPipe[1]) }
      close(descriptor)
      close(errorDescriptor)
      unlink(ownedLog.path)
      unlink(errorLog.path)
      throw ReleasePackageError.processFailure("cannot bind bounded process output")
    }
    if sensitiveStandardInput != nil {
      guard posix_spawn_file_actions_adddup2(&fileActions, inputPipe[0], STDIN_FILENO) == 0,
        posix_spawn_file_actions_addclose(&fileActions, inputPipe[0]) == 0,
        posix_spawn_file_actions_addclose(&fileActions, inputPipe[1]) == 0
      else {
        close(inputPipe[0])
        close(inputPipe[1])
        close(descriptor)
        close(errorDescriptor)
        unlink(ownedLog.path)
        unlink(errorLog.path)
        throw ReleasePackageError.processFailure("cannot bind sensitive process input")
      }
    }
    if let currentDirectory,
      posix_spawn_file_actions_addchdir(&fileActions, currentDirectory.path) != 0
    {
      if inputPipe[0] >= 0 { close(inputPipe[0]) }
      if inputPipe[1] >= 0 { close(inputPipe[1]) }
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
      if inputPipe[0] >= 0 { close(inputPipe[0]) }
      if inputPipe[1] >= 0 { close(inputPipe[1]) }
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
      if inputPipe[0] >= 0 { close(inputPipe[0]) }
      if inputPipe[1] >= 0 { close(inputPipe[1]) }
      close(descriptor)
      close(errorDescriptor)
      unlink(ownedLog.path)
      unlink(errorLog.path)
      throw ReleasePackageError.processFailure(
        "could not start \(executable): \(String(cString: strerror(spawnResult)))")
    }
    close(descriptor)
    close(errorDescriptor)
    if let sensitiveStandardInput {
      close(inputPipe[0])
      do {
        try sensitiveStandardInput.withUnsafeBytes { raw in
          guard let base = raw.baseAddress else { return }
          var written = 0
          while written < raw.count {
            let count = Darwin.write(inputPipe[1], base.advanced(by: written), raw.count - written)
            if count > 0 {
              written += count
            } else if count < 0, errno == EINTR {
              continue
            } else {
              throw ReleasePackageError.processFailure("cannot deliver sensitive process input")
            }
          }
        }
      } catch {
        close(inputPipe[1])
        _ = kill(-processIdentifier, SIGTERM)
        var abandonedStatus: Int32 = 0
        _ = waitpid(processIdentifier, &abandonedStatus, 0)
        throw error
      }
      close(inputPipe[1])
    }

    var waitStatus: Int32 = 0
    var leaderReaped = false
    let deadline = started.advanced(by: .seconds(timeout))
    var observationReached = false
    var observationFailure: Error?
    while !leaderReaped, clock.now < deadline {
      let waited = waitpid(processIdentifier, &waitStatus, WNOHANG)
      if waited == processIdentifier {
        leaderReaped = true
      } else if waited < 0, errno != EINTR {
        break
      } else if waited == 0 {
        if let interruptionObservation {
          do {
            if try interruptionObservation() {
              observationReached = true
              break
            }
          } catch {
            observationFailure = error
            break
          }
        }
        usleep(10_000)
      }
    }

    let timedOut = !leaderReaped && !observationReached && observationFailure == nil
    var descendantLeak = false
    if timedOut || observationReached || observationFailure != nil {
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
    if let observationFailure { throw observationFailure }
    if timedOut {
      throw ReleasePackageError.processFailure("\(executable) exceeded \(Int(timeout)) seconds")
    }
    if requireSuccess, !observationReached, result.exitStatus != 0 {
      let bounded = redact(
        String((result.output + result.errorOutput).prefix(4_096)),
        values: sensitiveValues)
      throw ReleasePackageError.processFailure(
        "\(executable) exited \(result.exitStatus): \(bounded)")
    }
    return InternalRunResult(result: result, observationReached: observationReached)
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
    switch executable {
    case "/usr/bin/sudo":
      let prefix = ["-u", arguments.count > 1 ? arguments[1] : "", "-H", "--"]
      let tail = arguments.count >= 4 ? Array(arguments.dropFirst(4)) : []
      let allowedTails = [
        [
          "/Library/Application Support/Reach/Host/reachd",
          "service", "install", "--no-load",
        ],
        ["/Library/Application Support/Reach/Host/reachd", "selftest"],
        [
          "/Library/Application Support/Reach/Host/reachd",
          "selftest", "--mlx", "--runs", "1",
        ],
        ["/Library/Application Support/Reach/Host/reachd", "doctor", "--dial"],
      ]
      guard arguments.count >= 6, Array(arguments.prefix(4)) == prefix,
        arguments[1].range(of: #"^#[1-9][0-9]*$"#, options: .regularExpression) != nil,
        allowedTails.contains(tail), environment.isEmpty, redactedArguments.isEmpty
      else {
        throw ReleasePackageError.invalidArgument("sudo invocation is outside guest acceptance")
      }
      return
    case "/usr/sbin/installer":
      guard Self.installerInvocationIsAllowed(arguments), environment.isEmpty,
        redactedArguments.isEmpty
      else {
        throw ReleasePackageError.invalidArgument(
          "installer invocation is outside the trusted package transaction")
      }
      return
    case "/usr/sbin/pkgutil":
      let identifiers = Set(["systems.reach.host", "systems.reach.meshd"])
      let accepted =
        arguments.count == 2
        && ((["--pkg-info-plist", "--files", "--forget"].contains(arguments[0])
          && identifiers.contains(arguments[1]))
          || (arguments[0] == "--check-signature" && arguments[1].hasPrefix("/")))
      guard accepted, environment.isEmpty, redactedArguments.isEmpty else {
        throw ReleasePackageError.invalidArgument("pkgutil invocation is outside release authority")
      }
      return
    case "/bin/launchctl":
      guard Self.launchctlInvocationIsAllowed(arguments), environment.isEmpty,
        redactedArguments.isEmpty
      else {
        throw ReleasePackageError.invalidArgument(
          "launchctl invocation is outside guest acceptance")
      }
      return
    case "/sbin/route":
      guard arguments == ["-n", "get", "-net", "10.86.0.0/24"],
        environment.isEmpty, redactedArguments.isEmpty
      else {
        throw ReleasePackageError.invalidArgument("route invocation is outside guest inspection")
      }
      return
    case "/usr/sbin/lsof":
      guard arguments.count == 6, arguments[0] == "-a", arguments[1] == "-p",
        arguments[2].range(of: #"^[1-9][0-9]*$"#, options: .regularExpression) != nil,
        arguments[3...] == ["-d", "txt", "-F0fDin"][...],
        environment.isEmpty, redactedArguments.isEmpty
      else {
        throw ReleasePackageError.invalidArgument(
          "lsof invocation is outside running-vnode inspection")
      }
      return
    default:
      break
    }
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

  static func installerInvocationIsAllowed(_ arguments: [String]) -> Bool {
    let ordinary =
      arguments.count == 4 && arguments[0] == "-pkg"
      && arguments[1].hasPrefix("/") && arguments[1] != "/"
      && arguments[2...] == ["-target", "/"][...]
    let choice =
      arguments.count == 6 && arguments[0] == "-applyChoiceChangesXML"
      && arguments[1].hasPrefix("/private/tmp/reach-s36-")
      && arguments[1].hasSuffix("/helper-deselection.plist")
      && arguments[2] == "-pkg" && arguments[3].hasPrefix("/")
      && arguments[3] != "/"
      && arguments[4...] == ["-target", "/"][...]
    return ordinary || choice
  }

  private static func launchctlInvocationIsAllowed(_ arguments: [String]) -> Bool {
    guard let verb = arguments.first else { return false }
    let hostTarget = #"^gui/[1-9][0-9]*/systems\.reach\.reachd$"#
    switch verb {
    case "print", "bootout":
      guard arguments.count == 2 else { return false }
      return arguments[1] == "system/systems.reach.meshd"
        || arguments[1].range(of: hostTarget, options: .regularExpression) != nil
    case "bootstrap":
      guard arguments.count == 3 else { return false }
      if arguments[1] == "system" {
        return arguments[2] == "/Library/LaunchDaemons/systems.reach.meshd.plist"
      }
      guard
        arguments[1].range(
          of: #"^gui/[1-9][0-9]*$"#, options: .regularExpression) != nil
      else { return false }
      return arguments[2].hasPrefix("/Users/")
        && arguments[2].hasSuffix("/Library/LaunchAgents/systems.reach.reachd.plist")
    default:
      return false
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

  static func tartInvocationIsAllowed(_ arguments: [String]) -> Bool {
    let base = "reach-s36-macos27-base"
    let acceptance = "reach-s36-macos27-acceptance"
    let exactNames = Set([base, acceptance])
    switch arguments.first {
    case "--version":
      return arguments == ["--version"]
    case "list":
      return arguments == ["list", "--source", "local", "--format", "json"]
    case "get":
      return arguments.count == 4 && exactNames.contains(arguments[1])
        && arguments[2...] == ["--format", "json"][...]
    case "create":
      return arguments.count == 8 && arguments[1] == base
        && arguments[2] == "--from-ipsw" && arguments[3].hasPrefix("/")
        && arguments[3] != "/" && arguments[3] != "/private/tmp"
        && arguments[4...]
          == [
            "--disk-size", "80", "--disk-format", "raw",
          ][...]
    case "set":
      return arguments == ["set", base, "--cpu", "8", "--memory", "16384"]
    case "clone":
      return arguments == ["clone", base, acceptance, "--prune-limit", "100"]
    case "run":
      return arguments == ["run", base, "--no-clipboard", "--no-audio"]
        || arguments == [
          "run", acceptance, "--no-graphics", "--no-clipboard", "--no-audio",
        ]
    case "stop":
      return arguments.count == 4 && exactNames.contains(arguments[1])
        && arguments[2...] == ["--timeout", "15"][...]
    case "ip":
      return arguments == [
        "ip", acceptance, "--wait", "60", "--resolver", "dhcp",
      ]
    case "delete":
      return arguments.count == 2 && exactNames.contains(arguments[1])
    default:
      return false
    }
  }

  static func tartEnvironmentIsAllowed(_ environment: [String: String]) -> Bool {
    guard let home = environment["HOME"],
      home.utf8.elementsEqual(FileManager.default.homeDirectoryForCurrentUser.path.utf8)
    else { return false }
    let keys = Set(environment.keys)
    if keys == ["HOME"] { return true }
    return keys == ["HOME", "TART_NO_AUTO_PRUNE"]
      && environment["TART_NO_AUTO_PRUNE"] == "1"
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
