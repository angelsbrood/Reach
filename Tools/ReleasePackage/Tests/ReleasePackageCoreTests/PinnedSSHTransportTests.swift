import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

private final class FakeSSHExecutor: SSHCommandExecuting {
  struct Expected {
    let executable: String
    let arguments: [String]
    let output: String
    var exitStatus: Int32 = 0
    var sensitiveInput: Bool = false
    var requireSuccess: Bool = true
  }

  var expected: [Expected]
  private(set) var observed: [Expected] = []

  init(_ expected: [Expected]) {
    self.expected = expected
  }

  func execute(
    executable: String, arguments: [String], timeout: TimeInterval,
    logURL: URL, sensitiveStandardInput: Data?, requireSuccess: Bool
  ) throws -> CommandResult {
    guard !expected.isEmpty else {
      throw ReleasePackageError.verification("unexpected fake SSH invocation")
    }
    let next = expected.removeFirst()
    guard next.executable == executable, next.arguments == arguments, timeout > 0,
      next.sensitiveInput == (sensitiveStandardInput != nil),
      next.requireSuccess == requireSuccess
    else {
      throw ReleasePackageError.verification("fake SSH invocation changed")
    }
    observed.append(next)
    return CommandResult(
      exitStatus: next.exitStatus, output: next.output, errorOutput: "", elapsedMilliseconds: 1)
  }
}

private struct SSHFixture {
  let root: URL
  let identity: URL
  let knownHosts: URL
  let logs: URL
  let address = "192.168.64.2"

  init(_ label: String) throws {
    root = try makeTemporaryDirectory(label)
    identity = root.appendingPathComponent("identity")
    knownHosts = root.appendingPathComponent("known-hosts")
    logs = root.appendingPathComponent("logs")
    try SecureFiles.atomicWrite(Data("private-key-fixture\n".utf8), to: identity)
    try SecureFiles.atomicWrite(
      Data("192.168.64.2 ssh-ed25519 AAAAC3NzaFixture\n".utf8), to: knownHosts)
  }

  var common: [String] {
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

  var sshPrefix: [String] {
    common + ["-p", "22", PinnedSSHTransport.remoteUser + "@" + address, "--"]
  }

  var scpPrefix: [String] {
    ["-q", "-p"] + common + ["-P", "22"]
  }
}

@Test func pinnedSSHProbeUsesOneHostKeyAndPublicKeyOnly() throws {
  let fixture = try SSHFixture("pinned-ssh-probe")
  defer { removeTemporaryDirectory(fixture.root) }
  let fake = FakeSSHExecutor([
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + ["/usr/bin/true"], output: ""),
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + ["/usr/bin/sw_vers"],
      output: "ProductVersion: 27.0\n"),
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + ["/usr/bin/uname", "-m"], output: "arm64\n"),
  ])
  let transport = try PinnedSSHTransport(
    address: fixture.address, identity: fixture.identity,
    knownHosts: fixture.knownHosts, logRoot: fixture.logs, executor: fake)
  let report = try transport.probe()
  #expect(report.architecture == "arm64")
  #expect(report.transport == "pinned-ssh-public-key")
  #expect(report.verdict == "pass")
  #expect(fake.expected.isEmpty)
  #expect(
    fake.observed.allSatisfy {
      !$0.arguments.contains(where: { $0.lowercased().contains("password=") })
    })
}

@Test func pinnedSSHInstallsAndExecutesOnlyTheHashVerifiedRootDriver() throws {
  let fixture = try SSHFixture("pinned-ssh-root-driver")
  defer { removeTemporaryDirectory(fixture.root) }
  let digest = String(repeating: "a", count: 64)
  var administratorInput = Data("private-fixture\n".utf8)
  defer { administratorInput.resetBytes(in: 0..<administratorInput.count) }
  let sudoPrefix = ["/usr/bin/sudo", "-S", "-k", "-p", "", "--"]
  let guestArguments = [
    "guest", "verify", "--authority", "/private/tmp/reach-s36-incoming/A",
    "--owner-uid", "501", "--owner-home", "/Users/reachadmin",
    "--helper", "directReady", "--state", "present", "--journal",
    "/private/tmp/journal.json", "--scratch", "/private/tmp/scratch",
  ]
  let fake = FakeSSHExecutor([
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + [
        "/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", PinnedSSHTransport.guestExecutable,
      ], output: "missing\n", exitStatus: 1, requireSuccess: false),
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + sudoPrefix + [
        "/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "0555",
        PinnedSSHTransport.stagedGuestExecutable, PinnedSSHTransport.guestExecutable,
      ], output: "", sensitiveInput: true),
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + [
        "/usr/bin/shasum", "-a", "256", PinnedSSHTransport.guestExecutable,
      ], output: digest + "  driver\n"),
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + [
        "/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", PinnedSSHTransport.guestExecutable,
      ], output: "root:wheel:555:2048\n"),
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + [
        "/bin/rm", "-f", PinnedSSHTransport.stagedGuestExecutable,
      ], output: ""),
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + sudoPrefix
        + [PinnedSSHTransport.guestExecutable] + guestArguments,
      output: "{}", sensitiveInput: true),
  ])
  let transport = try PinnedSSHTransport(
    address: fixture.address, identity: fixture.identity,
    knownHosts: fixture.knownHosts, logRoot: fixture.logs, executor: fake)
  try transport.installGuestDriver(
    expectedSHA256: digest, administratorInput: administratorInput)
  let result = try transport.executeGuest(
    arguments: guestArguments, administratorInput: administratorInput)
  #expect(result.output == "{}")
  #expect(fake.expected.isEmpty)
  #expect(fake.observed.filter(\.sensitiveInput).count == 2)
  #expect(
    fake.observed.allSatisfy {
      !$0.arguments.contains("private-fixture")
    })
}

@Test func pinnedSSHTransferUsesSCPPortGrammarAndRejectsLinks() throws {
  let fixture = try SSHFixture("pinned-ssh-transfer")
  defer { removeTemporaryDirectory(fixture.root) }
  let source = fixture.root.appendingPathComponent("A-authority")
  try SecureFiles.createPrivateDirectory(source)
  try SecureFiles.atomicWrite(
    Data("authority\n".utf8), to: source.appendingPathComponent("manifest.json"))
  let expected =
    fixture.scpPrefix + [
      "-r", source.path,
      PinnedSSHTransport.remoteUser + "@" + fixture.address + ":"
        + PinnedSSHTransport.incomingRoot + "/A",
    ]
  let fake = FakeSSHExecutor([
    .init(executable: "/usr/bin/scp", arguments: expected, output: "")
  ])
  let transport = try PinnedSSHTransport(
    address: fixture.address, identity: fixture.identity,
    knownHosts: fixture.knownHosts, logRoot: fixture.logs, executor: fake)
  try transport.transfer(source, remoteName: "A")
  #expect(fake.expected.isEmpty)
  #expect(expected.contains("-P"))
  #expect(expected.contains("-p"))

  let linkedRoot = fixture.root.appendingPathComponent("linked-authority")
  try SecureFiles.createPrivateDirectory(linkedRoot)
  #expect(symlink(source.path, linkedRoot.appendingPathComponent("escape").path) == 0)
  #expect(throws: ReleasePackageError.self) {
    try transport.transfer(linkedRoot, remoteName: "linked")
  }
}

@Test func pinnedSSHResetSentinelProvesCloneStateDoesNotSurvive() throws {
  let fixture = try SSHFixture("pinned-ssh-reset-sentinel")
  defer { removeTemporaryDirectory(fixture.root) }
  let stat = [
    "/usr/bin/stat", "-f", "%Su:%Sg:%Lp:%z", PinnedSSHTransport.resetSentinel,
  ]
  let fake = FakeSSHExecutor([
    .init(
      executable: "/usr/bin/ssh", arguments: fixture.sshPrefix + stat,
      output: "missing\n", exitStatus: 1, requireSuccess: false),
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + [
        "/usr/bin/touch", PinnedSSHTransport.resetSentinel,
      ], output: ""),
    .init(
      executable: "/usr/bin/ssh",
      arguments: fixture.sshPrefix + [
        "/bin/chmod", "600", PinnedSSHTransport.resetSentinel,
      ], output: ""),
    .init(
      executable: "/usr/bin/ssh", arguments: fixture.sshPrefix + stat,
      output: "reachadmin:staff:600:0\n"),
    .init(
      executable: "/usr/bin/ssh", arguments: fixture.sshPrefix + stat,
      output: "missing\n", exitStatus: 1, requireSuccess: false),
  ])
  let transport = try PinnedSSHTransport(
    address: fixture.address, identity: fixture.identity,
    knownHosts: fixture.knownHosts, logRoot: fixture.logs, executor: fake)
  try transport.createResetSentinel()
  try transport.requireResetSentinelAbsent()
  #expect(fake.expected.isEmpty)
}

@Test func pinnedSSHGuestGrammarRejectsShellAndAuthorityAmbiguity() throws {
  let safe = [
    "guest", "inspect", "--authority", "/private/tmp/reach-s36-incoming/A",
    "--owner-uid", "501", "--owner-home", "/Users/reachowner",
    "--host", "running", "--helper", "directReady", "--state", "present",
    "--scratch", "/private/tmp/reach-s36-scratch", "--output",
    "/private/tmp/reach-s36-export/inspect.json",
  ]
  try PinnedSSHTransport.validateGuestArguments(safe)
  try PinnedSSHTransport.validateGuestArguments([
    "guest", "owner-contention-begin", "--authority", "/private/tmp/A",
    "--owner-uid", "501", "--owner-home", "/Users/reachadmin",
    "--contender-uid", "502", "--contender-home", "/Users/contender",
    "--journal", "/private/tmp/reach-s36-contention.json",
    "--scratch", "/private/tmp/scratch", "--output", "/private/tmp/result.json",
  ])
  try PinnedSSHTransport.validateGuestArguments([
    "guest", "crash-daemon", "--authority", "/private/tmp/A",
    "--owner-uid", "501", "--owner-home", "/Users/reachadmin",
    "--scratch", "/private/tmp/scratch", "--output", "/private/tmp/result.json",
  ])
  let refused = [
    safe + ["--scratch", "/private/tmp/second"],
    ["guest", "inspect", "--authority", "/private/tmp/A;id"],
    ["guest", "inspect", "--authority", "/private/tmp/../etc"],
    ["guest", "shell", "--authority", "/private/tmp/A"],
    ["guest", "inspect", "--unknown", "/private/tmp/A"],
  ]
  for arguments in refused {
    #expect(throws: ReleasePackageError.self) {
      try PinnedSSHTransport.validateGuestArguments(arguments)
    }
  }
}

@Test func pinnedSSHRefusesUnpinnedOrNonprivateAuthorityFiles() throws {
  let fixture = try SSHFixture("pinned-ssh-authority-refusal")
  defer { removeTemporaryDirectory(fixture.root) }
  #expect(chmod(fixture.identity.path, 0o644) == 0)
  #expect(throws: ReleasePackageError.self) {
    try PinnedSSHTransport(
      address: fixture.address, identity: fixture.identity,
      knownHosts: fixture.knownHosts, logRoot: fixture.logs,
      executor: FakeSSHExecutor([]))
  }
  #expect(chmod(fixture.identity.path, 0o600) == 0)
  try SecureFiles.atomicWrite(
    Data("other ssh-ed25519 AAAAC3NzaFixture\n".utf8), to: fixture.knownHosts)
  #expect(throws: ReleasePackageError.self) {
    try PinnedSSHTransport(
      address: fixture.address, identity: fixture.identity,
      knownHosts: fixture.knownHosts, logRoot: fixture.logs,
      executor: FakeSSHExecutor([]))
  }
}
