import Foundation
import Testing

@testable import ReleasePackageCore

private func expectProcessGone(_ process: pid_t) {
  let clock = ContinuousClock()
  let deadline = clock.now.advanced(by: .seconds(1))
  while kill(process, 0) == 0, clock.now < deadline { usleep(10_000) }
  #expect(kill(process, 0) == -1)
  #expect(errno == ESRCH)
}

@Test func processRunnerSeparatesOutputAndSealsCommandWithoutEnvironment() throws {
  let root = try makeTemporaryDirectory("process")
  defer { removeTemporaryDirectory(root) }
  try SecureFiles.atomicWrite(Data("x".utf8), to: root.appendingPathComponent("visible"))
  let log = root.appendingPathComponent("ls.log")
  let result = try ProcessRunner().run("/bin/ls", [root.path], logURL: log)
  #expect(result.output.contains("visible"))
  #expect(result.errorOutput.isEmpty)
  let recordData = try Data(contentsOf: URL(fileURLWithPath: log.path + ".command.json"))
  let record = try JSONDecoder().decode(CommandRecord.self, from: recordData)
  #expect(record.executable == "/bin/ls")
  #expect(record.arguments == [root.path])
  #expect(record.stdoutSHA256 == Digests.sha256(Data(result.output.utf8)))
  #expect(!String(decoding: recordData, as: UTF8.self).contains("environment"))
}

@Test func processRunnerReportsStderrAndNonzeroStatus() throws {
  let root = try makeTemporaryDirectory("process-failure")
  defer { removeTemporaryDirectory(root) }
  let result = try ProcessRunner().run(
    "/bin/ls", [root.appendingPathComponent("missing").path],
    logURL: root.appendingPathComponent("failure.log"),
    requireSuccess: false
  )
  #expect(result.exitStatus != 0)
  #expect(result.output.isEmpty)
  #expect(result.errorOutput.contains("No such file"))
}

@Test func processRunnerBoundsAndRecordsTimeouts() throws {
  let root = try makeTemporaryDirectory("process-timeout")
  defer { removeTemporaryDirectory(root) }
  let log = root.appendingPathComponent("timeout.log")
  #expect(throws: ReleasePackageError.self) {
    try ProcessRunner().run("/bin/sleep", ["2"], timeout: 0.02, logURL: log)
  }
  let record = try JSONDecoder().decode(
    CommandRecord.self,
    from: Data(contentsOf: URL(fileURLWithPath: log.path + ".command.json"))
  )
  #expect(record.timedOut)
  #expect(record.exitStatus != 0)
}

@Test func processRunnerTimeoutKillsEveryDescendantInItsDedicatedGroup() throws {
  let root = try makeTemporaryDirectory("process-descendants")
  defer { removeTemporaryDirectory(root) }
  let marker = root.appendingPathComponent("child.pid")
  let script = root.appendingPathComponent("spawn-child.sh")
  try SecureFiles.atomicWrite(
    Data(
      """
      #!/bin/sh
      /bin/sleep 30 &
      child=$!
      printf '%s\\n' "$child" > "\(marker.path)"
      wait "$child"
      """.utf8),
    to: script,
    mode: 0o700
  )
  let runner = ProcessRunner(testExecutables: ["/bin/sh"])
  #expect(throws: ReleasePackageError.self) {
    try runner.run(
      "/bin/sh", [script.path], timeout: 0.25,
      logURL: root.appendingPathComponent("descendants.log"))
  }
  let childText = String(decoding: try Data(contentsOf: marker), as: UTF8.self)
    .trimmingCharacters(in: .whitespacesAndNewlines)
  let child = try #require(pid_t(childText))
  expectProcessGone(child)
}

@Test func processRunnerRejectsAndCleansDescendantAfterSuccessfulLeaderExit() throws {
  let root = try makeTemporaryDirectory("process-normal-exit-descendant")
  defer { removeTemporaryDirectory(root) }
  let marker = root.appendingPathComponent("child.pid")
  let script = root.appendingPathComponent("leave-child.sh")
  try SecureFiles.atomicWrite(
    Data(
      """
      #!/bin/sh
      (
        trap '' HUP
        exec /bin/sleep 30
      ) &
      child=$!
      printf '%s\\n' "$child" > "\(marker.path)"
      exit 0
      """.utf8),
    to: script,
    mode: 0o700
  )
  let runner = ProcessRunner(testExecutables: ["/bin/sh"])
  do {
    try runner.run(
      "/bin/sh", [script.path], timeout: 2,
      logURL: root.appendingPathComponent("normal-exit-descendant.log"))
    Issue.record("successful leader exit left a descendant without refusal")
  } catch let error as ReleasePackageError {
    #expect(
      error
        == .processFailure("/bin/sh left a descendant process outside its bounded lifetime"))
  }
  let record = try JSONDecoder().decode(
    CommandRecord.self,
    from: Data(
      contentsOf: root.appendingPathComponent("normal-exit-descendant.log.command.json"))
  )
  #expect(!record.timedOut)
  #expect(record.exitStatus == 0)
  let childText = String(decoding: try Data(contentsOf: marker), as: UTF8.self)
    .trimmingCharacters(in: .whitespacesAndNewlines)
  expectProcessGone(try #require(pid_t(childText)))
}

@Test func processRunnerRejectsEveryNonfixedExecutable() throws {
  #expect(throws: ReleasePackageError.self) {
    try ProcessRunner().run("/private/tmp/not-a-release-tool", [])
  }
  #expect(throws: ReleasePackageError.self) {
    try ProcessRunner().run("ls", [])
  }
}

@Test func processRunnerRedactsSensitiveArgumentsFromRecordsAndBoundedErrors() throws {
  let root = try makeTemporaryDirectory("process-redaction")
  defer { removeTemporaryDirectory(root) }
  let secret = root.appendingPathComponent("profile-secret-value").path
  let log = root.appendingPathComponent("redacted.log")
  do {
    _ = try ProcessRunner().run(
      "/bin/ls", [secret], logURL: log,
      redactedArguments: [0: "<redacted-profile>"])
    Issue.record("missing path unexpectedly succeeded")
  } catch {
    #expect(!String(describing: error).contains(secret))
  }
  let recordData = try Data(
    contentsOf: URL(fileURLWithPath: log.path + ".command.json"))
  let record = try JSONDecoder().decode(CommandRecord.self, from: recordData)
  #expect(record.arguments == ["<redacted-profile>"])
  #expect(!String(decoding: recordData, as: UTF8.self).contains(secret))
  #expect(
    String(
      decoding: try Data(contentsOf: URL(fileURLWithPath: log.path + ".stderr")), as: UTF8.self
    ).contains(secret))
}

@Test func processRunnerForbidsRawNotaryCredentialsAndUnapprovedXcrunTools() throws {
  let submissionID = "377a2eab-d486-4e6d-b08f-06b677075a5d"
  let profile = "private-profile"
  let approved: [([String], [Int: String])] = [
    (["notarytool", "--version"], [:]),
    (
      ["notarytool", "history", "--keychain-profile", profile, "--output-format", "json"],
      [3: "<redacted-profile>"]
    ),
    (
      [
        "notarytool", "submit", "/private/tmp/a.pkg", "--keychain-profile", profile,
        "--output-format", "json",
      ],
      [4: "<redacted-profile>"]
    ),
    (
      [
        "notarytool", "wait", submissionID, "--keychain-profile", profile,
        "--output-format", "json",
      ],
      [4: "<redacted-profile>"]
    ),
    (
      [
        "notarytool", "log", submissionID, "--keychain-profile", profile,
        "--output-format", "json",
      ],
      [4: "<redacted-profile>"]
    ),
  ]
  for (arguments, redaction) in approved {
    #expect(
      ProcessRunner.notarytoolInvocationIsAllowed(
        arguments, redactedArguments: redaction))
  }

  let refused = [
    ["notarytool", "submit", "/private/tmp/a.pkg", "-k", "key.p8"],
    ["notarytool", "submit", "/private/tmp/a.pkg", "-kkey.p8"],
    ["notarytool", "submit", "/private/tmp/a.pkg", "-d", "issuer"],
    ["notarytool", "submit", "/private/tmp/a.pkg", "-i", "key-id"],
    ["notarytool", "submit", "/private/tmp/a.pkg", "--password=secret"],
    [
      "notarytool", "submit", "/private/tmp/a.pkg", "--keychain-profile", profile,
      "--output-format", "json", "--force",
    ],
    [
      "notarytool", "submit", "/private/tmp/a.pkg", "--keychain-profile=\(profile)",
      "--output-format=json",
    ],
    [
      "notarytool", "wait", "not-a-uuid", "--keychain-profile", profile,
      "--output-format", "json",
    ],
    ["notarytool", "info", submissionID, "--keychain-profile", profile],
  ]
  for arguments in refused {
    #expect(
      !ProcessRunner.notarytoolInvocationIsAllowed(
        arguments, redactedArguments: [4: "<redacted-profile>"]))
  }
  #expect(
    !ProcessRunner.notarytoolInvocationIsAllowed(
      approved[2].0, redactedArguments: [:]))

  #expect(throws: ReleasePackageError.self) {
    try ProcessRunner().run(
      "/usr/bin/xcrun",
      ["notarytool", "submit", "/private/tmp/a.pkg", "--password", "secret"])
  }
  #expect(throws: ReleasePackageError.self) {
    try ProcessRunner().run(
      "/usr/bin/xcrun",
      ["notarytool", "submit", "/private/tmp/a.pkg", "-ksecret"])
  }
  #expect(throws: ReleasePackageError.self) {
    try ProcessRunner().run(
      "/usr/bin/xcrun",
      [
        "notarytool", "submit", "/private/tmp/a.pkg", "--keychain-profile", profile,
        "--output-format", "json", "--force",
      ],
      redactedArguments: [4: "<redacted-profile>"])
  }
  #expect(throws: ReleasePackageError.self) {
    try ProcessRunner().run(
      "/usr/bin/xcrun", ["notarytool", "history"],
      environment: ["APPLE_PASSWORD": "secret"])
  }
  #expect(
    ProcessRunner.notarytoolEnvironmentIsAllowed([
      "HOME": FileManager.default.homeDirectoryForCurrentUser.path
    ]))
  #expect(!ProcessRunner.notarytoolEnvironmentIsAllowed(["HOME": "/var/empty"]))
  #expect(throws: ReleasePackageError.self) {
    try ProcessRunner().run("/usr/bin/xcrun", ["simctl", "list"])
  }
}
