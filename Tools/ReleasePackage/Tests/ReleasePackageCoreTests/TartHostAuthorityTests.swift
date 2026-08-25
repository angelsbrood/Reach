import Foundation
import Testing

@testable import ReleasePackageCore

private final class FakeTartExecutor: TartCommandExecuting {
  struct Expected {
    let arguments: [String]
    let output: String
  }

  var expected: [Expected]
  private(set) var observed: [([String], [String: String])] = []

  init(_ expected: [Expected]) {
    self.expected = expected
  }

  func execute(
    arguments: [String], environment: [String: String], timeout: TimeInterval,
    logURL: URL, requireSuccess: Bool
  ) throws -> CommandResult {
    guard !expected.isEmpty else {
      throw ReleasePackageError.verification("unexpected fake Tart invocation")
    }
    let next = expected.removeFirst()
    guard next.arguments == arguments, timeout > 0, requireSuccess else {
      throw ReleasePackageError.verification("fake Tart invocation changed")
    }
    observed.append((arguments, environment))
    return CommandResult(
      exitStatus: 0, output: next.output, errorOutput: "", elapsedMilliseconds: 1)
  }
}

private func tartInventory(
  _ values: [(name: String, running: Bool, state: String)]
) throws -> String {
  let rows: [[String: Any]] = values.map {
    [
      "Source": "local", "Name": $0.name, "Disk": 80, "Size": 12,
      "Accessed": "2026-08-23T00:00:00Z", "Running": $0.running, "State": $0.state,
    ]
  }
  let data = try JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys])
  return String(decoding: data, as: UTF8.self)
}

private let tartConfiguration =
  """
  {"CPU":8,"Disk":80,"DiskFormat":"raw","Display":"1024x768","Memory":16384,"OS":"darwin","Running":false,"Size":"12.000","State":"stopped"}
  """

@Test func tartGrammarIsExactAndForbidsMovingOrSharedAuthority() {
  let base = "reach-s36-macos27-base"
  let acceptance = "reach-s36-macos27-acceptance"
  let approved = [
    ["--version"],
    ["list", "--source", "local", "--format", "json"],
    ["get", base, "--format", "json"],
    [
      "create", base, "--from-ipsw", "/private/tmp/macOS27.ipsw",
      "--disk-size", "80", "--disk-format", "raw",
    ],
    ["set", base, "--cpu", "8", "--memory", "16384"],
    ["clone", base, acceptance, "--prune-limit", "100"],
    ["run", base, "--no-clipboard", "--no-audio"],
    ["run", acceptance, "--no-graphics", "--no-clipboard", "--no-audio"],
    ["stop", acceptance, "--timeout", "15"],
    ["ip", acceptance, "--wait", "60", "--resolver", "dhcp"],
    ["delete", acceptance],
  ]
  for arguments in approved {
    #expect(ProcessRunner.tartInvocationIsAllowed(arguments))
  }
  let refused = [
    ["create", base, "--from-ipsw", "latest", "--disk-size", "80", "--disk-format", "raw"],
    ["clone", "ghcr.io/cirruslabs/macos-runner:latest", acceptance],
    ["clone", base, "another-vm", "--prune-limit", "100"],
    ["run", acceptance, "--no-graphics", "--dir", "/Users/example"],
    ["run", acceptance, "--provisioning-opts", "username=x,password=y"],
    ["ip", acceptance, "--wait", "60", "--resolver", "agent"],
    ["delete", base, acceptance],
  ]
  for arguments in refused {
    #expect(!ProcessRunner.tartInvocationIsAllowed(arguments))
  }
  let home = FileManager.default.homeDirectoryForCurrentUser.path
  #expect(ProcessRunner.tartEnvironmentIsAllowed(["HOME": home]))
  #expect(
    ProcessRunner.tartEnvironmentIsAllowed([
      "HOME": home, "TART_NO_AUTO_PRUNE": "1",
    ]))
  #expect(!ProcessRunner.tartEnvironmentIsAllowed(["HOME": "/var/empty"]))
  #expect(
    !ProcessRunner.tartEnvironmentIsAllowed([
      "HOME": home, "TART_NO_AUTO_PRUNE": "0",
    ]))
}

@Test func tartControllerClonesOnlyTheSealedBaseWithoutAutomaticPruning() throws {
  let root = try makeTemporaryDirectory("tart-clone")
  defer { removeTemporaryDirectory(root) }
  let initial = try tartInventory([
    (TartS36VM.base.rawValue, false, "stopped")
  ])
  let fake = FakeTartExecutor([
    .init(arguments: ["list", "--source", "local", "--format", "json"], output: initial),
    .init(
      arguments: [
        "clone", TartS36VM.base.rawValue, TartS36VM.acceptance.rawValue,
        "--prune-limit", "100",
      ], output: ""),
    .init(
      arguments: ["get", TartS36VM.acceptance.rawValue, "--format", "json"],
      output: tartConfiguration),
  ])
  let controller = try TartHostController(logRoot: root, executor: fake)
  let record = try controller.cloneAcceptance()
  #expect(record.cpuCount == 8)
  #expect(record.memoryMiB == 16_384)
  #expect(record.diskGiB == 80)
  #expect(fake.expected.isEmpty)
  #expect(fake.observed[1].1["TART_NO_AUTO_PRUNE"] == "1")
  #expect(
    fake.observed.allSatisfy {
      $0.1["HOME"] == FileManager.default.homeDirectoryForCurrentUser.path
    })
}

@Test func tartControllerRefusesUnknownOwnedNamesAndBaseDeletionWithAClone() throws {
  let root = try makeTemporaryDirectory("tart-refusal")
  defer { removeTemporaryDirectory(root) }
  let rogue = try tartInventory([
    ("reach-s36-unexpected", false, "stopped")
  ])
  let rogueFake = FakeTartExecutor([
    .init(arguments: ["list", "--source", "local", "--format", "json"], output: rogue)
  ])
  let rogueController = try TartHostController(logRoot: root, executor: rogueFake)
  #expect(throws: ReleasePackageError.self) { try rogueController.inventory() }

  let secondRoot = root.appendingPathComponent("second")
  let both = try tartInventory([
    (TartS36VM.base.rawValue, false, "stopped"),
    (TartS36VM.acceptance.rawValue, false, "stopped"),
  ])
  let deleteFake = FakeTartExecutor([
    .init(arguments: ["list", "--source", "local", "--format", "json"], output: both)
  ])
  let deleteController = try TartHostController(logRoot: secondRoot, executor: deleteFake)
  #expect(throws: ReleasePackageError.self) { try deleteController.delete(.base) }
  #expect(deleteFake.observed.count == 1)
}

@Test func tartJSONShapesAndGuestAddressFailClosed() throws {
  let extra =
    """
    [{"Accessed":"now","Disk":80,"Name":"reach-s36-macos27-base","Running":false,"Size":1,"Source":"local","State":"stopped","Unexpected":true}]
    """
  #expect(throws: ReleasePackageError.self) {
    try TartHostController.decodeInventory(Data(extra.utf8))
  }
  let root = try makeTemporaryDirectory("tart-address")
  defer { removeTemporaryDirectory(root) }
  let running = try tartInventory([
    (TartS36VM.acceptance.rawValue, true, "running")
  ])
  let fake = FakeTartExecutor([
    .init(arguments: ["list", "--source", "local", "--format", "json"], output: running),
    .init(
      arguments: [
        "ip", TartS36VM.acceptance.rawValue, "--wait", "60", "--resolver", "dhcp",
      ], output: "not-an-address\n"),
  ])
  let controller = try TartHostController(logRoot: root, executor: fake)
  #expect(throws: ReleasePackageError.self) { try controller.acceptanceAddress() }
}
