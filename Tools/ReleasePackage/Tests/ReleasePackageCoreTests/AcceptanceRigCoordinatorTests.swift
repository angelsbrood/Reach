import Foundation
import Testing

@testable import ReleasePackageCore

private struct RigHostStorage: HostStorageChecking {
  func require(_ phase: HostStoragePhase) throws -> HostStorageReport {
    HostStorageReport(
      phase: phase, availableBytes: UInt64.max - 1_024,
      totalBytes: UInt64.max,
      requiredBytes: phase.minimumAvailableBytes,
      filesystemAuthoritySHA256: String(repeating: "a", count: 64))
  }
}

private final class RigTartExecutor: TartCommandExecuting {
  struct Step {
    let arguments: [String]
    let output: String
  }

  var steps: [Step]
  private(set) var observed: [[String]] = []

  init(_ steps: [Step]) { self.steps = steps }

  func execute(
    arguments: [String], environment: [String: String], timeout: TimeInterval,
    logURL: URL, requireSuccess: Bool
  ) throws -> CommandResult {
    guard let next = steps.first, next.arguments == arguments,
      !environment.isEmpty, timeout > 0, requireSuccess
    else {
      throw ReleasePackageError.verification("unexpected rig Tart command")
    }
    steps.removeFirst()
    observed.append(arguments)
    return .init(
      exitStatus: 0, output: next.output, errorOutput: "", elapsedMilliseconds: 1)
  }
}

private func rigInventory(
  _ values: [(name: String, running: Bool, state: String)]
) throws -> String {
  let rows: [[String: Any]] = values.map {
    [
      "Source": "local", "Name": $0.name, "Disk": 80, "Size": 12,
      "Accessed": "2026-08-23T00:00:00Z", "Running": $0.running, "State": $0.state,
    ]
  }
  return String(
    decoding: try JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys]),
    as: UTF8.self)
}

private let rigConfiguration =
  """
  {"CPU":8,"Disk":80,"DiskFormat":"raw","Display":"1024x768","Memory":16384,"OS":"darwin","Running":false,"Size":"12.000","State":"stopped"}
  """

private func sealedRigJournal() throws -> AcceptanceRigJournal {
  func digest(_ value: Character) -> String { String(repeating: value, count: 64) }
  var journal = AcceptanceRigJournal(
    runID: UUID().uuidString, tartExecutableSHA256: digest("a"),
    createdAtUTC: "t0", updatedAtUTC: "t0")
  journal = try journal.imageVerified(
    authoritySHA256: digest("b"), inventorySHA256: digest("c"), at: "t1")
  let configuration = try JSONDecoder().decode(
    TartVMConfigurationRecord.self, from: Data(rigConfiguration.utf8))
  journal = try journal.baseCreated(
    configurationSHA256: Digests.sha256(try CanonicalJSON.encode(configuration.authority)),
    inventorySHA256: digest("d"), at: "t2")
  journal = try journal.baseProvisioningStarted(inventorySHA256: digest("e"), at: "t3")
  return try journal.baseSealed(
    provisioningSHA256: digest("f"), sealSHA256: digest("1"),
    inventorySHA256: digest("2"), at: "t4")
}

@Test func rigCoordinatorRecoversAnAlreadyCreatedCloneWithoutCloningAgain() throws {
  let root = try makeTemporaryDirectory("rig-coordinator-clone-recovery")
  defer { removeTemporaryDirectory(root) }
  let store = AcceptanceRigJournalStore(url: root.appendingPathComponent("rig.json"))
  try store.create(sealedRigJournal())
  let both = try rigInventory([
    (TartS36VM.base.rawValue, false, "stopped"),
    (TartS36VM.acceptance.rawValue, false, "stopped"),
  ])
  let fake = RigTartExecutor([
    .init(arguments: ["list", "--source", "local", "--format", "json"], output: both),
    .init(
      arguments: ["get", TartS36VM.acceptance.rawValue, "--format", "json"],
      output: rigConfiguration),
    .init(arguments: ["list", "--source", "local", "--format", "json"], output: both),
  ])
  let controller = try TartHostController(
    logRoot: root.appendingPathComponent("logs"), executor: fake)
  let value = try AcceptanceRigCoordinator(
    controller: controller, store: store,
    imageVerifier: MacOSRestoreImageInspector(),
    storage: RigHostStorage(),
    timestamp: { "t5" }
  ).cloneAcceptance()
  #expect(value.phase == .cloneCreated)
  #expect(value.cloneEpoch == 1)
  #expect(!fake.observed.contains(where: { $0.first == "clone" }))
  #expect(fake.steps.isEmpty)
}

@Test func rigConfigurationAuthorityIgnoresAllocationAndLifecycleButNotResources() throws {
  let original = try JSONDecoder().decode(
    TartVMConfigurationRecord.self, from: Data(rigConfiguration.utf8))
  let provisioned = try JSONDecoder().decode(
    TartVMConfigurationRecord.self,
    from: Data(
      rigConfiguration
        .replacingOccurrences(of: #""Size":"12.000""#, with: #""Size":"43.125""#)
        .replacingOccurrences(of: #""Running":false"#, with: #""Running":true"#)
        .replacingOccurrences(of: #""State":"stopped""#, with: #""State":"running""#)
        .utf8))
  #expect(original.authority == provisioned.authority)

  let changedCPU = try JSONDecoder().decode(
    TartVMConfigurationRecord.self,
    from: Data(rigConfiguration.replacingOccurrences(of: #""CPU":8"#, with: #""CPU":7"#).utf8))
  #expect(original.authority != changedCPU.authority)
}

@Test func rigCoordinatorCreatesExactlyOneCloneAndRefusesWrongConfiguration() throws {
  let root = try makeTemporaryDirectory("rig-coordinator-clone-create")
  defer { removeTemporaryDirectory(root) }
  let store = AcceptanceRigJournalStore(url: root.appendingPathComponent("rig.json"))
  try store.create(sealedRigJournal())
  let base = try rigInventory([
    (TartS36VM.base.rawValue, false, "stopped")
  ])
  let both = try rigInventory([
    (TartS36VM.base.rawValue, false, "stopped"),
    (TartS36VM.acceptance.rawValue, false, "stopped"),
  ])
  let changedConfiguration = rigConfiguration.replacingOccurrences(
    of: "\"CPU\":8", with: "\"CPU\":7")
  let fake = RigTartExecutor([
    .init(arguments: ["list", "--source", "local", "--format", "json"], output: base),
    .init(arguments: ["list", "--source", "local", "--format", "json"], output: base),
    .init(
      arguments: [
        "clone", TartS36VM.base.rawValue, TartS36VM.acceptance.rawValue,
        "--prune-limit", "100",
      ], output: ""),
    .init(
      arguments: ["get", TartS36VM.acceptance.rawValue, "--format", "json"],
      output: changedConfiguration),
  ])
  let controller = try TartHostController(
    logRoot: root.appendingPathComponent("logs"), executor: fake)
  #expect(throws: ReleasePackageError.self) {
    try AcceptanceRigCoordinator(
      controller: controller, store: store,
      imageVerifier: MacOSRestoreImageInspector(),
      storage: RigHostStorage(),
      timestamp: { "t5" }
    ).cloneAcceptance()
  }
  #expect((try store.load())?.phase == .baseSealed)
  #expect(!fake.observed.isEmpty)
  _ = both
}

@Test func rigCoordinatorBindsOneLiveHostAuthorityAndRevalidatesItsFiles() throws {
  let root = try makeTemporaryDirectory("rig-coordinator-host-authority")
  defer { removeTemporaryDirectory(root) }
  var journal = try sealedRigJournal()
  journal = try journal.cloneCreated(inventorySHA256: rigSHA("4"), at: "t5")
  journal = try journal.cloneRunning(inventorySHA256: rigSHA("5"), at: "t6")
  let store = AcceptanceRigJournalStore(url: root.appendingPathComponent("rig.json"))
  try store.create(journal)

  let identity = root.appendingPathComponent("identity")
  let knownHosts = root.appendingPathComponent("known-hosts")
  let tooling = root.appendingPathComponent("tooling")
  try SecureFiles.atomicWrite(Data("synthetic identity\n".utf8), to: identity)
  try SecureFiles.atomicWrite(Data("synthetic known host\n".utf8), to: knownHosts)
  try SecureFiles.createPrivateDirectory(tooling)
  let authority = try AcceptanceHostAuthority.capture(
    runID: journal.runID, identity: identity,
    knownHosts: knownHosts, toolingRoot: tooling)
  let authorityURL = root.appendingPathComponent("host-authority.json")
  try SecureFiles.atomicWrite(try CanonicalJSON.encode(authority), to: authorityURL)

  let controller = try TartHostController(
    logRoot: root.appendingPathComponent("logs"), executor: RigTartExecutor([]))
  let coordinator = AcceptanceRigCoordinator(
    controller: controller, store: store,
    imageVerifier: MacOSRestoreImageInspector(), storage: RigHostStorage(),
    timestamp: { "t7" })
  let bound = try coordinator.bindHostAuthority(authorityURL)
  #expect(bound.hostAuthoritySHA256 == (try Digests.sha256(file: authorityURL)))
  #expect(try coordinator.bindHostAuthority(authorityURL) == bound)

  try SecureFiles.atomicWrite(Data("substitute identity\n".utf8), to: identity)
  #expect(throws: ReleasePackageError.self) {
    try coordinator.bindHostAuthority(authorityURL)
  }
}

private func rigSHA(_ value: Character) -> String { String(repeating: value, count: 64) }
