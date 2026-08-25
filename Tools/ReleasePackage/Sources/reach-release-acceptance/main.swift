import Darwin
import Foundation
import ReleasePackageCore

private struct AcceptanceArguments {
  let mode: String
  let command: String
  private let values: [String: String]

  init(_ raw: [String]) throws {
    guard raw.count >= 2 else {
      throw ReleasePackageError.invalidArgument(Self.usage)
    }
    mode = raw[0]
    command = raw[1]
    var parsed: [String: String] = [:]
    var index = 2
    while index < raw.count {
      let key = raw[index]
      guard key.hasPrefix("--"), key.count > 2, index + 1 < raw.count,
        parsed[key] == nil
      else {
        throw ReleasePackageError.invalidArgument("every option requires one unique --name VALUE")
      }
      parsed[key] = raw[index + 1]
      index += 2
    }
    values = parsed
  }

  func validate(_ allowed: Set<String>) throws {
    let actual = Set(values.keys.map { String($0.dropFirst(2)) })
    guard actual.isSubset(of: allowed) else {
      throw ReleasePackageError.invalidArgument(
        "unknown options: \(actual.subtracting(allowed).sorted().joined(separator: ", "))")
    }
  }

  func validateExactly(required: Set<String>, optional: Set<String> = []) throws {
    let actual = Set(values.keys.map { String($0.dropFirst(2)) })
    guard required.isSubset(of: actual), actual.isSubset(of: required.union(optional)) else {
      throw ReleasePackageError.invalidArgument(
        "options must exactly match required authority: "
          + required.sorted().joined(separator: ", "))
    }
  }

  func path(_ key: String) throws -> URL {
    guard let value = values["--\(key)"] else {
      throw ReleasePackageError.invalidArgument("--\(key) requires an absolute path")
    }
    return try ReleasePathAuthority.absoluteURL(value, label: "--\(key)")
  }

  func optionalPath(_ key: String) throws -> URL? {
    guard let value = values["--\(key)"] else { return nil }
    return try ReleasePathAuthority.absoluteURL(value, label: "--\(key)")
  }

  func string(_ key: String) throws -> String {
    guard let value = values["--\(key)"], !value.isEmpty else {
      throw ReleasePackageError.invalidArgument("--\(key) requires a value")
    }
    return value
  }

  func optionalString(_ key: String) -> String? { values["--\(key)"] }

  func uid() throws -> UInt32 {
    try uid("owner-uid")
  }

  func uid(_ key: String) throws -> UInt32 {
    guard let value = UInt32(try string(key)), value != 0 else {
      throw ReleasePackageError.invalidArgument(
        "--\(key) must name a non-root numeric UID")
    }
    return value
  }

  static let usage = """
    usage:
      reach-release-acceptance guest inspect --authority PATH --owner-uid UID --owner-home PATH --host unbound|stopped|running --helper absent|stopped|unconfigured|directReady --state absent|present --scratch PATH --output PATH
      reach-release-acceptance guest static-trust --authority PATH --scratch PATH --output PATH
      reach-release-acceptance guest mandatory-deselection --authority PATH --owner-uid UID --owner-home PATH --scratch PATH --output PATH
      reach-release-acceptance guest owner-contention-begin|owner-contention-check|owner-contention-finish --authority PATH --owner-uid UID --owner-home PATH --contender-uid UID --contender-home PATH --journal PATH --scratch PATH --output PATH
      reach-release-acceptance guest crash-daemon|crash-helper --authority PATH --owner-uid UID --owner-home PATH --scratch PATH --output PATH
      reach-release-acceptance guest install|migrate|update|rollback|uninstall|verify --authority PATH [--prior-authority PATH] --owner-uid UID --owner-home PATH --helper unconfigured|directReady --state absent|present --journal PATH --scratch PATH [--stop-after PHASE]
      reach-release-acceptance guest interrupt-installer --authority PATH --prior-authority PATH --owner-uid UID --owner-home PATH --helper unconfigured|directReady --state absent|present --journal PATH --scratch PATH
      reach-release-acceptance guest recover --authority PATH [--prior-authority PATH] --owner-uid UID --owner-home PATH --helper unconfigured|directReady --state absent|present --journal PATH --scratch PATH [--stop-after PHASE]
      reach-release-acceptance host inventory|configuration --tart-sha256 SHA256 --logs PATH --output PATH [--vm base|acceptance]
      reach-release-acceptance host inspect-ipsw --ipsw PATH --ipsw-sha256 SHA256 --source-url URL --output PATH
      reach-release-acceptance host resources --phase preparation|continuation --output PATH
      reach-release-acceptance host prepare-rig --tart-sha256 SHA256 --logs PATH --rig-journal PATH --run-id UUID --output PATH
      reach-release-acceptance host create-base --tart-sha256 SHA256 --logs PATH --rig-journal PATH --ipsw PATH --ipsw-authority PATH --output PATH
      reach-release-acceptance host run-base --tart-sha256 SHA256 --logs PATH --rig-journal PATH
      reach-release-acceptance host seal-base --tart-sha256 SHA256 --logs PATH --rig-journal PATH --provisioning-report PATH --seal-report PATH --output PATH
      reach-release-acceptance host clone|run-acceptance|complete-rig --tart-sha256 SHA256 --logs PATH --rig-journal PATH [--output PATH]
      reach-release-acceptance host address --tart-sha256 SHA256 --logs PATH --rig-journal PATH --output PATH
      reach-release-acceptance host stop|delete --tart-sha256 SHA256 --logs PATH --rig-journal PATH --vm base|acceptance [--output PATH]
      reach-release-acceptance host bind-host-authority --tart-sha256 SHA256 --logs PATH --rig-journal PATH --identity PATH --known-hosts PATH --tooling-root PATH --host-authority PATH --output PATH
      reach-release-acceptance host ssh-probe|ssh-prepare --tart-sha256 SHA256 --logs PATH --rig-journal PATH --guest-ip IPV4 --identity PATH --known-hosts PATH --host-authority PATH [--output PATH]
      reach-release-acceptance host sentinel-create|sentinel-absent --tart-sha256 SHA256 --logs PATH --rig-journal PATH --guest-ip IPV4 --identity PATH --known-hosts PATH --host-authority PATH
      reach-release-acceptance host transfer --tart-sha256 SHA256 --logs PATH --rig-journal PATH --guest-ip IPV4 --identity PATH --known-hosts PATH --host-authority PATH --source PATH --remote-name NAME --kind authority|driver
      reach-release-acceptance host install-driver --tart-sha256 SHA256 --logs PATH --rig-journal PATH --guest-ip IPV4 --identity PATH --known-hosts PATH --host-authority PATH --driver-sha256 SHA256
      reach-release-acceptance host guest --tart-sha256 SHA256 --logs PATH --rig-journal PATH --guest-ip IPV4 --identity PATH --known-hosts PATH --host-authority PATH --arguments PATH --output PATH
      reach-release-acceptance host remove-driver --tart-sha256 SHA256 --logs PATH --rig-journal PATH --guest-ip IPV4 --identity PATH --known-hosts PATH --host-authority PATH
      reach-release-acceptance host fetch --tart-sha256 SHA256 --logs PATH --rig-journal PATH --guest-ip IPV4 --identity PATH --known-hosts PATH --host-authority PATH --remote-name NAME --output PATH
      reach-release-acceptance host evidence-begin --evidence-journal PATH --rig-journal PATH --output PATH
      reach-release-acceptance host evidence-record --evidence-journal PATH --rig-journal PATH --cell CELL --verdict pass|refused|stop --private-evidence PATH --redacted-summary PATH [--guest-journal PATH] --output PATH
      reach-release-acceptance host evidence-seal --evidence-journal PATH --rig-journal PATH --outcome OUTCOME --pack PATH --output PATH
      reach-release-acceptance host evidence-freeze-teardown --evidence-journal PATH --rig-journal PATH --host-authority PATH --authority PATH --output PATH
      reach-release-acceptance host evidence-rig-teardown --evidence-journal PATH --rig-journal PATH --phase clone-deleted|base-deleted --output PATH
      reach-release-acceptance host evidence-destroy --evidence-journal PATH --rig-journal PATH --kind credentials|tooling --authority PATH --inventory PATH --output PATH
      reach-release-acceptance host evidence-complete --evidence-journal PATH --rig-journal PATH --runtime-parity PATH --output PATH
    """
}

private func tartVM(_ value: String) throws -> TartS36VM {
  switch value {
  case "base": return .base
  case "acceptance": return .acceptance
  default: throw ReleasePackageError.invalidArgument("--vm must be base or acceptance")
  }
}

private func readAdministratorInput() throws -> Data {
  var buffer = [CChar](repeating: 0, count: 1_025)
  defer {
    for index in buffer.indices { buffer[index] = 0 }
  }
  guard
    readpassphrase(
      "Guest administrator password: ", &buffer, buffer.count, RPP_REQUIRE_TTY) != nil,
    let end = buffer.firstIndex(of: 0), end > 0
  else {
    throw ReleasePackageError.verification(
      "guest administrator password was not read from a terminal")
  }
  var result = Data(buffer[..<end].map { UInt8(bitPattern: $0) })
  result.append(0x0a)
  return result
}

private func runHost(_ arguments: AcceptanceArguments) throws {
  let tart = Set(["tart-sha256", "logs"])
  let rig = Set(["rig-journal"])
  let ssh = Set(["guest-ip", "identity", "known-hosts", "host-authority"])
  switch arguments.command {
  case "resources":
    try arguments.validateExactly(required: ["phase", "output"])
  case "inspect-ipsw":
    try arguments.validateExactly(
      required: ["ipsw", "ipsw-sha256", "source-url", "output"])
  case "inventory":
    try arguments.validateExactly(required: tart.union(["output"]))
  case "prepare-rig":
    try arguments.validateExactly(
      required: tart.union(rig).union(["run-id", "output"]))
  case "create-base":
    try arguments.validateExactly(
      required: tart.union(rig).union(["ipsw", "ipsw-authority", "output"]))
  case "run-base", "run-acceptance":
    try arguments.validateExactly(required: tart.union(rig))
  case "seal-base":
    try arguments.validateExactly(
      required: tart.union(rig).union(["provisioning-report", "seal-report", "output"]))
  case "clone", "complete-rig", "address":
    try arguments.validateExactly(required: tart.union(rig).union(["output"]))
  case "configuration":
    try arguments.validateExactly(required: tart.union(["vm", "output"]))
  case "stop", "delete":
    try arguments.validateExactly(
      required: tart.union(rig).union(["vm"]), optional: ["output"])
  case "bind-host-authority":
    try arguments.validateExactly(
      required: tart.union(rig).union([
        "identity", "known-hosts", "tooling-root", "host-authority", "output",
      ]))
  case "ssh-probe":
    try arguments.validateExactly(required: tart.union(rig).union(ssh).union(["output"]))
  case "ssh-prepare", "sentinel-create", "sentinel-absent":
    try arguments.validateExactly(required: tart.union(rig).union(ssh))
  case "transfer":
    try arguments.validateExactly(
      required: tart.union(rig).union(ssh).union(["source", "remote-name", "kind"]))
  case "install-driver":
    try arguments.validateExactly(
      required: tart.union(rig).union(ssh).union(["driver-sha256"]))
  case "guest":
    try arguments.validateExactly(
      required: tart.union(rig).union(ssh).union(["arguments", "output"]))
  case "fetch":
    try arguments.validateExactly(
      required: tart.union(rig).union(ssh).union(["remote-name", "output"]))
  case "remove-driver":
    try arguments.validateExactly(required: tart.union(rig).union(ssh))
  case "evidence-begin":
    try arguments.validateExactly(
      required: ["evidence-journal", "rig-journal", "output"])
  case "evidence-record":
    try arguments.validateExactly(
      required: [
        "evidence-journal", "rig-journal", "cell", "verdict",
        "private-evidence", "redacted-summary", "output",
      ], optional: ["guest-journal"])
  case "evidence-seal":
    try arguments.validateExactly(
      required: ["evidence-journal", "rig-journal", "outcome", "pack", "output"])
  case "evidence-freeze-teardown":
    try arguments.validateExactly(
      required: [
        "evidence-journal", "rig-journal", "host-authority", "authority", "output",
      ])
  case "evidence-rig-teardown":
    try arguments.validateExactly(
      required: ["evidence-journal", "rig-journal", "phase", "output"])
  case "evidence-destroy":
    try arguments.validateExactly(
      required: [
        "evidence-journal", "rig-journal", "kind", "authority", "inventory", "output",
      ])
  case "evidence-complete":
    try arguments.validateExactly(
      required: [
        "evidence-journal", "rig-journal", "runtime-parity", "output",
      ])
  default:
    throw ReleasePackageError.invalidArgument(AcceptanceArguments.usage)
  }
  if arguments.command == "inspect-ipsw" {
    let value = try MacOSRestoreImageInspector().inspect(
      localIPSW: arguments.path("ipsw"),
      expectedSHA256: arguments.string("ipsw-sha256"),
      sourceURL: arguments.string("source-url"))
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(value), to: arguments.path("output"))
    return
  }
  if arguments.command == "resources" {
    guard let phase = HostStoragePhase(rawValue: try arguments.string("phase")) else {
      throw ReleasePackageError.invalidArgument("unknown host storage phase")
    }
    let report = try HostStorageAuthority().require(phase)
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(report), to: arguments.path("output"))
    return
  }
  if arguments.command.hasPrefix("evidence-") {
    func output<T: Encodable>(_ value: T) throws {
      try SecureFiles.atomicWrite(
        try CanonicalJSON.encode(value), to: arguments.path("output"))
    }
    let coordinator = AcceptanceEvidenceCoordinator(
      evidenceStore: .init(url: try arguments.path("evidence-journal")),
      rigStore: .init(url: try arguments.path("rig-journal")))
    switch arguments.command {
    case "evidence-begin":
      try output(coordinator.begin())
    case "evidence-record":
      guard let cell = AcceptanceCell(rawValue: try arguments.string("cell")),
        let verdict = AcceptanceEvidenceVerdict(rawValue: try arguments.string("verdict"))
      else {
        throw ReleasePackageError.invalidArgument("unknown evidence cell or verdict")
      }
      try output(
        coordinator.record(
          cell: cell, verdict: verdict,
          privateEvidence: arguments.path("private-evidence"),
          redactedSummary: arguments.path("redacted-summary"),
          guestJournal: arguments.optionalPath("guest-journal")))
    case "evidence-seal":
      guard
        let outcome = AcceptanceCloseoutOutcome(
          rawValue: try arguments.string("outcome"))
      else {
        throw ReleasePackageError.invalidArgument("unknown evidence outcome")
      }
      try output(coordinator.seal(outcome: outcome, pack: arguments.path("pack")))
    case "evidence-freeze-teardown":
      let value = try coordinator.freezeTeardownAuthority(
        hostAuthority: arguments.path("host-authority"),
        output: arguments.path("authority"))
      try output(value)
    case "evidence-rig-teardown":
      guard let phase = AcceptanceEvidencePhase(rawValue: try arguments.string("phase")) else {
        throw ReleasePackageError.invalidArgument("unknown evidence teardown phase")
      }
      try output(coordinator.advanceRigTeardown(to: phase))
    case "evidence-destroy":
      let commandOutput = try arguments.path("output")
      try output(
        coordinator.destroyAuthority(
          kind: arguments.string("kind"), authority: arguments.path("authority"),
          inventory: arguments.path("inventory"), output: commandOutput))
    case "evidence-complete":
      try output(coordinator.complete(runtimeParity: arguments.path("runtime-parity")))
    default:
      throw ReleasePackageError.invalidArgument(AcceptanceArguments.usage)
    }
    return
  }
  let executable = try TartToolAuthority.resolve(
    expectedSHA256: arguments.string("tart-sha256"))
  let controller = try TartHostController(
    logRoot: arguments.path("logs"), tartExecutable: executable)
  _ = try controller.verifyVersion()
  func coordinator() throws -> AcceptanceRigCoordinator {
    try AcceptanceRigCoordinator(
      controller: controller,
      store: .init(url: try arguments.path("rig-journal")))
  }
  func write<T: Encodable>(_ value: T) throws {
    guard let output = try arguments.optionalPath("output") else { return }
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: output)
  }
  func requireRunningRig() throws -> AcceptanceRigJournal {
    try coordinator().requireRunningAcceptance()
  }
  func transport() throws -> PinnedSSHTransport {
    let rig = try requireRunningRig()
    let loaded = try AcceptanceHostAuthority.loadWithDigest(
      arguments.path("host-authority"))
    guard loaded.authority.runID == rig.runID,
      loaded.sha256 == rig.hostAuthoritySHA256
    else {
      throw ReleasePackageError.verification(
        "pinned SSH authority is not bound to the running rig")
    }
    try loaded.authority.verifyCredentials(
      identity: arguments.path("identity"),
      knownHosts: arguments.path("known-hosts"))
    try loaded.authority.verifyToolingRoot()
    return try PinnedSSHTransport(
      address: arguments.string("guest-ip"), identity: arguments.path("identity"),
      knownHosts: arguments.path("known-hosts"), logRoot: arguments.path("logs"))
  }
  switch arguments.command {
  case "inventory":
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(controller.inventory()), to: arguments.path("output"))
  case "prepare-rig":
    try write(
      coordinator().prepare(
        runID: arguments.string("run-id"),
        tartExecutableSHA256: arguments.string("tart-sha256")))
  case "create-base":
    try write(
      coordinator().createBase(
        ipsw: arguments.path("ipsw"),
        restoreImageAuthority: arguments.path("ipsw-authority")))
  case "run-base":
    try coordinator().runBaseForInteractiveProvisioning()
  case "seal-base":
    try write(
      coordinator().sealBase(
        provisioningReport: arguments.path("provisioning-report"),
        sealReport: arguments.path("seal-report")))
  case "clone":
    try write(coordinator().cloneAcceptance())
  case "run-acceptance":
    try coordinator().runAcceptanceHeadless()
  case "address":
    _ = try requireRunningRig()
    try SecureFiles.atomicWrite(
      Data((try controller.acceptanceAddress() + "\n").utf8), to: arguments.path("output"))
  case "configuration":
    let value = try controller.configuration(of: tartVM(try arguments.string("vm")))
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: arguments.path("output"))
  case "stop":
    guard try tartVM(arguments.string("vm")) == .acceptance else {
      throw ReleasePackageError.invalidArgument("only the acceptance clone may be stopped here")
    }
    try write(coordinator().stopAcceptance())
  case "delete":
    switch try tartVM(arguments.string("vm")) {
    case .acceptance: try write(coordinator().deleteAcceptance())
    case .base: try write(coordinator().deleteBase())
    }
  case "bind-host-authority":
    let rigCoordinator = try coordinator()
    let rigJournal = try rigCoordinator.requireRunningAcceptance()
    let value = try AcceptanceHostAuthority.capture(
      runID: rigJournal.runID,
      identity: arguments.path("identity"),
      knownHosts: arguments.path("known-hosts"),
      toolingRoot: arguments.path("tooling-root"))
    let authorityURL = try arguments.path("host-authority")
    let encoded = try CanonicalJSON.encode(value)
    var info = stat()
    if lstat(authorityURL.path, &info) == 0 {
      guard try AcceptanceHostAuthority.load(authorityURL) == value else {
        throw ReleasePackageError.verification("existing host authority differs")
      }
    } else {
      guard errno == ENOENT else {
        throw ReleasePackageError.verification("cannot inspect host authority path")
      }
      try SecureFiles.atomicWrite(encoded, to: authorityURL)
    }
    try write(rigCoordinator.bindHostAuthority(authorityURL))
  case "complete-rig":
    try write(coordinator().complete())
  case "ssh-probe":
    let report = try transport().probe()
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(report), to: arguments.path("output"))
  case "ssh-prepare":
    try transport().prepareTransferRoots()
  case "sentinel-create":
    try transport().createResetSentinel()
  case "sentinel-absent":
    try transport().requireResetSentinelAbsent()
  case "transfer":
    let kind = try arguments.string("kind")
    guard ["authority", "driver"].contains(kind) else {
      throw ReleasePackageError.invalidArgument("--kind must be authority or driver")
    }
    try transport().transfer(
      arguments.path("source"), remoteName: arguments.string("remote-name"),
      executable: kind == "driver")
  case "install-driver":
    var administratorInput = try readAdministratorInput()
    defer { administratorInput.resetBytes(in: 0..<administratorInput.count) }
    try transport().installGuestDriver(
      expectedSHA256: arguments.string("driver-sha256"),
      administratorInput: administratorInput)
  case "guest":
    let input = try arguments.path("arguments")
    let data = try Data(contentsOf: input, options: [.mappedIfSafe])
    let values = try JSONDecoder().decode([String].self, from: data)
    guard data == (try CanonicalJSON.encode(values)) else {
      throw ReleasePackageError.verification("guest argument file is not canonical JSON")
    }
    var administratorInput = try readAdministratorInput()
    defer { administratorInput.resetBytes(in: 0..<administratorInput.count) }
    let result = try transport().executeGuest(
      arguments: values, administratorInput: administratorInput)
    try SecureFiles.atomicWrite(Data(result.output.utf8), to: arguments.path("output"))
  case "remove-driver":
    var administratorInput = try readAdministratorInput()
    defer { administratorInput.resetBytes(in: 0..<administratorInput.count) }
    try transport().removeGuestDriver(administratorInput: administratorInput)
  case "fetch":
    try transport().fetchExport(
      named: arguments.string("remote-name"), to: arguments.path("output"))
  default:
    throw ReleasePackageError.invalidArgument(AcceptanceArguments.usage)
  }
}

private func parseHelper(_ value: String) throws -> InstalledHelperRequirement {
  guard let result = InstalledHelperRequirement(rawValue: value) else {
    throw ReleasePackageError.invalidArgument("unknown helper requirement")
  }
  return result
}

private func parseState(_ value: String) throws -> RetainedStateRequirement {
  guard let result = RetainedStateRequirement(rawValue: value) else {
    throw ReleasePackageError.invalidArgument("unknown state requirement")
  }
  return result
}

private func parseStop(_ value: String?) throws -> AcceptanceTransactionPhase? {
  guard let value else { return nil }
  guard let phase = AcceptanceTransactionPhase(rawValue: value),
    ![.accepted, .rolledBack, .uninstalled, .failed].contains(phase)
  else {
    throw ReleasePackageError.invalidArgument("--stop-after is not an interruption phase")
  }
  return phase
}

private func makeSystem(
  arguments: AcceptanceArguments,
  action: AcceptanceTransactionAction,
  prior: RetainedReleaseCatalogEntry?,
  target: RetainedReleaseCatalogEntry?,
  transactionID: String,
  journalURL: URL
) throws -> MacOSGuestTransactionSystem {
  try MacOSGuestTransactionSystem(
    entries: [prior, target].compactMap { $0 },
    ownerUID: arguments.uid(),
    ownerHome: arguments.path("owner-home"),
    action: action,
    prior: prior?.reference,
    target: target?.reference,
    finalHelper: parseHelper(try arguments.string("helper")),
    finalState: parseState(try arguments.string("state")),
    transactionID: transactionID,
    stateBaselineURL: URL(fileURLWithPath: journalURL.path + ".retained-state.json"),
    migrationRecordURL: URL(fileURLWithPath: journalURL.path + ".unmanaged.json"),
    scratch: arguments.path("scratch"))
}

do {
  let arguments = try AcceptanceArguments(Array(CommandLine.arguments.dropFirst()))
  if arguments.mode == "host" {
    try runHost(arguments)
    exit(0)
  }
  guard arguments.mode == "guest" else {
    throw ReleasePackageError.invalidArgument(AcceptanceArguments.usage)
  }
  let common: Set<String> = [
    "authority", "prior-authority", "owner-uid", "owner-home", "helper", "state",
    "journal", "scratch", "stop-after",
  ]
  switch arguments.command {
  case "static-trust":
    try arguments.validateExactly(required: ["authority", "scratch", "output"])
    let report = try MacOSGuestAcceptanceCells().verifyStaticTrust(
      retainedAuthority: arguments.path("authority"),
      scratch: arguments.path("scratch"), output: arguments.path("output"))
    FileHandle.standardOutput.write(try CanonicalJSON.encode(report))
  case "mandatory-deselection":
    try arguments.validateExactly(
      required: ["authority", "owner-uid", "owner-home", "scratch", "output"])
    let report = try MacOSGuestAcceptanceCells().installWithHelperDeselection(
      retainedAuthority: arguments.path("authority"), ownerUID: arguments.uid(),
      ownerHome: arguments.path("owner-home"), scratch: arguments.path("scratch"),
      output: arguments.path("output"))
    FileHandle.standardOutput.write(try CanonicalJSON.encode(report))
  case "owner-contention-begin", "owner-contention-check", "owner-contention-finish":
    try arguments.validateExactly(
      required: [
        "authority", "owner-uid", "owner-home", "contender-uid",
        "contender-home", "journal", "scratch", "output",
      ])
    let probe = MacOSOwnerContentionProbe()
    switch arguments.command {
    case "owner-contention-begin":
      let value = try probe.begin(
        retainedAuthority: arguments.path("authority"),
        primaryUID: arguments.uid(), primaryHome: arguments.path("owner-home"),
        contenderUID: arguments.uid("contender-uid"),
        contenderHome: arguments.path("contender-home"),
        journalURL: arguments.path("journal"), scratch: arguments.path("scratch"))
      try SecureFiles.atomicWrite(
        try CanonicalJSON.encode(value), to: arguments.path("output"))
      FileHandle.standardOutput.write(try CanonicalJSON.encode(value))
    case "owner-contention-check":
      let report = try probe.checkContender(
        retainedAuthority: arguments.path("authority"),
        primaryUID: arguments.uid(), primaryHome: arguments.path("owner-home"),
        contenderUID: arguments.uid("contender-uid"),
        contenderHome: arguments.path("contender-home"),
        journalURL: arguments.path("journal"), scratch: arguments.path("scratch"),
        output: arguments.path("output"))
      FileHandle.standardOutput.write(try CanonicalJSON.encode(report))
    case "owner-contention-finish":
      let report = try probe.finish(
        retainedAuthority: arguments.path("authority"),
        primaryUID: arguments.uid(), primaryHome: arguments.path("owner-home"),
        contenderUID: arguments.uid("contender-uid"),
        contenderHome: arguments.path("contender-home"),
        journalURL: arguments.path("journal"), scratch: arguments.path("scratch"),
        output: arguments.path("output"))
      FileHandle.standardOutput.write(try CanonicalJSON.encode(report))
    default:
      preconditionFailure("owner-contention command escaped its validated branch")
    }
  case "crash-daemon", "crash-helper":
    try arguments.validateExactly(
      required: ["authority", "owner-uid", "owner-home", "scratch", "output"])
    let target: SupervisedCrashTarget =
      arguments.command == "crash-daemon" ? .daemon : .helper
    let report = try MacOSSupervisedCrashRecovery().run(
      target: target,
      retainedAuthority: arguments.path("authority"),
      ownerUID: arguments.uid(), ownerHome: arguments.path("owner-home"),
      scratch: arguments.path("scratch"), output: arguments.path("output"))
    FileHandle.standardOutput.write(try CanonicalJSON.encode(report))
  case "inspect":
    try arguments.validate([
      "authority", "owner-uid", "owner-home", "host", "helper", "state", "scratch", "output",
    ])
    guard let host = InstalledHostRequirement(rawValue: try arguments.string("host")) else {
      throw ReleasePackageError.invalidArgument("unknown host requirement")
    }
    let entry = try RetainedReleaseCatalogEntry(root: arguments.path("authority"))
    let snapshot = try MacOSInstalledStateCollector().collect(
      retainedAuthority: entry.root,
      policy: .init(
        selectedOwnerUID: arguments.uid(), selectedOwnerHome: arguments.path("owner-home").path,
        host: host,
        helper: parseHelper(try arguments.string("helper")),
        retainedState: parseState(try arguments.string("state"))),
      ownerHome: arguments.path("owner-home"),
      scratch: arguments.path("scratch"), output: arguments.path("output"))
    FileHandle.standardOutput.write(try CanonicalJSON.encode(snapshot))
  case "install", "migrate", "update", "rollback", "uninstall", "verify":
    try arguments.validate(common)
    guard let action = AcceptanceTransactionAction(rawValue: arguments.command) else {
      throw ReleasePackageError.invalidArgument("unknown transaction action")
    }
    let authority = try RetainedReleaseCatalogEntry(root: arguments.path("authority"))
    let suppliedPrior = try arguments.optionalPath("prior-authority").map {
      try RetainedReleaseCatalogEntry(root: $0)
    }
    let prior: RetainedReleaseCatalogEntry?
    let target: RetainedReleaseCatalogEntry?
    switch action {
    case .install, .migrate, .verify:
      guard suppliedPrior == nil else {
        throw ReleasePackageError.invalidArgument("this action does not accept a prior authority")
      }
      prior = nil
      target = authority
    case .update, .rollback:
      guard let suppliedPrior else {
        throw ReleasePackageError.invalidArgument("this action requires --prior-authority")
      }
      prior = suppliedPrior
      target = authority
    case .uninstall:
      guard suppliedPrior == nil else {
        throw ReleasePackageError.invalidArgument("uninstall takes its current authority once")
      }
      prior = authority
      target = nil
    }
    let journal = AcceptanceJournal(
      transactionID: UUID().uuidString, action: action,
      prior: prior?.reference, target: target?.reference,
      selectedOwnerUID: try arguments.uid(),
      createdAtUTC: ISO8601DateFormatter().string(from: Date()),
      updatedAtUTC: ISO8601DateFormatter().string(from: Date()))
    let journalURL = try arguments.path("journal")
    let system = try makeSystem(
      arguments: arguments, action: action, prior: prior, target: target,
      transactionID: journal.transactionID, journalURL: journalURL)
    let result = try AcceptanceTransactionExecutor().begin(
      store: .init(url: journalURL), journal: journal,
      system: system, stopAfter: parseStop(arguments.optionalString("stop-after")))
    FileHandle.standardOutput.write(try CanonicalJSON.encode(result))
  case "recover", "interrupt-installer":
    try arguments.validate(common)
    let store = AcceptanceJournalStore(url: try arguments.path("journal"))
    let journal = try store.withExclusiveLock {
      guard let value = try store.load() else {
        throw ReleasePackageError.verification("no acceptance transaction exists")
      }
      return value
    }
    let authority = try RetainedReleaseCatalogEntry(root: arguments.path("authority"))
    let suppliedPrior = try arguments.optionalPath("prior-authority").map {
      try RetainedReleaseCatalogEntry(root: $0)
    }
    let catalog = [authority, suppliedPrior].compactMap { $0 }
    let prior = journal.prior.flatMap { reference in
      catalog.first(where: { $0.reference == reference })
    }
    let target = journal.target.flatMap { reference in
      catalog.first(where: { $0.reference == reference })
    }
    guard prior?.reference == journal.prior, target?.reference == journal.target else {
      throw ReleasePackageError.verification("recovery catalog does not match the durable journal")
    }
    let journalURL = try arguments.path("journal")
    let system = try makeSystem(
      arguments: arguments, action: journal.action, prior: prior, target: target,
      transactionID: journal.transactionID, journalURL: journalURL)
    let executor = AcceptanceTransactionExecutor()
    if arguments.command == "interrupt-installer" {
      guard arguments.optionalString("stop-after") == nil else {
        throw ReleasePackageError.invalidArgument(
          "interrupt-installer does not accept --stop-after")
      }
      let result = try executor.interruptInstaller(store: store, system: system)
      FileHandle.standardOutput.write(try CanonicalJSON.encode(result))
    } else {
      let result = try executor.recover(
        store: store, system: system,
        stopAfter: parseStop(arguments.optionalString("stop-after")))
      FileHandle.standardOutput.write(try CanonicalJSON.encode(result))
    }
  default:
    throw ReleasePackageError.invalidArgument(AcceptanceArguments.usage)
  }
} catch {
  FileHandle.standardError.write(Data("error: \(error)\n".utf8))
  exit(2)
}
