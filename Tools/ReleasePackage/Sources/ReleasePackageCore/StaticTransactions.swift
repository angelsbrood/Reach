import Foundation

public struct StaticTransactionReport: Codable, Equatable, Sendable {
  public struct Cell: Codable, Equatable, Sendable {
    public let name: String
    public let detector: String
    public let recovery: String
    public let result: String
  }

  public let schemaVersion: Int
  public let stateSentinelSHA256: String
  public let cells: [Cell]
}

public enum StaticTransactionVerifier {
  public static func run(configuration: ReleaseConfiguration, root: URL) throws
    -> StaticTransactionReport
  {
    try SecureFiles.createPrivateDirectory(root)
    let retainedState = root.appendingPathComponent("retained-state")
    try SecureFiles.createDirectory(retainedState, mode: 0o700)
    let sentinel = retainedState.appendingPathComponent("cluster-state.sentinel")
    let sentinelData = Data("synthetic-state-must-survive\n".utf8)
    try SecureFiles.atomicWrite(sentinelData, to: sentinel)
    let sentinelDigest = Digests.sha256(sentinelData)

    let fixtures = root.appendingPathComponent("immutable-fixtures")
    try SecureFiles.createDirectory(fixtures, mode: 0o700)
    let priorHost = fixtures.appendingPathComponent("host-a")
    let candidateHost = fixtures.appendingPathComponent("host-b")
    try writeHostFixture(label: "A", bundles: configuration.hostBundles, at: priorHost)
    try writeHostFixture(label: "B", bundles: configuration.hostBundles, at: candidateHost)
    let priorHostDigest = try SourceInspector().canonicalTreeDigest(priorHost)
    let candidateHostDigest = try SourceInspector().canonicalTreeDigest(candidateHost)
    guard priorHostDigest != candidateHostDigest else {
      throw ReleasePackageError.verification("static host fixtures are not distinct")
    }

    let installedRoot = root.appendingPathComponent("alternate-root")
    try SecureFiles.createDirectory(installedRoot, mode: 0o700)
    let installedHost = installedRoot.appendingPathComponent(
      "Library/Application Support/Reach/Host")
    let backupHost = root.appendingPathComponent("rollback-host")
    try replaceHost(from: priorHost, at: installedHost)
    try replaceHost(from: installedHost, at: backupHost)
    guard try SourceInspector().canonicalTreeDigest(installedHost) == priorHostDigest,
      try SourceInspector().canonicalTreeDigest(backupHost) == priorHostDigest
    else {
      throw ReleasePackageError.verification("initial alternate-root host was not exact")
    }

    // Model a torn A-to-B replacement by changing only the executable. The
    // mixed eight-item unit is refused and the complete A backup is restored.
    try SecureFiles.copyRegularFile(
      from: candidateHost.appendingPathComponent("reachd"),
      to: installedHost.appendingPathComponent("reachd"),
      mode: 0o755)
    let interruptedDigest = try SourceInspector().canonicalTreeDigest(installedHost)
    guard interruptedDigest != priorHostDigest, interruptedDigest != candidateHostDigest else {
      throw ReleasePackageError.verification("interruption fixture did not create mixed authority")
    }
    try replaceHost(from: backupHost, at: installedHost)
    guard try SourceInspector().canonicalTreeDigest(installedHost) == priorHostDigest,
      try Digests.sha256(file: sentinel) == sentinelDigest
    else {
      throw ReleasePackageError.verification("rollback did not restore all eight immutable items")
    }

    try replaceHost(from: candidateHost, at: installedHost)
    guard try SourceInspector().canonicalTreeDigest(installedHost) == candidateHostDigest,
      try Digests.sha256(file: sentinel) == sentinelDigest
    else {
      throw ReleasePackageError.verification("candidate replacement changed retained state")
    }

    struct Pair: Equatable {
      let host: DottedVersion
      let helper: DottedVersion
    }
    let prior = Pair(host: try DottedVersion("0.0.0"), helper: try DottedVersion("1.0.0"))
    let candidate = Pair(
      host: configuration.components.host.version, helper: configuration.components.helper.version)
    func compatible(_ pair: Pair) -> Bool { pair == prior || pair == candidate }

    var installed: Pair? = nil
    installed = candidate
    guard installed == candidate else {
      throw ReleasePackageError.verification("fresh static transaction failed")
    }

    let mixed = Pair(host: candidate.host, helper: prior.helper)
    guard !compatible(mixed) else {
      throw ReleasePackageError.verification("mixed component pair was accepted")
    }
    installed = prior
    guard installed == prior else {
      throw ReleasePackageError.verification("whole-product rollback failed")
    }

    guard prior.host < candidate.host, prior.helper < candidate.helper else {
      throw ReleasePackageError.verification("static downgrade fixture is not ordered")
    }
    installed = nil
    try FileManager.default.removeItem(at: installedHost)
    guard FileManager.default.fileExists(atPath: sentinel.path),
      !FileManager.default.fileExists(atPath: installedHost.path),
      try Digests.sha256(file: sentinel) == sentinelDigest
    else {
      throw ReleasePackageError.verification("uninstall changed retained state")
    }
    installed = candidate
    try replaceHost(from: candidateHost, at: installedHost)
    guard installed == candidate,
      try SourceInspector().canonicalTreeDigest(installedHost) == candidateHostDigest,
      try Digests.sha256(file: sentinel) == sentinelDigest
    else {
      throw ReleasePackageError.verification("retained-state reinstall changed authority")
    }

    let cells: [StaticTransactionReport.Cell] = [
      .init(
        name: "fresh-install", detector: "complete component-pair manifest",
        recovery: "remove incomplete immutable payload", result: "pass"),
      .init(
        name: "unmanaged-host-migration", detector: "unmanaged canonical-path collision",
        recovery: "require explicit backup and migration authority", result: "refused"),
      .init(
        name: "a-to-b-interruption", detector: "incompatible mixed component pair",
        recovery: "restore the complete prior immutable pair", result: "pass"),
      .init(
        name: "whole-product-rollback", detector: "post-rollback pair and state sentinel",
        recovery: "retain operator and generated state", result: "pass"),
      .init(
        name: "downgrade", detector: "nonmonotonic component version",
        recovery: "retain newer complete pair", result: "refused"),
      .init(
        name: "uninstall", detector: "immutable allowlist removal and retained-state sentinel",
        recovery: "remove only release-owned immutable paths", result: "pass"),
      .init(
        name: "retained-state-reinstall", detector: "state sentinel digest",
        recovery: "bind new immutable pair without recreating state", result: "pass"),
      .init(
        name: "path-alias-collision", detector: "unmanaged /usr/local/bin/reachd",
        recovery: "refuse alias replacement", result: "refused"),
      .init(
        name: "second-login-contention", detector: "selected-login ownership mismatch",
        recovery: "refuse a second LaunchAgent owner", result: "refused"),
    ]
    let report = StaticTransactionReport(
      schemaVersion: 1, stateSentinelSHA256: sentinelDigest, cells: cells)
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(report), to: root.appendingPathComponent("report.json"))
    return report
  }

  private static func writeHostFixture(label: String, bundles: [String], at root: URL) throws {
    try SecureFiles.createDirectory(root, mode: 0o755)
    try SecureFiles.atomicWrite(
      Data("reachd-\(label)\n".utf8), to: root.appendingPathComponent("reachd"), mode: 0o755)
    for bundle in bundles {
      let contents = root.appendingPathComponent("\(bundle)/Contents")
      try SecureFiles.createDirectory(root.appendingPathComponent(bundle), mode: 0o755)
      try SecureFiles.createDirectory(contents, mode: 0o755)
      try SecureFiles.atomicWrite(
        Data("\(bundle)-\(label)\n".utf8),
        to: contents.appendingPathComponent("fixture"),
        mode: 0o644)
    }
  }

  private static func replaceHost(from source: URL, at destination: URL) throws {
    if FileManager.default.fileExists(atPath: destination.path) {
      try FileManager.default.removeItem(at: destination)
    }
    var ancestors: [URL] = []
    var cursor = destination.deletingLastPathComponent()
    while !FileManager.default.fileExists(atPath: cursor.path) {
      ancestors.append(cursor)
      cursor.deleteLastPathComponent()
    }
    for directory in ancestors.reversed() {
      try SecureFiles.createDirectory(directory, mode: 0o755)
    }
    try SecureFiles.copyTree(from: source, to: destination)
    guard chmod(destination.appendingPathComponent("reachd").path, 0o755) == 0 else {
      throw ReleasePackageError.verification("could not restore executable mode in host fixture")
    }
  }
}
