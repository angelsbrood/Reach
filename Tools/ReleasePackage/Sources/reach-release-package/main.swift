import Foundation
import ReleasePackageCore

struct Arguments {
  let command: String
  private let values: [String: String]

  init(_ raw: [String]) throws {
    guard let command = raw.first else {
      throw ReleasePackageError.invalidArgument(Self.usage)
    }
    self.command = command
    var values: [String: String] = [:]
    var index = 1
    while index < raw.count {
      let key = raw[index]
      guard key.hasPrefix("--"), key.count > 2, index + 1 < raw.count else {
        throw ReleasePackageError.invalidArgument("every option requires --name VALUE")
      }
      guard values[key] == nil else {
        throw ReleasePackageError.invalidArgument("duplicate option \(key)")
      }
      values[key] = raw[index + 1]
      index += 2
    }
    self.values = values
  }

  func require(_ key: String) throws -> URL {
    guard let value = values["--\(key)"] else {
      throw ReleasePackageError.invalidArgument("--\(key) requires an absolute path")
    }
    return try ReleasePathAuthority.absoluteURL(value, label: "--\(key)")
  }

  func optional(_ key: String) throws -> URL? {
    guard let value = values["--\(key)"] else { return nil }
    return try ReleasePathAuthority.absoluteURL(value, label: "--\(key)")
  }

  func requireString(_ key: String) throws -> String {
    guard let value = values["--\(key)"], !value.isEmpty else {
      throw ReleasePackageError.invalidArgument("--\(key) requires a value")
    }
    return value
  }

  func optionalString(_ key: String) -> String? {
    values["--\(key)"]
  }

  func validateKeys(_ allowed: Set<String>) throws {
    let actual = Set(values.keys.map { String($0.dropFirst(2)) })
    guard actual.isSubset(of: allowed) else {
      throw ReleasePackageError.invalidArgument(
        "unknown options: \(actual.subtracting(allowed).sorted().joined(separator: ", "))")
    }
  }

  static let usage = """
    usage:
      reach-release-package snapshot-dependencies --repository PATH --swift-checkouts PATH --go-module-cache PATH --go-root PATH --notices PATH --output PATH --logs PATH
      reach-release-package build --repository PATH --release-tool-source PATH --configuration PATH --notices PATH --depot PATH --work PATH --output PATH
      reach-release-package verify --package PATH --release-tool-source PATH --configuration PATH --notices PATH --depot PATH --scratch PATH [--provenance PATH] [--notice-manifest PATH] [--report PATH]
      reach-release-package freeze-lineage --unsigned-authority PATH --unsigned-tool-source PATH --configuration PATH --notices PATH --depot PATH --scratch PATH --output PATH [--parent-authority PATH]
      reach-release-package sign --unsigned-authority PATH --unsigned-tool-source PATH --finalizer-tool-source PATH --configuration PATH --notices PATH --depot PATH --work PATH --output PATH [--lineage PATH] [--parent-authority PATH]
      reach-release-package notarize --signed-authority PATH --configuration PATH --notices PATH --depot PATH --keychain-profile PROFILE --state PATH --output PATH [--recover-submission UUID]
      reach-release-package verify-release --package PATH --provenance PATH --unsigned-tool-source PATH --finalizer-tool-source PATH --configuration PATH --notices PATH --depot PATH --scratch PATH --report PATH
      reach-release-package seal-authority --signed-authority PATH --unsigned-tool-source PATH --finalizer-tool-source PATH --configuration PATH --notices PATH --depot PATH --scratch PATH --output PATH
    """
}

do {
  let arguments = try Arguments(Array(CommandLine.arguments.dropFirst()))
  switch arguments.command {
  case "snapshot-dependencies":
    try arguments.validateKeys([
      "repository", "swift-checkouts", "go-module-cache", "go-root", "notices", "output", "logs",
    ])
    let logs = try arguments.require("logs")
    try SecureFiles.createPrivateDirectory(logs)
    let authority = try NoticeAuthority.load(from: arguments.require("notices"))
    let manifest = try DependencyDepotBuilder().snapshot(
      repository: arguments.require("repository"),
      swiftCheckouts: arguments.require("swift-checkouts"),
      goModuleCache: arguments.require("go-module-cache"),
      goRoot: arguments.require("go-root"),
      output: arguments.require("output"),
      noticeAuthority: authority,
      logDirectory: logs
    )
    FileHandle.standardOutput.write(try CanonicalJSON.encode(manifest))
  case "build":
    try arguments.validateKeys([
      "repository", "release-tool-source", "configuration", "notices", "depot", "work", "output",
    ])
    let result = try ReleaseBuilder().build(
      repository: arguments.require("repository"),
      releaseToolSource: arguments.require("release-tool-source"),
      configurationURL: arguments.require("configuration"),
      noticeAuthorityURL: arguments.require("notices"),
      dependencyDepot: arguments.require("depot"),
      workRoot: arguments.require("work"),
      outputRoot: arguments.require("output")
    )
    FileHandle.standardOutput.write(try CanonicalJSON.encode(result))
  case "verify":
    try arguments.validateKeys([
      "package", "release-tool-source", "configuration", "notices", "depot", "scratch",
      "provenance", "notice-manifest", "report",
    ])
    let scratch = try arguments.require("scratch")
    let report = try PackageVerifier().verify(
      package: arguments.require("package"),
      configurationURL: arguments.require("configuration"),
      noticeAuthorityURL: arguments.require("notices"),
      dependencyDepot: arguments.require("depot"),
      expectedReleaseToolSourceSHA256: try SourceInspector().canonicalTreeDigest(
        arguments.require("release-tool-source")),
      provenanceURL: arguments.optional("provenance"),
      noticeManifestURL: arguments.optional("notice-manifest"),
      scratch: scratch,
      logDirectory: scratch.appendingPathComponent("logs")
    )
    let encoded = try CanonicalJSON.encode(report)
    if let reportURL = try arguments.optional("report") {
      try SecureFiles.atomicWrite(encoded, to: reportURL)
    }
    FileHandle.standardOutput.write(encoded)
  case "sign":
    try arguments.validateKeys([
      "unsigned-authority", "unsigned-tool-source", "finalizer-tool-source", "configuration",
      "notices", "depot", "work", "output", "lineage", "parent-authority",
    ])
    let result = try SignedReleaseFinalizer().sign(
      unsignedAuthority: arguments.require("unsigned-authority"),
      unsignedToolSource: arguments.require("unsigned-tool-source"),
      finalizerToolSource: arguments.require("finalizer-tool-source"),
      configurationURL: arguments.require("configuration"),
      noticeAuthorityURL: arguments.require("notices"),
      dependencyDepot: arguments.require("depot"),
      workRoot: arguments.require("work"),
      outputRoot: arguments.require("output"),
      lineageURL: try arguments.optional("lineage"),
      parentAuthority: try arguments.optional("parent-authority"))
    FileHandle.standardOutput.write(try CanonicalJSON.encode(result))
  case "freeze-lineage":
    try arguments.validateKeys([
      "unsigned-authority", "unsigned-tool-source", "configuration", "notices", "depot",
      "scratch", "output", "parent-authority",
    ])
    let result = try ReleaseLineageFreezer().freeze(
      unsignedAuthority: arguments.require("unsigned-authority"),
      unsignedToolSource: arguments.require("unsigned-tool-source"),
      configurationURL: arguments.require("configuration"),
      noticeAuthorityURL: arguments.require("notices"),
      dependencyDepot: arguments.require("depot"),
      scratch: arguments.require("scratch"),
      output: arguments.require("output"),
      parentAuthority: try arguments.optional("parent-authority"))
    FileHandle.standardOutput.write(try CanonicalJSON.encode(result))
  case "notarize":
    try arguments.validateKeys([
      "signed-authority", "configuration", "notices", "depot", "keychain-profile", "state",
      "output", "recover-submission",
    ])
    let result = try ReleaseNotarizer().notarize(
      signedAuthority: arguments.require("signed-authority"),
      configurationURL: arguments.require("configuration"),
      noticeAuthorityURL: arguments.require("notices"),
      dependencyDepot: arguments.require("depot"),
      keychainProfile: arguments.requireString("keychain-profile"),
      stateURL: arguments.require("state"),
      outputRoot: arguments.require("output"),
      recoverSubmission: arguments.optionalString("recover-submission"))
    FileHandle.standardOutput.write(try CanonicalJSON.encode(result))
  case "verify-release":
    try arguments.validateKeys([
      "package", "provenance", "unsigned-tool-source", "finalizer-tool-source",
      "configuration", "notices", "depot", "scratch", "report",
    ])
    let report = try SignedReleaseVerifier().verify(
      package: arguments.require("package"),
      provenanceURL: arguments.require("provenance"),
      unsignedToolSource: arguments.require("unsigned-tool-source"),
      finalizerToolSource: arguments.require("finalizer-tool-source"),
      configurationURL: arguments.require("configuration"),
      noticeAuthorityURL: arguments.require("notices"),
      dependencyDepot: arguments.require("depot"),
      scratch: arguments.require("scratch"),
      reportURL: arguments.require("report"))
    FileHandle.standardOutput.write(try CanonicalJSON.encode(report))
  case "seal-authority":
    try arguments.validateKeys([
      "signed-authority", "unsigned-tool-source", "finalizer-tool-source", "configuration",
      "notices", "depot", "scratch", "output",
    ])
    let result = try RetainedReleaseAuthoritySealer().seal(
      signedAuthority: arguments.require("signed-authority"),
      unsignedToolSource: arguments.require("unsigned-tool-source"),
      finalizerToolSource: arguments.require("finalizer-tool-source"),
      configurationURL: arguments.require("configuration"),
      noticeAuthorityURL: arguments.require("notices"),
      dependencyDepot: arguments.require("depot"),
      scratch: arguments.require("scratch"),
      output: arguments.require("output"))
    FileHandle.standardOutput.write(try CanonicalJSON.encode(result))
  default:
    throw ReleasePackageError.invalidArgument(Arguments.usage)
  }
} catch {
  FileHandle.standardError.write(Data("error: \(error)\n".utf8))
  exit(2)
}
