import Darwin
import Foundation

public struct DependencyDepotManifest: Codable, Equatable, Sendable {
  public struct SwiftPin: Codable, Equatable, Sendable {
    public let identity: String
    public let location: String
    public let revision: String
    public let version: String?
    public let tree: String
    public let mirrorPath: String
  }

  public struct SwiftSubmodule: Codable, Equatable, Sendable {
    public let parentIdentity: String
    public let path: String
    public let url: String
    public let revision: String
    public let tree: String
    public let mirrorPath: String
  }

  public struct GoModule: Codable, Equatable, Sendable {
    public let path: String
    public let version: String
    public let moduleDirectory: String
    public let treeSHA256: String
  }

  public struct NoticeInput: Codable, Equatable, Sendable {
    public let familyID: String
    public let kind: String
    public let declaredPath: String
    public let depotPath: String
    public let sha256: String
  }

  public let schemaVersion: Int
  public let swiftPins: [SwiftPin]
  public let swiftSubmodules: [SwiftSubmodule]
  public let goModules: [GoModule]
  public let noticeInputs: [NoticeInput]
  public let goVersion: String
  public let goLicenseSHA256: String
  public let goPatentsSHA256: String
}

public struct DependencyDepotBuilder {
  private struct Resolved: Decodable {
    struct Pin: Decodable {
      struct State: Decodable {
        let revision: String
        let version: String?
      }
      let identity: String
      let location: String
      let state: State
    }
    let pins: [Pin]
  }

  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
  }

  public func snapshot(
    repository: URL,
    swiftCheckouts: URL,
    goModuleCache: URL,
    goRoot: URL,
    output: URL,
    noticeAuthority: NoticeAuthority,
    logDirectory: URL
  ) throws -> DependencyDepotManifest {
    try SecureFiles.createPrivateDirectory(output)
    let swiftRoot = output.appendingPathComponent("swift")
    let goRootOutput = output.appendingPathComponent("go/pkg/mod")
    try SecureFiles.createDirectory(swiftRoot, mode: 0o700)
    try SecureFiles.createDirectory(output.appendingPathComponent("go"), mode: 0o700)
    try SecureFiles.createDirectory(output.appendingPathComponent("go/pkg"), mode: 0o700)
    try SecureFiles.createDirectory(goRootOutput, mode: 0o700)

    let resolvedURL = repository.appendingPathComponent("reachd/Package.resolved")
    let resolved = try JSONDecoder().decode(Resolved.self, from: Data(contentsOf: resolvedURL))
    let expectedSwift = Set(noticeAuthority.swiftPins)
    guard Set(resolved.pins.map(\.identity)) == expectedSwift else {
      throw ReleasePackageError.invalidConfiguration(
        "notice Swift pin set does not equal Package.resolved")
    }

    let checkoutURLs = try FileManager.default.contentsOfDirectory(
      at: swiftCheckouts,
      includingPropertiesForKeys: nil,
      options: []
    ).filter { url in
      guard !url.lastPathComponent.hasPrefix(".") else { return false }
      var info = stat()
      return lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFDIR
    }
    var checkoutByRevision: [String: URL] = [:]
    for checkout in checkoutURLs {
      let status = try runner.run(
        "/usr/bin/git", ["status", "--porcelain"], currentDirectory: checkout
      ).output
      guard status.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw ReleasePackageError.sourceAuthority(
          "Swift dependency checkout is dirty: \(checkout.lastPathComponent)")
      }
      let revision = try runner.run(
        "/usr/bin/git", ["rev-parse", "HEAD"], currentDirectory: checkout
      )
      .output.trimmingCharacters(in: .whitespacesAndNewlines)
      guard checkoutByRevision.updateValue(checkout, forKey: revision) == nil else {
        throw ReleasePackageError.sourceAuthority("ambiguous Swift checkout revision \(revision)")
      }
    }

    var swiftPins: [DependencyDepotManifest.SwiftPin] = []
    var swiftSubmodules: [DependencyDepotManifest.SwiftSubmodule] = []
    for pin in resolved.pins.sorted(by: { $0.identity < $1.identity }) {
      guard
        noticeAuthority.expectedSwiftPins.first(where: { $0.identity == pin.identity })?.revision
          == pin.state.revision
      else {
        throw ReleasePackageError.sourceAuthority(
          "Swift notice authority does not match \(pin.identity)")
      }
      guard let checkout = checkoutByRevision[pin.state.revision] else {
        throw ReleasePackageError.sourceAuthority(
          "no cached checkout for Swift pin \(pin.identity) at \(pin.state.revision); inspected \(checkoutURLs.count) checkout directories"
        )
      }
      let tree = try runner.run(
        "/usr/bin/git", ["rev-parse", "HEAD^{tree}"], currentDirectory: checkout
      )
      .output.trimmingCharacters(in: .whitespacesAndNewlines)
      let relative = "swift/\(pin.identity).git"
      let destination = output.appendingPathComponent(relative)
      _ = try runner.run(
        "/usr/bin/git",
        ["clone", "--mirror", "--no-local", checkout.path, destination.path],
        logURL: logDirectory.appendingPathComponent("swift-mirror-\(pin.identity).log")
      )
      let mirroredRevision = try runner.run(
        "/usr/bin/git", ["rev-parse", pin.state.revision], currentDirectory: destination
      )
      .output.trimmingCharacters(in: .whitespacesAndNewlines)
      guard mirroredRevision == pin.state.revision else {
        throw ReleasePackageError.verification("Swift mirror changed revision for \(pin.identity)")
      }
      swiftPins.append(
        .init(
          identity: pin.identity,
          location: pin.location,
          revision: pin.state.revision,
          version: pin.state.version,
          tree: tree,
          mirrorPath: relative
        ))
      swiftSubmodules += try snapshotSwiftSubmodules(
        parentIdentity: pin.identity,
        checkout: checkout,
        output: output,
        logDirectory: logDirectory
      )
    }

    let meshHelper = repository.appendingPathComponent("mesh-helper")
    let goList = try runner.run(
      "/opt/homebrew/bin/go",
      ["list", "-mod=readonly", "-m", "-f", "{{.Path}}\t{{.Version}}\t{{.Dir}}", "all"],
      currentDirectory: meshHelper,
      environment: [
        "GOMODCACHE": goModuleCache.path,
        "GOPROXY": "off",
        "GOSUMDB": "off",
      ],
      logURL: logDirectory.appendingPathComponent("go-list-modules.log")
    ).output
    var modules: [DependencyDepotManifest.GoModule] = []
    var goSourceByModule: [String: URL] = [:]
    for rawLine in goList.split(separator: "\n") {
      let fields = rawLine.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
      guard fields.count == 3 else {
        throw ReleasePackageError.verification("malformed go list module output")
      }
      if fields[1].isEmpty { continue }
      guard
        noticeAuthority.expectedGoModules.first(where: { $0.path == fields[0] })?.revision
          == fields[1]
      else {
        throw ReleasePackageError.invalidConfiguration(
          "Go module is not notice-classified: \(fields[0])")
      }
      let source = URL(fileURLWithPath: fields[2]).standardizedFileURL
      let cache = goModuleCache.standardizedFileURL
      guard source.path.hasPrefix(cache.path + "/") else {
        throw ReleasePackageError.unsafePath("Go module escaped module cache: \(fields[0])")
      }
      let relative = String(source.path.dropFirst(cache.path.count + 1))
      let destination = goRootOutput.appendingPathComponent(relative)
      try createParentDirectories(destination.deletingLastPathComponent(), stoppingAt: goRootOutput)
      try SecureFiles.copyTree(from: source, to: destination, directoryMode: 0o755, fileMode: 0o644)
      let digest = try SourceInspector().canonicalTreeDigest(destination)
      modules.append(
        .init(
          path: fields[0], version: fields[1], moduleDirectory: "go/pkg/mod/\(relative)",
          treeSHA256: digest))
      goSourceByModule[fields[0]] = source
    }
    modules.sort { $0.path < $1.path }
    guard Set(modules.map(\.path)) == Set(noticeAuthority.goModules) else {
      throw ReleasePackageError.invalidConfiguration(
        "notice Go module set does not equal the resolved helper graph")
    }

    try copyGoDownloadAuthority(
      modules: modules, sourceCache: goModuleCache, destinationCache: goRootOutput)
    let goVersion = try runner.run("/opt/homebrew/bin/go", ["version"]).output
      .trimmingCharacters(in: .whitespacesAndNewlines)
    let goLicense = try goToolchainInput(goRoot: goRoot, relativePath: "LICENSE")
    let goPatents = goRoot.appendingPathComponent("PATENTS")
    let noticeInputs = try snapshotNoticeInputs(
      authority: noticeAuthority,
      repository: repository,
      swiftCheckouts: swiftCheckouts,
      goSourceByModule: goSourceByModule,
      goRoot: goRoot,
      output: output
    )
    let manifest = DependencyDepotManifest(
      schemaVersion: 1,
      swiftPins: swiftPins,
      swiftSubmodules: swiftSubmodules.sorted {
        ($0.parentIdentity, $0.path) < ($1.parentIdentity, $1.path)
      },
      goModules: modules,
      noticeInputs: noticeInputs,
      goVersion: goVersion,
      goLicenseSHA256: try Digests.sha256(file: goLicense),
      goPatentsSHA256: try Digests.sha256(file: goPatents)
    )
    try SecureFiles.atomicWrite(
      CanonicalJSON.encode(manifest),
      to: output.appendingPathComponent("dependency-depot.json")
    )
    let inventoryExclusions: Set<String> = [
      "dependency-depot.entries",
      "dependency-depot.sha256",
    ]
    let inventory = try SourceInspector().canonicalTreeEntries(
      output,
      excluding: inventoryExclusions
    )
    try SecureFiles.atomicWrite(
      Data((inventory.joined(separator: "\n") + "\n").utf8),
      to: output.appendingPathComponent("dependency-depot.entries")
    )
    let seal = try SourceInspector().canonicalTreeDigest(
      output,
      excluding: ["dependency-depot.sha256"]
    )
    try SecureFiles.atomicWrite(
      Data((seal + "\n").utf8),
      to: output.appendingPathComponent("dependency-depot.sha256")
    )
    let postSeal = try SourceInspector().canonicalTreeDigest(
      output,
      excluding: ["dependency-depot.sha256"]
    )
    guard postSeal == seal else {
      throw ReleasePackageError.verification("dependency depot changed while it was being sealed")
    }
    return manifest
  }

  private func snapshotSwiftSubmodules(
    parentIdentity: String,
    checkout: URL,
    output: URL,
    logDirectory: URL
  ) throws -> [DependencyDepotManifest.SwiftSubmodule] {
    let modulesFile = checkout.appendingPathComponent(".gitmodules")
    guard FileManager.default.fileExists(atPath: modulesFile.path) else { return [] }
    let pathOutput = try runner.run(
      "/usr/bin/git",
      ["config", "--file", ".gitmodules", "--get-regexp", "^submodule\\..*\\.path$"],
      currentDirectory: checkout
    ).output
    let statusOutput = try runner.run(
      "/usr/bin/git", ["submodule", "status", "--recursive"], currentDirectory: checkout
    ).output
    var statusByPath: [String: String] = [:]
    for raw in statusOutput.split(separator: "\n", omittingEmptySubsequences: true) {
      guard raw.first == " " else {
        throw ReleasePackageError.sourceAuthority(
          "Swift dependency submodule is not at its recorded revision: \(parentIdentity)")
      }
      let fields = raw.dropFirst().split(whereSeparator: { $0 == " " || $0 == "\t" })
      guard fields.count >= 2 else {
        throw ReleasePackageError.sourceAuthority(
          "malformed Swift submodule status for \(parentIdentity)")
      }
      statusByPath[String(fields[1])] = String(fields[0])
    }
    var result: [DependencyDepotManifest.SwiftSubmodule] = []
    for raw in pathOutput.split(separator: "\n", omittingEmptySubsequences: true) {
      let fields = raw.split(maxSplits: 1, whereSeparator: { $0 == " " || $0 == "\t" })
      guard fields.count == 2 else {
        throw ReleasePackageError.sourceAuthority(
          "malformed .gitmodules path authority for \(parentIdentity)")
      }
      let key = String(fields[0])
      let path = String(fields[1])
      guard key.hasPrefix("submodule."), key.hasSuffix(".path") else {
        throw ReleasePackageError.sourceAuthority(
          "unexpected .gitmodules key for \(parentIdentity)")
      }
      let name = String(key.dropFirst("submodule.".count).dropLast(".path".count))
      try SecureFiles.validateRelativePath(path)
      let url = try runner.run(
        "/usr/bin/git", ["config", "--file", ".gitmodules", "--get", "submodule.\(name).url"],
        currentDirectory: checkout
      ).output.trimmingCharacters(in: .whitespacesAndNewlines)
      guard url.hasPrefix("https://"), !url.contains("\n"),
        let revision = statusByPath.removeValue(forKey: path)
      else {
        throw ReleasePackageError.sourceAuthority(
          "unavailable Swift submodule authority for \(parentIdentity)/\(path)")
      }
      let source = checkout.appendingPathComponent(path)
      let observed = try runner.run(
        "/usr/bin/git", ["rev-parse", "HEAD"], currentDirectory: source
      )
      .output.trimmingCharacters(in: .whitespacesAndNewlines)
      let status = try runner.run(
        "/usr/bin/git", ["status", "--porcelain"], currentDirectory: source
      )
      .output.trimmingCharacters(in: .whitespacesAndNewlines)
      guard observed == revision, status.isEmpty else {
        throw ReleasePackageError.sourceAuthority(
          "Swift submodule checkout drifted: \(parentIdentity)/\(path)")
      }
      let tree = try runner.run(
        "/usr/bin/git", ["rev-parse", "HEAD^{tree}"], currentDirectory: source
      )
      .output.trimmingCharacters(in: .whitespacesAndNewlines)
      let safePath = path.replacingOccurrences(of: "/", with: "--")
      let relative = "swift-submodules/\(parentIdentity)--\(safePath).git"
      let destination = output.appendingPathComponent(relative)
      try createParentDirectories(destination.deletingLastPathComponent(), stoppingAt: output)
      _ = try runner.run(
        "/usr/bin/git", ["clone", "--mirror", "--no-local", source.path, destination.path],
        logURL: logDirectory.appendingPathComponent(
          "swift-submodule-\(parentIdentity)-\(safePath).log")
      )
      result.append(
        .init(
          parentIdentity: parentIdentity,
          path: path,
          url: url,
          revision: revision,
          tree: tree,
          mirrorPath: relative
        ))
    }
    guard statusByPath.isEmpty else {
      throw ReleasePackageError.sourceAuthority(
        "recursive Swift submodule graph is not fully declared for \(parentIdentity)")
    }
    return result
  }

  public func load(_ root: URL, noticeAuthority: NoticeAuthority? = nil) throws
    -> DependencyDepotManifest
  {
    let data = try Data(contentsOf: root.appendingPathComponent("dependency-depot.json"))
    let manifest = try JSONDecoder().decode(DependencyDepotManifest.self, from: data)
    guard manifest.schemaVersion == 1 else {
      throw ReleasePackageError.invalidConfiguration("unsupported dependency-depot schema")
    }
    let expectedInventory = try String(
      contentsOf: root.appendingPathComponent("dependency-depot.entries"),
      encoding: .utf8
    ).split(separator: "\n").map(String.init)
    let actualInventory = try SourceInspector().canonicalTreeEntries(
      root,
      excluding: ["dependency-depot.entries", "dependency-depot.sha256"]
    )
    guard expectedInventory == actualInventory else {
      let expected = Set(expectedInventory)
      let actual = Set(actualInventory)
      let removed = expected.subtracting(actual).sorted().prefix(3).joined(separator: " | ")
      let added = actual.subtracting(expected).sorted().prefix(3).joined(separator: " | ")
      throw ReleasePackageError.verification(
        "dependency depot inventory changed; removed [\(removed)] added [\(added)]")
    }
    let expectedSeal = try String(
      contentsOf: root.appendingPathComponent("dependency-depot.sha256"),
      encoding: .utf8
    ).trimmingCharacters(in: .whitespacesAndNewlines)
    let actualSeal = try SourceInspector().canonicalTreeDigest(
      root,
      excluding: ["dependency-depot.sha256"]
    )
    guard expectedSeal == actualSeal else {
      throw ReleasePackageError.verification(
        "dependency depot seal does not match: expected \(expectedSeal), observed \(actualSeal)")
    }
    if let noticeAuthority {
      guard
        manifest.swiftPins.map({ NoticeAuthority.Pin(identity: $0.identity, revision: $0.revision) }
        ) == noticeAuthority.expectedSwiftPins,
        manifest.goModules.map({ NoticeAuthority.Module(path: $0.path, revision: $0.version) })
          == noticeAuthority.expectedGoModules
      else {
        throw ReleasePackageError.verification(
          "dependency depot graph does not match checked-in notice authority")
      }
    }
    for input in manifest.noticeInputs {
      guard try Digests.sha256(file: root.appendingPathComponent(input.depotPath)) == input.sha256
      else {
        throw ReleasePackageError.verification(
          "notice input changed in dependency depot: \(input.familyID)")
      }
    }
    return manifest
  }

  private func copyGoDownloadAuthority(
    modules: [DependencyDepotManifest.GoModule],
    sourceCache: URL,
    destinationCache: URL
  ) throws {
    for module in modules {
      let moduleRelative = module.moduleDirectory.dropFirst("go/pkg/mod/".count)
      guard let at = moduleRelative.lastIndex(of: "@") else { continue }
      let escapedPath = moduleRelative[..<at]
      let sourceVersionRoot = sourceCache.appendingPathComponent("cache/download/\(escapedPath)/@v")
      let destinationVersionRoot = destinationCache.appendingPathComponent(
        "cache/download/\(escapedPath)/@v")
      try createParentDirectories(destinationVersionRoot, stoppingAt: destinationCache)
      for suffix in [".info", ".mod", ".zip", ".ziphash"] {
        let source = sourceVersionRoot.appendingPathComponent(module.version + suffix)
        if FileManager.default.fileExists(atPath: source.path) {
          try SecureFiles.copyInputFile(
            from: source,
            to: destinationVersionRoot.appendingPathComponent(module.version + suffix),
            mode: 0o644
          )
        }
      }
      let list = sourceVersionRoot.appendingPathComponent("list")
      if FileManager.default.fileExists(atPath: list.path),
        !FileManager.default.fileExists(
          atPath: destinationVersionRoot.appendingPathComponent("list").path)
      {
        try SecureFiles.copyInputFile(
          from: list, to: destinationVersionRoot.appendingPathComponent("list"), mode: 0o644)
      }
    }
  }

  private func snapshotNoticeInputs(
    authority: NoticeAuthority,
    repository: URL,
    swiftCheckouts: URL,
    goSourceByModule: [String: URL],
    goRoot: URL,
    output: URL
  ) throws -> [DependencyDepotManifest.NoticeInput] {
    let root = output.appendingPathComponent("notice-inputs")
    try SecureFiles.createDirectory(root, mode: 0o700)
    let checkouts = try FileManager.default.contentsOfDirectory(
      at: swiftCheckouts,
      includingPropertiesForKeys: nil,
      options: []
    ).filter { url in
      guard !url.lastPathComponent.hasPrefix(".") else { return false }
      var info = stat()
      return lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFDIR
    }
    var checkoutByName: [String: URL] = [:]
    for checkout in checkouts {
      checkoutByName[checkout.lastPathComponent] = checkout
    }

    var results: [DependencyDepotManifest.NoticeInput] = []
    for family in authority.families.sorted(by: { $0.id < $1.id }) {
      let sourceRoot: URL
      if family.sourceRoot == "." {
        sourceRoot = repository
      } else if family.sourceRoot == "mesh-helper" {
        sourceRoot = repository.appendingPathComponent("mesh-helper")
      } else if family.sourceRoot == "go-toolchain" {
        sourceRoot = goRoot
      } else if family.sourceRoot.hasPrefix("swift-checkouts/") {
        let name = String(family.sourceRoot.dropFirst("swift-checkouts/".count))
        guard let checkout = checkoutByName[name] else {
          throw ReleasePackageError.sourceAuthority(
            "notice source checkout is unavailable: \(name)")
        }
        sourceRoot = checkout
      } else if family.sourceRoot.hasPrefix("go-modules/") {
        let value = String(family.sourceRoot.dropFirst("go-modules/".count))
        guard let at = value.lastIndex(of: "@") else {
          throw ReleasePackageError.invalidConfiguration(
            "malformed Go notice source root: \(family.sourceRoot)")
        }
        let module = String(value[..<at])
        let version = String(value[value.index(after: at)...])
        guard let expected = authority.expectedGoModules.first(where: { $0.path == module }),
          expected.revision == version,
          let source = goSourceByModule[module]
        else {
          throw ReleasePackageError.sourceAuthority(
            "Go notice source is unavailable: \(family.sourceRoot)")
        }
        sourceRoot = source
      } else {
        throw ReleasePackageError.invalidConfiguration(
          "unknown notice source root: \(family.sourceRoot)")
      }

      let inputs =
        family.licensePaths.map { ("license", $0) } + family.noticePaths.map { ("notice", $0) }
      guard !inputs.isEmpty else {
        throw ReleasePackageError.invalidConfiguration(
          "notice family has no text inputs: \(family.id)")
      }
      for (index, input) in inputs.enumerated() {
        try SecureFiles.validateRelativePath(input.1)
        let source: URL
        if family.sourceRoot == "go-toolchain" {
          source = try goToolchainInput(goRoot: goRoot, relativePath: input.1)
        } else {
          source = sourceRoot.appendingPathComponent(input.1).standardizedFileURL
          guard source.path.hasPrefix(sourceRoot.standardizedFileURL.path + "/") else {
            throw ReleasePackageError.unsafePath(input.1)
          }
        }
        let relative = "notice-inputs/\(family.id)/\(String(format: "%03d", index))-\(input.0).txt"
        let destination = output.appendingPathComponent(relative)
        try createParentDirectories(destination.deletingLastPathComponent(), stoppingAt: root)
        try SecureFiles.copyInputFile(from: source, to: destination, mode: 0o600)
        results.append(
          .init(
            familyID: family.id,
            kind: input.0,
            declaredPath: input.1,
            depotPath: relative,
            sha256: try Digests.sha256(file: destination)
          ))
      }
    }
    return results.sorted {
      ($0.familyID, $0.kind, $0.declaredPath) < ($1.familyID, $1.kind, $1.declaredPath)
    }
  }

  private func goToolchainInput(goRoot: URL, relativePath: String) throws -> URL {
    try SecureFiles.validateRelativePath(relativePath)
    let direct = goRoot.appendingPathComponent(relativePath)
    if FileManager.default.fileExists(atPath: direct.path) { return direct }
    // Homebrew exposes the Go distribution LICENSE as formula metadata at
    // the Cellar version root while leaving PATENTS inside GOROOT.
    if relativePath == "LICENSE" {
      let formulaLicense = goRoot.deletingLastPathComponent().appendingPathComponent("LICENSE")
      if FileManager.default.fileExists(atPath: formulaLicense.path) { return formulaLicense }
    }
    throw ReleasePackageError.sourceAuthority(
      "Go toolchain notice input is unavailable: \(relativePath)")
  }

  private func createParentDirectories(_ target: URL, stoppingAt root: URL) throws {
    let normalized = URL(fileURLWithPath: target.path)
    let normalizedRoot = URL(fileURLWithPath: root.path)
    let components = normalized.pathComponents
    let rootComponents = normalizedRoot.pathComponents
    guard components.count >= rootComponents.count,
      Array(components.prefix(rootComponents.count)) == rootComponents
    else {
      throw ReleasePackageError.unsafePath(target.path)
    }
    var missing: [URL] = []
    var cursor = normalized
    while cursor.path != normalizedRoot.path,
      !FileManager.default.fileExists(atPath: cursor.path)
    {
      missing.append(cursor)
      cursor.deleteLastPathComponent()
    }
    for directory in missing.reversed() { try SecureFiles.createDirectory(directory, mode: 0o755) }
  }
}
