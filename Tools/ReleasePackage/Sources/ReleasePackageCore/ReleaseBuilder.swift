import Darwin
import Foundation

public struct ReleaseBuildResult: Codable, Equatable, Sendable {
  public let candidatePackage: String
  public let candidateSHA256: String
  public let normalizedSemanticSHA256: String
  public let dependencyDepotSHA256: String
  public let releaseProvenance: String
  public let noticeManifest: String
  public let payloadManifest: String
  public let staticTransactionReport: String
}

public struct ReleaseBuildComparison: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let compilePathAuthority: String
  public let compilerVisibleRootUTF8Length: Int
  public let metalToolchain: MetalToolchainAuthority?
  public let sourceAuthorityEqual: Bool
  public let reachdSHA256: [String]
  public let helperSHA256: [String]
  public let hostTreeSHA256: [String]
  public let helperTreeSHA256: [String]
  public let noticesSHA256: [String]
  public let payloadManifestSHA256: [String]
  public let hostComponentSHA256: [String]
  public let helperComponentSHA256: [String]
  public let outerContainerSHA256: [String]
  public let normalizedSemanticSHA256: String
  public let xarDifference: String
}

/// Swift's escaping-closure diagnostics retain the byte length of their
/// compiler-visible source filename even when `-file-prefix-map` rewrites the
/// filename itself. Every release pass therefore builds below a private root
/// with one fixed UTF-8 length. The caller's scratch-root spelling cannot
/// become executable code, while each invocation still owns disjoint storage.
struct CompilePathAuthority {
  static let rootUTF8Length = 240
  private static let componentPrefix = "compile-root-"

  static func passRoot(workRoot: URL, passName: String) throws -> URL {
    guard passName == "build-a" || passName == "build-b" else {
      throw ReleasePackageError.invalidArgument("unknown deterministic build pass")
    }
    let container = workRoot.appendingPathComponent(passName, isDirectory: true)
    let fixedBytes = container.path.utf8.count + 1 + componentPrefix.utf8.count
    let paddingBytes = rootUTF8Length - fixedBytes
    guard paddingBytes >= 16 else {
      throw ReleasePackageError.invalidArgument(
        "release work path is too long for the fixed compile-path authority")
    }
    let component = componentPrefix + String(repeating: "p", count: paddingBytes)
    let result = container.appendingPathComponent(component, isDirectory: true)
    guard result.path.utf8.count == rootUTF8Length else {
      throw ReleasePackageError.verification(
        "fixed compile-path authority did not reach its exact UTF-8 length")
    }
    return result
  }
}

public struct ReleaseBuilder {
  private struct BuildPass {
    let name: String
    let source: SourceAuthority
    let export: URL
    let reachd: URL
    let helper: URL
    let hostStage: URL
    let helperStage: URL
    let notices: GeneratedNotices
    let manifest: PayloadManifest
    let manifestURL: URL
    let hostComponent: ComponentArtifact
    let helperComponent: ComponentArtifact
    let outer: OuterPackageArtifact
    let verification: VerificationReport
  }

  private let runner: ProcessRunner
  private let metalResolver: InstalledMetalToolchainResolver

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
    metalResolver = InstalledMetalToolchainResolver(runner: runner)
  }

  init(runner: ProcessRunner, metalResolver: InstalledMetalToolchainResolver) {
    self.runner = runner
    self.metalResolver = metalResolver
  }

  public func build(
    repository: URL,
    releaseToolSource: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    workRoot: URL,
    outputRoot: URL
  ) throws -> ReleaseBuildResult {
    let workRoot = try ReleasePathAuthority.mutableRoot(workRoot, label: "release work root")
    let outputRoot = try ReleasePathAuthority.mutableRoot(outputRoot, label: "release output root")
    try requireEmptyPrivateRoot(workRoot)
    try requireEmptyPrivateRoot(outputRoot)
    let configuration = try ReleaseConfiguration.load(from: configurationURL)
    let noticeAuthority = try NoticeAuthority.load(from: noticeAuthorityURL)
    let depot = try DependencyDepotBuilder(runner: runner).load(
      dependencyDepot,
      noticeAuthority: noticeAuthority
    )
    let depotSeal = try String(
      contentsOf: dependencyDepot.appendingPathComponent("dependency-depot.sha256"),
      encoding: .utf8
    ).trimmingCharacters(in: .whitespacesAndNewlines)
    let releaseConfigurationHash = try Digests.sha256(file: configurationURL)
    let noticeAuthorityHash = try Digests.sha256(file: noticeAuthorityURL)
    let releaseToolSourceHash = try SourceInspector().canonicalTreeDigest(releaseToolSource)
    let toolchainLogs = workRoot.appendingPathComponent("toolchain-logs")
    try SecureFiles.createDirectory(toolchainLogs, mode: 0o700)
    let metal = try metalResolver.resolve(
      logURL: toolchainLogs.appendingPathComponent("metal-component-initial.log"))
    let toolchain = try inspectToolchain(depot: depot, metal: metal, logs: toolchainLogs)

    let passAContainer = workRoot.appendingPathComponent("build-a", isDirectory: true)
    let passBContainer = workRoot.appendingPathComponent("build-b", isDirectory: true)
    try SecureFiles.createDirectory(passAContainer, mode: 0o700)
    try SecureFiles.createDirectory(passBContainer, mode: 0o700)
    let passA = try buildPass(
      name: "build-a",
      repository: repository,
      configuration: configuration,
      configurationURL: configurationURL,
      noticeAuthority: noticeAuthority,
      noticeAuthorityURL: noticeAuthorityURL,
      depot: depot,
      depotRoot: dependencyDepot,
      depotSeal: depotSeal,
      releaseConfigurationHash: releaseConfigurationHash,
      releaseToolSourceHash: releaseToolSourceHash,
      noticeAuthorityHash: noticeAuthorityHash,
      toolchain: toolchain,
      metal: metal,
      root: CompilePathAuthority.passRoot(workRoot: workRoot, passName: "build-a")
    )
    let passB = try buildPass(
      name: "build-b",
      repository: repository,
      configuration: configuration,
      configurationURL: configurationURL,
      noticeAuthority: noticeAuthority,
      noticeAuthorityURL: noticeAuthorityURL,
      depot: depot,
      depotRoot: dependencyDepot,
      depotSeal: depotSeal,
      releaseConfigurationHash: releaseConfigurationHash,
      releaseToolSourceHash: releaseToolSourceHash,
      noticeAuthorityHash: noticeAuthorityHash,
      toolchain: toolchain,
      metal: metal,
      root: CompilePathAuthority.passRoot(workRoot: workRoot, passName: "build-b")
    )
    try compare(passA, passB)

    let normalizedTOCA = try normalizedXARTOC(passA.outer.toc)
    let normalizedTOCB = try normalizedXARTOC(passB.outer.toc)
    guard normalizedTOCA == normalizedTOCB else {
      throw ReleasePackageError.verification("outer XARs differ beyond creation-time metadata")
    }
    let candidateName = "Reach-\(configuration.product.version)-unsigned.pkg"
    let candidate = outputRoot.appendingPathComponent(candidateName)
    try SecureFiles.copyRegularFile(from: passA.outer.package, to: candidate, mode: 0o600)
    let noticeManifestURL = outputRoot.appendingPathComponent("notice-manifest.json")
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(passA.notices.manifest), to: noticeManifestURL)
    let noticesURL = outputRoot.appendingPathComponent("THIRD-PARTY-NOTICES.md")
    try SecureFiles.atomicWrite(passA.notices.markdown, to: noticesURL)
    let externalManifest = outputRoot.appendingPathComponent("payload-manifest.json")
    try SecureFiles.copyRegularFile(from: passA.manifestURL, to: externalManifest, mode: 0o600)
    let configCopy = outputRoot.appendingPathComponent("release.json")
    let noticeAuthorityCopy = outputRoot.appendingPathComponent("notices.json")
    try SecureFiles.copyRegularFile(from: configurationURL, to: configCopy, mode: 0o600)
    try SecureFiles.copyRegularFile(from: noticeAuthorityURL, to: noticeAuthorityCopy, mode: 0o600)

    let artifacts = outputRoot.appendingPathComponent("artifacts")
    try SecureFiles.createDirectory(artifacts, mode: 0o700)
    let retained = try retainArtifacts(passA: passA, passB: passB, at: artifacts)
    let semanticDigest = passA.verification.normalizedSemanticSHA256
    let provenance = ReleaseProvenance(
      schemaVersion: configuration.schemaVersion == 1 ? 1 : 2,
      p0: .init(
        name: "P0-source",
        authority: passA.source,
        releaseConfigurationSHA256: releaseConfigurationHash,
        releaseToolSourceSHA256: releaseToolSourceHash,
        noticeAuthoritySHA256: noticeAuthorityHash,
        dependencyDepotSHA256: depotSeal,
        metalToolchain: metal.authority
      ),
      p1: .init(
        name: "P1-payload",
        embeddedManifest: try artifact(path: "payload-manifest.json", url: externalManifest),
        notices: try artifact(path: "THIRD-PARTY-NOTICES.md", url: noticesURL),
        hostComponents: retained.hostComponents,
        helperComponents: retained.helperComponents,
        hostBOMs: retained.hostBOMs,
        helperBOMs: retained.helperBOMs
      ),
      u1: .init(
        name: "U1-unsigned-container-semantics",
        containers: [
          try artifact(path: "artifacts/build-a/Reach.pkg", url: retained.outerA),
          try artifact(path: "artifacts/build-b/Reach.pkg", url: retained.outerB),
        ],
        selectedContainer: try artifact(path: candidateName, url: candidate),
        normalizedSemanticSHA256: semanticDigest,
        distributionSHA256: try Digests.sha256(file: passA.outer.distribution)
      )
    )
    let provenanceURL = outputRoot.appendingPathComponent("release-provenance.json")
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(provenance), to: provenanceURL)
    let comparison = ReleaseBuildComparison(
      schemaVersion: 3,
      compilePathAuthority:
        "unaliased canonical root with fixed UTF-8 byte length before compiler invocation",
      compilerVisibleRootUTF8Length: CompilePathAuthority.rootUTF8Length,
      metalToolchain: metal.authority,
      sourceAuthorityEqual: passA.source == passB.source,
      reachdSHA256: try [passA.reachd, passB.reachd].map(Digests.sha256(file:)),
      helperSHA256: try [passA.helper, passB.helper].map(Digests.sha256(file:)),
      hostTreeSHA256: try [passA.hostStage, passB.hostStage].map {
        try SourceInspector().canonicalTreeDigest($0)
      },
      helperTreeSHA256: try [passA.helperStage, passB.helperStage].map {
        try SourceInspector().canonicalTreeDigest($0)
      },
      noticesSHA256: [
        Digests.sha256(passA.notices.markdown), Digests.sha256(passB.notices.markdown),
      ],
      payloadManifestSHA256: try [passA.manifestURL, passB.manifestURL].map(Digests.sha256(file:)),
      hostComponentSHA256: [passA.hostComponent.packageSHA256, passB.hostComponent.packageSHA256],
      helperComponentSHA256: [
        passA.helperComponent.packageSHA256, passB.helperComponent.packageSHA256,
      ],
      outerContainerSHA256: [passA.outer.packageSHA256, passB.outer.packageSHA256],
      normalizedSemanticSHA256: semanticDigest,
      xarDifference: "creation-time only after recursive semantic normalization"
    )
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(comparison),
      to: outputRoot.appendingPathComponent("release-build-comparison.json")
    )
    let staticTransactions = try StaticTransactionVerifier.run(
      configuration: configuration,
      root: workRoot.appendingPathComponent("static-transactions")
    )
    let staticTransactionURL = outputRoot.appendingPathComponent("static-transaction-report.json")
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(staticTransactions), to: staticTransactionURL)
    let finalVerification = try PackageVerifier(runner: runner).verify(
      package: candidate,
      configurationURL: configCopy,
      noticeAuthorityURL: noticeAuthorityCopy,
      dependencyDepot: dependencyDepot,
      expectedReleaseToolSourceSHA256: releaseToolSourceHash,
      provenanceURL: provenanceURL,
      noticeManifestURL: noticeManifestURL,
      scratch: workRoot.appendingPathComponent("final-verification"),
      logDirectory: workRoot.appendingPathComponent("final-verification-logs")
    )
    guard finalVerification.normalizedSemanticSHA256 == semanticDigest else {
      throw ReleasePackageError.verification("selected package changed during retention")
    }
    try writeSHA256SUMS(outputRoot)
    return ReleaseBuildResult(
      candidatePackage: candidate.path,
      candidateSHA256: try Digests.sha256(file: candidate),
      normalizedSemanticSHA256: semanticDigest,
      dependencyDepotSHA256: depotSeal,
      releaseProvenance: provenanceURL.path,
      noticeManifest: noticeManifestURL.path,
      payloadManifest: externalManifest.path,
      staticTransactionReport: staticTransactionURL.path
    )
  }

  private func buildPass(
    name: String,
    repository: URL,
    configuration: ReleaseConfiguration,
    configurationURL: URL,
    noticeAuthority: NoticeAuthority,
    noticeAuthorityURL: URL,
    depot: DependencyDepotManifest,
    depotRoot: URL,
    depotSeal: String,
    releaseConfigurationHash: String,
    releaseToolSourceHash: String,
    noticeAuthorityHash: String,
    toolchain: ToolchainAuthority,
    metal: MountedMetalToolchain,
    root: URL
  ) throws -> BuildPass {
    try SecureFiles.createPrivateDirectory(root)
    let logs = root.appendingPathComponent("logs")
    try SecureFiles.createDirectory(logs, mode: 0o700)
    let export = root.appendingPathComponent("source")
    let source = try SourceInspector(runner: runner).validateAndExport(
      repository: repository,
      exportRoot: export,
      configuration: configuration,
      logDirectory: logs
    )
    let notices = try NoticeGenerator.generate(
      authority: noticeAuthority, depot: depot, depotRoot: depotRoot)
    let compiled = root.appendingPathComponent("compiled")
    try SecureFiles.createDirectory(compiled, mode: 0o700)
    let reachd = try buildReachd(
      export: export,
      depot: depot,
      depotRoot: depotRoot,
      sourceTimestamp: source.commitTimestamp,
      root: root.appendingPathComponent("swift-build"),
      output: compiled.appendingPathComponent("reachd"),
      logs: logs,
      metal: metal
    )
    let helper = try buildHelper(
      export: export,
      depotRoot: depotRoot,
      sourceTimestamp: source.commitTimestamp,
      root: root.appendingPathComponent("go-build"),
      output: compiled.appendingPathComponent("systems.reach.meshd"),
      logs: logs
    )
    let stages = root.appendingPathComponent("payloads")
    try SecureFiles.createDirectory(stages, mode: 0o700)
    let hostStage = stages.appendingPathComponent("host")
    let helperStage = stages.appendingPathComponent("helper")
    try stageHost(
      export: export,
      reachd: reachd,
      notices: notices.markdown,
      configuration: configuration,
      root: hostStage
    )
    try stageHelper(export: export, helper: helper, root: helperStage)
    try SwiftBuildMetalGraphVerifier.rejectPathLeak(
      below: hostStage, transientPath: metal.root.path)
    try SwiftBuildMetalGraphVerifier.rejectPathLeak(
      below: hostStage,
      transientPath: "/private/var/run/com.apple.security.cryptexd/mnt/")
    try SwiftBuildMetalGraphVerifier.rejectPathLeak(
      below: hostStage,
      transientPath: "/var/run/com.apple.security.cryptexd/mnt/")
    try SecureFiles.scrubExtendedAttributesRecursively(hostStage)
    try SecureFiles.scrubExtendedAttributesRecursively(helperStage)
    let preManifestHost = try PayloadTree.inspect(root: hostStage)
    let helperTree = try PayloadTree.inspect(root: helperStage)
    let linked = try linkedSystemLibraries(reachd, logs: logs)
    let manifest = try PayloadManifest.make(
      configuration: configuration,
      source: source,
      releaseConfigurationSHA256: releaseConfigurationHash,
      releaseToolSourceSHA256: releaseToolSourceHash,
      noticeAuthoritySHA256: noticeAuthorityHash,
      dependencyDepotSHA256: depotSeal,
      depot: depot,
      toolchain: toolchain,
      linkedSystemLibraries: linked,
      noticeSetSHA256: notices.manifest.noticeSetSHA256,
      hostRecords: preManifestHost.records,
      helperRecords: helperTree.records
    )
    let manifestURL = hostStage.appendingPathComponent(
      "Library/Application Support/Reach/Release/payload-manifest.json")
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(manifest), to: manifestURL, mode: 0o644)
    try SecureFiles.setModificationTime(manifestURL, seconds: source.commitTimestamp)
    try SecureFiles.scrubExtendedAttributesRecursively(hostStage)
    let hostTree = try PayloadTree.inspect(root: hostStage)
    guard hostTree.records.count == 50, helperTree.records.count == 6 else {
      throw ReleasePackageError.verification("payload cardinality changed")
    }
    let components = root.appendingPathComponent("components")
    try SecureFiles.createDirectory(components, mode: 0o700)
    let assembler = PackageAssembler(runner: runner)
    let hostComponent = try assembler.assembleComponent(
      payloadRoot: hostStage,
      identifier: configuration.components.host.identifier,
      version: configuration.components.host.version,
      modificationTime: source.commitTimestamp,
      workspace: root.appendingPathComponent("host-component-work"),
      outputPackage: components.appendingPathComponent("systems.reach.host.pkg"),
      logDirectory: logs
    )
    let helperComponent = try assembler.assembleComponent(
      payloadRoot: helperStage,
      identifier: configuration.components.helper.identifier,
      version: configuration.components.helper.version,
      modificationTime: source.commitTimestamp,
      workspace: root.appendingPathComponent("helper-component-work"),
      outputPackage: components.appendingPathComponent("systems.reach.meshd.pkg"),
      logDirectory: logs
    )
    let outer = try assembler.assembleOuterPackage(
      configuration: configuration,
      hostComponent: hostComponent.package,
      helperComponent: helperComponent.package,
      workspace: root.appendingPathComponent("outer-work"),
      outputPackage: root.appendingPathComponent("Reach.pkg"),
      logDirectory: logs
    )
    let noticeManifestURL = root.appendingPathComponent("notice-manifest.json")
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(notices.manifest), to: noticeManifestURL)
    let verification = try PackageVerifier(runner: runner).verify(
      package: outer.package,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: depotRoot,
      expectedReleaseToolSourceSHA256: releaseToolSourceHash,
      noticeManifestURL: noticeManifestURL,
      scratch: root.appendingPathComponent("verification"),
      logDirectory: logs
    )
    try metalResolver.revalidate(
      metal, logURL: logs.appendingPathComponent("metal-component-pass-final.log"))
    return BuildPass(
      name: name,
      source: source,
      export: export,
      reachd: reachd,
      helper: helper,
      hostStage: hostStage,
      helperStage: helperStage,
      notices: notices,
      manifest: manifest,
      manifestURL: manifestURL,
      hostComponent: hostComponent,
      helperComponent: helperComponent,
      outer: outer,
      verification: verification
    )
  }

  private func buildReachd(
    export: URL,
    depot: DependencyDepotManifest,
    depotRoot: URL,
    sourceTimestamp: Int64,
    root: URL,
    output: URL,
    logs: URL,
    metal: MountedMetalToolchain
  ) throws -> URL {
    try SecureFiles.createPrivateDirectory(root)
    let mirrorsDirectory = export.appendingPathComponent("reachd/.swiftpm/configuration")
    try makeDirectories(mirrorsDirectory, stoppingAt: export)
    struct Mirror: Encodable {
      let mirror: String
      let original: String
    }
    struct Mirrors: Encodable {
      let object: [Mirror]
      let version: Int
    }
    let mirrors = Mirrors(
      object: depot.swiftPins.map {
        Mirror(
          mirror: depotRoot.appendingPathComponent($0.mirrorPath).absoluteString,
          original: $0.location
        )
      }.sorted { $0.original < $1.original },
      version: 1
    )
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(mirrors),
      to: mirrorsDirectory.appendingPathComponent("mirrors.json")
    )
    let cache = root.appendingPathComponent("cache")
    let config = root.appendingPathComponent("config")
    let security = root.appendingPathComponent("security")
    let scratch = root.appendingPathComponent("scratch")
    let moduleCache = root.appendingPathComponent("module-cache")
    let home = root.appendingPathComponent("home")
    let tmp = root.appendingPathComponent("tmp")
    for directory in [cache, config, security, scratch, moduleCache, home, tmp] {
      try SecureFiles.createDirectory(directory, mode: 0o700)
    }
    let gitConfig = root.appendingPathComponent("gitconfig")
    var gitConfigText = "[protocol \"file\"]\n\tallow = always\n"
    for submodule in depot.swiftSubmodules.sorted(by: { $0.url < $1.url }) {
      let mirror = depotRoot.appendingPathComponent(submodule.mirrorPath).absoluteString
      gitConfigText += "[url \"\(mirror)\"]\n\tinsteadOf = \(submodule.url)\n"
    }
    try SecureFiles.atomicWrite(Data(gitConfigText.utf8), to: gitConfig)
    var arguments = [
      "build", "--toolchain", metal.root.path,
      "--disable-sandbox", "--skip-update", "--force-resolved-versions",
      "--disable-prefetching", "--disable-netrc", "--disable-keychain",
      "--disable-dependency-cache",
      "--disable-code-coverage", "--manifest-cache", "local",
      "--jobs", "1",
      "--cache-path", cache.path, "--config-path", config.path, "--security-path", security.path,
      "--package-path", export.appendingPathComponent("reachd").path,
      "--scratch-path", scratch.path, "--configuration", "release", "-v",
      "-Xswiftc", "-warnings-as-errors",
    ]
    for mapping in [
      (export.path, "/Reach/Source"), (root.path, "/Reach/Build"), (depotRoot.path, "/Reach/Depot"),
    ] {
      arguments += ["-Xswiftc", "-file-prefix-map", "-Xswiftc", "\(mapping.0)=\(mapping.1)"]
      arguments += ["-Xswiftc", "-debug-prefix-map", "-Xswiftc", "\(mapping.0)=\(mapping.1)"]
      arguments += ["-Xcc", "-ffile-prefix-map=\(mapping.0)=\(mapping.1)"]
      arguments += ["-Xcc", "-fdebug-prefix-map=\(mapping.0)=\(mapping.1)"]
    }
    arguments += [
      "-Xcc", "-Werror",
      "-Xlinker", "-reproducible",
      "-Xlinker", "-objc_stubs_fast",
    ]
    let environment = [
      "CLANG_MODULE_CACHE_PATH": moduleCache.path,
      "SWIFTPM_MODULECACHE_OVERRIDE": moduleCache.path,
      "XDG_CACHE_HOME": cache.path,
      "HOME": home.path,
      "TMPDIR": tmp.path,
      "MACOSX_DEPLOYMENT_TARGET": "27.0",
      "SOURCE_DATE_EPOCH": String(sourceTimestamp),
      "SWIFT_DETERMINISTIC_HASHING": "1",
      "ZERO_AR_DATE": "1",
      "LLVM_PROFILE_FILE": root.appendingPathComponent("unexpected.profraw").path,
      "CLANG_COVERAGE_MAPPING": "NO",
      "GCC_GENERATE_TEST_COVERAGE_FILES": "NO",
      "GCC_INSTRUMENT_PROGRAM_FLOW_ARCS": "NO",
      "GIT_CONFIG_GLOBAL": gitConfig.path,
      "GIT_CONFIG_NOSYSTEM": "1",
      // SwiftPM records the physical selection in --toolchain. Its Xcode build
      // layer independently consults TOOLCHAINS when resolving Metal build
      // tools, so provide the same authenticated path explicitly rather than
      // inheriting ambient selection state.
      "TOOLCHAINS": metal.root.path,
    ]
    try metalResolver.revalidate(
      metal, logURL: logs.appendingPathComponent("metal-component-pre-resolve.log"))
    _ = try runner.run(
      "/usr/bin/swift",
      [
        "package", "--toolchain", metal.root.path,
        "--disable-sandbox", "--skip-update", "--force-resolved-versions",
        "--disable-prefetching", "--disable-netrc", "--disable-keychain",
        "--disable-dependency-cache", "--manifest-cache", "local",
        "--cache-path", cache.path, "--config-path", config.path, "--security-path", security.path,
        "--package-path", export.appendingPathComponent("reachd").path,
        "--scratch-path", scratch.path, "resolve",
      ],
      environment: environment,
      logURL: logs.appendingPathComponent("swift-resolve.log")
    )
    try metalResolver.revalidate(
      metal, logURL: logs.appendingPathComponent("metal-component-post-resolve.log"))
    try metalResolver.revalidate(
      metal, logURL: logs.appendingPathComponent("metal-component-pre-bin-path.log"))
    let binArguments = [
      "build", "--toolchain", metal.root.path,
      "--disable-sandbox", "--skip-update", "--force-resolved-versions",
      "--jobs", "1",
      "--cache-path", cache.path, "--config-path", config.path, "--security-path", security.path,
      "--package-path", export.appendingPathComponent("reachd").path,
      "--scratch-path", scratch.path, "--configuration", "release", "--show-bin-path",
    ]
    let preflightBin = try runner.run(
      "/usr/bin/swift", binArguments,
      environment: environment,
      logURL: logs.appendingPathComponent("swift-bin-path-preflight.log")
    ).output.trimmingCharacters(in: .whitespacesAndNewlines)
    try metalResolver.revalidate(
      metal, logURL: logs.appendingPathComponent("metal-component-post-bin-path.log"))
    try GeneratedMetalSourceNormalizer.normalize(
      scratch: scratch,
      reportURL: logs.appendingPathComponent("generated-metal-source-normalization.json"))
    try metalResolver.revalidate(
      metal, logURL: logs.appendingPathComponent("metal-component-pre-build.log"))
    _ = try runner.run(
      "/usr/bin/swift", arguments,
      environment: environment,
      timeout: 7_200,
      logURL: logs.appendingPathComponent("swift-build.log")
    )
    try metalResolver.revalidate(
      metal, logURL: logs.appendingPathComponent("metal-component-post-build.log"))
    let bin = try runner.run(
      "/usr/bin/swift", binArguments,
      environment: environment,
      logURL: logs.appendingPathComponent("swift-bin-path-post-build.log")
    ).output.trimmingCharacters(in: .whitespacesAndNewlines)
    try metalResolver.revalidate(
      metal, logURL: logs.appendingPathComponent("metal-component-final-bin-path.log"))
    guard bin.utf8.elementsEqual(preflightBin.utf8) else {
      throw ReleasePackageError.verification(
        "Swift build and bin-path resolution selected different output authority")
    }
    try SwiftBuildMetalGraphVerifier.verify(
      scratch: scratch,
      buildLog: logs.appendingPathComponent("swift-build.log"),
      mounted: metal)
    let binURL = URL(fileURLWithPath: bin)
    let built = binURL.appendingPathComponent("reachd")
    try SecureFiles.copyRegularFile(from: built, to: output, mode: 0o755)
    _ = try runner.run(
      "/usr/bin/strip",
      ["-x", output.path],
      logURL: logs.appendingPathComponent("strip-reachd.log")
    )
    _ = try runner.run(
      "/usr/bin/codesign",
      ["--remove-signature", output.path],
      logURL: logs.appendingPathComponent("codesign-remove-linker-signature-reachd.log")
    )
    let fixups = try runner.run(
      "/usr/bin/dyld_info", ["-fixups", output.path],
      logURL: logs.appendingPathComponent("dyld-fixups-reachd.log")
    ).output
    try ReleaseMachONormalizer.normalizeDefaultObjCFastStubs(
      at: output,
      dyldFixups: fixups,
      recordURL: logs.appendingPathComponent("objc-fast-stub-normalization.json")
    )
    _ = try runner.run(
      "/usr/bin/codesign",
      ["--force", "--sign", "-", "--timestamp=none", "--identifier", "reachd", output.path],
      logURL: logs.appendingPathComponent("codesign-reachd.log")
    )
    try SecureFiles.removeExtendedAttributes(output)
    try SecureFiles.setModificationTime(output, seconds: sourceTimestamp)
    try validateBuiltExecutable(
      output,
      label: "reachd",
      forbiddenPaths: [
        export.path, root.path, depotRoot.path,
        metal.root.path,
        FileManager.default.homeDirectoryForCurrentUser.path,
      ],
      logs: logs)
    let buildItems = try FileManager.default.contentsOfDirectory(
      at: binURL, includingPropertiesForKeys: nil)
    let bundles = buildItems.filter { $0.pathExtension == "bundle" }.map(\.lastPathComponent)
      .sorted()
    guard bundles == ReleaseConfigurationExpected.hostBundles else {
      throw ReleasePackageError.verification(
        "Swift build did not produce exactly seven authorized bundles")
    }
    for bundle in bundles {
      let source = binURL.appendingPathComponent(bundle)
      let destination = output.deletingLastPathComponent().appendingPathComponent(bundle)
      try SecureFiles.copyTree(from: source, to: destination)
      try canonicalizeTreeTimes(destination, seconds: sourceTimestamp)
    }
    guard
      FileManager.default.fileExists(
        atPath: output.deletingLastPathComponent().appendingPathComponent(
          "mlx-swift_Cmlx.bundle/Contents/Resources/default.metallib"
        ).path
      )
    else {
      throw ReleasePackageError.verification("MLX metallib is missing")
    }
    try SwiftBuildMetalGraphVerifier.rejectPathLeak(
      below: output.deletingLastPathComponent(), transientPath: metal.root.path)
    try SwiftBuildMetalGraphVerifier.rejectPathLeak(
      below: output.deletingLastPathComponent(),
      transientPath: "/private/var/run/com.apple.security.cryptexd/mnt/")
    try SwiftBuildMetalGraphVerifier.rejectPathLeak(
      below: output.deletingLastPathComponent(),
      transientPath: "/var/run/com.apple.security.cryptexd/mnt/")
    try metalResolver.revalidate(
      metal, logURL: logs.appendingPathComponent("metal-component-reachd-final.log"))
    guard
      !FileManager.default.fileExists(
        atPath: root.appendingPathComponent("unexpected.profraw").path)
    else {
      throw ReleasePackageError.verification("release executable generated a coverage profile")
    }
    return output
  }

  private func buildHelper(
    export: URL,
    depotRoot: URL,
    sourceTimestamp: Int64,
    root: URL,
    output: URL,
    logs: URL
  ) throws -> URL {
    try SecureFiles.createPrivateDirectory(root)
    let cache = root.appendingPathComponent("cache")
    let path = root.appendingPathComponent("path")
    let home = root.appendingPathComponent("home")
    let tmp = root.appendingPathComponent("tmp")
    for directory in [cache, path, home, tmp] {
      try SecureFiles.createDirectory(directory, mode: 0o700)
    }
    let environment = [
      "GOMODCACHE": depotRoot.appendingPathComponent("go/pkg/mod").path,
      "GOCACHE": cache.path,
      "GOPATH": path.path,
      "GOENV": "off", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local",
      "GOOS": "darwin", "GOARCH": "arm64", "CGO_ENABLED": "1",
      "HOME": home.path, "TMPDIR": tmp.path,
      "SOURCE_DATE_EPOCH": String(sourceTimestamp),
    ]
    let helperSource = export.appendingPathComponent("mesh-helper")
    _ = try runner.run(
      "/opt/homebrew/bin/go", ["mod", "verify"],
      currentDirectory: helperSource,
      environment: environment,
      timeout: 1_800,
      logURL: logs.appendingPathComponent("go-mod-verify.log")
    )
    _ = try runner.run(
      "/opt/homebrew/bin/go",
      [
        "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=",
        "-o", output.path, "./cmd/reach-meshd",
      ],
      currentDirectory: helperSource,
      environment: environment,
      timeout: 3_600,
      logURL: logs.appendingPathComponent("go-build.log")
    )
    try SecureFiles.removeExtendedAttributes(output)
    _ = try runner.run(
      "/usr/bin/codesign",
      [
        "--force", "--sign", "-", "--timestamp=none", "--identifier", "systems.reach.meshd",
        output.path,
      ],
      logURL: logs.appendingPathComponent("codesign-helper.log")
    )
    try SecureFiles.removeExtendedAttributes(output)
    guard chmod(output.path, 0o555) == 0 else {
      throw ReleasePackageError.verification("could not canonicalize helper mode")
    }
    try SecureFiles.setModificationTime(output, seconds: sourceTimestamp)
    try validateBuiltExecutable(
      output,
      label: "meshd",
      forbiddenPaths: [
        export.path, root.path, depotRoot.path,
        FileManager.default.homeDirectoryForCurrentUser.path,
      ],
      logs: logs)
    return output
  }

  private func stageHost(
    export: URL,
    reachd: URL,
    notices: Data,
    configuration: ReleaseConfiguration,
    root: URL
  ) throws {
    try SecureFiles.createDirectory(root, mode: 0o755)
    let host = root.appendingPathComponent("Library/Application Support/Reach/Host")
    let release = root.appendingPathComponent("Library/Application Support/Reach/Release")
    let alias = root.appendingPathComponent("usr/local/bin/reachd")
    try makeDirectories(host, stoppingAt: root)
    try makeDirectories(release, stoppingAt: root)
    try makeDirectories(alias.deletingLastPathComponent(), stoppingAt: root)
    try SecureFiles.copyRegularFile(
      from: reachd, to: host.appendingPathComponent("reachd"), mode: 0o755)
    for bundle in configuration.hostBundles {
      try SecureFiles.copyTree(
        from: reachd.deletingLastPathComponent().appendingPathComponent(bundle),
        to: host.appendingPathComponent(bundle)
      )
    }
    try SecureFiles.copyRegularFile(
      from: export.appendingPathComponent("LICENSE"), to: release.appendingPathComponent("LICENSE"),
      mode: 0o644)
    try SecureFiles.atomicWrite(
      notices, to: release.appendingPathComponent("THIRD-PARTY-NOTICES.md"), mode: 0o644)
    try SecureFiles.createSymlink(
      at: alias, target: "/Library/Application Support/Reach/Host/reachd")
  }

  private func stageHelper(export: URL, helper: URL, root: URL) throws {
    try SecureFiles.createDirectory(root, mode: 0o755)
    let binary = root.appendingPathComponent("Library/PrivilegedHelperTools/systems.reach.meshd")
    let plist = root.appendingPathComponent("Library/LaunchDaemons/systems.reach.meshd.plist")
    try makeDirectories(binary.deletingLastPathComponent(), stoppingAt: root)
    try makeDirectories(plist.deletingLastPathComponent(), stoppingAt: root)
    try SecureFiles.copyRegularFile(from: helper, to: binary, mode: 0o555)
    try SecureFiles.copyRegularFile(
      from: export.appendingPathComponent("mesh-helper/package/systems.reach.meshd.plist"),
      to: plist,
      mode: 0o644
    )
    _ = try runner.run("/usr/bin/plutil", ["-lint", plist.path])
  }

  private func compare(_ lhs: BuildPass, _ rhs: BuildPass) throws {
    guard lhs.source == rhs.source,
      try Digests.sha256(file: lhs.reachd) == Digests.sha256(file: rhs.reachd),
      try Digests.sha256(file: lhs.helper) == Digests.sha256(file: rhs.helper),
      try SourceInspector().canonicalTreeDigest(lhs.hostStage)
        == SourceInspector().canonicalTreeDigest(rhs.hostStage),
      try SourceInspector().canonicalTreeDigest(lhs.helperStage)
        == SourceInspector().canonicalTreeDigest(rhs.helperStage),
      lhs.notices == rhs.notices,
      lhs.manifest == rhs.manifest,
      lhs.hostComponent.semantics == rhs.hostComponent.semantics,
      lhs.helperComponent.semantics == rhs.helperComponent.semantics,
      lhs.verification.normalizedSemanticSHA256 == rhs.verification.normalizedSemanticSHA256
    else {
      throw ReleasePackageError.verification("fresh release builds are not reproducible")
    }
    try compareComponentTOCs(
      lhs.hostComponent.package, rhs.hostComponent.package, label: "host",
      root: lhs.outer.package.deletingLastPathComponent())
    try compareComponentTOCs(
      lhs.helperComponent.package, rhs.helperComponent.package, label: "helper",
      root: rhs.outer.package.deletingLastPathComponent())
  }

  private func compareComponentTOCs(_ lhs: URL, _ rhs: URL, label: String, root: URL) throws {
    let directory = root.appendingPathComponent("toc-compare-\(label)-\(UUID().uuidString)")
    try SecureFiles.createPrivateDirectory(directory)
    let one = directory.appendingPathComponent("one.xml")
    let two = directory.appendingPathComponent("two.xml")
    _ = try runner.run("/usr/bin/xar", ["--dump-toc=\(one.path)", "-f", lhs.path])
    _ = try runner.run("/usr/bin/xar", ["--dump-toc=\(two.path)", "-f", rhs.path])
    guard try normalizedXARTOC(one) == normalizedXARTOC(two) else {
      throw ReleasePackageError.verification("\(label) component XAR differs beyond creation time")
    }
  }

  private func normalizedXARTOC(_ url: URL) throws -> String {
    let value = try String(contentsOf: url, encoding: .utf8)
    let pattern = "<creation-time>[^<]*</creation-time>"
    return value.replacingOccurrences(
      of: pattern, with: "<creation-time>normalized</creation-time>", options: .regularExpression)
  }

  private func inspectToolchain(
    depot: DependencyDepotManifest,
    metal: MountedMetalToolchain,
    logs: URL
  ) throws -> ToolchainAuthority {
    try SecureFiles.createDirectory(logs, mode: 0o700)
    let xcode = try runner.run(
      "/usr/bin/xcodebuild", ["-version"], logURL: logs.appendingPathComponent("xcode.log")
    ).output
    let swift = try runner.run(
      "/usr/bin/swift", ["--version"], logURL: logs.appendingPathComponent("swift.log")
    ).output
    let sdkPath = try runner.run(
      "/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"],
      logURL: logs.appendingPathComponent("sdk-path.log")
    ).output
    let sdkVersion = try runner.run(
      "/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-version"],
      logURL: logs.appendingPathComponent("sdk-version.log")
    ).output
    let build = try runner.run(
      "/usr/bin/sw_vers", ["-buildVersion"], logURL: logs.appendingPathComponent("macos-build.log")
    ).output
    return ToolchainAuthority(
      xcode: xcode.trimmingCharacters(in: .whitespacesAndNewlines),
      swift: swift.trimmingCharacters(in: .whitespacesAndNewlines),
      sdkPath: sdkPath.trimmingCharacters(in: .whitespacesAndNewlines),
      sdkVersion: sdkVersion.trimmingCharacters(in: .whitespacesAndNewlines),
      macOSBuild: build.trimmingCharacters(in: .whitespacesAndNewlines),
      go: depot.goVersion,
      metal: metal.authority
    )
  }

  private func linkedSystemLibraries(_ executable: URL, logs: URL) throws -> [String] {
    let lines = try runner.run(
      "/usr/bin/otool", ["-L", executable.path],
      logURL: logs.appendingPathComponent("otool-linked.log")
    ).output.split(separator: "\n").dropFirst()
    let paths = lines.compactMap { line -> String? in
      let value = String(line).trimmingCharacters(in: .whitespaces)
      return value.split(separator: " ").first.map(String.init)
    }
    guard paths.allSatisfy({ $0.hasPrefix("/System/Library/") || $0.hasPrefix("/usr/lib/") }) else {
      throw ReleasePackageError.verification("reachd links a non-system dynamic library")
    }
    return paths.sorted()
  }

  private func validateBuiltExecutable(
    _ url: URL, label: String, forbiddenPaths: [String], logs: URL
  ) throws {
    let file = try runner.run(
      "/usr/bin/file", [url.path], logURL: logs.appendingPathComponent("file-\(label).log")
    ).output
    guard file.contains("Mach-O 64-bit executable arm64"), !file.contains("universal"),
      !file.contains("x86_64")
    else {
      throw ReleasePackageError.verification("\(label) is not arm64-only")
    }
    let load = try runner.run(
      "/usr/bin/otool", ["-l", url.path],
      logURL: logs.appendingPathComponent("otool-load-\(label).log")
    ).output
    guard !load.contains("__llvm_") else {
      throw ReleasePackageError.verification("coverage section in \(label)")
    }
    let strings = try runner.run(
      "/usr/bin/strings", [url.path], logURL: logs.appendingPathComponent("strings-\(label).log")
    ).output
    for path in forbiddenPaths where strings.contains(path) {
      throw ReleasePackageError.verification("\(label) retained a private source/build path")
    }
    _ = try runner.run(
      "/usr/bin/codesign", ["--verify", "--strict", url.path],
      logURL: logs.appendingPathComponent("codesign-verify-\(label).log"))
  }

  private func canonicalizeTreeTimes(_ root: URL, seconds: Int64) throws {
    let entries = try SecureFiles.enumerateTree(root).sorted { $0.path > $1.path }
    for entry in entries { try SecureFiles.setModificationTime(entry, seconds: seconds) }
    try SecureFiles.setModificationTime(root, seconds: seconds)
  }

  private func makeDirectories(_ target: URL, stoppingAt root: URL) throws {
    let normalized = URL(fileURLWithPath: target.path)
    let base = URL(fileURLWithPath: root.path)
    let components = normalized.pathComponents
    let baseComponents = base.pathComponents
    guard components.count >= baseComponents.count,
      Array(components.prefix(baseComponents.count)) == baseComponents
    else {
      throw ReleasePackageError.unsafePath(target.path)
    }
    var missing: [URL] = []
    var cursor = normalized
    while cursor.path != base.path, !FileManager.default.fileExists(atPath: cursor.path) {
      missing.append(cursor)
      cursor.deleteLastPathComponent()
    }
    for directory in missing.reversed() { try SecureFiles.createDirectory(directory, mode: 0o755) }
  }

  private func requireEmptyPrivateRoot(_ root: URL) throws {
    try SecureFiles.createPrivateDirectory(root)
    let contents = try FileManager.default.contentsOfDirectory(atPath: root.path)
    guard contents.isEmpty else {
      throw ReleasePackageError.unsafePath("release output root must be empty: \(root.path)")
    }
  }

  private struct RetainedArtifacts {
    let hostComponents: [ReleaseProvenance.Artifact]
    let helperComponents: [ReleaseProvenance.Artifact]
    let hostBOMs: [ReleaseProvenance.Artifact]
    let helperBOMs: [ReleaseProvenance.Artifact]
    let outerA: URL
    let outerB: URL
  }

  private func retainArtifacts(passA: BuildPass, passB: BuildPass, at root: URL) throws
    -> RetainedArtifacts
  {
    var hostComponents: [ReleaseProvenance.Artifact] = []
    var helperComponents: [ReleaseProvenance.Artifact] = []
    var hostBOMs: [ReleaseProvenance.Artifact] = []
    var helperBOMs: [ReleaseProvenance.Artifact] = []
    var outers: [URL] = []
    for pass in [passA, passB] {
      let directory = root.appendingPathComponent(pass.name)
      try SecureFiles.createDirectory(directory, mode: 0o700)
      let host = directory.appendingPathComponent("systems.reach.host.pkg")
      let helper = directory.appendingPathComponent("systems.reach.meshd.pkg")
      let hostBOM = directory.appendingPathComponent("systems.reach.host.Bom")
      let helperBOM = directory.appendingPathComponent("systems.reach.meshd.Bom")
      let outer = directory.appendingPathComponent("Reach.pkg")
      try SecureFiles.copyRegularFile(from: pass.hostComponent.package, to: host, mode: 0o600)
      try SecureFiles.copyRegularFile(from: pass.helperComponent.package, to: helper, mode: 0o600)
      try SecureFiles.copyRegularFile(from: pass.hostComponent.bom, to: hostBOM, mode: 0o600)
      try SecureFiles.copyRegularFile(from: pass.helperComponent.bom, to: helperBOM, mode: 0o600)
      try SecureFiles.copyRegularFile(from: pass.outer.package, to: outer, mode: 0o600)
      hostComponents.append(
        try artifact(path: "artifacts/\(pass.name)/systems.reach.host.pkg", url: host))
      helperComponents.append(
        try artifact(path: "artifacts/\(pass.name)/systems.reach.meshd.pkg", url: helper))
      hostBOMs.append(
        try artifact(path: "artifacts/\(pass.name)/systems.reach.host.Bom", url: hostBOM))
      helperBOMs.append(
        try artifact(path: "artifacts/\(pass.name)/systems.reach.meshd.Bom", url: helperBOM))
      outers.append(outer)
    }
    return RetainedArtifacts(
      hostComponents: hostComponents,
      helperComponents: helperComponents,
      hostBOMs: hostBOMs,
      helperBOMs: helperBOMs,
      outerA: outers[0],
      outerB: outers[1]
    )
  }

  private func artifact(path: String, url: URL) throws -> ReleaseProvenance.Artifact {
    var info = stat()
    guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
      throw ReleasePackageError.verification("provenance artifact is not a regular file: \(path)")
    }
    return .init(path: path, size: UInt64(info.st_size), sha256: try Digests.sha256(file: url))
  }

  private func writeSHA256SUMS(_ root: URL) throws {
    let files = try SecureFiles.enumerateTree(root).filter { url in
      var info = stat()
      return lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG
        && url.lastPathComponent != "SHA256SUMS"
    }.sorted { $0.path.utf8.lexicographicallyPrecedes($1.path.utf8) }
    var lines = ""
    for file in files {
      let relative = String(file.path.dropFirst(root.path.count + 1))
      lines += "\(try Digests.sha256(file: file))  \(relative)\n"
    }
    try SecureFiles.atomicWrite(Data(lines.utf8), to: root.appendingPathComponent("SHA256SUMS"))
  }
}

private enum ReleaseConfigurationExpected {
  static let hostBundles = [
    "mlx-swift_Cmlx.bundle",
    "swift-crypto_CCryptoBoringSSL.bundle",
    "swift-crypto_CCryptoBoringSSLShims.bundle",
    "swift-crypto_Crypto.bundle",
    "swift-crypto_CryptoBoringWrapper.bundle",
    "swift-crypto_CryptoExtras.bundle",
    "swift-transformers_Hub.bundle",
  ]
}
