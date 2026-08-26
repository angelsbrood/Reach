import Darwin
import Foundation

public struct SignedReleaseResult: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let signedAuthority: String
  public let p2Package: String
  public let p2SHA256: String
  public let p3Package: String
  public let p3SHA256: String
  public let provenance: String
  public let teamID: String
}

public struct SignedReleaseFinalizer {
  private let runner: ProcessRunner
  private let resolveSigningContext: () throws -> DeveloperIDSigningContext
  private let requireLiveMetalAuthority: (MetalToolchainAuthority, URL) throws -> Void

  public init() {
    runner = ProcessRunner()
    let runner = runner
    resolveSigningContext = { try DeveloperIDIdentityResolver().resolveSigningContext() }
    requireLiveMetalAuthority = { authority, logURL in
      _ = try InstalledMetalToolchainResolver(runner: runner).requireAuthority(
        authority, logURL: logURL)
    }
  }

  init(runner: ProcessRunner, identityResolver: DeveloperIDIdentityResolver) {
    self.runner = runner
    resolveSigningContext = { try identityResolver.resolveSigningContext() }
    requireLiveMetalAuthority = { authority, logURL in
      _ = try InstalledMetalToolchainResolver(runner: runner).requireAuthority(
        authority, logURL: logURL)
    }
  }

  init(
    runner: ProcessRunner,
    requireLiveMetalAuthority: @escaping (MetalToolchainAuthority, URL) throws -> Void,
    resolveSigningContext: @escaping () throws -> DeveloperIDSigningContext
  ) {
    self.runner = runner
    self.requireLiveMetalAuthority = requireLiveMetalAuthority
    self.resolveSigningContext = resolveSigningContext
  }

  public func sign(
    unsignedAuthority: URL,
    unsignedToolSource: URL,
    finalizerToolSource: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    workRoot: URL,
    outputRoot: URL,
    lineageURL: URL? = nil,
    parentAuthority: URL? = nil
  ) throws -> SignedReleaseResult {
    let workRoot = try ReleasePathAuthority.mutableRoot(workRoot, label: "signed release work root")
    let outputRoot = try ReleasePathAuthority.mutableRoot(
      outputRoot, label: "signed release output root")
    try requireEmptyPrivateRoot(workRoot)
    try requireEmptyPrivateRoot(outputRoot)
    let logs = workRoot.appendingPathComponent("logs")
    try SecureFiles.createPrivateDirectory(logs)

    let configuration = try ReleaseConfiguration.load(from: configurationURL)
    let noticeAuthority = try NoticeAuthority.load(from: noticeAuthorityURL)
    let depot = try DependencyDepotBuilder(runner: runner).load(
      dependencyDepot, noticeAuthority: noticeAuthority)
    let depotSeal = try String(
      contentsOf: dependencyDepot.appendingPathComponent("dependency-depot.sha256"),
      encoding: .utf8
    ).trimmingCharacters(in: .whitespacesAndNewlines)
    let unsignedToolDigest = try SourceInspector().canonicalTreeDigest(unsignedToolSource)
    let finalizerToolDigest = try SourceInspector().canonicalTreeDigest(finalizerToolSource)
    let lineage: ReleaseLineageAuthority?
    let selection: UnsignedReleaseSelection
    var successorParent: (root: URL, provenance: MultiReleaseSignedProvenance, p5: URL)?
    switch configuration.schemaVersion {
    case 1:
      guard lineageURL == nil, parentAuthority == nil,
        unsignedToolDigest == SignedReleaseContract.unsignedToolSourceSHA256
      else {
        throw ReleasePackageError.verification(
          "historical signing authority cannot accept a replacement lineage")
      }
      lineage = nil
      selection = .historicalS35
    case 2:
      guard let lineageURL else {
        throw ReleasePackageError.verification(
          "schema-2 signing requires an explicit frozen lineage authority")
      }
      let loaded = try ReleaseLineageAuthority.load(from: lineageURL)
      try loaded.validate(configuration: configuration, configurationURL: configurationURL)
      guard loaded.unsignedToolSourceSHA256 == unsignedToolDigest else {
        throw ReleasePackageError.verification(
          "frozen lineage and unsigned-tool source do not match")
      }
      lineage = loaded
      selection = .lineage(loaded)
      switch loaded.declaration {
      case .replacement:
        guard parentAuthority == nil else {
          throw ReleasePackageError.verification(
            "replacement signing cannot accept substitute parent bytes")
        }
      case .successor(let declared):
        guard let parentAuthority else {
          throw ReleasePackageError.verification(
            "successor signing requires the retained parent authority")
        }
        successorParent = try verifySuccessorParent(
          parentAuthority,
          declared: declared,
          lineage: loaded,
          scratch: workRoot.appendingPathComponent("parent-preflight"))
      }
    default:
      throw ReleasePackageError.verification("unsupported signing configuration schema")
    }
    try Self.requireToolSourceBoundary(
      schemaVersion: configuration.schemaVersion,
      unsignedToolDigest: unsignedToolDigest,
      finalizerToolDigest: finalizerToolDigest)

    let materialized = try SignedPayloadMaterializer(runner: runner).materialize(
      unsignedAuthority: unsignedAuthority,
      unsignedToolSource: unsignedToolSource,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      workRoot: workRoot,
      selection: selection
    )
    // Static U1 verification is portable. Finalization deliberately adds the
    // stronger build-host gate before output authority changes or the login
    // Keychain is queried.
    let signingContext = try Self.establishFinalizationAuthority(
      declaredMetal: materialized.manifest.validatedMetalAuthority(for: configuration),
      metalLog: logs.appendingPathComponent("metal-component-finalization-host.log"),
      requireLiveMetalAuthority: requireLiveMetalAuthority,
      retainUnsignedAuthority: {
        try retainUnsignedAuthority(
          materialized.provenance, from: unsignedAuthority, at: outputRoot)
      },
      resolveSigningContext: resolveSigningContext)
    let identities = signingContext.identities
    try identities.application.validate()
    try identities.installer.validate()
    let hostExecutable = materialized.hostRoot.appendingPathComponent(
      "Library/Application Support/Reach/Host/reachd")
    let helperExecutable = materialized.helperRoot.appendingPathComponent(
      "Library/PrivilegedHelperTools/systems.reach.meshd")
    let retainedHelperComponent: ReleaseProvenance.Artifact?
    if lineage?.declaration.components.helper == .unchanged {
      guard let successorParent else {
        throw ReleasePackageError.verification(
          "unchanged helper lacks its retained signed parent")
      }
      retainedHelperComponent = try carryForwardUnchangedHelper(
        from: successorParent,
        lineage: try requireLineage(lineage),
        currentRoot: materialized.helperRoot,
        workRoot: workRoot.appendingPathComponent("unchanged-helper"))
    } else {
      retainedHelperComponent = nil
    }
    try signLeaf(
      hostExecutable,
      identifier: "reachd",
      selector: identities.application.certificateSHA1,
      keychainPath: signingContext.loginKeychainPath,
      canonicalMode: 0o755,
      log: logs.appendingPathComponent("sign-reachd.log"))
    if lineage?.declaration.components.helper != .unchanged {
      try signLeaf(
        helperExecutable,
        identifier: "systems.reach.meshd",
        selector: identities.application.certificateSHA1,
        keychainPath: signingContext.loginKeychainPath,
        canonicalMode: 0o555,
        log: logs.appendingPathComponent("sign-meshd.log"))
    }

    let inspector = CodeSignatureInspector(runner: runner)
    let leaves = try [
      inspector.inspectLeaf(
        hostExecutable,
        relativePath: "/Library/Application Support/Reach/Host/reachd",
        expectedIdentifier: "reachd",
        expectedCertificate: identities.application,
        logDirectory: logs),
      inspector.inspectLeaf(
        helperExecutable,
        relativePath: "/Library/PrivilegedHelperTools/systems.reach.meshd",
        expectedIdentifier: "systems.reach.meshd",
        expectedCertificate: identities.application,
        logDirectory: logs),
    ]

    let hostBeforeManifest = try PayloadTree.inspect(root: materialized.hostRoot)
    let helperTree = try PayloadTree.inspect(root: materialized.helperRoot)
    let manifest = try PayloadManifest.make(
      configuration: configuration,
      source: materialized.manifest.source,
      releaseConfigurationSHA256: try Digests.sha256(file: configurationURL),
      releaseToolSourceSHA256: finalizerToolDigest,
      noticeAuthoritySHA256: try Digests.sha256(file: noticeAuthorityURL),
      dependencyDepotSHA256: depotSeal,
      depot: depot,
      toolchain: materialized.manifest.toolchain,
      linkedSystemLibraries: materialized.manifest.linkedSystemLibraries,
      noticeSetSHA256: materialized.manifest.noticeSetSHA256,
      hostRecords: hostBeforeManifest.records,
      helperRecords: helperTree.records
    )
    let manifestInPayload = materialized.hostRoot.appendingPathComponent(
      "Library/Application Support/Reach/Release/payload-manifest.json")
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(manifest), to: manifestInPayload, mode: 0o644)
    try SecureFiles.setModificationTime(
      manifestInPayload, seconds: materialized.manifest.source.commitTimestamp)
    try SecureFiles.scrubExtendedAttributesRecursively(materialized.hostRoot)
    try SecureFiles.scrubExtendedAttributesRecursively(materialized.helperRoot)

    let p2Directory = outputRoot.appendingPathComponent("p2")
    try SecureFiles.createDirectory(p2Directory, mode: 0o700)
    let assembler = PackageAssembler(runner: runner)
    let hostComponent = try assembler.assembleComponent(
      payloadRoot: materialized.hostRoot,
      identifier: configuration.components.host.identifier,
      version: configuration.components.host.version,
      modificationTime: materialized.manifest.source.commitTimestamp,
      workspace: workRoot.appendingPathComponent("p2-host-component"),
      outputPackage: p2Directory.appendingPathComponent("systems.reach.host.pkg"),
      logDirectory: logs
    )
    let helperPackage = p2Directory.appendingPathComponent("systems.reach.meshd.pkg")
    let helperBOM: URL
    if let retainedHelperComponent, let successorParent {
      let source = successorParent.root.appendingPathComponent(retainedHelperComponent.path)
      try Self.copyExactRetainedComponent(
        source: source, artifact: retainedHelperComponent, destination: helperPackage)
      let expanded = workRoot.appendingPathComponent("retained-helper-component")
      try SecureFiles.createPrivateDirectory(expanded)
      _ = try runner.run(
        "/usr/bin/xar", ["-xf", helperPackage.path], currentDirectory: expanded,
        logURL: logs.appendingPathComponent("xar-retained-helper.log"))
      guard
        Set(try FileManager.default.contentsOfDirectory(atPath: expanded.path))
          == Set(["Bom", "Payload", "PackageInfo"])
      else {
        throw ReleasePackageError.verification(
          "retained helper component member authority changed")
      }
      helperBOM = expanded.appendingPathComponent("Bom")
    } else {
      let assembled = try assembler.assembleComponent(
        payloadRoot: materialized.helperRoot,
        identifier: configuration.components.helper.identifier,
        version: configuration.components.helper.version,
        modificationTime: materialized.manifest.source.commitTimestamp,
        workspace: workRoot.appendingPathComponent("p2-helper-component"),
        outputPackage: helperPackage,
        logDirectory: logs
      )
      helperBOM = assembled.bom
    }
    try SecureFiles.copyRegularFile(
      from: hostComponent.bom,
      to: p2Directory.appendingPathComponent("systems.reach.host.Bom"), mode: 0o600)
    try SecureFiles.copyRegularFile(
      from: helperBOM,
      to: p2Directory.appendingPathComponent("systems.reach.meshd.Bom"), mode: 0o600)
    let externalManifest = p2Directory.appendingPathComponent("payload-manifest.json")
    try SecureFiles.copyRegularFile(from: manifestInPayload, to: externalManifest, mode: 0o600)
    let p2Name = "Reach-\(configuration.product.version)-p2-unsigned.pkg"
    let p2Package = p2Directory.appendingPathComponent(p2Name)
    _ = try assembler.assembleOuterPackage(
      configuration: configuration,
      hostComponent: hostComponent.package,
      helperComponent: helperPackage,
      workspace: workRoot.appendingPathComponent("p2-outer"),
      outputPackage: p2Package,
      logDirectory: logs
    )
    let noticeManifest = outputRoot.appendingPathComponent("notice-manifest.json")
    let p2Verification = try PackageVerifier(runner: runner).verifySignedPayload(
      package: p2Package,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      expectedFinalizerToolSourceSHA256: finalizerToolDigest,
      noticeManifestURL: noticeManifest,
      scratch: workRoot.appendingPathComponent("p2-verification"),
      logDirectory: workRoot.appendingPathComponent("p2-verification/logs"),
      outerSigned: false
    )
    try runSignedSmoke(
      reachd: hostExecutable, helper: helperExecutable,
      workRoot: workRoot.appendingPathComponent("signed-smoke"))

    let p3Name = "Reach-\(configuration.product.version)-signed.pkg"
    let p3Package = outputRoot.appendingPathComponent(p3Name)
    let installerSelector = identities.installer.certificateSHA1
    _ = try runner.run(
      "/usr/bin/productsign",
      [
        "--keychain", signingContext.loginKeychainPath,
        "--sign", installerSelector, "--timestamp", p2Package.path, p3Package.path,
      ],
      logURL: logs.appendingPathComponent("productsign.log"),
      redactedArguments: [
        1: "<redacted-keychain-path>",
        3: "<redacted-installer-selector>",
      ]
    )
    guard chmod(p3Package.path, 0o600) == 0 else {
      throw ReleasePackageError.verification("cannot canonicalize P3 package mode")
    }
    try SecureFiles.removeExtendedAttributes(p3Package)
    let packageTimestamp = try inspector.inspectInstallerPackage(
      p3Package, expectedCertificate: identities.installer, logDirectory: logs)
    let p3Verification = try PackageVerifier(runner: runner).verifySignedPayload(
      package: p3Package,
      configurationURL: configurationURL,
      noticeAuthorityURL: noticeAuthorityURL,
      dependencyDepot: dependencyDepot,
      expectedFinalizerToolSourceSHA256: finalizerToolDigest,
      noticeManifestURL: noticeManifest,
      scratch: workRoot.appendingPathComponent("p3-verification"),
      logDirectory: workRoot.appendingPathComponent("p3-verification/logs"),
      outerSigned: true
    )
    guard p3Verification.normalizedSemanticSHA256 == p2Verification.normalizedSemanticSHA256 else {
      throw ReleasePackageError.verification("P3 payload changed while signing the container")
    }
    let p3VerificationURL = outputRoot.appendingPathComponent("p3-payload-verification.json")
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(p3Verification), to: p3VerificationURL)
    let assessment = try runner.run(
      "/usr/sbin/spctl", ["--assess", "--type", "install", "--verbose=4", p3Package.path],
      logURL: logs.appendingPathComponent("spctl-pre-notary.log"), requireSuccess: false)

    let signedHelperComponent = try artifact(
      path: "p2/systems.reach.meshd.pkg", url: helperPackage)
    if let retainedHelperComponent, signedHelperComponent != retainedHelperComponent {
      throw ReleasePackageError.verification(
        "unchanged helper component is not the exact retained parent artifact")
    }
    let p2Stage = SignedReleaseProvenance.SignedPayloadStage(
      name: "P2-signed-payload",
      unsignedParent: try artifact(
        path: materialized.provenance.u1.selectedContainer.path,
        url: outputRoot.appendingPathComponent(
          materialized.provenance.u1.selectedContainer.path)),
      unsignedToolSourceSHA256: unsignedToolDigest,
      finalizerToolSourceSHA256: finalizerToolDigest,
      applicationCertificate: identities.application,
      signedLeaves: leaves,
      embeddedManifest: try artifact(path: "p2/payload-manifest.json", url: externalManifest),
      hostComponent: try artifact(
        path: "p2/systems.reach.host.pkg", url: hostComponent.package),
      helperComponent: signedHelperComponent,
      hostBOM: try artifact(
        path: "p2/systems.reach.host.Bom",
        url: p2Directory.appendingPathComponent("systems.reach.host.Bom")),
      helperBOM: try artifact(
        path: "p2/systems.reach.meshd.Bom",
        url: p2Directory.appendingPathComponent("systems.reach.meshd.Bom")),
      unsignedContainer: try artifact(path: "p2/\(p2Name)", url: p2Package),
      normalizedSemanticSHA256: p2Verification.normalizedSemanticSHA256
    )
    let p3Stage = SignedReleaseProvenance.SignedContainerStage(
      name: "P3-signed-installer",
      p2ContainerSHA256: try Digests.sha256(file: p2Package),
      signedContainer: try artifact(path: p3Name, url: p3Package),
      payloadVerification: try artifact(
        path: "p3-payload-verification.json", url: p3VerificationURL),
      installerCertificate: identities.installer,
      secureTimestampUTC: packageTimestamp,
      packageIdentifiers: [
        configuration.components.host.identifier, configuration.components.helper.identifier,
      ],
      preNotaryAssessment: assessmentAuthority(assessment))
    let provenanceURL = outputRoot.appendingPathComponent("release-provenance.json")
    if let lineage {
      let signedProvenance = MultiReleaseSignedProvenance(
        schemaVersion: 3,
        lineage: lineage,
        p0: materialized.provenance.p0,
        p1: materialized.provenance.p1,
        u1: materialized.provenance.u1,
        p2: p2Stage,
        p3: p3Stage)
      try signedProvenance.validateStructure()
      try SecureFiles.atomicWrite(
        try CanonicalJSON.encode(signedProvenance), to: provenanceURL)
      try SecureFiles.atomicWrite(
        try CanonicalJSON.encode(lineage),
        to: outputRoot.appendingPathComponent("release-lineage.json"))
    } else {
      let signedProvenance = SignedReleaseProvenance(
        schemaVersion: 2,
        p0: materialized.provenance.p0,
        p1: materialized.provenance.p1,
        u1: materialized.provenance.u1,
        p2: p2Stage,
        p3: p3Stage)
      try signedProvenance.validate()
      try SecureFiles.atomicWrite(
        try CanonicalJSON.encode(signedProvenance), to: provenanceURL)
    }
    try writeSHA256SUMS(outputRoot)
    return SignedReleaseResult(
      schemaVersion: lineage == nil ? 1 : 2,
      signedAuthority: outputRoot.path,
      p2Package: p2Package.path,
      p2SHA256: try Digests.sha256(file: p2Package),
      p3Package: p3Package.path,
      p3SHA256: try Digests.sha256(file: p3Package),
      provenance: provenanceURL.path,
      teamID: identities.application.teamID
    )
  }

  static func requireToolSourceBoundary(
    schemaVersion: Int,
    unsignedToolDigest: String,
    finalizerToolDigest: String
  ) throws {
    switch schemaVersion {
    case 1:
      guard finalizerToolDigest != unsignedToolDigest else {
        throw ReleasePackageError.verification(
          "historical unsigned and finalizer tool-source authorities are not separated")
      }
    case 2:
      // A schema-2 lineage binds the unsigned source through its frozen U1
      // authority and records the finalizer source independently at P2. The
      // two roles may come from the same synchronized source tree; equality
      // does not permit either caller to substitute a different tree.
      break
    default:
      throw ReleasePackageError.verification("unsupported signing configuration schema")
    }
  }

  private func requireLineage(_ value: ReleaseLineageAuthority?) throws
    -> ReleaseLineageAuthority
  {
    guard let value else {
      throw ReleasePackageError.verification("multi-release lineage is missing")
    }
    return value
  }

  private func verifySuccessorParent(
    _ root: URL,
    declared: ReleaseLineage.Successor,
    lineage: ReleaseLineageAuthority,
    scratch: URL
  ) throws -> (root: URL, provenance: MultiReleaseSignedProvenance, p5: URL) {
    guard case .retained(let retained) = lineage.predecessor,
      retained.versions == declared.parent,
      retained.p5.sha256 == declared.parentP5SHA256,
      retained.provenance.sha256 == declared.parentProvenanceSHA256
    else {
      throw ReleasePackageError.verification("successor lineage lacks its exact retained parent")
    }
    let provenanceURL = root.appendingPathComponent("release-provenance.json")
    let provenance = try MultiReleaseSignedProvenance.load(from: provenanceURL)
    guard try Digests.sha256(file: provenanceURL) == retained.provenance.sha256,
      provenance.lineage.release == declared.parent,
      let p5 = provenance.p5,
      p5.stapledContainer == retained.p5
    else {
      throw ReleasePackageError.verification("retained successor parent changed")
    }
    let p5URL = root.appendingPathComponent(p5.stapledContainer.path)
    let report = try SignedReleaseVerifier(runner: runner).verify(
      package: p5URL,
      provenanceURL: provenanceURL,
      unsignedToolSource: root.appendingPathComponent("unsigned-tool-source"),
      finalizerToolSource: root.appendingPathComponent("finalizer-tool-source"),
      configurationURL: root.appendingPathComponent("release.json"),
      noticeAuthorityURL: root.appendingPathComponent("notices.json"),
      dependencyDepot: root.appendingPathComponent("dependency-depot"),
      scratch: scratch)
    guard report.stage == "P5", report.packageSHA256 == retained.p5.sha256,
      report.stapleValidated, report.localAssessmentPassed
    else {
      throw ReleasePackageError.verification("retained successor parent failed P5 verification")
    }
    return (root, provenance, p5URL)
  }

  private func carryForwardUnchangedHelper(
    from parent: (root: URL, provenance: MultiReleaseSignedProvenance, p5: URL),
    lineage: ReleaseLineageAuthority,
    currentRoot: URL,
    workRoot: URL
  ) throws -> ReleaseProvenance.Artifact {
    guard case .retained(let retained) = lineage.predecessor,
      lineage.components.count == 2,
      lineage.components[1].disposition == .unchanged,
      parent.provenance.p2.helperComponent == retained.helperComponent,
      parent.provenance.p2.signedLeaves.contains(where: {
        $0.path == "/Library/PrivilegedHelperTools/systems.reach.meshd"
          && $0.artifact == retained.helperLeaf
      })
    else {
      throw ReleasePackageError.verification("unchanged helper parent binding changed")
    }
    try SecureFiles.createPrivateDirectory(workRoot)
    let materializer = SignedPayloadMaterializer(runner: runner)
    let retainedComponent = parent.root.appendingPathComponent(retained.helperComponent.path)
    let p2Root = try materializer.materializeStandaloneComponent(
      retainedComponent,
      destination: workRoot.appendingPathComponent("p2-helper"),
      scratch: workRoot.appendingPathComponent("p2-materialization"),
      label: "retained parent helper")
    let p5Root = try materializer.materializeComponent(
      named: "systems.reach.meshd.pkg",
      fromOuterPackage: parent.p5,
      destination: workRoot.appendingPathComponent("p5-helper"),
      scratch: workRoot.appendingPathComponent("p5-materialization"),
      label: "retained P5 helper")
    guard
      try SourceInspector().canonicalTreeDigest(p2Root)
        == SourceInspector().canonicalTreeDigest(p5Root)
    else {
      throw ReleasePackageError.verification(
        "retained parent P2 and P5 helper payloads differ")
    }
    try Self.requireUnchangedPayload(
      current: currentRoot,
      parent: p5Root,
      executablePath: "Library/PrivilegedHelperTools/systems.reach.meshd")
    try FileManager.default.removeItem(at: currentRoot)
    let carried = try materializer.materializeComponent(
      named: "systems.reach.meshd.pkg",
      fromOuterPackage: parent.p5,
      destination: currentRoot,
      scratch: workRoot.appendingPathComponent("carry-materialization"),
      label: "carried parent helper")
    let executable = carried.appendingPathComponent(
      "Library/PrivilegedHelperTools/systems.reach.meshd")
    guard try Digests.sha256(file: executable) == retained.helperLeaf.sha256,
      try SourceInspector().canonicalTreeDigest(carried)
        == SourceInspector().canonicalTreeDigest(p5Root)
    else {
      throw ReleasePackageError.verification("carried helper is not the exact parent payload")
    }
    return retained.helperComponent
  }

  static func copyExactRetainedComponent(
    source: URL,
    artifact: ReleaseProvenance.Artifact,
    destination: URL
  ) throws {
    try SecureFiles.validateRelativePath(artifact.path)
    var sourceInfo = stat()
    guard lstat(source.path, &sourceInfo) == 0,
      (sourceInfo.st_mode & S_IFMT) == S_IFREG,
      sourceInfo.st_nlink == 1,
      UInt64(sourceInfo.st_size) == artifact.size,
      try Digests.sha256(file: source) == artifact.sha256
    else {
      throw ReleasePackageError.verification(
        "retained helper component bytes changed")
    }
    try SecureFiles.copyRegularFile(from: source, to: destination, mode: 0o600)
    guard try Digests.sha256(file: destination) == artifact.sha256 else {
      throw ReleasePackageError.verification(
        "retained helper component was not copied byte-for-byte")
    }
  }

  static func requireUnchangedPayload(
    current: URL,
    parent: URL,
    executablePath: String
  ) throws {
    let currentRecords = try PayloadTree.inspect(root: current).records
    let parentRecords = try PayloadTree.inspect(root: parent).records
    guard currentRecords.map(\.path) == parentRecords.map(\.path),
      currentRecords.count == parentRecords.count
    else {
      throw ReleasePackageError.verification("unchanged component payload paths drifted")
    }
    let archivePath = "./\(executablePath)"
    for (lhs, rhs) in zip(currentRecords, parentRecords) {
      if lhs.path == archivePath {
        guard lhs.kind == rhs.kind, lhs.mode == rhs.mode, lhs.uid == rhs.uid,
          lhs.gid == rhs.gid, lhs.linkTarget == rhs.linkTarget
        else {
          throw ReleasePackageError.verification(
            "unchanged component executable metadata drifted")
        }
      } else if lhs != rhs {
        throw ReleasePackageError.verification(
          "unchanged component non-executable bytes drifted: \(lhs.path)")
      }
    }
    let currentExecutable = current.appendingPathComponent(executablePath)
    let parentExecutable = parent.appendingPathComponent(executablePath)
    guard
      try MachORuntimeContentDigest.digest(currentExecutable)
        == MachORuntimeContentDigest.digest(parentExecutable)
    else {
      throw ReleasePackageError.verification(
        "unchanged component executable runtime sections drifted")
    }
  }

  private func signLeaf(
    _ executable: URL,
    identifier: String,
    selector: String,
    keychainPath: String,
    canonicalMode: mode_t,
    log: URL
  ) throws {
    guard chmod(executable.path, canonicalMode | S_IWUSR) == 0 else {
      throw ReleasePackageError.verification("cannot prepare signed executable mode")
    }
    _ = try runner.run(
      "/usr/bin/codesign",
      [
        "--keychain", keychainPath, "--force", "--sign", selector, "--identifier", identifier,
        "--options", "runtime", "--timestamp", executable.path,
      ],
      logURL: log,
      redactedArguments: [
        1: "<redacted-keychain-path>",
        4: "<redacted-application-selector>",
      ]
    )
    try SecureFiles.removeExtendedAttributes(executable)
    guard chmod(executable.path, canonicalMode) == 0 else {
      throw ReleasePackageError.verification("cannot restore signed executable mode")
    }
  }

  private func runSignedSmoke(reachd: URL, helper: URL, workRoot: URL) throws {
    try SecureFiles.createPrivateDirectory(workRoot)
    let smokeRunner = ProcessRunner(testExecutables: [reachd.path, helper.path])
    let environment = Self.signedSmokeEnvironment(workRoot: workRoot)
    _ = try smokeRunner.run(
      reachd.path, ["--help"], environment: environment, timeout: 60,
      logURL: workRoot.appendingPathComponent("reachd-help.log"))
    _ = try smokeRunner.run(
      reachd.path, ["selftest"], environment: environment, timeout: 120,
      logURL: workRoot.appendingPathComponent("reachd-selftest.log"))
    _ = try smokeRunner.run(
      reachd.path, ["selftest", "--mlx"], environment: environment, timeout: 1_800,
      logURL: workRoot.appendingPathComponent("reachd-mlx-selftest.log"))
    _ = try smokeRunner.run(
      helper.path, ["version"], environment: environment, timeout: 30,
      logURL: workRoot.appendingPathComponent("meshd-version.log"))
  }

  static func signedSmokeEnvironment(workRoot: URL) -> [String: String] {
    let loginHome = FileManager.default.homeDirectoryForCurrentUser
    return [
      // `selftest` deliberately exercises ephemeral Keychain identities and
      // removes them on exit. A synthetic HOME makes trusted signed code lose
      // the user's default login Keychain, so bind that authority explicitly
      // while keeping every file/cache side effect in private scratch state.
      "HOME": loginHome.path,
      "HF_HUB_CACHE": loginHome.appendingPathComponent(".cache/huggingface/hub").path,
      "TMPDIR": workRoot.path,
    ]
  }

  static func establishFinalizationAuthority(
    declaredMetal: MetalToolchainAuthority?,
    metalLog: URL,
    requireLiveMetalAuthority: (MetalToolchainAuthority, URL) throws -> Void,
    retainUnsignedAuthority: () throws -> Void,
    resolveSigningContext: () throws -> DeveloperIDSigningContext
  ) throws -> DeveloperIDSigningContext {
    if let declaredMetal {
      try requireLiveMetalAuthority(declaredMetal, metalLog)
    }
    try retainUnsignedAuthority()
    return try resolveSigningContext()
  }

  private func retainUnsignedAuthority(
    _ provenance: ReleaseProvenance,
    from sourceRoot: URL,
    at outputRoot: URL
  ) throws {
    let artifacts =
      [provenance.p1.embeddedManifest, provenance.p1.notices]
      + provenance.p1.hostComponents
      + provenance.p1.helperComponents
      + provenance.p1.hostBOMs
      + provenance.p1.helperBOMs
      + provenance.u1.containers
      + [provenance.u1.selectedContainer]
    for artifact in Dictionary(grouping: artifacts, by: \.path).values.compactMap(\.first) {
      try SecureFiles.validateRelativePath(artifact.path)
      let source = sourceRoot.appendingPathComponent(artifact.path)
      guard try Digests.sha256(file: source) == artifact.sha256 else {
        throw ReleasePackageError.verification("retained U1 artifact changed: \(artifact.path)")
      }
      let destination = outputRoot.appendingPathComponent(artifact.path)
      try createParents(for: destination, below: outputRoot)
      try SecureFiles.copyRegularFile(from: source, to: destination, mode: 0o600)
    }
    for name in ["notice-manifest.json", "release.json", "notices.json"] {
      try SecureFiles.copyRegularFile(
        from: sourceRoot.appendingPathComponent(name),
        to: outputRoot.appendingPathComponent(name), mode: 0o600)
    }
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(provenance),
      to: outputRoot.appendingPathComponent("u1-release-provenance.json"))
  }

  private func createParents(for file: URL, below root: URL) throws {
    let relative = String(file.deletingLastPathComponent().path.dropFirst(root.path.count))
      .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    var cursor = root
    if !relative.isEmpty {
      for component in relative.split(separator: "/") {
        cursor.appendPathComponent(String(component))
        if !FileManager.default.fileExists(atPath: cursor.path) {
          try SecureFiles.createDirectory(cursor, mode: 0o700)
        }
      }
    }
  }

  private func artifact(path: String, url: URL) throws -> ReleaseProvenance.Artifact {
    try SecureFiles.validateRelativePath(path)
    var info = stat()
    guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1
    else {
      throw ReleasePackageError.unsafePath("artifact is not a single-link regular file: \(path)")
    }
    return .init(
      path: path, size: UInt64(info.st_size), sha256: try Digests.sha256(file: url))
  }

  private func assessmentAuthority(_ result: CommandResult) -> AssessmentAuthority {
    .init(
      exitStatus: result.exitStatus,
      stdoutSHA256: Digests.sha256(Data(result.output.utf8)),
      stderrSHA256: Digests.sha256(Data(result.errorOutput.utf8)))
  }

  private func requireEmptyPrivateRoot(_ root: URL) throws {
    try SecureFiles.createPrivateDirectory(root)
    guard try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty else {
      throw ReleasePackageError.unsafePath("release root must be empty: \(root.path)")
    }
  }

  private func writeSHA256SUMS(_ root: URL) throws {
    let entries = try SecureFiles.enumerateTree(root).filter { url in
      var info = stat()
      return lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG
        && url.lastPathComponent != "SHA256SUMS"
    }.sorted { $0.path < $1.path }
    let lines =
      try entries.map { url in
        let relative = String(url.path.dropFirst(root.path.count + 1))
        return "\(try Digests.sha256(file: url))  ./\(relative)"
      }.joined(separator: "\n") + "\n"
    try SecureFiles.atomicWrite(
      Data(lines.utf8), to: root.appendingPathComponent("SHA256SUMS"))
  }
}
