import Darwin
import Foundation

public struct VerificationReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let packageSHA256: String
  public let normalizedSemanticSHA256: String
  public let embeddedManifestSHA256: String
  public let noticeSetSHA256: String
  public let hostFiles: Int
  public let helperFiles: Int
  public let scriptsPresent: Bool
  public let resourcesPresent: Bool
}

public struct PackageVerifier {
  private let runner: ProcessRunner
  private let assembler: PackageAssembler

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
    assembler = PackageAssembler(runner: runner)
  }

  public func verify(
    package: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    expectedReleaseToolSourceSHA256: String,
    provenanceURL: URL? = nil,
    noticeManifestURL: URL? = nil,
    scratch: URL,
    logDirectory: URL
  ) throws -> VerificationReport {
    try requireRegularFile(package, label: "unsigned product package", mode: 0o600)
    try SecureFiles.createPrivateDirectory(scratch)
    try SecureFiles.createDirectory(logDirectory, mode: 0o700)
    let configuration = try ReleaseConfiguration.load(from: configurationURL)
    let noticeAuthority = try NoticeAuthority.load(from: noticeAuthorityURL)
    let depot = try DependencyDepotBuilder(runner: runner).load(
      dependencyDepot, noticeAuthority: noticeAuthority)
    let depotSeal = try String(
      contentsOf: dependencyDepot.appendingPathComponent("dependency-depot.sha256"),
      encoding: .utf8
    ).trimmingCharacters(in: .whitespacesAndNewlines)
    let generatedNotices = try NoticeGenerator.generate(
      authority: noticeAuthority,
      depot: depot,
      depotRoot: dependencyDepot
    )
    let signature = try runner.run(
      "/usr/sbin/pkgutil",
      ["--check-signature", package.path],
      logURL: logDirectory.appendingPathComponent("verify-package-signature.log"),
      requireSuccess: false
    )
    guard signature.exitStatus != 0,
      (signature.output + signature.errorOutput).contains("Status: no signature")
    else {
      throw ReleasePackageError.verification("U1 container must be unsigned")
    }
    let expanded = scratch.appendingPathComponent("expanded")
    try SecureFiles.createDirectory(expanded, mode: 0o700)
    let memberOrder = try runner.run(
      "/usr/bin/xar",
      ["-tf", package.path],
      logURL: logDirectory.appendingPathComponent("verify-outer-list.log")
    ).output.split(separator: "\n").map(String.init)
    let expectedOrder = [
      "systems.reach.host.pkg",
      "systems.reach.host.pkg/Bom",
      "systems.reach.host.pkg/Payload",
      "systems.reach.host.pkg/PackageInfo",
      "systems.reach.meshd.pkg",
      "systems.reach.meshd.pkg/Bom",
      "systems.reach.meshd.pkg/Payload",
      "systems.reach.meshd.pkg/PackageInfo",
      "Distribution",
    ]
    guard memberOrder == expectedOrder else {
      throw ReleasePackageError.verification("outer package member order or allowlist changed")
    }
    _ = try runner.run(
      "/usr/bin/xar",
      ["-xf", package.path],
      currentDirectory: expanded,
      logURL: logDirectory.appendingPathComponent("verify-outer-extract.log")
    )
    let distribution = expanded.appendingPathComponent("Distribution")
    try requireRegularFile(distribution, label: "Distribution")
    let host = try inspectComponent(
      directory: expanded.appendingPathComponent("systems.reach.host.pkg"),
      identifier: configuration.components.host.identifier,
      version: configuration.components.host.version,
      scratch: scratch.appendingPathComponent("host-inspection"),
      logDirectory: logDirectory
    )
    let helper = try inspectComponent(
      directory: expanded.appendingPathComponent("systems.reach.meshd.pkg"),
      identifier: configuration.components.helper.identifier,
      version: configuration.components.helper.version,
      scratch: scratch.appendingPathComponent("helper-inspection"),
      logDirectory: logDirectory
    )
    guard
      try Data(contentsOf: distribution)
        == PackageDocuments.productbuildDistribution(
          configuration: configuration,
          hostInstallKBytes: host.installKBytes,
          helperInstallKBytes: helper.installKBytes
        )
    else {
      throw ReleasePackageError.verification("Distribution authority changed")
    }
    try validateHostAllowlist(host.members.map(\.record), configuration: configuration)
    try validateHelperAllowlist(helper.members.map(\.record))

    guard
      let manifestMember = host.members.first(where: {
        $0.record.path == "./Library/Application Support/Reach/Release/payload-manifest.json"
      })
    else {
      throw ReleasePackageError.verification("embedded payload manifest is missing")
    }
    let manifest = try JSONDecoder().decode(PayloadManifest.self, from: manifestMember.data)
    guard manifest.schemaVersion == 1,
      manifest.product.name == configuration.product.name,
      manifest.product.version == configuration.product.version,
      manifest.product.architecture == configuration.product.architecture,
      manifest.product.minimumMacOS == configuration.product.minimumMacOS,
      manifest.host.identifier == configuration.components.host.identifier,
      manifest.host.version == configuration.components.host.version,
      manifest.helper.identifier == configuration.components.helper.identifier,
      manifest.helper.version == configuration.components.helper.version,
      manifest.compatibility == configuration.compatibility,
      manifest.releaseConfigurationSHA256 == (try Digests.sha256(file: configurationURL)),
      manifest.releaseToolSourceSHA256 == expectedReleaseToolSourceSHA256,
      manifest.noticeAuthoritySHA256 == (try Digests.sha256(file: noticeAuthorityURL)),
      manifest.dependencyDepotSHA256 == depotSeal,
      manifest.swiftPins
        == depot.swiftPins.map({
          .init(identity: $0.identity, revision: $0.revision, version: $0.version, tree: $0.tree)
        }),
      manifest.goModules
        == depot.goModules.map({
          .init(identity: $0.path, revision: $0.version, version: $0.version, tree: $0.treeSHA256)
        }),
      manifest.packageIdentifiers == [
        configuration.components.host.identifier, configuration.components.helper.identifier,
      ],
      !manifest.payload.contains(where: {
        $0.path == "/Library/Application Support/Reach/Release/payload-manifest.json"
      })
    else {
      throw ReleasePackageError.verification("embedded payload manifest authority changed")
    }
    let actualMembers =
      try host.members.map {
        try ManifestPayloadMember(
          record: $0.record, componentIdentifier: configuration.components.host.identifier)
      }
      + helper.members.map {
        try ManifestPayloadMember(
          record: $0.record, componentIdentifier: configuration.components.helper.identifier)
      }
    let expectedManifestMembers = actualMembers.filter {
      $0.path != "/Library/Application Support/Reach/Release/payload-manifest.json"
    }.sorted { ($0.path, $0.componentIdentifier) < ($1.path, $1.componentIdentifier) }
    guard manifest.payload == expectedManifestMembers else {
      throw ReleasePackageError.verification("embedded manifest does not match package payload")
    }
    let bundleLines =
      expectedManifestMembers.filter {
        $0.path.hasPrefix("/Library/Application Support/Reach/Host/") && $0.path.contains(".bundle")
      }.map {
        "\($0.path)\t\($0.type)\t\($0.mode)\t\($0.size)\t\($0.sha256 ?? "-")"
      }.joined(separator: "\n") + "\n"
    guard manifest.bundleTreeSHA256 == Digests.sha256(Data(bundleLines.utf8)) else {
      throw ReleasePackageError.verification("embedded bundle-tree digest changed")
    }
    guard
      let noticesMember = host.members.first(where: {
        $0.record.path == "./Library/Application Support/Reach/Release/THIRD-PARTY-NOTICES.md"
      }), noticesMember.data == generatedNotices.markdown,
      manifest.noticeSetSHA256 == generatedNotices.manifest.noticeSetSHA256
    else {
      throw ReleasePackageError.verification("notice payload or notice-set authority changed")
    }

    if let noticeManifestURL {
      try requireRegularFile(noticeManifestURL, label: "external notice manifest", mode: 0o600)
      let noticeManifestData = try Data(contentsOf: noticeManifestURL)
      let noticeManifest = try JSONDecoder().decode(NoticeManifest.self, from: noticeManifestData)
      guard noticeManifestData == (try CanonicalJSON.encode(noticeManifest)),
        noticeManifest == generatedNotices.manifest,
        noticeManifest.noticesSHA256 == Digests.sha256(noticesMember.data),
        noticeManifest.noticeSetSHA256 == manifest.noticeSetSHA256
      else {
        throw ReleasePackageError.verification("external notice manifest does not match package")
      }
    }

    let semantics = UnsignedPackageSemantics(
      schemaVersion: 1,
      productVersion: configuration.product.version,
      architecture: configuration.product.architecture,
      distributionSHA256: try Digests.sha256(file: distribution),
      outerMemberOrder: memberOrder,
      scriptsPresent: false,
      resourcesPresent: false,
      components: [host.semantics, helper.semantics]
    )
    let semanticDigest = Digests.sha256(try CanonicalJSON.encode(semantics))
    let packageDigest = try Digests.sha256(file: package)
    if let provenanceURL {
      try requireRegularFile(provenanceURL, label: "external release provenance", mode: 0o600)
      let provenanceData = try Data(contentsOf: provenanceURL)
      try validateTopLevelKeys(
        provenanceData,
        expected: ["schemaVersion", "p0", "p1", "u1"]
      )
      let provenance = try JSONDecoder().decode(ReleaseProvenance.self, from: provenanceData)
      let authorityRoot = provenanceURL.deletingLastPathComponent()
      let candidateName = "Reach-\(configuration.product.version)-unsigned.pkg"
      let externalManifest = try provenanceArtifact(
        root: authorityRoot, path: "payload-manifest.json")
      let externalNotices = try provenanceArtifact(
        root: authorityRoot, path: "THIRD-PARTY-NOTICES.md")
      let externalManifestData = try Data(
        contentsOf: authorityRoot.appendingPathComponent(externalManifest.path))
      let externalNoticesData = try Data(
        contentsOf: authorityRoot.appendingPathComponent(externalNotices.path))
      guard externalManifestData == manifestMember.data,
        externalNoticesData == noticesMember.data
      else {
        throw ReleasePackageError.verification("external provenance does not match package")
      }
      let expectedProvenance = ReleaseProvenance(
        schemaVersion: 1,
        p0: .init(
          name: "P0-source",
          authority: manifest.source,
          releaseConfigurationSHA256: try Digests.sha256(file: configurationURL),
          releaseToolSourceSHA256: expectedReleaseToolSourceSHA256,
          noticeAuthoritySHA256: try Digests.sha256(file: noticeAuthorityURL),
          dependencyDepotSHA256: depotSeal
        ),
        p1: .init(
          name: "P1-payload",
          embeddedManifest: externalManifest,
          notices: externalNotices,
          hostComponents: try ["build-a", "build-b"].map {
            try provenanceArtifact(
              root: authorityRoot, path: "artifacts/\($0)/systems.reach.host.pkg")
          },
          helperComponents: try ["build-a", "build-b"].map {
            try provenanceArtifact(
              root: authorityRoot, path: "artifacts/\($0)/systems.reach.meshd.pkg")
          },
          hostBOMs: try ["build-a", "build-b"].map {
            try provenanceArtifact(
              root: authorityRoot, path: "artifacts/\($0)/systems.reach.host.Bom")
          },
          helperBOMs: try ["build-a", "build-b"].map {
            try provenanceArtifact(
              root: authorityRoot, path: "artifacts/\($0)/systems.reach.meshd.Bom")
          }
        ),
        u1: .init(
          name: "U1-unsigned-container-semantics",
          containers: try ["build-a", "build-b"].map {
            try provenanceArtifact(root: authorityRoot, path: "artifacts/\($0)/Reach.pkg")
          },
          selectedContainer: try provenanceArtifact(
            root: authorityRoot, path: candidateName, fileOverride: package),
          normalizedSemanticSHA256: semanticDigest,
          distributionSHA256: Digests.sha256(
            PackageDocuments.distribution(configuration: configuration))
        )
      )
      guard provenanceData == (try CanonicalJSON.encode(provenance)) else {
        throw ReleasePackageError.verification("external provenance is not canonical JSON")
      }
      guard provenance.p0 == expectedProvenance.p0 else {
        throw ReleasePackageError.verification("external P0 source provenance changed")
      }
      guard provenance.p1 == expectedProvenance.p1 else {
        throw ReleasePackageError.verification("external P1 payload provenance changed")
      }
      guard provenance.u1 == expectedProvenance.u1 else {
        throw ReleasePackageError.verification("external U1 container provenance changed")
      }
      guard provenance == expectedProvenance,
        expectedProvenance.u1.selectedContainer.sha256 == packageDigest
      else {
        throw ReleasePackageError.verification(
          "external provenance stages or retained artifacts do not match package authority")
      }
      guard expectedProvenance.p1.hostBOMs[0].sha256 == host.semantics.bomSHA256,
        expectedProvenance.p1.helperBOMs[0].sha256 == helper.semantics.bomSHA256
      else {
        throw ReleasePackageError.verification(
          "retained build-a BOMs do not match the selected container")
      }
    }
    let reachdLibraries = try inspectMachO(
      host.members, path: "./Library/Application Support/Reach/Host/reachd", scratch: scratch,
      label: "reachd", expectedIdentifier: "reachd", logDirectory: logDirectory)
    _ = try inspectMachO(
      helper.members, path: "./Library/PrivilegedHelperTools/systems.reach.meshd", scratch: scratch,
      label: "meshd", expectedIdentifier: "systems.reach.meshd", logDirectory: logDirectory)
    guard manifest.linkedSystemLibraries == reachdLibraries else {
      throw ReleasePackageError.verification("embedded linked-library authority changed")
    }
    return VerificationReport(
      schemaVersion: 1,
      packageSHA256: packageDigest,
      normalizedSemanticSHA256: semanticDigest,
      embeddedManifestSHA256: Digests.sha256(manifestMember.data),
      noticeSetSHA256: manifest.noticeSetSHA256,
      hostFiles: host.members.count,
      helperFiles: helper.members.count,
      scriptsPresent: false,
      resourcesPresent: false
    )
  }

  private struct InspectedComponent {
    let members: [ODCArchive.Member]
    let semantics: ComponentSemantics
    let installKBytes: UInt64
  }

  private func inspectComponent(
    directory: URL,
    identifier: String,
    version: DottedVersion,
    scratch: URL,
    logDirectory: URL
  ) throws -> InspectedComponent {
    try requireDirectory(directory, label: "component \(identifier)")
    let allowed = Set(["Bom", "Payload", "PackageInfo"])
    let actual = Set(try FileManager.default.contentsOfDirectory(atPath: directory.path))
    guard actual == allowed else {
      throw ReleasePackageError.verification(
        "component contains an unexpected member: \(identifier)")
    }
    for member in allowed {
      try requireRegularFile(
        directory.appendingPathComponent(member), label: "\(identifier)/\(member)")
    }
    try SecureFiles.createPrivateDirectory(scratch)
    let archiveGzip = scratch.appendingPathComponent("Archive.gz")
    try SecureFiles.copyRegularFile(
      from: directory.appendingPathComponent("Payload"), to: archiveGzip, mode: 0o600)
    _ = try runner.run(
      "/usr/bin/gzip",
      ["-d", "-k", archiveGzip.path],
      logURL: logDirectory.appendingPathComponent("verify-gzip-\(identifier).log")
    )
    let archive = scratch.appendingPathComponent("Archive")
    let members = try ODCArchive.parseMembers(Data(contentsOf: archive, options: [.mappedIfSafe]))
    let records = members.map(\.record)
    let listing = try runner.run(
      "/usr/bin/lsbom",
      [directory.appendingPathComponent("Bom").path],
      logURL: logDirectory.appendingPathComponent("verify-lsbom-\(identifier).log")
    ).output
    guard Data(listing.utf8) == assembler.expectedBOMListing(records) else {
      throw ReleasePackageError.verification("BOM and payload disagree for \(identifier)")
    }
    let tree = PayloadTree(
      nodes: members.map { member in
        PayloadNode(record: member.record, source: nil, linkTarget: member.record.linkTarget)
      })
    guard
      try Data(contentsOf: directory.appendingPathComponent("PackageInfo"))
        == PackageDocuments.packageInfo(
          identifier: identifier,
          version: version,
          tree: tree
        )
    else {
      throw ReleasePackageError.verification("PackageInfo changed for \(identifier)")
    }
    return InspectedComponent(
      members: members,
      semantics: ComponentSemantics(
        identifier: identifier,
        version: version,
        packageInfoSHA256: try Digests.sha256(
          file: directory.appendingPathComponent("PackageInfo")),
        bomSHA256: try Digests.sha256(file: directory.appendingPathComponent("Bom")),
        bomListingSHA256: Digests.sha256(Data(listing.utf8)),
        payloadSHA256: try Digests.sha256(file: directory.appendingPathComponent("Payload")),
        uncompressedPayloadSHA256: try Digests.sha256(file: archive),
        payload: records
      ),
      installKBytes: tree.installKBytes
    )
  }

  private func validateHostAllowlist(
    _ records: [PayloadRecord], configuration: ReleaseConfiguration
  ) throws {
    var expected: Set<String> = [
      ".", "./Library", "./Library/Application Support", "./Library/Application Support/Reach",
      "./Library/Application Support/Reach/Host", "./Library/Application Support/Reach/Host/reachd",
      "./Library/Application Support/Reach/Release",
      "./Library/Application Support/Reach/Release/LICENSE",
      "./Library/Application Support/Reach/Release/THIRD-PARTY-NOTICES.md",
      "./Library/Application Support/Reach/Release/payload-manifest.json",
      "./usr", "./usr/local", "./usr/local/bin", "./usr/local/bin/reachd",
    ]
    let files: [String: [String]] = [
      "mlx-swift_Cmlx.bundle": ["Info.plist", "Resources", "Resources/default.metallib"],
      "swift-crypto_CCryptoBoringSSL.bundle": [
        "Info.plist", "Resources", "Resources/PrivacyInfo.xcprivacy",
      ],
      "swift-crypto_CCryptoBoringSSLShims.bundle": [
        "Info.plist", "Resources", "Resources/PrivacyInfo.xcprivacy",
      ],
      "swift-crypto_Crypto.bundle": ["Info.plist", "Resources", "Resources/PrivacyInfo.xcprivacy"],
      "swift-crypto_CryptoBoringWrapper.bundle": [
        "Info.plist", "Resources", "Resources/PrivacyInfo.xcprivacy",
      ],
      "swift-crypto_CryptoExtras.bundle": [
        "Info.plist", "Resources", "Resources/PrivacyInfo.xcprivacy",
      ],
      "swift-transformers_Hub.bundle": [
        "Info.plist", "Resources", "Resources/gpt2_tokenizer_config.json",
        "Resources/t5_tokenizer_config.json",
      ],
    ]
    for bundle in configuration.hostBundles {
      guard let members = files[bundle] else {
        throw ReleasePackageError.invalidConfiguration(
          "bundle allowlist lacks structural authority")
      }
      let base = "./Library/Application Support/Reach/Host/\(bundle)"
      expected.insert(base)
      expected.insert(base + "/Contents")
      for member in members { expected.insert(base + "/Contents/" + member) }
    }
    guard Set(records.map(\.path)) == expected, records.count == 50 else {
      throw ReleasePackageError.verification("host payload path allowlist changed")
    }
    for record in records {
      let permissions = record.mode & 0o7777
      switch record.kind {
      case .directory:
        guard permissions == 0o755 else {
          throw ReleasePackageError.verification("host directory mode changed")
        }
      case .symlink:
        guard record.path == "./usr/local/bin/reachd", permissions == 0o777,
          record.linkTarget == "/Library/Application Support/Reach/Host/reachd"
        else { throw ReleasePackageError.verification("host alias authority changed") }
      case .file:
        let expectedMode: UInt32 =
          record.path == "./Library/Application Support/Reach/Host/reachd" ? 0o755 : 0o644
        guard permissions == expectedMode else {
          throw ReleasePackageError.verification("host file mode changed: \(record.path)")
        }
      }
    }
  }

  private func validateHelperAllowlist(_ records: [PayloadRecord]) throws {
    let expected = Set([
      ".", "./Library", "./Library/LaunchDaemons",
      "./Library/LaunchDaemons/systems.reach.meshd.plist",
      "./Library/PrivilegedHelperTools", "./Library/PrivilegedHelperTools/systems.reach.meshd",
    ])
    guard Set(records.map(\.path)) == expected, records.count == 6 else {
      throw ReleasePackageError.verification("helper payload path allowlist changed")
    }
    for record in records {
      let permissions = record.mode & 0o7777
      if record.kind == .directory {
        guard permissions == 0o755 else {
          throw ReleasePackageError.verification("helper directory mode changed")
        }
      } else if record.path.hasSuffix("systems.reach.meshd.plist") {
        guard permissions == 0o644 else {
          throw ReleasePackageError.verification("helper plist mode changed")
        }
      } else {
        guard permissions == 0o555 else {
          throw ReleasePackageError.verification("helper executable mode changed")
        }
      }
    }
  }

  private func inspectMachO(
    _ members: [ODCArchive.Member],
    path: String,
    scratch: URL,
    label: String,
    expectedIdentifier: String,
    logDirectory: URL
  ) throws -> [String] {
    guard let member = members.first(where: { $0.record.path == path }) else {
      throw ReleasePackageError.verification("missing Mach-O \(label)")
    }
    let executable = scratch.appendingPathComponent(label)
    try SecureFiles.atomicWrite(member.data, to: executable, mode: 0o700)
    let file = try runner.run(
      "/usr/bin/file", [executable.path],
      logURL: logDirectory.appendingPathComponent("verify-file-\(label).log")
    ).output
    guard file.contains("Mach-O 64-bit executable arm64"), !file.contains("universal"),
      !file.contains("x86_64")
    else {
      throw ReleasePackageError.verification("\(label) is not arm64-only")
    }
    let load = try runner.run(
      "/usr/bin/otool", ["-l", executable.path],
      logURL: logDirectory.appendingPathComponent("verify-otool-load-\(label).log")
    ).output
    guard !load.contains("__llvm_") else {
      throw ReleasePackageError.verification("coverage sections found in \(label)")
    }
    let libraries = try runner.run(
      "/usr/bin/otool", ["-L", executable.path],
      logURL: logDirectory.appendingPathComponent("verify-otool-libraries-\(label).log")
    ).output.split(separator: "\n").dropFirst().map {
      String($0).trimmingCharacters(in: .whitespaces).split(separator: " ").first.map(String.init)
        ?? ""
    }
    guard libraries.allSatisfy({ $0.hasPrefix("/System/Library/") || $0.hasPrefix("/usr/lib/") })
    else {
      throw ReleasePackageError.verification("non-system dynamic library in \(label)")
    }
    _ = try runner.run(
      "/usr/bin/codesign", ["--verify", "--strict", executable.path],
      logURL: logDirectory.appendingPathComponent("verify-codesign-\(label).log")
    )
    let signature = try runner.run(
      "/usr/bin/codesign", ["-d", "--verbose=4", executable.path],
      logURL: logDirectory.appendingPathComponent("verify-codesign-detail-\(label).log")
    )
    let signatureDetail = signature.output + signature.errorOutput
    guard signatureDetail.contains("Identifier=\(expectedIdentifier)\n"),
      signatureDetail.contains("Signature=adhoc\n"),
      signatureDetail.contains("TeamIdentifier=not set\n")
    else {
      throw ReleasePackageError.verification(
        "\(label) is not the expected deterministic ad-hoc code")
    }
    return libraries.sorted()
  }

  private func requireRegularFile(_ url: URL, label: String, mode: mode_t? = nil) throws {
    var info = stat()
    guard lstat(url.path, &info) == 0,
      (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1,
      mode == nil || (info.st_mode & 0o7777) == mode
    else {
      throw ReleasePackageError.unsafePath("\(label) must be a single-link regular file")
    }
  }

  private func requireDirectory(_ url: URL, label: String) throws {
    var info = stat()
    guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else {
      throw ReleasePackageError.unsafePath("\(label) must be a directory, not a link")
    }
  }

  private func provenanceArtifact(
    root: URL,
    path: String,
    fileOverride: URL? = nil
  ) throws -> ReleaseProvenance.Artifact {
    try SecureFiles.validateRelativePath(path)
    try requireDirectory(root, label: "provenance authority root")
    var cursor = root
    let components = path.split(separator: "/").map(String.init)
    for component in components.dropLast() {
      cursor.appendPathComponent(component)
      try requireDirectory(cursor, label: "provenance artifact parent")
    }
    let file = fileOverride ?? root.appendingPathComponent(path)
    try requireRegularFile(file, label: "provenance artifact \(path)", mode: 0o600)
    var info = stat()
    guard lstat(file.path, &info) == 0 else {
      throw ReleasePackageError.verification("cannot inspect provenance artifact \(path)")
    }
    return .init(
      path: path,
      size: UInt64(info.st_size),
      sha256: try Digests.sha256(file: file)
    )
  }

  private func validateTopLevelKeys(_ data: Data, expected: Set<String>) throws {
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(object.keys) == expected
    else {
      throw ReleasePackageError.verification(
        "provenance contains unknown or missing top-level stages")
    }
  }
}
