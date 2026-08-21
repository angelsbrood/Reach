import Darwin
import Foundation

public struct ComponentArtifact: Equatable, Sendable {
  public let identifier: String
  public let version: DottedVersion
  public let package: URL
  public let packageSHA256: String
  public let packageInfo: URL
  public let bom: URL
  public let payload: URL
  public let rawPayload: URL
  public let bomListing: Data
  public let semantics: ComponentSemantics
}

public struct OuterPackageArtifact: Equatable, Sendable {
  public let package: URL
  public let packageSHA256: String
  public let distribution: URL
  public let memberOrder: [String]
  public let toc: URL
}

public struct PackageAssembler {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
  }

  public func assembleComponent(
    payloadRoot: URL,
    identifier: String,
    version: DottedVersion,
    modificationTime: Int64,
    workspace: URL,
    outputPackage: URL,
    logDirectory: URL
  ) throws -> ComponentArtifact {
    try SecureFiles.createPrivateDirectory(workspace)
    let component = workspace.appendingPathComponent("component")
    try SecureFiles.createDirectory(component, mode: 0o700)
    let tree = try PayloadTree.inspect(root: payloadRoot)
    let raw = workspace.appendingPathComponent("Payload.raw")
    try tree.writeODC(to: raw, modificationTime: modificationTime)
    let parsed = try ODCArchive.parse(Data(contentsOf: raw, options: [.mappedIfSafe]))
    guard parsed == tree.records else {
      throw ReleasePackageError.verification("ODC round trip does not match payload authority")
    }

    _ = try runner.run(
      "/usr/bin/gzip",
      ["-9", "-n", "-k", raw.path],
      logURL: logDirectory.appendingPathComponent("gzip-\(identifier).log")
    )
    let gzip = URL(fileURLWithPath: raw.path + ".gz")
    try verifyDeterministicGzip(gzip)
    let payload = component.appendingPathComponent("Payload")
    try SecureFiles.copyRegularFile(from: gzip, to: payload, mode: 0o600)

    let bomInput = workspace.appendingPathComponent("BomInput")
    try SecureFiles.atomicWrite(tree.bomInput(), to: bomInput)
    let bom = component.appendingPathComponent("Bom")
    _ = try runner.run(
      "/usr/bin/mkbom",
      ["-i", bomInput.path, bom.path],
      logURL: logDirectory.appendingPathComponent("mkbom-\(identifier).log")
    )
    guard chmod(bom.path, 0o600) == 0 else {
      throw ReleasePackageError.verification("could not canonicalize BOM mode")
    }
    try SecureFiles.removeExtendedAttributes(bom)
    let listingResult = try runner.run(
      "/usr/bin/lsbom",
      [bom.path],
      logURL: logDirectory.appendingPathComponent("lsbom-\(identifier).log")
    )
    let listing = Data(listingResult.output.utf8)
    guard listing == expectedBOMListing(tree.records) else {
      throw ReleasePackageError.verification(
        "BOM does not match payload authority for \(identifier)")
    }

    let packageInfo = component.appendingPathComponent("PackageInfo")
    try SecureFiles.atomicWrite(
      PackageDocuments.packageInfo(identifier: identifier, version: version, tree: tree),
      to: packageInfo
    )
    try requireMode(0o600, at: packageInfo)
    try requireMode(0o600, at: bom)
    try requireMode(0o600, at: payload)

    _ = try runner.run(
      "/usr/bin/xar",
      [
        "-cf", outputPackage.path,
        "--distribution",
        "--no-compress", "^Payload$",
        "Bom", "Payload", "PackageInfo",
      ],
      currentDirectory: component,
      logURL: logDirectory.appendingPathComponent("xar-\(identifier).log")
    )
    guard chmod(outputPackage.path, 0o600) == 0 else {
      throw ReleasePackageError.verification("could not canonicalize component-package mode")
    }
    try SecureFiles.removeExtendedAttributes(outputPackage)
    let members = try runner.run(
      "/usr/bin/xar",
      ["-tf", outputPackage.path],
      logURL: logDirectory.appendingPathComponent("xar-list-\(identifier).log")
    ).output.split(separator: "\n").map(String.init)
    guard members == ["Bom", "Payload", "PackageInfo"] else {
      throw ReleasePackageError.verification(
        "component XAR has unexpected members for \(identifier)")
    }
    let semantics = ComponentSemantics(
      identifier: identifier,
      version: version,
      packageInfoSHA256: try Digests.sha256(file: packageInfo),
      bomSHA256: try Digests.sha256(file: bom),
      bomListingSHA256: Digests.sha256(listing),
      payloadSHA256: try Digests.sha256(file: payload),
      uncompressedPayloadSHA256: try Digests.sha256(file: raw),
      payload: tree.records
    )
    return ComponentArtifact(
      identifier: identifier,
      version: version,
      package: outputPackage,
      packageSHA256: try Digests.sha256(file: outputPackage),
      packageInfo: packageInfo,
      bom: bom,
      payload: payload,
      rawPayload: raw,
      bomListing: listing,
      semantics: semantics
    )
  }

  public func assembleOuterPackage(
    configuration: ReleaseConfiguration,
    hostComponent: URL,
    helperComponent: URL,
    workspace: URL,
    outputPackage: URL,
    logDirectory: URL
  ) throws -> OuterPackageArtifact {
    try SecureFiles.createPrivateDirectory(workspace)
    let components = workspace.appendingPathComponent("components")
    try SecureFiles.createDirectory(components, mode: 0o700)
    try SecureFiles.copyRegularFile(
      from: hostComponent,
      to: components.appendingPathComponent("systems.reach.host.pkg"),
      mode: 0o600
    )
    try SecureFiles.copyRegularFile(
      from: helperComponent,
      to: components.appendingPathComponent("systems.reach.meshd.pkg"),
      mode: 0o600
    )
    let distribution = workspace.appendingPathComponent("Distribution.xml")
    try SecureFiles.atomicWrite(
      PackageDocuments.distribution(configuration: configuration), to: distribution)
    _ = try runner.run(
      "/usr/bin/productbuild",
      [
        "--distribution", distribution.path,
        "--package-path", components.path,
        outputPackage.path,
      ],
      environment: ["HOME": workspace.path, "TMPDIR": workspace.path],
      logURL: logDirectory.appendingPathComponent("productbuild.log")
    )
    guard chmod(outputPackage.path, 0o600) == 0 else {
      throw ReleasePackageError.verification("could not canonicalize product-package mode")
    }
    try SecureFiles.removeExtendedAttributes(outputPackage)
    let members = try runner.run(
      "/usr/bin/xar",
      ["-tf", outputPackage.path],
      logURL: logDirectory.appendingPathComponent("outer-xar-list.log")
    ).output.split(separator: "\n").map(String.init)
    let expected = [
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
    guard members == expected,
      !members.contains(where: {
        $0 == "Scripts" || $0.hasPrefix("Scripts/") || $0 == "Resources"
          || $0.hasPrefix("Resources/")
      })
    else {
      throw ReleasePackageError.verification("outer package member authority changed")
    }
    let toc = workspace.appendingPathComponent("outer-toc.xml")
    _ = try runner.run(
      "/usr/bin/xar",
      ["--dump-toc=\(toc.path)", "-f", outputPackage.path],
      logURL: logDirectory.appendingPathComponent("outer-xar-toc.log")
    )
    return OuterPackageArtifact(
      package: outputPackage,
      packageSHA256: try Digests.sha256(file: outputPackage),
      distribution: distribution,
      memberOrder: members,
      toc: toc
    )
  }

  public func expectedBOMListing(_ records: [PayloadRecord]) -> Data {
    var result = ""
    for record in records {
      switch record.kind {
      case .directory:
        result += "\(record.path)\t\(record.bomMode)\t0/0\n"
      case .file:
        result +=
          "\(record.path)\t\(record.bomMode)\t0/0\t\(record.size)\t\(record.posixChecksum)\n"
      case .symlink:
        result +=
          "\(record.path)\t\(record.bomMode)\t0/0\t\(record.size)\t\(record.posixChecksum)\t\(record.linkTarget ?? "")\n"
      }
    }
    return Data(result.utf8)
  }

  private func verifyDeterministicGzip(_ url: URL) throws {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    guard data.count >= 10,
      data[0] == 0x1f, data[1] == 0x8b, data[2] == 8,
      data[3] == 0,
      data[4] == 0, data[5] == 0, data[6] == 0, data[7] == 0
    else {
      throw ReleasePackageError.verification(
        "gzip header contains a name, timestamp, or unsupported flags")
    }
  }

  private func requireMode(_ expected: mode_t, at url: URL) throws {
    var info = stat()
    guard lstat(url.path, &info) == 0, (info.st_mode & 0o7777) == expected else {
      throw ReleasePackageError.verification(
        "noncanonical component metadata mode at \(url.lastPathComponent)")
    }
  }
}
