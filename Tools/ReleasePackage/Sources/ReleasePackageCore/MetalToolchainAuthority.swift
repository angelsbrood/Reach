import Darwin
import Foundation

public struct MetalToolchainAuthority: Codable, Equatable, Sendable {
  public struct Metadata: Codable, Equatable, Sendable {
    public let path: String
    public let sha256: String

    public init(path: String, sha256: String) {
      self.path = path
      self.sha256 = sha256
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
      lhs.path.utf8.elementsEqual(rhs.path.utf8)
        && lhs.sha256.utf8.elementsEqual(rhs.sha256.utf8)
    }
  }

  public struct Tool: Codable, Equatable, Sendable {
    public let path: String
    public let resolvedPath: String
    public let sha256: String
    public let version: String

    public init(path: String, resolvedPath: String, sha256: String, version: String) {
      self.path = path
      self.resolvedPath = resolvedPath
      self.sha256 = sha256
      self.version = version
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
      lhs.path.utf8.elementsEqual(rhs.path.utf8)
        && lhs.resolvedPath.utf8.elementsEqual(rhs.resolvedPath.utf8)
        && lhs.sha256.utf8.elementsEqual(rhs.sha256.utf8)
        && lhs.version.utf8.elementsEqual(rhs.version.utf8)
    }
  }

  public let schemaVersion: Int
  public let componentIdentifier: String
  public let componentBuild: String
  public let metadata: [Metadata]
  public let tools: [Tool]

  public init(
    schemaVersion: Int = 1,
    componentIdentifier: String,
    componentBuild: String,
    metadata: [Metadata],
    tools: [Tool]
  ) {
    self.schemaVersion = schemaVersion
    self.componentIdentifier = componentIdentifier
    self.componentBuild = componentBuild
    self.metadata = metadata
    self.tools = tools
  }

  public static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.schemaVersion == rhs.schemaVersion
      && lhs.componentIdentifier.utf8.elementsEqual(rhs.componentIdentifier.utf8)
      && lhs.componentBuild.utf8.elementsEqual(rhs.componentBuild.utf8)
      && lhs.metadata == rhs.metadata
      && lhs.tools == rhs.tools
  }

  public func validate() throws {
    let sha = #"^[0-9a-f]{64}$"#
    let expectedMetadata = [
      "ToolchainInfo.plist",
      "usr/metal/32023/ToolchainInfo.json",
      "usr/metal/32023/ToolchainInfo.plist",
    ]
    let expectedTools = ["usr/bin/metal", "usr/bin/metallib"]
    guard schemaVersion == 1,
      componentIdentifier.range(
        of: #"^com\.apple\.dt\.toolchain\.Metal\.[A-Za-z0-9.]+$"#,
        options: .regularExpression) != nil,
      componentBuild.range(of: #"^[A-Za-z0-9]+$"#, options: .regularExpression) != nil,
      metadata.map(\.path) == expectedMetadata,
      tools.map(\.path) == expectedTools,
      metadata.allSatisfy({
        $0.sha256.range(of: sha, options: .regularExpression) != nil
      }),
      tools.allSatisfy({
        $0.resolvedPath.range(
          of: #"^usr/bin/[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil
          && $0.sha256.range(of: sha, options: .regularExpression) != nil
          && !$0.version.isEmpty
          && !$0.version.contains("/private/var/run/com.apple.security.cryptexd/mnt/")
      })
    else {
      throw ReleasePackageError.verification("Metal toolchain authority is malformed")
    }
  }
}

struct MetalComponentRecord: Equatable {
  let assetPath: String
  let build: String
  let status: String
  let identifier: String
  let searchPath: String

  static func parse(_ output: String) throws -> Self {
    let lines = output.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    let nonempty = lines.filter { !$0.isEmpty }
    let labels = [
      "Asset Path: ", "Build Version: ", "Status: ", "Toolchain Identifier: ",
      "Toolchain Search Path: ",
    ]
    guard nonempty.count == labels.count else {
      throw ReleasePackageError.verification(
        "Metal component query did not return one exact installed record")
    }
    var values: [String] = []
    for (line, label) in zip(nonempty, labels) {
      guard line.hasPrefix(label) else {
        throw ReleasePackageError.verification(
          "Metal component query returned malformed or duplicate fields")
      }
      let value = String(line.dropFirst(label.count))
      guard !value.isEmpty, !value.contains("\0") else {
        throw ReleasePackageError.verification("Metal component field is empty")
      }
      values.append(value)
    }
    let record = Self(
      assetPath: values[0], build: values[1], status: values[2], identifier: values[3],
      searchPath: values[4])
    guard record.status == "installed" else {
      throw ReleasePackageError.verification("Metal component is not installed")
    }
    guard
      record.assetPath.hasPrefix(
        "/System/Library/AssetsV2/com_apple_MobileAsset_MetalToolchain/"),
      record.assetPath.hasSuffix(".asset/AssetData"),
      record.identifier.range(
        of: #"^com\.apple\.dt\.toolchain\.Metal\.[A-Za-z0-9.]+$"#,
        options: .regularExpression) != nil,
      record.build.range(of: #"^[A-Za-z0-9]+$"#, options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("Metal component identity is malformed")
    }
    let mountPrefix = "/private/var/run/com.apple.security.cryptexd/mnt/"
    guard record.searchPath.hasPrefix(mountPrefix) else {
      throw ReleasePackageError.verification(
        "Metal component is outside the cryptex mount boundary")
    }
    let mountName = String(record.searchPath.dropFirst(mountPrefix.count))
    guard
      mountName.range(
        of: #"^com\.apple\.MobileAsset\.MetalToolchain-[A-Za-z0-9._-]+$"#,
        options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("Metal component mount path is malformed")
    }
    return record
  }
}

struct MetalToolchainVnode: Equatable {
  let device: UInt64
  let inode: UInt64
}

struct MountedMetalToolchain: Equatable {
  let record: MetalComponentRecord
  let root: URL
  let rootVnode: MetalToolchainVnode
  let memberVnodes: [String: MetalToolchainVnode]
  let authority: MetalToolchainAuthority
}

struct GeneratedMetalSourceNormalizationReport: Codable, Equatable {
  struct Entry: Codable, Equatable {
    let path: String
    let inputSHA256: String
    let outputSHA256: String
    let replacementCount: Int
  }

  let schemaVersion: Int
  let sourceMountSHA256: String
  let stableRoot: String
  let entries: [Entry]
}

enum GeneratedMetalSourceNormalizer {
  static let stableRoot = "/Reach/MetalToolchain"
  private static let transientRootPattern =
    #"/private/var/run/com\.apple\.security\.cryptexd/mnt/com\.apple\.MobileAsset\.MetalToolchain-[A-Za-z0-9._-]+/Metal\.xctoolchain"#
  private static let inputs: [(path: String, sha256: String)] = [
    (
      "checkouts/mlx-swift/Source/Cmlx/mlx-generated/gemm_nax.cpp",
      "69026a166cc7e3e4f3d41de5827f582d7d8225187a9a00b463f1cf02b3f8d6c6"
    ),
    (
      "checkouts/mlx-swift/Source/Cmlx/mlx-generated/steel_attention_nax.cpp",
      "987f765c2a2ea4067c42dd05d06fc87703f5b2745f3b4f18cd012fb454adf1f6"
    ),
  ]

  static func normalize(scratch: URL, reportURL: URL) throws {
    var entries: [GeneratedMetalSourceNormalizationReport.Entry] = []
    var sourceMount: String?
    for input in inputs {
      let url = scratch.appendingPathComponent(input.path)
      let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
      guard descriptor >= 0 else {
        throw ReleasePackageError.verification(
          "cannot open pinned generated Metal source: \(input.path)")
      }
      let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
      var info = stat()
      guard fstat(descriptor, &info) == 0,
        (info.st_mode & S_IFMT) == S_IFREG,
        info.st_nlink == 1,
        info.st_mode & (S_IWGRP | S_IWOTH) == 0,
        info.st_size > 0,
        info.st_size <= 64 * 1_024 * 1_024
      else {
        try? handle.close()
        throw ReleasePackageError.verification(
          "pinned generated Metal source has unsafe authority: \(input.path)")
      }
      let data: Data
      do {
        data = try handle.readToEnd() ?? Data()
        try handle.close()
      } catch {
        try? handle.close()
        throw ReleasePackageError.verification(
          "cannot read pinned generated Metal source: \(input.path)")
      }
      guard data.count == Int(info.st_size), Digests.sha256(data) == input.sha256 else {
        throw ReleasePackageError.verification(
          "pinned generated Metal source changed before normalization: \(input.path)")
      }
      let normalized = try normalizeContents(data)
      if let existing = sourceMount {
        guard existing.utf8.elementsEqual(normalized.sourceMount.utf8) else {
          throw ReleasePackageError.verification(
            "generated Metal sources name different transient authorities")
        }
      } else {
        sourceMount = normalized.sourceMount
      }
      try SecureFiles.atomicWrite(normalized.data, to: url, mode: 0o644)
      entries.append(
        .init(
          path: input.path,
          inputSHA256: input.sha256,
          outputSHA256: Digests.sha256(normalized.data),
          replacementCount: normalized.replacementCount))
    }
    guard let sourceMount else {
      throw ReleasePackageError.verification("generated Metal source authority is empty")
    }
    let report = GeneratedMetalSourceNormalizationReport(
      schemaVersion: 1,
      sourceMountSHA256: Digests.sha256(Data(sourceMount.utf8)),
      stableRoot: stableRoot,
      entries: entries)
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(report), to: reportURL)
  }

  static func normalizeContents(_ data: Data) throws -> (
    data: Data, sourceMount: String, replacementCount: Int
  ) {
    guard let text = String(data: data, encoding: .utf8),
      !text.contains(stableRoot)
    else {
      throw ReleasePackageError.verification(
        "generated Metal source is non-UTF8 or already normalized")
    }
    let expression = try NSRegularExpression(pattern: transientRootPattern)
    let range = NSRange(text.startIndex..<text.endIndex, in: text)
    let matches = expression.matches(in: text, range: range)
    guard matches.count == 2 else {
      throw ReleasePackageError.verification(
        "generated Metal source has an unexpected transient-path cardinality")
    }
    let values = matches.compactMap { match -> String? in
      guard let swiftRange = Range(match.range, in: text) else { return nil }
      return String(text[swiftRange])
    }
    guard values.count == 2, values[0].utf8.elementsEqual(values[1].utf8) else {
      throw ReleasePackageError.verification(
        "generated Metal source has ambiguous transient authority")
    }
    let normalized = text.replacingOccurrences(of: values[0], with: stableRoot)
    guard !normalized.contains("/private/var/run/com.apple.security.cryptexd/mnt/"),
      normalized.components(separatedBy: stableRoot).count - 1 == 2
    else {
      throw ReleasePackageError.verification(
        "generated Metal source normalization did not close the transient path")
    }
    return (Data(normalized.utf8), values[0], matches.count)
  }
}

struct InstalledMetalToolchainResolver {
  typealias Query = (_ logURL: URL) throws -> String
  typealias Inspect = (_ record: MetalComponentRecord) throws -> MountedMetalToolchain

  private let query: Query
  private let inspect: Inspect

  init(runner: ProcessRunner) {
    query = { logURL in
      try runner.run(
        "/usr/bin/xcodebuild", ["-showComponent", "MetalToolchain"],
        environment: [:], logURL: logURL, redactedArguments: [:]
      ).output
    }
    inspect = { record in
      try Self.inspectInstalled(record, runner: runner)
    }
  }

  init(query: @escaping Query, inspect: @escaping Inspect) {
    self.query = query
    self.inspect = inspect
  }

  func resolve(logURL: URL) throws -> MountedMetalToolchain {
    let record = try MetalComponentRecord.parse(query(logURL))
    let mounted = try inspect(record)
    try mounted.authority.validate()
    guard mounted.record == record else {
      throw ReleasePackageError.verification("Metal component changed during inspection")
    }
    return mounted
  }

  func revalidate(_ expected: MountedMetalToolchain, logURL: URL) throws {
    let current = try resolve(logURL: logURL)
    guard current == expected else {
      throw ReleasePackageError.verification(
        "Metal toolchain mount, vnode, metadata, tool hash, or version changed during release work")
    }
  }

  @discardableResult
  func requireAuthority(
    _ expected: MetalToolchainAuthority, logURL: URL
  ) throws -> MountedMetalToolchain {
    try expected.validate()
    let current = try resolve(logURL: logURL)
    guard current.authority == expected else {
      throw ReleasePackageError.verification(
        "installed Metal authority does not match the declared build authority")
    }
    return current
  }

  private static func inspectInstalled(
    _ record: MetalComponentRecord, runner: ProcessRunner
  ) throws -> MountedMetalToolchain {
    let search = try ReleasePathAuthority.absoluteURL(
      record.searchPath, label: "installed Metal component search path")
    let root = try ReleasePathAuthority.absoluteURL(
      search.appendingPathComponent("Metal.xctoolchain").path,
      label: "installed Metal toolchain root")
    let rootInfo = try inspectDirectory(root, label: "Metal toolchain root")
    var filesystem = statfs()
    guard statfs(root.path, &filesystem) == 0 else {
      throw ReleasePackageError.verification("cannot inspect Metal toolchain filesystem")
    }
    try validateRootSecurity(
      uid: rootInfo.uid,
      mode: rootInfo.mode,
      readOnly: filesystem.f_flags & UInt32(MNT_RDONLY) != 0)

    let metadataPaths = [
      "ToolchainInfo.plist",
      "usr/metal/32023/ToolchainInfo.json",
      "usr/metal/32023/ToolchainInfo.plist",
    ]
    let toolPaths = ["usr/bin/metal", "usr/bin/metallib"]
    var memberVnodes: [String: MetalToolchainVnode] = [:]
    var metadata: [MetalToolchainAuthority.Metadata] = []
    var metadataData: [String: Data] = [:]
    for path in metadataPaths {
      let inspected = try inspectRegularFile(root.appendingPathComponent(path), label: path)
      memberVnodes[path] = inspected.vnode
      metadataData[path] = inspected.data
      metadata.append(.init(path: path, sha256: Digests.sha256(inspected.data)))
    }
    guard let rootMetadataData = metadataData["ToolchainInfo.plist"] else {
      throw ReleasePackageError.verification("Metal root metadata is missing")
    }
    let rootMetadata = try PropertyListSerialization.propertyList(
      from: rootMetadataData, options: [], format: nil)
    guard let dictionary = rootMetadata as? [String: Any], dictionary.count == 1,
      dictionary["Identifier"] as? String == record.identifier
    else {
      throw ReleasePackageError.verification(
        "Metal toolchain metadata does not match the installed component")
    }

    let toolExecutables = Set(toolPaths.map { root.appendingPathComponent($0).path })
    let versionRunner = ProcessRunner(authenticatedMetalExecutables: toolExecutables)
    var tools: [MetalToolchainAuthority.Tool] = []
    for path in toolPaths {
      let url = root.appendingPathComponent(path)
      let inspected = try inspectTool(root: root, path: path)
      memberVnodes[path] = inspected.aliasVnode
      memberVnodes[inspected.resolvedPath] = inspected.executableVnode
      let versionResult = try versionRunner.run(
        url.path, ["--version"], environment: [:], redactedArguments: [:])
      let normalizedVersion = normalizeVersion(
        versionResult.output + versionResult.errorOutput, root: root.path)
      guard !normalizedVersion.isEmpty else {
        throw ReleasePackageError.verification("Metal tool version is empty: \(path)")
      }
      tools.append(
        .init(
          path: path,
          resolvedPath: inspected.resolvedPath,
          sha256: Digests.sha256(inspected.data),
          version: normalizedVersion))
    }
    let authority = MetalToolchainAuthority(
      componentIdentifier: record.identifier,
      componentBuild: record.build,
      metadata: metadata,
      tools: tools)
    try authority.validate()
    return MountedMetalToolchain(
      record: record,
      root: root,
      rootVnode: rootInfo.vnode,
      memberVnodes: memberVnodes,
      authority: authority)
  }

  struct RootInfo {
    let vnode: MetalToolchainVnode
    let uid: uid_t
    let mode: mode_t
  }

  static func validateRootSecurity(uid: uid_t, mode: mode_t, readOnly: Bool) throws {
    guard uid == 0, mode & (S_IWGRP | S_IWOTH) == 0, readOnly else {
      throw ReleasePackageError.verification(
        "Metal toolchain root is writable, substituted, or non-root")
    }
  }

  private static func inspectDirectory(_ url: URL, label: String) throws -> RootInfo {
    var info = stat()
    guard lstat(url.path, &info) == 0,
      (info.st_mode & S_IFMT) == S_IFDIR
    else {
      throw ReleasePackageError.verification("\(label) is not immutable root authority")
    }
    return .init(
      vnode: .init(device: UInt64(info.st_dev), inode: UInt64(info.st_ino)),
      uid: info.st_uid,
      mode: info.st_mode)
  }

  private static func inspectRegularFile(
    _ url: URL, label: String
  ) throws -> (data: Data, vnode: MetalToolchainVnode) {
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open Metal authority member \(label)")
    }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    var info = stat()
    guard fstat(descriptor, &info) == 0,
      (info.st_mode & S_IFMT) == S_IFREG,
      info.st_uid == 0,
      info.st_mode & (S_IWGRP | S_IWOTH) == 0
    else {
      try? handle.close()
      throw ReleasePackageError.verification(
        "Metal authority member is writable, substituted, or non-root: \(label)")
    }
    let data: Data
    do {
      data = try handle.readToEnd() ?? Data()
      try handle.close()
    } catch {
      try? handle.close()
      throw ReleasePackageError.verification("cannot read Metal authority member \(label)")
    }
    guard data.count == Int(info.st_size) else {
      throw ReleasePackageError.verification("Metal authority member changed while read: \(label)")
    }
    return (data, .init(device: UInt64(info.st_dev), inode: UInt64(info.st_ino)))
  }

  private static func inspectTool(
    root: URL, path: String
  ) throws -> (
    data: Data,
    aliasVnode: MetalToolchainVnode,
    resolvedPath: String,
    executableVnode: MetalToolchainVnode
  ) {
    let url = root.appendingPathComponent(path)
    var info = stat()
    guard lstat(url.path, &info) == 0, info.st_uid == 0, info.st_nlink == 1 else {
      throw ReleasePackageError.verification(
        "Metal tool alias is missing, substituted, or non-root: \(path)")
    }
    let aliasVnode = MetalToolchainVnode(
      device: UInt64(info.st_dev), inode: UInt64(info.st_ino))
    if (info.st_mode & S_IFMT) == S_IFREG {
      let executable = try inspectRegularFile(url, label: path)
      return (executable.data, aliasVnode, path, executable.vnode)
    }
    guard (info.st_mode & S_IFMT) == S_IFLNK else {
      throw ReleasePackageError.verification("Metal tool alias has an unsafe type: \(path)")
    }
    var bytes = [UInt8](repeating: 0, count: Int(PATH_MAX))
    let count = readlink(url.path, &bytes, bytes.count)
    guard count > 0, count < bytes.count,
      let target = String(bytes: bytes[..<count], encoding: .utf8),
      target.range(of: #"^[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("Metal tool alias target is unsafe: \(path)")
    }
    let parent = path.split(separator: "/").dropLast().joined(separator: "/")
    let resolvedPath = parent + "/" + target
    let executable = try inspectRegularFile(
      root.appendingPathComponent(resolvedPath), label: resolvedPath)
    return (executable.data, aliasVnode, resolvedPath, executable.vnode)
  }

  private static func normalizeVersion(_ raw: String, root: String) -> String {
    raw.replacingOccurrences(of: root, with: "<METAL_TOOLCHAIN>")
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }
}

enum SwiftBuildMetalGraphVerifier {
  struct ExecutionIdentity {
    let physicalPath: String
    let vnode: MetalToolchainVnode
  }

  private struct UTF8PathIdentity: Hashable {
    let bytes: Data

    init(_ value: String) {
      bytes = Data(value.utf8)
    }
  }

  private struct Manifest: Decodable {
    let commands: [String: Command]
  }

  private struct Command: Decodable {
    let tool: String
    let description: String?
    let args: [String]?
  }

  private enum Role {
    case compile(source: UTF8PathIdentity)
    case link(output: UTF8PathIdentity)
  }

  private struct BoundEntry {
    let parentDescriptor: Int32
    let name: Data
    let vnode: MetalToolchainVnode
    let fileType: mode_t
    let maximumParentEntries: Int
    let label: String
  }

  private static let maximumXCBuildDataEntries = 8
  private static let maximumManifestEntries = 16
  private static let maximumManifestBytes = 32 * 1_024 * 1_024
  private static let maximumCommands = 10_000
  private static let maximumAuthorityDirectoryEntries = 4_096
  private static let expectedCompileInputs: [(source: String, air: String)] = [
    ("arg_reduce.metal", "arg_reduce.air"),
    ("conv.metal", "conv.air"),
    ("gemv.metal", "gemv.air"),
    ("layer_norm.metal", "layer_norm.air"),
    ("random.metal", "random.air"),
    ("rms_norm.metal", "rms_norm.air"),
    ("rope.metal", "rope.air"),
    ("scaled_dot_product_attention.metal", "scaled_dot_product_attention.air"),
    ("steel/attn/kernels/steel_attention.metal", "steel_attention.air"),
  ]

  static func verify(
    scratch: URL,
    buildLog: URL,
    mounted: MountedMetalToolchain,
    inspectExecution: (String) throws -> ExecutionIdentity = inspectExecutionPath
  ) throws {
    _ = buildLog
    let data = try readManifest(below: scratch)
    let manifest: Manifest
    do {
      manifest = try JSONDecoder().decode(Manifest.self, from: data)
    } catch {
      throw ReleasePackageError.verification("retained XCBuild manifest is invalid JSON")
    }
    guard !manifest.commands.isEmpty, manifest.commands.count <= maximumCommands else {
      throw ReleasePackageError.verification("retained XCBuild command graph is unbounded")
    }

    guard let metal = mounted.authority.tools.first(where: { $0.path == "usr/bin/metal" }),
      let expectedVnode = mounted.memberVnodes[metal.resolvedPath]
    else {
      throw ReleasePackageError.verification("frozen Metal compiler authority is incomplete")
    }
    let expectedPhysical = mounted.root.appendingPathComponent(metal.resolvedPath).path
    let compileRoot = scratch.appendingPathComponent(
      "checkouts/mlx-swift/Source/Cmlx/mlx-generated/metal", isDirectory: true)
    let airRoot = scratch.appendingPathComponent(
      "out/Intermediates.noindex/mlx-swift.build/Release/"
        + "mlx-swift_Cmlx-b.build/Metal",
      isDirectory: true)
    let expectedCompileGraph: [UTF8PathIdentity: UTF8PathIdentity] = Dictionary(
      uniqueKeysWithValues: expectedCompileInputs.map {
        (
          UTF8PathIdentity(compileRoot.appendingPathComponent($0.source).path),
          UTF8PathIdentity(airRoot.appendingPathComponent($0.air).path)
        )
      })
    let expectedAIR = Set(expectedCompileGraph.values)
    let expectedLinkOutput = UTF8PathIdentity(
      scratch.appendingPathComponent(
        "out/Products/Release/mlx-swift_Cmlx.bundle/Contents/Resources/default.metallib"
      ).path)
    var compileSources = Set<UTF8PathIdentity>()
    var linkCount = 0

    for (key, command) in manifest.commands {
      let description = command.description ?? ""
      let arguments = command.args ?? []
      let role = try classify(
        key: key, description: description, arguments: arguments)
      guard let role else { continue }
      guard command.tool == "shell" else {
        throw ReleasePackageError.verification(
          "retained Metal role is not an XCBuild shell task")
      }
      guard let executable = arguments.first, executable.hasPrefix("/"),
        !executable.contains("\0")
      else {
        throw ReleasePackageError.verification(
          "retained Metal task did not use an absolute executable")
      }
      let identity = try inspectExecution(executable)
      guard identity.physicalPath.utf8.elementsEqual(expectedPhysical.utf8),
        identity.vnode == expectedVnode
      else {
        throw ReleasePackageError.verification(
          "retained Metal task did not resolve to frozen physical authority")
      }

      switch role {
      case .compile(let source):
        guard let expectedAir = expectedCompileGraph[source],
          compileSources.insert(source).inserted,
          arguments.filter({ $0.hasSuffix(".metal") }).map(UTF8PathIdentity.init) == [source],
          arguments.filter({ $0.hasSuffix(".air") }).map(UTF8PathIdentity.init) == [expectedAir],
          arguments.dropFirst().first == "-c"
        else {
          throw ReleasePackageError.verification(
            "retained MLX Metal compile role changed")
        }
      case .link(let output):
        linkCount += 1
        let linkAIR = arguments.filter { $0.hasSuffix(".air") }.map(UTF8PathIdentity.init)
        guard linkCount == 1, output == expectedLinkOutput,
          arguments.filter({ $0.hasSuffix(".metal") }).isEmpty,
          linkAIR.count == expectedAIR.count, Set(linkAIR) == expectedAIR,
          arguments.filter({ $0.hasSuffix(".metallib") }).map(UTF8PathIdentity.init) == [output],
          !arguments.dropFirst().contains("-c")
        else {
          throw ReleasePackageError.verification("retained Metal AIR link role changed")
        }
      }
    }
    guard compileSources == Set(expectedCompileGraph.keys), linkCount == 1 else {
      throw ReleasePackageError.verification(
        "retained XCBuild manifest lacks the exact MLX Metal compile/link graph")
    }
  }

  private static func readManifest(below scratch: URL) throws -> Data {
    let exactScratch = try ReleasePathAuthority.absoluteURL(
      scratch.path, label: "retained XCBuild scratch authority")
    guard exactScratch.path.utf8.elementsEqual(scratch.path.utf8) else {
      throw ReleasePackageError.verification(
        "retained XCBuild scratch authority changed spelling")
    }
    let rootDescriptor = open(
      exactScratch.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard rootDescriptor >= 0 else {
      throw ReleasePackageError.verification("cannot anchor retained XCBuild scratch authority")
    }
    var descriptors = [rootDescriptor]
    defer {
      for descriptor in descriptors.reversed() {
        close(descriptor)
      }
    }
    let rootVnode = try requireOpenedDirectory(
      rootDescriptor, label: "retained XCBuild scratch authority")
    try requirePathStillNames(
      exactScratch, vnode: rootVnode, label: "retained XCBuild scratch authority")

    var bindings: [BoundEntry] = []
    func descend(
      from parent: Int32,
      name: Data,
      maximumParentEntries: Int,
      label: String
    ) throws -> Int32 {
      let opened = try openBoundDirectory(
        at: parent, name: name, maximumParentEntries: maximumParentEntries, label: label)
      descriptors.append(opened.descriptor)
      bindings.append(opened.binding)
      return opened.descriptor
    }

    let out = try descend(
      from: rootDescriptor, name: Data("out".utf8),
      maximumParentEntries: maximumAuthorityDirectoryEntries, label: "out")
    let intermediates = try descend(
      from: out, name: Data("Intermediates.noindex".utf8),
      maximumParentEntries: maximumAuthorityDirectoryEntries,
      label: "Intermediates.noindex")
    let xcBuildData = try descend(
      from: intermediates, name: Data("XCBuildData".utf8),
      maximumParentEntries: maximumAuthorityDirectoryEntries, label: "XCBuildData")
    let xcBuildEntries = try directoryEntryNames(
      xcBuildData, maximum: maximumXCBuildDataEntries, label: "XCBuildData")
    let candidates = xcBuildEntries.filter(isXCBuildDataName)
    guard candidates.count == 1 else {
      throw ReleasePackageError.verification(
        "retained XCBuild manifest authority is missing or ambiguous")
    }
    let manifestDirectory = try descend(
      from: xcBuildData, name: candidates[0],
      maximumParentEntries: maximumXCBuildDataEntries,
      label: "XCBuild manifest directory")
    let manifest = try readBoundRegularFile(
      at: manifestDirectory, name: Data("manifest.json".utf8),
      maximumParentEntries: maximumManifestEntries, label: "XCBuild manifest")
    bindings.append(manifest.binding)

    for binding in bindings {
      try revalidate(binding)
    }
    try requirePathStillNames(
      exactScratch, vnode: rootVnode, label: "retained XCBuild scratch authority")
    return manifest.data
  }

  private static func openBoundDirectory(
    at parentDescriptor: Int32,
    name: Data,
    maximumParentEntries: Int,
    label: String
  ) throws -> (descriptor: Int32, binding: BoundEntry) {
    let entries = try directoryEntryNames(
      parentDescriptor, maximum: maximumParentEntries, label: label)
    try requireExactEntry(name, in: entries, label: label)
    let systemName = try exactSystemName(name, label: label)
    var before = stat()
    guard fstatat(parentDescriptor, systemName, &before, AT_SYMLINK_NOFOLLOW) == 0,
      (before.st_mode & S_IFMT) == S_IFDIR
    else {
      throw ReleasePackageError.verification("retained \(label) is not a physical directory")
    }
    let descriptor = openat(
      parentDescriptor, systemName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open retained \(label) authority")
    }
    do {
      let openedVnode = try requireOpenedDirectory(descriptor, label: label)
      guard openedVnode == vnode(of: before) else {
        throw ReleasePackageError.verification("retained \(label) changed while opening")
      }
      var after = stat()
      guard fstatat(parentDescriptor, systemName, &after, AT_SYMLINK_NOFOLLOW) == 0,
        (after.st_mode & S_IFMT) == S_IFDIR, vnode(of: after) == openedVnode
      else {
        throw ReleasePackageError.verification("retained \(label) changed while binding")
      }
      return (
        descriptor,
        .init(
          parentDescriptor: parentDescriptor, name: name, vnode: openedVnode,
          fileType: S_IFDIR, maximumParentEntries: maximumParentEntries, label: label)
      )
    } catch {
      close(descriptor)
      throw error
    }
  }

  private static func readBoundRegularFile(
    at parentDescriptor: Int32,
    name: Data,
    maximumParentEntries: Int,
    label: String
  ) throws -> (data: Data, binding: BoundEntry) {
    let entries = try directoryEntryNames(
      parentDescriptor, maximum: maximumParentEntries, label: label)
    try requireExactEntry(name, in: entries, label: label)
    let systemName = try exactSystemName(name, label: label)
    var before = stat()
    guard fstatat(parentDescriptor, systemName, &before, AT_SYMLINK_NOFOLLOW) == 0,
      (before.st_mode & S_IFMT) == S_IFREG, before.st_nlink == 1,
      before.st_size > 0, before.st_size <= maximumManifestBytes
    else {
      throw ReleasePackageError.verification("retained \(label) is unsafe or oversized")
    }
    let descriptor = openat(parentDescriptor, systemName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open retained \(label)")
    }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    do {
      var opened = stat()
      guard fstat(descriptor, &opened) == 0, sameFileAuthority(before, opened) else {
        throw ReleasePackageError.verification("retained \(label) changed while opening")
      }
      let data = try handle.readToEnd() ?? Data()
      var after = stat()
      guard fstat(descriptor, &after) == 0, sameFileAuthority(opened, after),
        data.count == Int(opened.st_size), data.count <= maximumManifestBytes
      else {
        throw ReleasePackageError.verification("retained \(label) changed while read")
      }
      try handle.close()
      return (
        data,
        .init(
          parentDescriptor: parentDescriptor, name: name, vnode: vnode(of: opened),
          fileType: S_IFREG, maximumParentEntries: maximumParentEntries, label: label)
      )
    } catch let error as ReleasePackageError {
      try? handle.close()
      throw error
    } catch {
      try? handle.close()
      throw ReleasePackageError.verification("cannot read retained \(label)")
    }
  }

  private static func directoryEntryNames(
    _ descriptor: Int32,
    maximum: Int,
    label: String
  ) throws -> [Data] {
    let enumerationDescriptor = openat(
      descriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard enumerationDescriptor >= 0 else {
      throw ReleasePackageError.verification("cannot enumerate retained \(label) authority")
    }
    guard let directory = fdopendir(enumerationDescriptor) else {
      close(enumerationDescriptor)
      throw ReleasePackageError.verification("cannot enumerate retained \(label) authority")
    }
    defer { closedir(directory) }
    let dot = Data(".".utf8)
    let dotDot = Data("..".utf8)
    var entries: [Data] = []
    while true {
      errno = 0
      guard let entry = readdir(directory) else {
        guard errno == 0 else {
          throw ReleasePackageError.verification(
            "cannot complete retained \(label) enumeration")
        }
        break
      }
      let length = Int(entry.pointee.d_namlen)
      let bytes = withUnsafeBytes(of: &entry.pointee.d_name) {
        Data($0.prefix(length))
      }
      if bytes == dot || bytes == dotDot { continue }
      entries.append(bytes)
      guard entries.count <= maximum else {
        throw ReleasePackageError.verification("retained \(label) directory is unbounded")
      }
    }
    return entries
  }

  private static func requireExactEntry(
    _ expected: Data,
    in entries: [Data],
    label: String
  ) throws {
    guard entries.filter({ $0 == expected }).count == 1 else {
      throw ReleasePackageError.verification(
        "retained \(label) lacks its exact on-disk byte spelling")
    }
  }

  private static func exactSystemName(_ data: Data, label: String) throws -> String {
    guard let name = String(data: data, encoding: .utf8), !name.isEmpty,
      !name.contains("/"), !name.contains("\0"), Data(name.utf8) == data
    else {
      throw ReleasePackageError.verification("retained \(label) name is unsafe")
    }
    return name
  }

  private static func isXCBuildDataName(_ name: Data) -> Bool {
    let suffix = Data(".xcbuilddata".utf8)
    guard name.count == 32 + suffix.count, name.suffix(suffix.count) == suffix else {
      return false
    }
    return name.prefix(32).allSatisfy { byte in
      (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
        || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte)
    }
  }

  private static func requireOpenedDirectory(
    _ descriptor: Int32,
    label: String
  ) throws -> MetalToolchainVnode {
    var info = stat()
    guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else {
      throw ReleasePackageError.verification("retained \(label) is not an opened directory")
    }
    return vnode(of: info)
  }

  private static func requirePathStillNames(
    _ url: URL,
    vnode expected: MetalToolchainVnode,
    label: String
  ) throws {
    let exact = try ReleasePathAuthority.absoluteURL(url.path, label: label)
    guard exact.path.utf8.elementsEqual(url.path.utf8) else {
      throw ReleasePackageError.verification("retained \(label) changed spelling")
    }
    let descriptor = open(exact.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot re-open retained \(label)")
    }
    defer { close(descriptor) }
    guard try requireOpenedDirectory(descriptor, label: label) == expected else {
      throw ReleasePackageError.verification("retained \(label) vnode changed")
    }
  }

  private static func revalidate(_ binding: BoundEntry) throws {
    let entries = try directoryEntryNames(
      binding.parentDescriptor, maximum: binding.maximumParentEntries,
      label: binding.label)
    try requireExactEntry(binding.name, in: entries, label: binding.label)
    let systemName = try exactSystemName(binding.name, label: binding.label)
    var info = stat()
    guard fstatat(binding.parentDescriptor, systemName, &info, AT_SYMLINK_NOFOLLOW) == 0,
      (info.st_mode & S_IFMT) == binding.fileType,
      vnode(of: info) == binding.vnode
    else {
      throw ReleasePackageError.verification("retained \(binding.label) binding changed")
    }
  }

  private static func vnode(of info: stat) -> MetalToolchainVnode {
    .init(device: UInt64(info.st_dev), inode: UInt64(info.st_ino))
  }

  private static func sameFileAuthority(_ lhs: stat, _ rhs: stat) -> Bool {
    vnode(of: lhs) == vnode(of: rhs)
      && (lhs.st_mode & S_IFMT) == S_IFREG
      && (rhs.st_mode & S_IFMT) == S_IFREG
      && lhs.st_nlink == 1 && rhs.st_nlink == 1
      && lhs.st_size == rhs.st_size
      && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
      && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
      && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
      && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
  }

  private static func classify(
    key: String, description: String, arguments: [String]
  ) throws -> Role? {
    let compilePrefix = "CompileMetalFile "
    let linkPrefix = "MetalLink "
    let keyCompile = key.range(of: ":\(compilePrefix)")
    let keyLink = key.range(of: ":\(linkPrefix)")
    let descriptionCompile = description.hasPrefix(compilePrefix)
    let descriptionLink = description.hasPrefix(linkPrefix)
    let executableName =
      arguments.first.map {
        URL(fileURLWithPath: $0).lastPathComponent.lowercased()
      } ?? ""
    let argumentLooksMetal = arguments.dropFirst().contains { argument in
      argument.hasSuffix(".metal") || argument.hasSuffix(".air")
        || argument.hasSuffix(".metallib")
    }
    let looksMetalFamily =
      keyCompile != nil || keyLink != nil || descriptionCompile
      || descriptionLink || executableName.contains("metal") || executableName == "air-lld"
      || argumentLooksMetal
    guard looksMetalFamily else { return nil }

    if descriptionCompile, let keyCompile {
      let source = String(description.dropFirst(compilePrefix.count))
      let expectedKeySuffix = Data((":" + compilePrefix).utf8) + Data(source.utf8)
      guard !source.isEmpty,
        Data(key.utf8).suffix(expectedKeySuffix.count).elementsEqual(expectedKeySuffix),
        keyCompile.lowerBound < key.endIndex,
        !descriptionLink, keyLink == nil
      else {
        throw ReleasePackageError.verification("retained Metal compile role is ambiguous")
      }
      return .compile(source: UTF8PathIdentity(source))
    }
    if descriptionLink, let keyLink {
      let output = String(description.dropFirst(linkPrefix.count))
      let expectedKeySuffix = Data((":" + linkPrefix).utf8) + Data(output.utf8)
      guard !output.isEmpty,
        Data(key.utf8).suffix(expectedKeySuffix.count).elementsEqual(expectedKeySuffix),
        keyLink.lowerBound < key.endIndex,
        !descriptionCompile, keyCompile == nil
      else {
        throw ReleasePackageError.verification("retained Metal link role is ambiguous")
      }
      return .link(output: UTF8PathIdentity(output))
    }
    throw ReleasePackageError.verification(
      "retained XCBuild manifest contains an unexpected Metal-family role")
  }

  private static func inspectExecutionPath(_ path: String) throws -> ExecutionIdentity {
    guard let pointer = realpath(path, nil) else {
      throw ReleasePackageError.verification("cannot resolve retained Metal tool invocation")
    }
    defer { free(pointer) }
    let physicalPath = String(cString: pointer)
    let descriptor = open(physicalPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open retained Metal tool invocation")
    }
    defer { close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
      throw ReleasePackageError.verification("retained Metal invocation is not executable data")
    }
    return .init(
      physicalPath: physicalPath,
      vnode: .init(device: UInt64(info.st_dev), inode: UInt64(info.st_ino)))
  }

  static func rejectPathLeak(below root: URL, transientPath: String) throws {
    let needle = Data(transientPath.utf8)
    for url in try SecureFiles.enumerateTree(root) {
      var info = stat()
      guard lstat(url.path, &info) == 0 else {
        throw ReleasePackageError.verification("cannot inspect release payload for path leakage")
      }
      guard (info.st_mode & S_IFMT) == S_IFREG else { continue }
      let data = try Data(contentsOf: url, options: [.mappedIfSafe])
      guard data.range(of: needle) == nil else {
        throw ReleasePackageError.verification(
          "ephemeral Metal cryptex mount leaked into release payload semantics")
      }
    }
  }
}
