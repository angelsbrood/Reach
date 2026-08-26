import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

private let validComponentOutput = """
  Asset Path: /System/Library/AssetsV2/com_apple_MobileAsset_MetalToolchain/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.asset/AssetData
  Build Version: 27A5237l
  Status: installed
  Toolchain Identifier: com.apple.dt.toolchain.Metal.32023.921.1
  Toolchain Search Path: /private/var/run/com.apple.security.cryptexd/mnt/com.apple.MobileAsset.MetalToolchain-v27.1.fixture
  """

private func mountedMetal(
  authority: MetalToolchainAuthority = testMetalToolchainAuthority(),
  inode: UInt64 = 2,
  root: URL = URL(
    fileURLWithPath:
      "/private/var/run/com.apple.security.cryptexd/mnt/com.apple.MobileAsset.MetalToolchain-v27.1.fixture/Metal.xctoolchain"
  )
) throws -> MountedMetalToolchain {
  .init(
    record: try MetalComponentRecord.parse(validComponentOutput),
    root: root,
    rootVnode: .init(device: 1, inode: inode),
    memberVnodes: [
      "ToolchainInfo.plist": .init(device: 1, inode: 3),
      "usr/metal/32023/ToolchainInfo.json": .init(device: 1, inode: 4),
      "usr/metal/32023/ToolchainInfo.plist": .init(device: 1, inode: 5),
      "usr/bin/metal": .init(device: 1, inode: 6),
      "usr/bin/metallib": .init(device: 1, inode: 7),
      "usr/bin/air-lld": .init(device: 1, inode: 8),
    ],
    authority: authority)
}

private let expectedMetalSources = [
  "arg_reduce.metal",
  "conv.metal",
  "gemv.metal",
  "layer_norm.metal",
  "random.metal",
  "rms_norm.metal",
  "rope.metal",
  "scaled_dot_product_attention.metal",
  "steel/attn/kernels/steel_attention.metal",
]

@discardableResult
private func writeMetalManifest(
  scratch: URL,
  executable: String,
  compileSources: [String] = expectedMetalSources,
  includeLink: Bool = true,
  directoryName: String = "0123456789abcdef0123456789abcdef.xcbuilddata",
  decoyExecutable: String? = nil,
  sourceRootOverride: URL? = nil,
  sourcePathTransform: ((String) -> String)? = nil,
  airPathTransform: ((String) -> String)? = nil,
  metallibPathTransform: ((String) -> String)? = nil,
  extraCommands: [String: [String: Any]] = [:]
) throws -> URL {
  var directory = scratch
  for component in ["out", "Intermediates.noindex", "XCBuildData", directoryName] {
    directory.appendPathComponent(component, isDirectory: true)
    if !FileManager.default.fileExists(atPath: directory.path) {
      try SecureFiles.createDirectory(directory, mode: 0o700)
    }
  }
  var commands = extraCommands
  var airPaths: [String] = []
  for sourceName in compileSources {
    let sourceRoot =
      sourceRootOverride
      ?? scratch.appendingPathComponent(
        "checkouts/mlx-swift/Source/Cmlx/mlx-generated/metal", isDirectory: true)
    let unmodifiedSource = sourceRoot.appendingPathComponent(sourceName).path
    let source = sourcePathTransform?(unmodifiedSource) ?? unmodifiedSource
    let airName =
      URL(fileURLWithPath: sourceName).deletingPathExtension()
      .lastPathComponent + ".air"
    let unmodifiedAIR = scratch.appendingPathComponent(
      "out/Intermediates.noindex/mlx-swift.build/Release/"
        + "mlx-swift_Cmlx-b.build/Metal/\(airName)"
    ).path
    let air = airPathTransform?(unmodifiedAIR) ?? unmodifiedAIR
    airPaths.append(air)
    let description = "CompileMetalFile \(source)"
    var command: [String: Any] = [
      "tool": "shell",
      "description": description,
      "args": [executable, "-c", "-o", air, source],
    ]
    if let decoyExecutable { command["decoy"] = decoyExecutable }
    commands["P0:target-mlx-swift_Cmlx:Release:\(description)"] = command
  }
  if includeLink {
    let unmodifiedOutput = scratch.appendingPathComponent(
      "out/Products/Release/mlx-swift_Cmlx.bundle/Contents/Resources/default.metallib"
    ).path
    let output = metallibPathTransform?(unmodifiedOutput) ?? unmodifiedOutput
    let description = "MetalLink \(output)"
    var command: [String: Any] = [
      "tool": "shell",
      "description": description,
      "args": [executable, "-o", output] + airPaths,
    ]
    if let decoyExecutable { command["decoy"] = decoyExecutable }
    commands["P0:target-mlx-swift_Cmlx:Release:\(description)"] = command
  }
  let data = try JSONSerialization.data(
    withJSONObject: ["commands": commands], options: [.sortedKeys])
  let manifest = directory.appendingPathComponent("manifest.json")
  try SecureFiles.atomicWrite(data, to: manifest)
  return manifest
}

@Test func metalComponentParserRequiresOneExactInstalledPhysicalRecord() throws {
  let parsed = try MetalComponentRecord.parse(validComponentOutput)
  #expect(parsed.build == "27A5237l")
  #expect(parsed.status == "installed")
  #expect(parsed.identifier == "com.apple.dt.toolchain.Metal.32023.921.1")

  for changed in [
    "",
    validComponentOutput.replacingOccurrences(of: "Status: installed", with: "Status: available"),
    validComponentOutput + "\nStatus: installed\n",
    validComponentOutput.replacingOccurrences(
      of: "/private/var/run/com.apple.security.cryptexd/mnt/",
      with: "/Users/example/"),
    validComponentOutput.replacingOccurrences(
      of: "Toolchain Identifier: com.apple.dt.toolchain.Metal.32023.921.1",
      with: "Toolchain Identifier: XcodeDefault"),
  ] {
    #expect(throws: ReleasePackageError.self) {
      _ = try MetalComponentRecord.parse(changed)
    }
  }
}

@Test func metalAuthorityRefusesSchemaIdentityMetadataAndToolMutations() throws {
  let valid = testMetalToolchainAuthority()
  try valid.validate()
  let variants = [
    MetalToolchainAuthority(
      schemaVersion: 0,
      componentIdentifier: valid.componentIdentifier,
      componentBuild: valid.componentBuild,
      metadata: valid.metadata,
      tools: valid.tools),
    MetalToolchainAuthority(
      componentIdentifier: "XcodeDefault",
      componentBuild: valid.componentBuild,
      metadata: valid.metadata,
      tools: valid.tools),
    MetalToolchainAuthority(
      componentIdentifier: valid.componentIdentifier,
      componentBuild: "bad build",
      metadata: valid.metadata,
      tools: valid.tools),
    MetalToolchainAuthority(
      componentIdentifier: valid.componentIdentifier,
      componentBuild: valid.componentBuild,
      metadata: Array(valid.metadata.dropLast()),
      tools: valid.tools),
    MetalToolchainAuthority(
      componentIdentifier: valid.componentIdentifier,
      componentBuild: valid.componentBuild,
      metadata: valid.metadata,
      tools: [
        .init(
          path: "usr/bin/metal", resolvedPath: "usr/bin/metal", sha256: "bad",
          version: "changed"),
        valid.tools[1],
      ]),
    MetalToolchainAuthority(
      componentIdentifier: valid.componentIdentifier,
      componentBuild: valid.componentBuild,
      metadata: valid.metadata,
      tools: [
        valid.tools[0],
        .init(
          path: "usr/bin/metallib", resolvedPath: "usr/bin/air-lld",
          sha256: valid.tools[1].sha256,
          version: "/private/var/run/com.apple.security.cryptexd/mnt/leak"),
      ]),
  ]
  for variant in variants {
    #expect(throws: ReleasePackageError.self) { try variant.validate() }
  }
}

@Test func resolverRevalidatesVnodeAndEveryStableAuthorityField() throws {
  let expected = try mountedMetal()
  var current = expected
  let resolver = InstalledMetalToolchainResolver(
    query: { _ in validComponentOutput },
    inspect: { _ in current })
  let initial = try resolver.resolve(
    logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-query.log"))
  #expect(initial == expected)
  try resolver.revalidate(
    expected, logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-revalidate.log"))

  current = try mountedMetal(inode: 99)
  #expect(throws: ReleasePackageError.self) {
    try resolver.revalidate(
      expected, logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-vnode.log"))
  }
  current = try mountedMetal(
    authority: .init(
      componentIdentifier: expected.authority.componentIdentifier,
      componentBuild: expected.authority.componentBuild,
      metadata: expected.authority.metadata,
      tools: [
        .init(
          path: "usr/bin/metal", resolvedPath: "usr/bin/metal",
          sha256: String(repeating: "9", count: 64),
          version: expected.authority.tools[0].version),
        expected.authority.tools[1],
      ]))
  #expect(throws: ReleasePackageError.self) {
    try resolver.revalidate(
      expected, logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-hash.log"))
  }

  current = try mountedMetal(
    authority: .init(
      componentIdentifier: expected.authority.componentIdentifier,
      componentBuild: "27A9999z",
      metadata: expected.authority.metadata,
      tools: expected.authority.tools))
  #expect(throws: ReleasePackageError.self) {
    try resolver.revalidate(
      expected, logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-build.log"))
  }
  current = try mountedMetal(
    authority: .init(
      componentIdentifier: expected.authority.componentIdentifier,
      componentBuild: expected.authority.componentBuild,
      metadata: [
        .init(
          path: expected.authority.metadata[0].path,
          sha256: String(repeating: "8", count: 64))
      ] + expected.authority.metadata.dropFirst(),
      tools: expected.authority.tools))
  #expect(throws: ReleasePackageError.self) {
    try resolver.revalidate(
      expected, logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-metadata.log"))
  }
  current = try mountedMetal(
    authority: .init(
      componentIdentifier: expected.authority.componentIdentifier,
      componentBuild: expected.authority.componentBuild,
      metadata: expected.authority.metadata,
      tools: [
        .init(
          path: expected.authority.tools[0].path,
          resolvedPath: expected.authority.tools[0].resolvedPath,
          sha256: expected.authority.tools[0].sha256,
          version: "changed version")
      ] + expected.authority.tools.dropFirst()))
  #expect(throws: ReleasePackageError.self) {
    try resolver.revalidate(
      expected, logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-version.log"))
  }

  current = expected
  _ = try resolver.requireAuthority(
    expected.authority,
    logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-explicit-host.log"))
  current = try mountedMetal(
    authority: .init(
      componentIdentifier: expected.authority.componentIdentifier,
      componentBuild: "27A9999z",
      metadata: expected.authority.metadata,
      tools: expected.authority.tools))
  #expect(throws: ReleasePackageError.self) {
    _ = try resolver.requireAuthority(
      expected.authority,
      logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-explicit-mismatch.log"))
  }
}

@Test func metalAuthorityAndInstalledResolverTreatVersionTextAsExactUTF8Bytes() throws {
  let decomposedVersion = "Apple metal cafe\u{301}\nAIR tools"
  let composedVersion = decomposedVersion.precomposedStringWithCanonicalMapping
  #expect(decomposedVersion == composedVersion)
  #expect(!decomposedVersion.utf8.elementsEqual(composedVersion.utf8))

  let baseline = testMetalToolchainAuthority()
  let expected = MetalToolchainAuthority(
    componentIdentifier: baseline.componentIdentifier,
    componentBuild: baseline.componentBuild,
    metadata: baseline.metadata,
    tools: [
      .init(
        path: baseline.tools[0].path,
        resolvedPath: baseline.tools[0].resolvedPath,
        sha256: baseline.tools[0].sha256,
        version: decomposedVersion),
      baseline.tools[1],
    ])
  let substituted = MetalToolchainAuthority(
    componentIdentifier: baseline.componentIdentifier,
    componentBuild: baseline.componentBuild,
    metadata: baseline.metadata,
    tools: [
      .init(
        path: baseline.tools[0].path,
        resolvedPath: baseline.tools[0].resolvedPath,
        sha256: baseline.tools[0].sha256,
        version: composedVersion),
      baseline.tools[1],
    ])
  try expected.validate()
  try substituted.validate()
  #expect(expected != substituted)

  let expectedMounted = try mountedMetal(authority: expected)
  var current = expectedMounted
  let resolver = InstalledMetalToolchainResolver(
    query: { _ in validComponentOutput },
    inspect: { _ in current })
  _ = try resolver.requireAuthority(
    expected, logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-unicode-exact.log"))
  try resolver.revalidate(
    expectedMounted,
    logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-unicode-revalidate-exact.log"))

  current = try mountedMetal(authority: substituted)
  #expect(throws: ReleasePackageError.self) {
    _ = try resolver.requireAuthority(
      expected,
      logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-unicode-substituted.log"))
  }
  #expect(throws: ReleasePackageError.self) {
    try resolver.revalidate(
      expectedMounted,
      logURL: URL(fileURLWithPath: "/private/tmp/unused-metal-unicode-revalidate-substituted.log"))
  }
}

@Test func mountedMetalRootMustBeRootOwnedReadOnlyAndNotGroupOrOtherWritable() throws {
  try InstalledMetalToolchainResolver.validateRootSecurity(
    uid: 0, mode: mode_t(S_IFDIR | 0o755), readOnly: true)
  for fixture in [
    (uid_t(501), mode_t(S_IFDIR | 0o755), true),
    (uid_t(0), mode_t(S_IFDIR | 0o775), true),
    (uid_t(0), mode_t(S_IFDIR | 0o757), true),
    (uid_t(0), mode_t(S_IFDIR | 0o755), false),
  ] {
    #expect(throws: ReleasePackageError.self) {
      try InstalledMetalToolchainResolver.validateRootSecurity(
        uid: fixture.0, mode: fixture.1, readOnly: fixture.2)
    }
  }
}

@Test func swiftBuildGraphRequiresOnlyTheFrozenPhysicalMetalTools() throws {
  let root = try makeTemporaryDirectory("metal-graph")
  defer { removeTemporaryDirectory(root) }
  let toolchainRoot = root.appendingPathComponent("Metal.xctoolchain")
  let mounted = try mountedMetal(root: toolchainRoot)
  let scratch = root.appendingPathComponent("scratch")
  try SecureFiles.createPrivateDirectory(scratch)
  let log = root.appendingPathComponent("build.log")
  try SecureFiles.atomicWrite(Data(), to: log)
  let executable = toolchainRoot.appendingPathComponent("usr/bin/metal").path
  try writeMetalManifest(scratch: scratch, executable: executable)
  let identities: [String: SwiftBuildMetalGraphVerifier.ExecutionIdentity] = [
    executable: .init(
      physicalPath: executable,
      vnode: mounted.memberVnodes["usr/bin/metal"]!)
  ]
  let inspect: (String) throws -> SwiftBuildMetalGraphVerifier.ExecutionIdentity = { path in
    guard let identity = identities[path] else {
      throw ReleasePackageError.verification("fixture selected an unbound Metal tool")
    }
    return identity
  }
  try SwiftBuildMetalGraphVerifier.verify(
    scratch: scratch, buildLog: log, mounted: mounted, inspectExecution: inspect)
}

@Test func swiftBuildGraphRejectsDecoysWrongExecutablesAndMissingRoles() throws {
  let root = try makeTemporaryDirectory("metal-graph-adversarial")
  defer { removeTemporaryDirectory(root) }
  let toolchainRoot = root.appendingPathComponent("Metal.xctoolchain")
  let mounted = try mountedMetal(root: toolchainRoot)
  let correct = toolchainRoot.appendingPathComponent("usr/bin/metal").path
  let log = root.appendingPathComponent("build.log")
  try SecureFiles.atomicWrite(Data(), to: log)
  let identity: (String) throws -> SwiftBuildMetalGraphVerifier.ExecutionIdentity = { path in
    guard path == correct else {
      throw ReleasePackageError.verification("fixture selected a non-frozen executable")
    }
    return .init(
      physicalPath: correct, vnode: mounted.memberVnodes["usr/bin/metal"]!)
  }

  for (label, executable, sources, includeLink, extra) in [
    ("decoy-wrong-real", "/private/tmp/evil/metal", expectedMetalSources, true, [:]),
    ("arbitrary-absolute", "/usr/local/bin/metallib", expectedMetalSources, true, [:]),
    ("relative", "metal", expectedMetalSources, true, [:]),
    ("missing-compile", correct, Array(expectedMetalSources.dropLast()), true, [:]),
    ("missing-link", correct, expectedMetalSources, false, [:]),
    (
      "extra-role", correct, expectedMetalSources, true,
      [
        "P0:unexpected": [
          "tool": "shell", "description": "Unexpected",
          "args": ["/usr/local/bin/metallib", "input.air"],
        ]
      ]
    ),
  ] as [(String, String, [String], Bool, [String: [String: Any]])] {
    let scratch = root.appendingPathComponent(label)
    try SecureFiles.createPrivateDirectory(scratch)
    try writeMetalManifest(
      scratch: scratch, executable: executable, compileSources: sources,
      includeLink: includeLink, decoyExecutable: label == "decoy-wrong-real" ? correct : nil,
      extraCommands: extra)
    #expect(throws: ReleasePackageError.self) {
      try SwiftBuildMetalGraphVerifier.verify(
        scratch: scratch, buildLog: log, mounted: mounted, inspectExecution: identity)
    }
  }

  let substitutedSource = root.appendingPathComponent("substituted-source")
  try SecureFiles.createPrivateDirectory(substitutedSource)
  try writeMetalManifest(
    scratch: substitutedSource, executable: correct,
    sourceRootOverride: URL(fileURLWithPath: "/private/tmp/decoy-mlx-sources"))
  #expect(throws: ReleasePackageError.self) {
    try SwiftBuildMetalGraphVerifier.verify(
      scratch: substitutedSource, buildLog: log, mounted: mounted,
      inspectExecution: identity)
  }
}

@Test func swiftBuildGraphTreatsEveryPathAsExactUTF8Bytes() throws {
  let root = try makeTemporaryDirectory("metal-graph-unicode")
  defer { removeTemporaryDirectory(root) }
  let toolchainRoot = root.appendingPathComponent("Metal.xctoolchain")
  let mounted = try mountedMetal(root: toolchainRoot)
  let executable = toolchainRoot.appendingPathComponent("usr/bin/metal").path
  let identity: (String) throws -> SwiftBuildMetalGraphVerifier.ExecutionIdentity = { path in
    guard path.utf8.elementsEqual(executable.utf8) else {
      throw ReleasePackageError.verification("fixture selected a non-frozen executable")
    }
    return .init(
      physicalPath: executable, vnode: mounted.memberVnodes["usr/bin/metal"]!)
  }
  let log = root.appendingPathComponent("build.log")
  try SecureFiles.atomicWrite(Data(), to: log)

  let exact = root.appendingPathComponent("exact-e\u{301}")
  try SecureFiles.createPrivateDirectory(exact)
  try writeMetalManifest(scratch: exact, executable: executable)
  try SwiftBuildMetalGraphVerifier.verify(
    scratch: exact, buildLog: log, mounted: mounted, inspectExecution: identity)

  let composeSource: (String) -> String = {
    $0.hasSuffix("/arg_reduce.metal") ? $0.precomposedStringWithCanonicalMapping : $0
  }
  let composeAIR: (String) -> String = {
    $0.hasSuffix("/arg_reduce.air") ? $0.precomposedStringWithCanonicalMapping : $0
  }
  let composeMetallib: (String) -> String = { $0.precomposedStringWithCanonicalMapping }
  let variants:
    [(
      label: String,
      source: ((String) -> String)?,
      air: ((String) -> String)?,
      metallib: ((String) -> String)?
    )] = [
      ("source", composeSource, nil, nil),
      ("air", nil, composeAIR, nil),
      ("metallib", nil, nil, composeMetallib),
    ]
  for variant in variants {
    let scratch = root.appendingPathComponent("\(variant.label)-e\u{301}")
    try SecureFiles.createPrivateDirectory(scratch)
    try writeMetalManifest(
      scratch: scratch, executable: executable,
      sourcePathTransform: variant.source,
      airPathTransform: variant.air,
      metallibPathTransform: variant.metallib)
    #expect(throws: ReleasePackageError.self) {
      try SwiftBuildMetalGraphVerifier.verify(
        scratch: scratch, buildLog: log, mounted: mounted, inspectExecution: identity)
    }
  }
}

@Test func swiftBuildGraphRejectsSymlinkedManifestAncestors() throws {
  let root = try makeTemporaryDirectory("metal-graph-symlink-ancestors")
  defer { removeTemporaryDirectory(root) }
  let toolchainRoot = root.appendingPathComponent("Metal.xctoolchain")
  let mounted = try mountedMetal(root: toolchainRoot)
  let executable = toolchainRoot.appendingPathComponent("usr/bin/metal").path
  let identity: (String) throws -> SwiftBuildMetalGraphVerifier.ExecutionIdentity = { path in
    guard path.utf8.elementsEqual(executable.utf8) else {
      throw ReleasePackageError.verification("fixture selected a non-frozen executable")
    }
    return .init(
      physicalPath: executable, vnode: mounted.memberVnodes["usr/bin/metal"]!)
  }
  let log = root.appendingPathComponent("build.log")
  try SecureFiles.atomicWrite(Data(), to: log)

  for label in ["out", "intermediates"] {
    let scratch = root.appendingPathComponent("scratch-\(label)")
    let decoy = root.appendingPathComponent("decoy-\(label)")
    try SecureFiles.createPrivateDirectory(scratch)
    try SecureFiles.createPrivateDirectory(decoy)
    let rewrite: (String) -> String = {
      $0.replacingOccurrences(of: decoy.path, with: scratch.path)
    }
    try writeMetalManifest(
      scratch: decoy, executable: executable,
      sourceRootOverride: scratch.appendingPathComponent(
        "checkouts/mlx-swift/Source/Cmlx/mlx-generated/metal", isDirectory: true),
      airPathTransform: rewrite,
      metallibPathTransform: rewrite)

    if label == "out" {
      guard
        symlink(
          decoy.appendingPathComponent("out").path,
          scratch.appendingPathComponent("out").path) == 0
      else {
        throw ReleasePackageError.processFailure("cannot create symlinked out fixture")
      }
    } else {
      let out = scratch.appendingPathComponent("out")
      try SecureFiles.createDirectory(out, mode: 0o700)
      guard
        symlink(
          decoy.appendingPathComponent("out/Intermediates.noindex").path,
          out.appendingPathComponent("Intermediates.noindex").path) == 0
      else {
        throw ReleasePackageError.processFailure(
          "cannot create symlinked Intermediates.noindex fixture")
      }
    }
    do {
      try SwiftBuildMetalGraphVerifier.verify(
        scratch: scratch, buildLog: log, mounted: mounted, inspectExecution: identity)
      Issue.record("symlinked \(label) manifest ancestor unexpectedly passed")
    } catch let error as ReleasePackageError {
      #expect(error.description.contains("is not a physical directory"))
    } catch {
      Issue.record("symlinked \(label) manifest ancestor returned unexpected error: \(error)")
    }
  }
}

@Test func swiftBuildGraphRejectsAmbiguousInvalidAndOversizedManifests() throws {
  let root = try makeTemporaryDirectory("metal-graph-bounds")
  defer { removeTemporaryDirectory(root) }
  let toolchainRoot = root.appendingPathComponent("Metal.xctoolchain")
  let mounted = try mountedMetal(root: toolchainRoot)
  let executable = toolchainRoot.appendingPathComponent("usr/bin/metal").path
  let identity: (String) throws -> SwiftBuildMetalGraphVerifier.ExecutionIdentity = { _ in
    .init(physicalPath: executable, vnode: mounted.memberVnodes["usr/bin/metal"]!)
  }
  let log = root.appendingPathComponent("build.log")
  try SecureFiles.atomicWrite(Data(), to: log)

  let ambiguous = root.appendingPathComponent("ambiguous")
  try SecureFiles.createPrivateDirectory(ambiguous)
  try writeMetalManifest(scratch: ambiguous, executable: executable)
  try writeMetalManifest(
    scratch: ambiguous, executable: executable,
    directoryName: "fedcba9876543210fedcba9876543210.xcbuilddata")
  #expect(throws: ReleasePackageError.self) {
    try SwiftBuildMetalGraphVerifier.verify(
      scratch: ambiguous, buildLog: log, mounted: mounted, inspectExecution: identity)
  }

  let invalid = root.appendingPathComponent("invalid")
  try SecureFiles.createPrivateDirectory(invalid)
  let invalidManifest = try writeMetalManifest(scratch: invalid, executable: executable)
  try FileManager.default.removeItem(at: invalidManifest)
  try SecureFiles.atomicWrite(Data("not-json".utf8), to: invalidManifest)
  #expect(throws: ReleasePackageError.self) {
    try SwiftBuildMetalGraphVerifier.verify(
      scratch: invalid, buildLog: log, mounted: mounted, inspectExecution: identity)
  }

  let oversized = root.appendingPathComponent("oversized")
  try SecureFiles.createPrivateDirectory(oversized)
  let oversizedManifest = try writeMetalManifest(scratch: oversized, executable: executable)
  let descriptor = open(oversizedManifest.path, O_WRONLY | O_CLOEXEC)
  #expect(descriptor >= 0)
  if descriptor >= 0 {
    defer { close(descriptor) }
    #expect(ftruncate(descriptor, off_t(32 * 1_024 * 1_024 + 1)) == 0)
  }
  #expect(throws: ReleasePackageError.self) {
    try SwiftBuildMetalGraphVerifier.verify(
      scratch: oversized, buildLog: log, mounted: mounted, inspectExecution: identity)
  }
}

@Test func ephemeralMetalMountCannotEnterPayloadSemantics() throws {
  let root = try makeTemporaryDirectory("metal-leak")
  defer { removeTemporaryDirectory(root) }
  let clean = root.appendingPathComponent("clean")
  try SecureFiles.createPrivateDirectory(clean)
  try SecureFiles.atomicWrite(Data("stable".utf8), to: clean.appendingPathComponent("value"))
  try SwiftBuildMetalGraphVerifier.rejectPathLeak(
    below: clean, transientPath: "/private/var/run/cryptex/fixture")
  try SecureFiles.atomicWrite(
    Data("/private/var/run/cryptex/fixture".utf8),
    to: clean.appendingPathComponent("leak"))
  #expect(throws: ReleasePackageError.self) {
    try SwiftBuildMetalGraphVerifier.rejectPathLeak(
      below: clean, transientPath: "/private/var/run/cryptex/fixture")
  }
}

@Test func generatedMetalSourceNormalizationIsPinnedAndClosesOnlyTwoMarkers() throws {
  let transient =
    "/private/var/run/com.apple.security.cryptexd/mnt/com.apple.MobileAsset.MetalToolchain-v1.fixture/Metal.xctoolchain"
  let fixture = """
    // Contents from \"\(transient)/usr/metal/include/units.h\"
    #line 1 \"\(transient)/usr/metal/include/units.h\"
    """
  let normalized = try GeneratedMetalSourceNormalizer.normalizeContents(Data(fixture.utf8))
  #expect(normalized.replacementCount == 2)
  #expect(normalized.sourceMount.utf8.elementsEqual(transient.utf8))
  #expect(!String(decoding: normalized.data, as: UTF8.self).contains(transient))
  #expect(
    String(decoding: normalized.data, as: UTF8.self)
      .components(separatedBy: GeneratedMetalSourceNormalizer.stableRoot).count - 1 == 2)

  for changed in [
    fixture.replacingOccurrences(of: "#line 1", with: "#line 1 \"\(transient)\"\n#line 1"),
    fixture.replacingOccurrences(
      of: "#line 1 \"\(transient)",
      with:
        "#line 1 \"/private/var/run/com.apple.security.cryptexd/mnt/com.apple.MobileAsset.MetalToolchain-v2.fixture/Metal.xctoolchain"
    ),
    fixture.replacingOccurrences(of: transient, with: GeneratedMetalSourceNormalizer.stableRoot),
  ] {
    #expect(throws: ReleasePackageError.self) {
      _ = try GeneratedMetalSourceNormalizer.normalizeContents(Data(changed.utf8))
    }
  }
}

@Test func xcodebuildAndIdentifierOnlyToolchainFormsFailClosed() throws {
  #expect(ProcessRunner.xcodebuildInvocationIsAllowed(["-version"]))
  #expect(
    ProcessRunner.xcodebuildInvocationIsAllowed(["-showComponent", "MetalToolchain"]))
  for arguments in [
    ["-downloadComponent", "MetalToolchain"],
    ["-showComponent", "MetalToolchain", "extra"],
    ["-runFirstLaunch"],
    ["-checkFirstLaunchStatus"],
  ] {
    #expect(!ProcessRunner.xcodebuildInvocationIsAllowed(arguments))
  }
  #expect(throws: ReleasePackageError.self) {
    _ = try ProcessRunner().run(
      "/usr/bin/xcrun",
      ["--toolchain", "com.apple.dt.toolchain.Metal.32023.921.1", "metal", "--version"])
  }
  #expect(throws: ReleasePackageError.self) {
    _ = try ProcessRunner(authenticatedMetalExecutables: ["/private/tmp/metal"])
      .run("/private/tmp/metal", ["-c", "input.metal"])
  }
}

@Test func historicalManifestCompatibilityAndCurrentSchemaDowngradeAreDistinct() throws {
  let historicalJSON = """
    {"xcode":"X","swift":"S","sdkPath":"/SDK","sdkVersion":"27","macOSBuild":"B","go":"G"}
    """
  let historical = try JSONDecoder().decode(
    ToolchainAuthority.self, from: Data(historicalJSON.utf8))
  #expect(historical.metal == nil)
  #expect(!String(decoding: try CanonicalJSON.encode(historical), as: UTF8.self).contains("metal"))

  let root = try makeTemporaryDirectory("metal-schema")
  defer { removeTemporaryDirectory(root) }
  let tree = try PayloadTree.inspect(root: canonicalPayloadFixture(at: root))
  let configuration = try ReleaseConfiguration.load(
    from: repositoryRoot().appendingPathComponent("release/release.json"))
  let depot = DependencyDepotManifest(
    schemaVersion: 1, swiftPins: [], swiftSubmodules: [], goModules: [], noticeInputs: [],
    goVersion: "go test", goLicenseSHA256: String(repeating: "a", count: 64),
    goPatentsSHA256: String(repeating: "b", count: 64))
  let source = SourceAuthority(
    commit: String(repeating: "c", count: 40), commitTimestamp: 1,
    main: String(repeating: "c", count: 40), originMain: String(repeating: "c", count: 40),
    submodules: [], exportedTreeSHA256: String(repeating: "d", count: 64),
    packageResolvedSHA256: String(repeating: "e", count: 64),
    goModSHA256: String(repeating: "f", count: 64),
    goSumSHA256: String(repeating: "0", count: 64))
  let current = try PayloadManifest.make(
    configuration: configuration, source: source,
    releaseConfigurationSHA256: String(repeating: "1", count: 64),
    releaseToolSourceSHA256: String(repeating: "2", count: 64),
    noticeAuthoritySHA256: String(repeating: "3", count: 64),
    dependencyDepotSHA256: String(repeating: "4", count: 64), depot: depot,
    toolchain: .init(
      xcode: "X", swift: "S", sdkPath: "/SDK", sdkVersion: "27", macOSBuild: "B", go: "G",
      metal: testMetalToolchainAuthority()),
    linkedSystemLibraries: [], noticeSetSHA256: String(repeating: "5", count: 64),
    hostRecords: tree.records, helperRecords: [])
  #expect(current.schemaVersion == 2)
  #expect(try current.validatedMetalAuthority(for: configuration) != nil)

  var object = try #require(
    JSONSerialization.jsonObject(with: try CanonicalJSON.encode(current)) as? [String: Any])
  object["schemaVersion"] = 1
  let downgraded = try JSONDecoder().decode(
    PayloadManifest.self,
    from: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
  #expect(throws: ReleasePackageError.self) {
    _ = try downgraded.validatedMetalAuthority(for: configuration)
  }

  var withoutMetal = try #require(
    JSONSerialization.jsonObject(with: try CanonicalJSON.encode(current)) as? [String: Any])
  var toolchain = try #require(withoutMetal["toolchain"] as? [String: Any])
  toolchain.removeValue(forKey: "metal")
  withoutMetal["toolchain"] = toolchain
  let removed = try JSONDecoder().decode(
    PayloadManifest.self,
    from: JSONSerialization.data(withJSONObject: withoutMetal, options: [.sortedKeys]))
  #expect(throws: ReleasePackageError.self) {
    _ = try removed.validatedMetalAuthority(for: configuration)
  }
}
