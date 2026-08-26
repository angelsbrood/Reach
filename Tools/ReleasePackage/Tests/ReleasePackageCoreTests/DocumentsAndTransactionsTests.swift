import Foundation
import Testing

@testable import ReleasePackageCore

@Test func packageDocumentsFreezeScriptlessMandatoryComponents() throws {
  let configuration = try ReleaseConfiguration.load(
    from: repositoryRoot().appendingPathComponent("release/release.json"))
  let distribution = String(
    decoding: PackageDocuments.distribution(configuration: configuration), as: UTF8.self)
  #expect(distribution.contains("customize=\"never\""))
  #expect(distribution.contains("require-scripts=\"false\""))
  #expect(distribution.contains("hostArchitectures=\"arm64\""))
  #expect(
    distribution.components(separatedBy: "visible=\"false\" selected=\"true\" enabled=\"false\"")
      .count == 3)
  #expect(distribution.components(separatedBy: "active=\"true\"").count == 3)
  #expect(!distribution.contains("script" + "s>"))

  let normalized = String(
    decoding: PackageDocuments.productbuildDistribution(
      configuration: configuration,
      hostInstallKBytes: 12,
      helperInstallKBytes: 3
    ), as: UTF8.self)
  #expect(normalized.contains("installKBytes=\"12\""))
  #expect(normalized.contains(">#systems.reach.host.pkg</pkg-ref>"))
  #expect(normalized.contains("standalone=\"yes\""))
}

@Test func payloadManifestHasNoSelfEntryAndBindsToolSource() throws {
  let root = try makeTemporaryDirectory("manifest")
  defer { removeTemporaryDirectory(root) }
  let tree = try PayloadTree.inspect(root: canonicalPayloadFixture(at: root))
  let configuration = try ReleaseConfiguration.load(
    from: repositoryRoot().appendingPathComponent("release/release.json"))
  let depot = DependencyDepotManifest(
    schemaVersion: 1,
    swiftPins: [], swiftSubmodules: [], goModules: [], noticeInputs: [],
    goVersion: "go test", goLicenseSHA256: String(repeating: "a", count: 64),
    goPatentsSHA256: String(repeating: "b", count: 64)
  )
  let source = SourceAuthority(
    commit: String(repeating: "c", count: 40), commitTimestamp: 1,
    main: String(repeating: "c", count: 40), originMain: String(repeating: "c", count: 40),
    submodules: [], exportedTreeSHA256: String(repeating: "d", count: 64),
    packageResolvedSHA256: String(repeating: "e", count: 64),
    goModSHA256: String(repeating: "f", count: 64), goSumSHA256: String(repeating: "0", count: 64)
  )
  let manifest = try PayloadManifest.make(
    configuration: configuration, source: source,
    releaseConfigurationSHA256: String(repeating: "1", count: 64),
    releaseToolSourceSHA256: String(repeating: "2", count: 64),
    noticeAuthoritySHA256: String(repeating: "3", count: 64),
    dependencyDepotSHA256: String(repeating: "4", count: 64), depot: depot,
    toolchain: .init(
      xcode: "X", swift: "S", sdkPath: "/SDK", sdkVersion: "27", macOSBuild: "B", go: "G",
      metal: testMetalToolchainAuthority()),
    linkedSystemLibraries: ["/usr/lib/libSystem.B.dylib"],
    noticeSetSHA256: String(repeating: "5", count: 64),
    hostRecords: tree.records, helperRecords: []
  )
  #expect(manifest.releaseToolSourceSHA256 == String(repeating: "2", count: 64))
  #expect(!manifest.payload.contains(where: { $0.path.hasSuffix("payload-manifest.json") }))
}

@Test func staticTransactionMatrixPreservesStateAndRefusesMixedAuthority() throws {
  let root = try makeTemporaryDirectory("transactions-parent")
  defer { removeTemporaryDirectory(root) }
  let configuration = try ReleaseConfiguration.load(
    from: repositoryRoot().appendingPathComponent("release/release.json"))
  let report = try StaticTransactionVerifier.run(
    configuration: configuration,
    root: root.appendingPathComponent("transactions")
  )
  #expect(report.cells.count == 9)
  #expect(report.cells.first(where: { $0.name == "a-to-b-interruption" })?.result == "pass")
  #expect(report.cells.first(where: { $0.name == "downgrade" })?.result == "refused")
  #expect(report.cells.first(where: { $0.name == "path-alias-collision" })?.result == "refused")
  #expect(
    try Digests.sha256(
      file: root.appendingPathComponent("transactions/retained-state/cluster-state.sentinel"))
      == report.stateSentinelSHA256)
}
