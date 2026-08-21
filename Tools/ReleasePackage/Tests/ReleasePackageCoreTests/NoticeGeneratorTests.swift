import Foundation
import Testing

@testable import ReleasePackageCore

@Test func noticesAreDeterministicAndRejectDriftOrUnknownFamilies() throws {
  let root = try makeTemporaryDirectory("notices")
  defer { removeTemporaryDirectory(root) }
  let depotRoot = root.appendingPathComponent("depot")
  try SecureFiles.createPrivateDirectory(depotRoot)
  try SecureFiles.createDirectory(depotRoot.appendingPathComponent("inputs"), mode: 0o700)
  let license = depotRoot.appendingPathComponent("inputs/LICENSE")
  let licenseData = Data("Synthetic license text\n".utf8)
  try SecureFiles.atomicWrite(licenseData, to: license)
  let input = DependencyDepotManifest.NoticeInput(
    familyID: "synthetic", kind: "license", declaredPath: "LICENSE",
    depotPath: "inputs/LICENSE", sha256: Digests.sha256(licenseData)
  )
  let depot = DependencyDepotManifest(
    schemaVersion: 1, swiftPins: [], swiftSubmodules: [], goModules: [], noticeInputs: [input],
    goVersion: "go test", goLicenseSHA256: String(repeating: "a", count: 64),
    goPatentsSHA256: String(repeating: "b", count: 64)
  )
  let authority = NoticeAuthority(
    schemaVersion: 1, expectedSwiftPins: [], expectedGoModules: [],
    families: [
      .init(
        id: "synthetic", scope: "test", sourceRoot: ".", licensePaths: ["LICENSE"], noticePaths: [])
    ]
  )
  let first = try NoticeGenerator.generate(authority: authority, depot: depot, depotRoot: depotRoot)
  let second = try NoticeGenerator.generate(
    authority: authority, depot: depot, depotRoot: depotRoot)
  #expect(first == second)
  #expect(String(decoding: first.markdown, as: UTF8.self).contains("Synthetic license text"))

  try SecureFiles.atomicWrite(Data("changed\n".utf8), to: license)
  #expect(throws: ReleasePackageError.self) {
    try NoticeGenerator.generate(authority: authority, depot: depot, depotRoot: depotRoot)
  }
  try SecureFiles.atomicWrite(licenseData, to: license)
  let unknown = DependencyDepotManifest.NoticeInput(
    familyID: "unknown", kind: "license", declaredPath: "LICENSE",
    depotPath: "inputs/LICENSE", sha256: Digests.sha256(licenseData)
  )
  let depotWithUnknown = DependencyDepotManifest(
    schemaVersion: 1, swiftPins: [], swiftSubmodules: [], goModules: [],
    noticeInputs: [input, unknown],
    goVersion: "go test", goLicenseSHA256: depot.goLicenseSHA256,
    goPatentsSHA256: depot.goPatentsSHA256
  )
  #expect(throws: ReleasePackageError.self) {
    try NoticeGenerator.generate(
      authority: authority, depot: depotWithUnknown, depotRoot: depotRoot)
  }
}
