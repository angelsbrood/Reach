import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

private struct FakeRestoreImageLoader: MacOSRestoreImageLoading {
  let loaded: LoadedMacOSRestoreImage

  func load(from localURL: URL) throws -> LoadedMacOSRestoreImage {
    loaded
  }
}

@Test func restoreImageAuthorityBindsExactAppleBytesAndSupportedFinalGuest() throws {
  let root = try makeTemporaryDirectory("restore-image-authority")
  defer { removeTemporaryDirectory(root) }
  let ipsw = root.appendingPathComponent("UniversalMac_27.0_26A123_Restore.ipsw")
  try SecureFiles.atomicWrite(Data("synthetic-ipsw\n".utf8), to: ipsw)
  let digest = try Digests.sha256(file: ipsw)
  let loader = FakeRestoreImageLoader(
    loaded: .init(
      localURL: ipsw, productVersion: "27.0.0", buildVersion: "26A123",
      supported: true, minimumCPUCount: 4, minimumMemoryBytes: 8 * 1_024 * 1_024 * 1_024,
      hardwareModelSHA256: String(repeating: "a", count: 64)))
  let value = try MacOSRestoreImageInspector(loader: loader).inspect(
    localIPSW: ipsw, expectedSHA256: digest,
    sourceURL:
      "https://updates.cdn-apple.com/2026/macos/UniversalMac_27.0_26A123_Restore.ipsw")
  #expect(value.productVersion == "27.0.0")
  #expect(value.buildVersion == "26A123")
  #expect(value.fileSHA256 == digest)
  #expect(value.sourceHost == "updates.cdn-apple.com")

  let authority = root.appendingPathComponent("restore-image.json")
  try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: authority)
  #expect(
    try MacOSRestoreImageInspector(loader: loader).verify(
      recordURL: authority, localIPSW: ipsw) == value)

  let changedSemantics = FakeRestoreImageLoader(
    loaded: .init(
      localURL: ipsw, productVersion: "27.0.0", buildVersion: "26A124",
      supported: true, minimumCPUCount: 4,
      minimumMemoryBytes: 8 * 1_024 * 1_024 * 1_024,
      hardwareModelSHA256: String(repeating: "a", count: 64)))
  #expect(throws: ReleasePackageError.self) {
    try MacOSRestoreImageInspector(loader: changedSemantics).verify(
      recordURL: authority, localIPSW: ipsw)
  }
}

@Test func restoreImageAuthorityRefusesBetaUnsupportedAndSourceSubstitution() throws {
  let root = try makeTemporaryDirectory("restore-image-refusal")
  defer { removeTemporaryDirectory(root) }
  let ipsw = root.appendingPathComponent("UniversalMac_27.0_26A123_Restore.ipsw")
  try SecureFiles.atomicWrite(Data("synthetic-ipsw\n".utf8), to: ipsw)
  let digest = try Digests.sha256(file: ipsw)

  for loaded in [
    LoadedMacOSRestoreImage(
      localURL: ipsw, productVersion: "27.0.0", buildVersion: "26A123a",
      supported: true, minimumCPUCount: 4, minimumMemoryBytes: 8 * 1_024 * 1_024 * 1_024,
      hardwareModelSHA256: String(repeating: "a", count: 64)),
    LoadedMacOSRestoreImage(
      localURL: ipsw, productVersion: "27.0.0", buildVersion: "26A123",
      supported: false, minimumCPUCount: 4,
      minimumMemoryBytes: 8 * 1_024 * 1_024 * 1_024,
      hardwareModelSHA256: String(repeating: "a", count: 64)),
  ] {
    #expect(throws: ReleasePackageError.self) {
      try MacOSRestoreImageInspector(loader: FakeRestoreImageLoader(loaded: loaded)).inspect(
        localIPSW: ipsw, expectedSHA256: digest,
        sourceURL:
          "https://updates.cdn-apple.com/2026/macos/UniversalMac_27.0_26A123_Restore.ipsw")
    }
  }

  let supported = FakeRestoreImageLoader(
    loaded: .init(
      localURL: ipsw, productVersion: "27.0.0", buildVersion: "26A123",
      supported: true, minimumCPUCount: 4, minimumMemoryBytes: 8 * 1_024 * 1_024 * 1_024,
      hardwareModelSHA256: String(repeating: "a", count: 64)))
  #expect(throws: ReleasePackageError.self) {
    try MacOSRestoreImageInspector(loader: supported).inspect(
      localIPSW: ipsw, expectedSHA256: digest,
      sourceURL:
        "https://example.com/UniversalMac_27.0_26A123_Restore.ipsw")
  }
  #expect(throws: ReleasePackageError.self) {
    try MacOSRestoreImageInspector(loader: supported).inspect(
      localIPSW: ipsw, expectedSHA256: String(repeating: "0", count: 64),
      sourceURL:
        "https://updates.cdn-apple.com/2026/macos/UniversalMac_27.0_26A123_Restore.ipsw")
  }
}
