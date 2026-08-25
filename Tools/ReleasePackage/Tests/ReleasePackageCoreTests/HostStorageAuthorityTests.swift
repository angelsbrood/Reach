import Foundation
import Testing

@testable import ReleasePackageCore

private struct FakeHostStorage: HostStorageChecking {
  let values: [HostStoragePhase: UInt64]

  func require(_ phase: HostStoragePhase) throws -> HostStorageReport {
    guard let available = values[phase], available >= phase.minimumAvailableBytes else {
      throw ReleasePackageError.verification("synthetic storage floor refused")
    }
    let report = HostStorageReport(
      phase: phase, availableBytes: available,
      totalBytes: available + 1_024,
      requiredBytes: phase.minimumAvailableBytes,
      filesystemAuthoritySHA256: String(repeating: "a", count: 64))
    try report.validate()
    return report
  }
}

@Test func storageReportBindsPreparationAndContinuationFloors() throws {
  let storage = FakeHostStorage(values: [
    .preparation: HostStoragePhase.preparation.minimumAvailableBytes,
    .continuation: HostStoragePhase.continuation.minimumAvailableBytes,
  ])
  let preparation = try storage.require(.preparation)
  let continuation = try storage.require(.continuation)
  #expect(preparation.requiredBytes == 150 * 1_024 * 1_024 * 1_024)
  #expect(continuation.requiredBytes == 60 * 1_024 * 1_024 * 1_024)
  #expect(throws: ReleasePackageError.self) {
    try HostStorageReport(
      phase: .preparation,
      availableBytes: HostStoragePhase.preparation.minimumAvailableBytes - 1,
      totalBytes: HostStoragePhase.preparation.minimumAvailableBytes,
      requiredBytes: HostStoragePhase.preparation.minimumAvailableBytes,
      filesystemAuthoritySHA256: String(repeating: "b", count: 64)
    ).validate()
  }
}

@Test func physicalStorageAuthorityReportsWithoutLeakingItsPath() throws {
  let root = try makeTemporaryDirectory("storage-authority")
  defer { removeTemporaryDirectory(root) }
  let report = try HostStorageAuthority(root: root).require(.continuation)
  #expect(report.verdict == "pass")
  #expect(report.filesystemAuthoritySHA256.count == 64)
  let encoded = String(decoding: try CanonicalJSON.encode(report), as: UTF8.self)
  #expect(!encoded.contains(root.path))
}
