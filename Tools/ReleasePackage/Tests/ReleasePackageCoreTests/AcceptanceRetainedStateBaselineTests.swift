import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

private func retainedBaseline(_ transactionID: String) -> AcceptanceRetainedStateBaseline {
  .init(
    transactionID: transactionID,
    selectedOwnerUID: 501,
    observation: .init(
      present: true, ownerUID: 501, itemCount: 7,
      authoritySHA256: String(repeating: "a", count: 64),
      caCreationCount: 1))
}

@Test func retainedStateBaselineIsCanonicalDurableAndIdempotent() throws {
  let root = try makeTemporaryDirectory("retained-state-baseline")
  defer { removeTemporaryDirectory(root) }
  let url = root.appendingPathComponent("transaction.retained-state.json")
  let store = AcceptanceRetainedStateBaselineStore(url: url)
  let value = retainedBaseline(UUID().uuidString)
  try store.createOrVerify(value)
  try store.createOrVerify(value)
  #expect(try store.load() == value)

  let changed = AcceptanceRetainedStateBaseline(
    transactionID: value.transactionID,
    selectedOwnerUID: value.selectedOwnerUID,
    observation: .init(
      present: true, ownerUID: 501, itemCount: 8,
      authoritySHA256: String(repeating: "b", count: 64),
      caCreationCount: 1))
  #expect(throws: ReleasePackageError.self) {
    try store.createOrVerify(changed)
  }
}

@Test func retainedStateBaselineRefusesModeAndTransactionSubstitution() throws {
  let root = try makeTemporaryDirectory("retained-state-baseline-refusal")
  defer { removeTemporaryDirectory(root) }
  let url = root.appendingPathComponent("transaction.retained-state.json")
  let store = AcceptanceRetainedStateBaselineStore(url: url)
  let value = retainedBaseline(UUID().uuidString)
  try store.createOrVerify(value)
  #expect(chmod(url.path, 0o644) == 0)
  #expect(throws: ReleasePackageError.self) { try store.load() }
  #expect(chmod(url.path, 0o600) == 0)

  let other = retainedBaseline(UUID().uuidString)
  #expect(throws: ReleasePackageError.self) {
    try store.createOrVerify(other)
  }
}
