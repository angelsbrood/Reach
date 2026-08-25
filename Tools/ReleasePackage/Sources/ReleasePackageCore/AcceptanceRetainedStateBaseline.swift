import Darwin
import Foundation

struct AcceptanceRetainedStateBaseline: Codable, Equatable, Sendable {
  let schemaVersion: Int
  let transactionID: String
  let selectedOwnerUID: UInt32
  let observation: RetainedStateObservation

  init(
    transactionID: String,
    selectedOwnerUID: UInt32,
    observation: RetainedStateObservation
  ) {
    schemaVersion = 1
    self.transactionID = transactionID
    self.selectedOwnerUID = selectedOwnerUID
    self.observation = observation
  }

  func validate() throws {
    guard schemaVersion == 1, UUID(uuidString: transactionID) != nil,
      selectedOwnerUID != 0
    else {
      throw ReleasePackageError.verification("retained-state baseline authority is malformed")
    }
  }
}

struct AcceptanceRetainedStateBaselineStore {
  let url: URL

  func createOrVerify(_ value: AcceptanceRetainedStateBaseline) throws {
    try value.validate()
    if let existing = try load() {
      guard existing == value else {
        throw ReleasePackageError.verification("retained-state baseline changed")
      }
      return
    }
    try SecureFiles.createPrivateDirectory(url.deletingLastPathComponent())
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: url)
    guard try load() == value else {
      throw ReleasePackageError.verification("retained-state baseline was not durable")
    }
  }

  func load() throws -> AcceptanceRetainedStateBaseline? {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      if errno == ENOENT { return nil }
      throw ReleasePackageError.verification("cannot inspect retained-state baseline")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
      (info.st_mode & 0o7777) == 0o600
    else {
      throw ReleasePackageError.unsafePath(
        "retained-state baseline must be a mode-0600 single-link file")
    }
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let value = try JSONDecoder().decode(AcceptanceRetainedStateBaseline.self, from: data)
    guard data == (try CanonicalJSON.encode(value)) else {
      throw ReleasePackageError.verification("retained-state baseline is not canonical JSON")
    }
    try value.validate()
    return value
  }
}
