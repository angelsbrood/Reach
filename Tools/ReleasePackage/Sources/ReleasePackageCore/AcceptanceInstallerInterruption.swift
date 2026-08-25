import Darwin
import Foundation

public enum AcceptanceInstalledAuthority: String, Codable, Sendable {
  case prior
  case target
  case mixed
}

public struct AcceptanceInstallerInterruptionReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let transactionID: String
  public let transactionJournalSHA256: String
  public let targetP5SHA256: String
  public let boundary: String
  public let observedAuthority: AcceptanceInstalledAuthority
  public let observedAtUTC: String

  public init(
    transactionID: String,
    transactionJournalSHA256: String,
    targetP5SHA256: String,
    observedAuthority: AcceptanceInstalledAuthority,
    observedAtUTC: String
  ) {
    schemaVersion = 1
    self.transactionID = transactionID
    self.transactionJournalSHA256 = transactionJournalSHA256
    self.targetP5SHA256 = targetP5SHA256
    boundary = "component-receipt-transition"
    self.observedAuthority = observedAuthority
    self.observedAtUTC = observedAtUTC
  }

  public func validate() throws {
    guard schemaVersion == 1, UUID(uuidString: transactionID) != nil,
      Self.validSHA256(transactionJournalSHA256), Self.validSHA256(targetP5SHA256),
      boundary == "component-receipt-transition", !observedAtUTC.isEmpty
    else {
      throw ReleasePackageError.verification(
        "Installer interruption evidence is malformed")
    }
  }

  private static func validSHA256(_ value: String) -> Bool {
    value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
  }
}

extension AcceptanceJournalStore {
  public var installerInterruptionURL: URL {
    URL(fileURLWithPath: url.path + ".installer-interruption.json")
  }

  func createInstallerInterruption(
    _ value: AcceptanceInstallerInterruptionReport
  ) throws {
    try value.validate()
    var info = stat()
    guard lstat(installerInterruptionURL.path, &info) != 0, errno == ENOENT else {
      throw ReleasePackageError.verification(
        "Installer interruption evidence already exists")
    }
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(value), to: installerInterruptionURL)
  }

  public func loadInstallerInterruption() throws
    -> AcceptanceInstallerInterruptionReport?
  {
    var info = stat()
    guard lstat(installerInterruptionURL.path, &info) == 0 else {
      if errno == ENOENT { return nil }
      throw ReleasePackageError.verification(
        "cannot inspect Installer interruption evidence")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
      (info.st_mode & 0o7777) == 0o600
    else {
      throw ReleasePackageError.unsafePath(
        "Installer interruption evidence must be a mode-0600 single-link file")
    }
    let data = try Data(contentsOf: installerInterruptionURL, options: [.mappedIfSafe])
    let value = try JSONDecoder().decode(
      AcceptanceInstallerInterruptionReport.self, from: data)
    guard data == (try CanonicalJSON.encode(value)) else {
      throw ReleasePackageError.verification(
        "Installer interruption evidence is not canonical JSON")
    }
    try value.validate()
    return value
  }
}
