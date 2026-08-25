import Darwin
import Foundation

public enum HostStoragePhase: String, Codable, Sendable {
  case preparation
  case continuation

  public var minimumAvailableBytes: UInt64 {
    switch self {
    case .preparation: 150 * 1_024 * 1_024 * 1_024
    case .continuation: 60 * 1_024 * 1_024 * 1_024
    }
  }
}

public struct HostStorageReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let phase: HostStoragePhase
  public let availableBytes: UInt64
  public let totalBytes: UInt64
  public let requiredBytes: UInt64
  public let filesystemAuthoritySHA256: String
  public let verdict: String

  public init(
    phase: HostStoragePhase,
    availableBytes: UInt64,
    totalBytes: UInt64,
    requiredBytes: UInt64,
    filesystemAuthoritySHA256: String
  ) {
    schemaVersion = 1
    self.phase = phase
    self.availableBytes = availableBytes
    self.totalBytes = totalBytes
    self.requiredBytes = requiredBytes
    self.filesystemAuthoritySHA256 = filesystemAuthoritySHA256
    verdict = "pass"
  }

  public func validate() throws {
    guard schemaVersion == 1, requiredBytes == phase.minimumAvailableBytes,
      availableBytes >= requiredBytes, totalBytes >= availableBytes,
      filesystemAuthoritySHA256.range(
        of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
      verdict == "pass"
    else {
      throw ReleasePackageError.verification("host storage report is malformed or insufficient")
    }
  }
}

protocol HostStorageChecking {
  func require(_ phase: HostStoragePhase) throws -> HostStorageReport
}

/// Binds the S36 capacity promise to the filesystem that physically contains
/// the selected caller root. The report deliberately contains no path or
/// volume name; only a stable digest of the kernel filesystem identifier is
/// retained as evidence.
public struct HostStorageAuthority: HostStorageChecking {
  private let root: URL

  public init(root: URL = FileManager.default.homeDirectoryForCurrentUser) throws {
    let physical = try ReleasePathAuthority.absoluteURL(root.path, label: "host storage root")
    var info = stat()
    guard lstat(physical.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else {
      throw ReleasePackageError.unsafePath("host storage root must be an existing directory")
    }
    self.root = physical
  }

  public func require(_ phase: HostStoragePhase) throws -> HostStorageReport {
    var value = statfs()
    guard statfs(root.path, &value) == 0, value.f_bsize > 0,
      value.f_bavail >= 0, value.f_blocks >= 0
    else {
      throw ReleasePackageError.verification("cannot inspect host storage capacity")
    }
    let blockSize = UInt64(value.f_bsize)
    let available = UInt64(value.f_bavail).multipliedReportingOverflow(by: blockSize)
    let total = UInt64(value.f_blocks).multipliedReportingOverflow(by: blockSize)
    guard !available.overflow, !total.overflow,
      available.partialValue >= phase.minimumAvailableBytes
    else {
      throw ReleasePackageError.verification(
        "S36 host storage fell below the \(phase.minimumAvailableBytes)-byte \(phase.rawValue) floor"
      )
    }
    var filesystemID = value.f_fsid
    let authority = withUnsafeBytes(of: &filesystemID) { Digests.sha256(Data($0)) }
    let report = HostStorageReport(
      phase: phase, availableBytes: available.partialValue,
      totalBytes: total.partialValue, requiredBytes: phase.minimumAvailableBytes,
      filesystemAuthoritySHA256: authority)
    try report.validate()
    return report
  }
}
