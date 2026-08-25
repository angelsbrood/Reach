import Darwin
import Foundation

/// Private host-side authority joining the exact pinned-SSH credentials and
/// one S36-owned tooling root to a durable rig run. Paths remain outside the
/// privacy-minimized evidence pack; the rig journal retains only this file's
/// digest.
public struct AcceptanceHostAuthority: Codable, Equatable, Sendable {
  public struct Record: Codable, Equatable, Sendable {
    public let role: String
    public let path: String
    public let kind: String
    public let device: UInt64
    public let inode: UInt64
    public let sha256: String?

    public init(
      role: String, path: String, kind: String,
      device: UInt64, inode: UInt64, sha256: String?
    ) {
      self.role = role
      self.path = path
      self.kind = kind
      self.device = device
      self.inode = inode
      self.sha256 = sha256
    }
  }

  public let schemaVersion: Int
  public let runID: String
  public let identity: Record
  public let knownHosts: Record
  public let toolingRoot: Record

  public init(
    runID: String, identity: Record, knownHosts: Record, toolingRoot: Record
  ) {
    schemaVersion = 1
    self.runID = runID
    self.identity = identity
    self.knownHosts = knownHosts
    self.toolingRoot = toolingRoot
  }

  public func validate() throws {
    let records = [identity, knownHosts, toolingRoot]
    guard schemaVersion == 1, UUID(uuidString: runID) != nil,
      identity.role == "ssh-identity", knownHosts.role == "ssh-known-hosts",
      toolingRoot.role == "tooling-root",
      identity.kind == "file", knownHosts.kind == "file",
      toolingRoot.kind == "directory",
      records.map(\.path).count == Set(records.map(\.path)).count,
      records.allSatisfy({
        $0.path.hasPrefix("/") && $0.path != "/" && !$0.path.contains("..")
          && !$0.path.contains("//") && $0.device > 0 && $0.inode > 0
      }),
      [identity, knownHosts].allSatisfy({
        $0.sha256?.range(
          of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
      }), toolingRoot.sha256 == nil
    else {
      throw ReleasePackageError.verification("S36 host authority is malformed")
    }
  }

  public static func capture(
    runID: String, identity: URL, knownHosts: URL, toolingRoot: URL
  ) throws -> Self {
    let value = Self(
      runID: runID,
      identity: try fileRecord(identity, role: "ssh-identity"),
      knownHosts: try fileRecord(knownHosts, role: "ssh-known-hosts"),
      toolingRoot: try directoryRecord(toolingRoot, role: "tooling-root"))
    try value.validate()
    return value
  }

  public static func load(_ url: URL) throws -> Self {
    try loadWithDigest(url).authority
  }

  package static func loadWithDigest(
    _ url: URL
  ) throws -> (authority: Self, sha256: String) {
    let data = try privateFileData(url, label: "S36 host authority")
    let value = try JSONDecoder().decode(Self.self, from: data)
    guard data == (try CanonicalJSON.encode(value)) else {
      throw ReleasePackageError.verification("S36 host authority is not canonical")
    }
    try value.validate()
    return (value, Digests.sha256(data))
  }

  public func verifyCredentials(identity: URL, knownHosts: URL) throws {
    try validate()
    let actualIdentity = try Self.fileRecord(identity, role: "ssh-identity")
    let actualKnownHosts = try Self.fileRecord(knownHosts, role: "ssh-known-hosts")
    guard actualIdentity == self.identity, actualKnownHosts == self.knownHosts else {
      throw ReleasePackageError.verification(
        "pinned SSH credentials differ from the rig-bound host authority")
    }
  }

  public func verifyToolingRoot() throws {
    try validate()
    guard
      try Self.directoryRecord(
        URL(fileURLWithPath: toolingRoot.path), role: "tooling-root") == toolingRoot
    else {
      throw ReleasePackageError.verification(
        "S36 tooling root differs from the rig-bound host authority")
    }
  }

  private static func fileRecord(_ url: URL, role: String) throws -> Record {
    try fileSnapshot(url, role: role).record
  }

  private static func fileSnapshot(
    _ url: URL, role: String
  ) throws -> (record: Record, data: Data) {
    let physical = try exactPhysical(url, label: role)
    let descriptor = open(physical.path, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open " + role)
    }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    var info = stat()
    guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, info.st_uid == getuid(), (info.st_mode & 0o7777) == 0o600
    else {
      try? handle.close()
      throw ReleasePackageError.unsafePath(role + " must be one owner-private file")
    }
    let data: Data
    do {
      data = try handle.readToEnd() ?? Data()
      try handle.close()
    } catch {
      try? handle.close()
      throw ReleasePackageError.verification("cannot read " + role)
    }
    guard data.count == Int(info.st_size) else {
      throw ReleasePackageError.verification(role + " changed while reading")
    }
    return (
      .init(
        role: role, path: physical.path, kind: "file",
        device: UInt64(info.st_dev), inode: UInt64(info.st_ino),
        sha256: Digests.sha256(data)),
      data
    )
  }

  private static func directoryRecord(_ url: URL, role: String) throws -> Record {
    let physical = try exactPhysical(url, label: role)
    var info = stat()
    guard lstat(physical.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
      info.st_uid == getuid(), (info.st_mode & 0o7777) == 0o700
    else {
      throw ReleasePackageError.unsafePath(role + " must be one owner-private directory")
    }
    return .init(
      role: role, path: physical.path, kind: "directory",
      device: UInt64(info.st_dev), inode: UInt64(info.st_ino), sha256: nil)
  }

  private static func exactPhysical(_ url: URL, label: String) throws -> URL {
    let physical = try ReleasePathAuthority.absoluteURL(url.path, label: label)
    guard physical.path.utf8.elementsEqual(url.path.utf8), url.path != "/" else {
      throw ReleasePackageError.unsafePath(label + " lacks exact physical spelling")
    }
    return physical
  }

  private static func privateFileData(_ url: URL, label: String) throws -> Data {
    try fileSnapshot(url, role: label).data
  }
}
