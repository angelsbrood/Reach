import Darwin
import Foundation

public struct AcceptanceJournalStore {
  public let url: URL

  public init(url: URL) {
    self.url = url
  }

  public func withExclusiveLock<T>(_ body: () throws -> T) throws -> T {
    try SecureFiles.createPrivateDirectory(url.deletingLastPathComponent())
    let lockURL = URL(fileURLWithPath: url.path + ".lock")
    let descriptor = open(lockURL.path, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open acceptance journal lock")
    }
    defer { close(descriptor) }
    guard fchmod(descriptor, 0o600) == 0, flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
      throw ReleasePackageError.verification("acceptance journal is already in use")
    }
    defer { _ = flock(descriptor, LOCK_UN) }
    return try body()
  }

  public func load() throws -> AcceptanceJournal? {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      if errno == ENOENT { return nil }
      throw ReleasePackageError.verification("cannot inspect acceptance journal")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
      (info.st_mode & 0o7777) == 0o600
    else {
      throw ReleasePackageError.unsafePath(
        "acceptance journal must be a mode-0600 single-link regular file")
    }
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let value = try JSONDecoder().decode(AcceptanceJournal.self, from: data)
    guard data == (try CanonicalJSON.encode(value)) else {
      throw ReleasePackageError.verification("acceptance journal is not canonical JSON")
    }
    try value.validate()
    return value
  }

  public func create(_ value: AcceptanceJournal) throws {
    try value.validate()
    guard !FileManager.default.fileExists(atPath: url.path) else {
      throw ReleasePackageError.verification("acceptance transaction already exists")
    }
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: url)
  }

  @discardableResult
  public func transition(
    to phase: AcceptanceTransactionPhase,
    at timestamp: String,
    failureCode: String? = nil
  ) throws -> AcceptanceJournal {
    guard let current = try load() else {
      throw ReleasePackageError.verification("acceptance transaction is not prepared")
    }
    let next = try current.transitioning(
      to: phase, at: timestamp, failureCode: failureCode)
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(next), to: url)
    return next
  }
}
