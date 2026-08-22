import Darwin
import Foundation

struct NotarizationJournalStore {
  let url: URL

  func withExclusiveLock<T>(_ body: () throws -> T) throws -> T {
    let parent = url.deletingLastPathComponent()
    try SecureFiles.createPrivateDirectory(parent)
    let lockURL = URL(fileURLWithPath: url.path + ".lock")
    let descriptor = open(lockURL.path, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open notarization journal lock")
    }
    defer { close(descriptor) }
    guard fchmod(descriptor, 0o600) == 0, flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
      throw ReleasePackageError.verification("notarization journal is already in use")
    }
    defer { _ = flock(descriptor, LOCK_UN) }
    return try body()
  }

  func load() throws -> NotarizationJournal? {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      if errno == ENOENT { return nil }
      throw ReleasePackageError.verification("cannot inspect notarization journal")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1,
      (info.st_mode & 0o7777) == 0o600
    else {
      throw ReleasePackageError.unsafePath(
        "notarization journal must be a mode-0600 single-link regular file")
    }
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let value = try JSONDecoder().decode(NotarizationJournal.self, from: data)
    guard data == (try CanonicalJSON.encode(value)) else {
      throw ReleasePackageError.verification("notarization journal is not canonical JSON")
    }
    try value.validate()
    return value
  }

  func write(_ value: NotarizationJournal) throws {
    try value.validate()
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: url)
  }
}
