import Darwin
import Foundation

public enum SecureFiles {
  public static func enumerateTree(
    _ root: URL,
    includingPropertiesForKeys keys: [URLResourceKey] = []
  ) throws -> [URL] {
    var traversalFailure: ReleasePackageError?
    guard
      let enumerator = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: keys,
        options: [],
        errorHandler: { url, _ in
          traversalFailure = .verification(
            "cannot enumerate release authority below \(url.path)")
          return false
        }
      )
    else {
      throw ReleasePackageError.verification("cannot enumerate release authority at \(root.path)")
    }
    var entries: [URL] = []
    while let value = enumerator.nextObject() {
      guard let url = value as? URL else {
        throw ReleasePackageError.verification(
          "filesystem enumerator returned a non-URL authority member")
      }
      entries.append(url)
    }
    if let traversalFailure { throw traversalFailure }
    return entries
  }

  public static func createPrivateDirectory(_ url: URL) throws {
    let parent = url.deletingLastPathComponent()
    try rejectSymlink(url: parent)
    if mkdir(url.path, 0o700) != 0 {
      if errno != EEXIST { throw posix("mkdir", url) }
      var info = stat()
      guard lstat(url.path, &info) == 0,
        (info.st_mode & S_IFMT) == S_IFDIR,
        (info.st_mode & 0o777) == 0o700
      else {
        throw ReleasePackageError.unsafePath(
          "private root must be a mode-0700 directory: \(url.path)")
      }
    }
  }

  public static func createDirectory(_ url: URL, mode: mode_t) throws {
    try rejectSymlink(url: url.deletingLastPathComponent())
    if mkdir(url.path, mode) != 0, errno != EEXIST { throw posix("mkdir", url) }
    var info = stat()
    guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else {
      throw ReleasePackageError.unsafePath("expected directory at \(url.path)")
    }
    guard chmod(url.path, mode) == 0 else { throw posix("chmod", url) }
    try removeExtendedAttributes(url)
  }

  public static func atomicWrite(_ data: Data, to url: URL, mode: mode_t = 0o600) throws {
    try rejectSymlink(url: url.deletingLastPathComponent())
    let temporary = url.deletingLastPathComponent()
      .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
    let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
    guard descriptor >= 0 else { throw posix("open", temporary) }
    guard fchmod(descriptor, mode) == 0 else {
      close(descriptor)
      unlink(temporary.path)
      throw posix("fchmod", temporary)
    }
    var succeeded = false
    defer {
      close(descriptor)
      if !succeeded { unlink(temporary.path) }
    }
    try data.withUnsafeBytes { raw in
      guard let base = raw.baseAddress else { return }
      var offset = 0
      while offset < raw.count {
        let count = Darwin.write(descriptor, base.advanced(by: offset), raw.count - offset)
        guard count > 0 else { throw posix("write", temporary) }
        offset += count
      }
    }
    guard fsync(descriptor) == 0 else { throw posix("fsync", temporary) }
    guard rename(temporary.path, url.path) == 0 else { throw posix("rename", url) }
    succeeded = true
    try syncDirectory(url.deletingLastPathComponent())
  }

  public static func copyRegularFile(from source: URL, to destination: URL, mode: mode_t) throws {
    var info = stat()
    guard lstat(source.path, &info) == 0,
      (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1
    else {
      throw ReleasePackageError.unsafePath(
        "source must be a single-link regular file: \(source.path)")
    }
    try atomicWrite(
      Data(contentsOf: source, options: [.mappedIfSafe]),
      to: destination,
      mode: mode | S_IWUSR
    )
    try removeExtendedAttributes(destination)
    guard chmod(destination.path, mode) == 0 else { throw posix("chmod", destination) }
  }

  /// Copies a read-only dependency or toolchain input into fresh depot
  /// storage. The source may itself be hard-linked (as Homebrew licenses
  /// are), but the destination never preserves that link authority.
  public static func copyInputFile(from source: URL, to destination: URL, mode: mode_t) throws {
    let descriptor = open(source.path, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else { throw posix("open input", source) }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    var info = stat()
    guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
      try? handle.close()
      throw ReleasePackageError.unsafePath(
        "dependency input must be a regular file: \(source.path)")
    }
    let data: Data
    do {
      data = try handle.readToEnd() ?? Data()
      try handle.close()
    } catch {
      try? handle.close()
      throw ReleasePackageError.verification(
        "cannot read dependency input \(source.path): \(error)")
    }
    guard data.count == Int(info.st_size) else {
      throw ReleasePackageError.verification(
        "dependency input changed while it was read: \(source.path)")
    }
    try atomicWrite(data, to: destination, mode: mode)
    guard chmod(destination.path, mode) == 0 else { throw posix("chmod", destination) }
    try removeExtendedAttributes(destination)
  }

  public static func copyTree(
    from source: URL, to destination: URL, directoryMode: mode_t = 0o755,
    fileMode: mode_t = 0o644, preserveSourceModes: Bool = false
  ) throws {
    var info = stat()
    guard lstat(source.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else {
      throw ReleasePackageError.unsafePath("tree source is not a directory: \(source.path)")
    }
    let sourceRootMode = info.st_mode & 0o7777
    if preserveSourceModes {
      try requireSafeRetainedMode(sourceRootMode, path: source.path)
    }
    try createDirectory(
      destination, mode: preserveSourceModes ? sourceRootMode : directoryMode)
    let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey]
    let entries = try enumerateTree(source, includingPropertiesForKeys: keys)
      .sorted { $0.path < $1.path }
    for entry in entries {
      let relative = String(entry.path.dropFirst(source.path.count + 1))
      try validateRelativePath(relative)
      guard
        !relative.split(separator: "/").contains(where: { $0 == ".DS_Store" || $0.hasPrefix("._") })
      else {
        throw ReleasePackageError.unsafePath(
          "Apple metadata is not copied into release authority: \(relative)")
      }
      let target = destination.appendingPathComponent(relative)
      var entryInfo = stat()
      guard lstat(entry.path, &entryInfo) == 0 else { throw posix("lstat", entry) }
      switch entryInfo.st_mode & S_IFMT {
      case S_IFDIR:
        let mode = entryInfo.st_mode & 0o7777
        if preserveSourceModes { try requireSafeRetainedMode(mode, path: entry.path) }
        try createDirectory(target, mode: preserveSourceModes ? mode : directoryMode)
      case S_IFREG:
        var parentInfo = stat()
        let parent = target.deletingLastPathComponent()
        guard lstat(parent.path, &parentInfo) == 0,
          (parentInfo.st_mode & S_IFMT) == S_IFDIR
        else {
          throw ReleasePackageError.unsafePath(
            "tree destination parent is not a physical directory: \(parent.path)")
        }
        let mode = entryInfo.st_mode & 0o7777
        if preserveSourceModes { try requireSafeRetainedMode(mode, path: entry.path) }
        try copyRegularFile(from: entry, to: target, mode: preserveSourceModes ? mode : fileMode)
      default:
        throw ReleasePackageError.unsafePath(
          "bundle contains a symlink or special file: \(entry.path)")
      }
    }
  }

  private static func requireSafeRetainedMode(_ mode: mode_t, path: String) throws {
    guard mode & 0o7022 == 0 else {
      throw ReleasePackageError.unsafePath(
        "retained authority input has an unsafe mode: \(path)")
    }
  }

  public static func createSymlink(at url: URL, target: String) throws {
    guard target.hasPrefix("/"), target == "/Library/Application Support/Reach/Host/reachd" else {
      throw ReleasePackageError.unsafePath("unexpected release alias target")
    }
    try rejectSymlink(url: url.deletingLastPathComponent())
    guard symlink(target, url.path) == 0 else { throw posix("symlink", url) }
  }

  public static func validateRelativePath(_ value: String) throws {
    guard !value.isEmpty,
      !value.hasPrefix("/"),
      !value.contains("\0"),
      !value.split(separator: "/", omittingEmptySubsequences: false).contains(".."),
      !value.split(separator: "/", omittingEmptySubsequences: false).contains(".")
    else {
      throw ReleasePackageError.unsafePath(value)
    }
  }

  public static func rejectSymlink(url: URL) throws {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      if errno == ENOENT { return }
      throw posix("lstat", url)
    }
    guard (info.st_mode & S_IFMT) != S_IFLNK else {
      throw ReleasePackageError.unsafePath("symlink not allowed: \(url.path)")
    }
  }

  public static func removeExtendedAttributes(_ url: URL) throws {
    let count = listxattr(url.path, nil, 0, XATTR_NOFOLLOW)
    if count < 0 {
      if errno == ENOTSUP { return }
      throw posix("listxattr", url)
    }
    guard count > 0 else { return }
    var buffer = [CChar](repeating: 0, count: count)
    let loaded = listxattr(url.path, &buffer, buffer.count, XATTR_NOFOLLOW)
    guard loaded >= 0 else { throw posix("listxattr", url) }
    var start = 0
    while start < loaded {
      let end = buffer[start..<loaded].firstIndex(of: 0) ?? loaded
      let name = String(decoding: buffer[start..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self)
      guard !name.isEmpty else {
        throw ReleasePackageError.verification("empty extended-attribute name at \(url.path)")
      }
      guard removexattr(url.path, name, XATTR_NOFOLLOW) == 0 else {
        throw posix("removexattr", url)
      }
      start = end + 1
    }
  }

  public static func scrubExtendedAttributesRecursively(_ root: URL) throws {
    var entries = try enumerateTree(root).sorted { $0.path > $1.path }
    entries.append(root)
    for entry in entries {
      var info = stat()
      guard lstat(entry.path, &info) == 0 else { throw posix("lstat", entry) }
      let type = info.st_mode & S_IFMT
      let originalMode = info.st_mode & 0o7777
      let needsWrite = type != S_IFLNK && (originalMode & S_IWUSR) == 0
      if needsWrite, chmod(entry.path, originalMode | S_IWUSR) != 0 {
        throw posix("temporary chmod", entry)
      }
      do {
        try removeExtendedAttributes(entry)
      } catch {
        if needsWrite { _ = chmod(entry.path, originalMode) }
        throw error
      }
      if needsWrite, chmod(entry.path, originalMode) != 0 {
        throw posix("restore chmod", entry)
      }
    }
  }

  public static func setModificationTime(_ url: URL, seconds: Int64) throws {
    guard let value = Int(exactly: seconds) else {
      throw ReleasePackageError.verification("modification time is outside the platform range")
    }
    var times = [
      timeval(tv_sec: value, tv_usec: 0),
      timeval(tv_sec: value, tv_usec: 0),
    ]
    guard lutimes(url.path, &times) == 0 else { throw posix("lutimes", url) }
  }

  public static func syncDirectory(_ url: URL) throws {
    let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard descriptor >= 0 else { throw posix("open directory", url) }
    defer { close(descriptor) }
    guard fsync(descriptor) == 0 else { throw posix("fsync directory", url) }
  }

  private static func posix(_ operation: String, _ url: URL) -> ReleasePackageError {
    .verification("\(operation) failed for \(url.path): \(String(cString: strerror(errno)))")
  }
}
