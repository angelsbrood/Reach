import Darwin
import Foundation

/// Release paths are authority, not conveniences. The CLI and core therefore
/// reject lexical aliases and symlinked ancestors instead of silently
/// canonicalizing them after a caller has calculated a compiler-visible path.
public enum ReleasePathAuthority {
  public static func absoluteURL(_ raw: String, label: String) throws -> URL {
    guard raw.hasPrefix("/"), raw != "/", !raw.contains("\0") else {
      throw ReleasePackageError.invalidArgument("\(label) requires an absolute non-root path")
    }
    let components = raw.split(separator: "/", omittingEmptySubsequences: false)
    guard components.first?.isEmpty == true,
      components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
    else {
      throw ReleasePackageError.unsafePath(
        "\(label) must not contain empty, dot, or dot-dot path components")
    }
    let url = URL(fileURLWithPath: raw)
    guard url.path.utf8.elementsEqual(raw.utf8) else {
      throw ReleasePackageError.unsafePath("\(label) must use one canonical lexical spelling")
    }
    try rejectSymlinkAncestors(of: url, label: label)
    return url
  }

  /// Revalidates a programmatic mutable root before any release files are
  /// created. A URL caller cannot bypass the CLI's lexical and symlink rules.
  public static func mutableRoot(_ url: URL, label: String) throws -> URL {
    guard url.isFileURL else {
      throw ReleasePackageError.unsafePath("\(label) must be a file URL")
    }
    let canonical = try absoluteURL(url.path, label: label)
    guard canonical.path.utf8.elementsEqual(url.path.utf8) else {
      throw ReleasePackageError.unsafePath("\(label) changed while validating its authority")
    }
    var info = stat()
    if lstat(canonical.path, &info) == 0 {
      guard (info.st_mode & S_IFMT) == S_IFDIR else {
        throw ReleasePackageError.unsafePath("\(label) must be a directory when it exists")
      }
    } else if errno != ENOENT {
      throw ReleasePackageError.verification(
        "cannot inspect \(label) at \(canonical.path): \(String(cString: strerror(errno)))")
    }
    return canonical
  }

  private static func rejectSymlinkAncestors(of url: URL, label: String) throws {
    var cursor = URL(fileURLWithPath: "/", isDirectory: true)
    var deepestExisting = cursor
    for component in url.pathComponents.dropFirst() {
      cursor.appendPathComponent(component)
      var info = stat()
      if lstat(cursor.path, &info) != 0 {
        if errno == ENOENT {
          try requirePhysicalSpelling(deepestExisting, label: label)
          return
        }
        throw ReleasePackageError.verification(
          "cannot inspect \(label) ancestor \(cursor.path): \(String(cString: strerror(errno)))")
      }
      guard (info.st_mode & S_IFMT) != S_IFLNK else {
        throw ReleasePackageError.unsafePath(
          "\(label) has a symlinked ancestor: \(cursor.path)")
      }
      deepestExisting = cursor
    }
    try requirePhysicalSpelling(deepestExisting, label: label)
  }

  private static func requirePhysicalSpelling(_ url: URL, label: String) throws {
    guard let resolvedPointer = realpath(url.path, nil) else {
      throw ReleasePackageError.verification(
        "cannot resolve \(label) prefix \(url.path): \(String(cString: strerror(errno)))")
    }
    defer { free(resolvedPointer) }
    let resolved = String(cString: resolvedPointer)
    guard resolved.utf8.elementsEqual(url.path.utf8) else {
      throw ReleasePackageError.unsafePath(
        "\(label) must use the on-disk spelling of its existing prefix: \(resolved)")
    }
  }
}
