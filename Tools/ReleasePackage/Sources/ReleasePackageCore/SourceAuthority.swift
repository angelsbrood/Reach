import Darwin
import Foundation

public struct SourceAuthority: Codable, Equatable, Sendable {
  public struct Submodule: Codable, Equatable, Sendable {
    public let path: String
    public let revision: String
  }

  public let commit: String
  public let commitTimestamp: Int64
  public let main: String
  public let originMain: String
  public let submodules: [Submodule]
  public let exportedTreeSHA256: String
  public let packageResolvedSHA256: String
  public let goModSHA256: String
  public let goSumSHA256: String
}

public struct SourceInspector {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
  }

  public func validateAndExport(
    repository: URL,
    exportRoot: URL,
    configuration: ReleaseConfiguration,
    logDirectory: URL
  ) throws -> SourceAuthority {
    try SecureFiles.rejectSymlink(url: repository)
    let head = try git(["rev-parse", "HEAD"], at: repository).trimmed
    let main = try git(["rev-parse", "main"], at: repository).trimmed
    let origin = try git(["rev-parse", "origin/main"], at: repository).trimmed
    guard head == main, main == origin else {
      throw ReleasePackageError.sourceAuthority("HEAD, main, and origin/main must be identical")
    }
    guard head.range(of: "^[0-9a-f]{40}$", options: .regularExpression) != nil else {
      throw ReleasePackageError.sourceAuthority("HEAD is not a full SHA-1 commit")
    }

    let status = try git(["status", "--porcelain=v1", "--untracked-files=all"], at: repository)
    for rawLine in status.split(separator: "\n", omittingEmptySubsequences: true) {
      let line = String(rawLine)
      guard line.hasPrefix("?? ") else {
        throw ReleasePackageError.sourceAuthority("tracked or staged change present: \(line)")
      }
      let path = String(line.dropFirst(3))
      guard
        configuration.untrackedAllowlist.contains(where: { allowed in
          path == String(allowed.dropLast()) || path.hasPrefix(allowed)
        })
      else {
        throw ReleasePackageError.sourceAuthority("untracked path is not allowlisted: \(path)")
      }
    }

    let submoduleOutput = try git(["submodule", "status", "--recursive"], at: repository)
    var submodules: [SourceAuthority.Submodule] = []
    for rawLine in submoduleOutput.split(separator: "\n", omittingEmptySubsequences: true) {
      let line = String(rawLine)
      guard line.first == " " else {
        throw ReleasePackageError.sourceAuthority(
          "submodule is dirty, missing, or at the wrong revision")
      }
      let pieces = line.dropFirst().split(separator: " ", maxSplits: 2)
      guard pieces.count >= 2 else {
        throw ReleasePackageError.sourceAuthority("malformed submodule status")
      }
      submodules.append(.init(path: String(pieces[1]), revision: String(pieces[0])))
    }
    submodules.sort { $0.path < $1.path }

    let timestampString = try git(["show", "-s", "--format=%ct", "HEAD"], at: repository).trimmed
    guard let timestamp = Int64(timestampString), timestamp > 0 else {
      throw ReleasePackageError.sourceAuthority("commit timestamp is invalid")
    }

    try SecureFiles.createPrivateDirectory(exportRoot)
    let archive = exportRoot.deletingLastPathComponent().appendingPathComponent(
      "source-\(UUID().uuidString).tar")
    defer { try? FileManager.default.removeItem(at: archive) }
    _ = try runner.run(
      "/usr/bin/git",
      ["archive", "--format=tar", "--output", archive.path, "HEAD"],
      currentDirectory: repository,
      logURL: logDirectory.appendingPathComponent("git-archive.log")
    )
    _ = try runner.run(
      "/usr/bin/tar",
      ["-xf", archive.path, "-C", exportRoot.path],
      logURL: logDirectory.appendingPathComponent("git-archive-extract.log")
    )

    let treeDigest = try canonicalTreeDigest(exportRoot)
    return SourceAuthority(
      commit: head,
      commitTimestamp: timestamp,
      main: main,
      originMain: origin,
      submodules: submodules,
      exportedTreeSHA256: treeDigest,
      packageResolvedSHA256: try Digests.sha256(
        file: exportRoot.appendingPathComponent("reachd/Package.resolved")),
      goModSHA256: try Digests.sha256(
        file: exportRoot.appendingPathComponent("mesh-helper/go.mod")),
      goSumSHA256: try Digests.sha256(file: exportRoot.appendingPathComponent("mesh-helper/go.sum"))
    )
  }

  public func canonicalTreeDigest(_ root: URL, excluding excludedPaths: Set<String> = []) throws
    -> String
  {
    let lines = try canonicalTreeEntries(root, excluding: excludedPaths)
    return Digests.sha256(Data((lines.joined(separator: "\n") + "\n").utf8))
  }

  public func canonicalTreeEntries(_ root: URL, excluding excludedPaths: Set<String> = []) throws
    -> [String]
  {
    let manager = FileManager.default
    var lines: [String] = []
    let rootPrefix = root.path.hasSuffix("/") ? root.path : root.path + "/"
    for url in try SecureFiles.enumerateTree(root) {
      guard url.path.hasPrefix(rootPrefix) else {
        throw ReleasePackageError.unsafePath("enumerated path escaped authority root: \(url.path)")
      }
      let relative = String(url.path.dropFirst(rootPrefix.count))
      try SecureFiles.validateRelativePath(relative)
      if excludedPaths.contains(relative)
        || excludedPaths.contains(where: { relative.hasPrefix($0 + "/") })
      {
        continue
      }
      var info = stat()
      guard lstat(url.path, &info) == 0 else {
        throw ReleasePackageError.verification("cannot inspect exported path \(relative)")
      }
      let mode = String(format: "%04o", info.st_mode & 0o7777)
      switch info.st_mode & S_IFMT {
      case S_IFDIR:
        lines.append("dir\t\(mode)\t\(relative)")
      case S_IFREG:
        guard info.st_nlink == 1 else {
          throw ReleasePackageError.unsafePath("hard link in exported source: \(relative)")
        }
        lines.append(
          "file\t\(mode)\t\(info.st_size)\t\(try Digests.sha256(file: url))\t\(relative)")
      case S_IFLNK:
        let target = try manager.destinationOfSymbolicLink(atPath: url.path)
        lines.append(
          "link\t\(mode)\t\(target.utf8.count)\t\(Digests.sha256(Data(target.utf8)))\t\(relative)\t\(target)"
        )
      default:
        throw ReleasePackageError.unsafePath("special file in exported source: \(relative)")
      }
    }
    lines.sort()
    return lines
  }

  private func git(_ arguments: [String], at repository: URL) throws -> String {
    try runner.run("/usr/bin/git", arguments, currentDirectory: repository).output
  }
}

extension String {
  fileprivate var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
