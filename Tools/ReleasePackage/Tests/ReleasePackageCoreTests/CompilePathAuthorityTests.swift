import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

@Suite("Compile path authority")
struct CompilePathAuthorityTests {
  @Test("different caller roots produce one exact compiler-visible root length")
  func variedCallerRootLengths() throws {
    let roots = [
      URL(fileURLWithPath: "/private/tmp/r"),
      URL(fileURLWithPath: "/private/tmp/reach-release-a-deliberately-longer-root"),
      URL(
        fileURLWithPath:
          "/private/tmp/reach-release-a-third-root-with-a-different-length-for-cross-process-proof"
      ),
    ]

    for root in roots {
      let buildA = try CompilePathAuthority.passRoot(workRoot: root, passName: "build-a")
      let buildB = try CompilePathAuthority.passRoot(workRoot: root, passName: "build-b")
      #expect(buildA.path.utf8.count == CompilePathAuthority.rootUTF8Length)
      #expect(buildB.path.utf8.count == CompilePathAuthority.rootUTF8Length)
      #expect(buildA.path != buildB.path)
      #expect(buildA.lastPathComponent.hasPrefix("compile-root-"))
    }
  }

  @Test("unknown passes and overlong roots fail closed")
  func refusals() throws {
    #expect(throws: ReleasePackageError.self) {
      _ = try CompilePathAuthority.passRoot(
        workRoot: URL(fileURLWithPath: "/private/tmp/reach"), passName: "build-c")
    }
    let overlong = "/private/tmp/" + String(repeating: "x", count: 230)
    #expect(throws: ReleasePackageError.self) {
      _ = try CompilePathAuthority.passRoot(
        workRoot: URL(fileURLWithPath: overlong), passName: "build-a")
    }
  }

  @Test("lexical dot segments are refused before URL authority is constructed")
  func dotSegmentsAreRefused() {
    let canonical = try? ReleasePathAuthority.absoluteURL(
      "/private/tmp/reach-release/work", label: "release work root")
    #expect(canonical?.path == "/private/tmp/reach-release/work")
    for path in [
      "/private/tmp/reach-release/./work",
      "/private/tmp/reach-release/../work",
      "/private/tmp//reach-release/work",
      "/private/tmp/reach-release/work/",
    ] {
      #expect(throws: ReleasePackageError.self) {
        _ = try ReleasePathAuthority.absoluteURL(path, label: "release work root")
      }
    }
  }

  @Test("a nested symlink ancestor is refused before root creation")
  func nestedSymlinkAncestorIsRefused() throws {
    let parent = try makeTemporaryDirectory("compile-path-symlink")
    defer { removeTemporaryDirectory(parent) }
    let real = parent.appendingPathComponent("real")
    try SecureFiles.createDirectory(real, mode: 0o700)
    let nested = real.appendingPathComponent("nested")
    try SecureFiles.createDirectory(nested, mode: 0o700)
    let alias = parent.appendingPathComponent("alias")
    #expect(symlink(nested.path, alias.path) == 0)

    let proposed = alias.appendingPathComponent("work")
    #expect(!FileManager.default.fileExists(atPath: proposed.path))
    #expect(throws: ReleasePackageError.self) {
      _ = try ReleasePathAuthority.mutableRoot(proposed, label: "release work root")
    }
    #expect(!FileManager.default.fileExists(atPath: proposed.path))
  }

  @Test("a case-folded alias is refused on case-insensitive filesystems")
  func caseFoldedAliasIsRefused() throws {
    let parent = try makeTemporaryDirectory("compile-path-case")
    defer { removeTemporaryDirectory(parent) }
    let physical = parent.appendingPathComponent("PhysicalSpelling")
    try SecureFiles.createDirectory(physical, mode: 0o700)
    let alias = parent.appendingPathComponent("physicalspelling")
    var info = stat()
    guard lstat(alias.path, &info) == 0 else {
      // Case-sensitive volumes have no alias to exercise.
      return
    }

    let proposed = alias.appendingPathComponent("work")
    #expect(!FileManager.default.fileExists(atPath: proposed.path))
    #expect(throws: ReleasePackageError.self) {
      _ = try ReleasePathAuthority.mutableRoot(proposed, label: "release work root")
    }
    #expect(!FileManager.default.fileExists(atPath: proposed.path))
  }

  @Test("a Unicode-normalized alias is refused byte-exactly")
  func unicodeNormalizedAliasIsRefused() throws {
    let parent = try makeTemporaryDirectory("compile-path-unicode")
    defer { removeTemporaryDirectory(parent) }
    let decomposedName = "Physical-e\u{301}"
    let precomposedName = "Physical-\u{E9}"
    #expect(!decomposedName.utf8.elementsEqual(precomposedName.utf8))

    let physical = parent.appendingPathComponent(decomposedName)
    try SecureFiles.createDirectory(physical, mode: 0o700)
    let alias = parent.appendingPathComponent(precomposedName)
    var info = stat()
    guard lstat(alias.path, &info) == 0 else {
      // Filesystems without normalization aliases have no alias to exercise.
      return
    }
    guard let resolvedPointer = realpath(alias.path, nil) else {
      Issue.record("realpath failed for the normalization-alias fixture")
      return
    }
    defer { free(resolvedPointer) }
    let resolved = String(cString: resolvedPointer)
    #expect(resolved == alias.path)
    guard !resolved.utf8.elementsEqual(alias.path.utf8) else {
      // The filesystem returned the caller's exact bytes, so there is no
      // distinct physical spelling for this fixture.
      return
    }

    let proposed = alias.appendingPathComponent("work")
    #expect(!FileManager.default.fileExists(atPath: proposed.path))
    #expect(throws: ReleasePackageError.self) {
      _ = try ReleasePathAuthority.mutableRoot(proposed, label: "release work root")
    }
    #expect(!FileManager.default.fileExists(atPath: proposed.path))
  }
}
