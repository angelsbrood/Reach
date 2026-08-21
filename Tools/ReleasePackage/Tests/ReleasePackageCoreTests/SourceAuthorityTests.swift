import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

@Test func sourceAuthorityRequiresSynchronizedCleanRefsAndOnlyTasksUntracked() throws {
  let root = try makeTemporaryDirectory("source-authority")
  defer { removeTemporaryDirectory(root) }
  let repository = root.appendingPathComponent("repository")
  let remote = root.appendingPathComponent("remote.git")
  try SecureFiles.createPrivateDirectory(repository)
  for name in ["logs-one", "logs-two", "logs-three"] {
    try SecureFiles.createPrivateDirectory(root.appendingPathComponent(name))
  }
  let runner = ProcessRunner()
  try runner.run("/usr/bin/git", ["init", "--bare", remote.path])
  try runner.run("/usr/bin/git", ["init", "-b", "main"], currentDirectory: repository)
  for directory in ["reachd", "mesh-helper"] {
    try SecureFiles.createDirectory(repository.appendingPathComponent(directory), mode: 0o755)
  }
  try SecureFiles.atomicWrite(
    Data("resolved\n".utf8), to: repository.appendingPathComponent("reachd/Package.resolved"),
    mode: 0o644)
  try SecureFiles.atomicWrite(
    Data("module example\n".utf8), to: repository.appendingPathComponent("mesh-helper/go.mod"),
    mode: 0o644)
  try SecureFiles.atomicWrite(
    Data("sum\n".utf8), to: repository.appendingPathComponent("mesh-helper/go.sum"), mode: 0o644)
  try runner.run("/usr/bin/git", ["add", "."], currentDirectory: repository)
  try runner.run(
    "/usr/bin/git",
    [
      "-c", "user.name=Reach Test", "-c", "user.email=reach-test@example.invalid", "commit", "-m",
      "fixture",
    ],
    currentDirectory: repository,
    environment: [
      "GIT_AUTHOR_DATE": "2026-08-20T00:00:00Z", "GIT_COMMITTER_DATE": "2026-08-20T00:00:00Z",
    ]
  )
  try runner.run(
    "/usr/bin/git", ["remote", "add", "origin", remote.path], currentDirectory: repository)
  try runner.run("/usr/bin/git", ["push", "-u", "origin", "main"], currentDirectory: repository)

  let configuration = try ReleaseConfiguration.load(
    from: repositoryRoot().appendingPathComponent("release/release.json"))
  let inspector = SourceInspector()
  let authority = try inspector.validateAndExport(
    repository: repository,
    exportRoot: root.appendingPathComponent("export-one"),
    configuration: configuration,
    logDirectory: root.appendingPathComponent("logs-one")
  )
  #expect(authority.commit == authority.main)
  #expect(authority.main == authority.originMain)

  try SecureFiles.createDirectory(repository.appendingPathComponent("tasks"), mode: 0o755)
  try SecureFiles.atomicWrite(
    Data("unrelated\n".utf8), to: repository.appendingPathComponent("tasks/todo.md"), mode: 0o644)
  _ = try inspector.validateAndExport(
    repository: repository,
    exportRoot: root.appendingPathComponent("export-two"),
    configuration: configuration,
    logDirectory: root.appendingPathComponent("logs-two")
  )

  try SecureFiles.atomicWrite(
    Data("not allowed\n".utf8), to: repository.appendingPathComponent("stray.txt"), mode: 0o644)
  #expect(throws: ReleasePackageError.self) {
    try inspector.validateAndExport(
      repository: repository,
      exportRoot: root.appendingPathComponent("export-three"),
      configuration: configuration,
      logDirectory: root.appendingPathComponent("logs-three")
    )
  }
}

@Test func canonicalTreeRefusesHardlinksAndSpecialFiles() throws {
  let root = try makeTemporaryDirectory("source-tree")
  defer { removeTemporaryDirectory(root) }
  let tree = root.appendingPathComponent("tree")
  try SecureFiles.createPrivateDirectory(tree)
  let file = tree.appendingPathComponent("one")
  try SecureFiles.atomicWrite(Data("one".utf8), to: file)
  #expect(link(file.path, tree.appendingPathComponent("two").path) == 0)
  #expect(throws: ReleasePackageError.self) { try SourceInspector().canonicalTreeDigest(tree) }
}

@Test func everyReleaseTreeTraversalFailsClosedOnUnreadableDescendants() throws {
  let root = try makeTemporaryDirectory("tree-enumeration-failure")
  defer { removeTemporaryDirectory(root) }
  let tree = root.appendingPathComponent("tree")
  try SecureFiles.createDirectory(tree, mode: 0o755)
  let blocked = tree.appendingPathComponent("blocked")
  try SecureFiles.createDirectory(blocked, mode: 0o755)
  try SecureFiles.atomicWrite(Data("private\n".utf8), to: blocked.appendingPathComponent("value"))
  #expect(chmod(blocked.path, 0o000) == 0)
  defer { _ = chmod(blocked.path, 0o755) }
  #expect(throws: ReleasePackageError.self) { try SecureFiles.enumerateTree(tree) }
  #expect(throws: ReleasePackageError.self) { try SourceInspector().canonicalTreeDigest(tree) }
  #expect(throws: ReleasePackageError.self) {
    try SecureFiles.copyTree(from: tree, to: root.appendingPathComponent("copy"))
  }
}
