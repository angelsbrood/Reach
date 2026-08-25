import Testing

@testable import ReleasePackageCore

@Test func unmanagedMigrationRequiresTheLiveImageToBeTheExactRetainedVnode() throws {
  let path = "/Users/example/.local/libexec/reach/reachd"
  let live = "p123\0\nftxt\0D0x100000e\0i4567\0n\(path)\0\n"
  let exact = try UnmanagedHostMigration.runningImageVnode(
    procPath: path, expectedExecutable: path,
    expectedDevice: 0x100000e, expectedInode: 4567,
    lsofOutput: live)
  #expect(exact.device == 0x100000e)
  #expect(exact.inode == 4567)

  let deleted = "p123\0\nftxt\0D0x100000e\0i4567\0n\(path) (deleted)\0\n"
  #expect(throws: ReleasePackageError.self) {
    try UnmanagedHostMigration.runningImageVnode(
      procPath: path, expectedExecutable: path,
      expectedDevice: 0x100000e, expectedInode: 4567,
      lsofOutput: deleted)
  }

  #expect(throws: ReleasePackageError.self) {
    try UnmanagedHostMigration.runningImageVnode(
      procPath: path, expectedExecutable: path,
      expectedDevice: 0x100000e, expectedInode: 9999,
      lsofOutput: live)
  }

  #expect(throws: ReleasePackageError.self) {
    try UnmanagedHostMigration.runningImageVnode(
      procPath: path, expectedExecutable: path,
      expectedDevice: 0x100000e, expectedInode: 4567,
      lsofOutput: "p123\0\nftxt\0D0x100000e\0i9999\0n\(path)-replacement\0\n")
  }
}

@Test func unmanagedMigrationCollisionPolicyRefusesEveryCompetingAuthority() throws {
  try UnmanagedMigrationCollisionPolicy.requireClear(
    presentExecutablePaths: [], siblingNames: ["unrelated"])

  for path in [
    "/usr/local/bin/reachd", "/opt/homebrew/bin/reachd", "/usr/bin/reachd",
    "/bin/reachd", "/usr/sbin/reachd", "/sbin/reachd",
  ] {
    #expect(throws: ReleasePackageError.self) {
      try UnmanagedMigrationCollisionPolicy.requireClear(
        presentExecutablePaths: [path], siblingNames: [])
    }
  }
  #expect(throws: ReleasePackageError.self) {
    try UnmanagedMigrationCollisionPolicy.requireClear(
      presentExecutablePaths: [],
      siblingNames: ["reach.s36-retired-00000000-0000-0000-0000-000000000000"])
  }
}
