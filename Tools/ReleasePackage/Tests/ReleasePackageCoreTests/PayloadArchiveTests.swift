import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

@Test func payloadODCIsDeterministicAndRoundTripsEveryAuthorityField() throws {
  let root = try makeTemporaryDirectory("odc")
  defer { removeTemporaryDirectory(root) }
  let payload = try canonicalPayloadFixture(at: root)
  let tree = try PayloadTree.inspect(root: payload)
  let first = root.appendingPathComponent("one.cpio")
  let second = root.appendingPathComponent("two.cpio")
  try tree.writeODC(to: first, modificationTime: 1_700_000_000)
  try tree.writeODC(to: second, modificationTime: 1_700_000_000)
  #expect(try Data(contentsOf: first) == Data(contentsOf: second))
  #expect(try ODCArchive.parse(Data(contentsOf: first)) == tree.records)
  #expect(tree.records.last?.linkTarget == "/Library/Application Support/Reach/Host/reachd")
}

@Test func posixChecksumMatchesAppleCksum() throws {
  let root = try makeTemporaryDirectory("checksum")
  defer { removeTemporaryDirectory(root) }
  let data = Data("the river reaches the sea\n".utf8)
  let file = root.appendingPathComponent("input")
  try SecureFiles.atomicWrite(data, to: file)
  let output = try ProcessRunner().run("/usr/bin/cksum", [file.path]).output
  let expected = try #require(UInt32(output.split(separator: " ").first ?? ""))
  #expect(POSIXChecksum.checksum(data) == expected)
}

@Test func bomAndCpioShareOneCanonicalRecordTable() throws {
  let root = try makeTemporaryDirectory("bom")
  defer { removeTemporaryDirectory(root) }
  let payload = try canonicalPayloadFixture(at: root)
  let tree = try PayloadTree.inspect(root: payload)
  let input = root.appendingPathComponent("BomInput")
  let bom = root.appendingPathComponent("Bom")
  try SecureFiles.atomicWrite(tree.bomInput(), to: input)
  try ProcessRunner().run(
    "/usr/bin/mkbom", ["-i", input.path, bom.path], logURL: root.appendingPathComponent("mkbom.log")
  )
  let listing = try ProcessRunner().run(
    "/usr/bin/lsbom", [bom.path], logURL: root.appendingPathComponent("lsbom.log")
  ).output
  #expect(Data(listing.utf8) == PackageAssembler().expectedBOMListing(tree.records))
  #expect(listing.contains("/Library/Application Support/Reach/Host/reachd"))
}

@Test func payloadRejectsCustomXattrsHardlinksModesAndUnexpectedSymlinks() throws {
  let root = try makeTemporaryDirectory("payload-refusals")
  defer { removeTemporaryDirectory(root) }

  let xattrRoot = root.appendingPathComponent("xattr-root")
  try SecureFiles.createPrivateDirectory(xattrRoot)
  let xattrPayload = try canonicalPayloadFixture(at: xattrRoot)
  let xattrFile = xattrPayload.appendingPathComponent(
    "Library/Application Support/Reach/Host/reachd")
  let value = Data([1])
  let result = value.withUnsafeBytes { raw in
    setxattr(
      xattrFile.path, "com.example.reach-release-test", raw.baseAddress, raw.count, 0,
      XATTR_NOFOLLOW)
  }
  #expect(result == 0)
  #expect(throws: ReleasePackageError.self) { try PayloadTree.inspect(root: xattrPayload) }

  let hardRoot = root.appendingPathComponent("hard-root")
  try SecureFiles.createPrivateDirectory(hardRoot)
  let hardPayload = try canonicalPayloadFixture(at: hardRoot, includeAlias: false)
  let hardFile = hardPayload.appendingPathComponent("Library/Application Support/Reach/Host/reachd")
  #expect(
    link(
      hardFile.path, hardFile.deletingLastPathComponent().appendingPathComponent("duplicate").path)
      == 0)
  #expect(throws: ReleasePackageError.self) { try PayloadTree.inspect(root: hardPayload) }

  let modeRoot = root.appendingPathComponent("mode-root")
  try SecureFiles.createPrivateDirectory(modeRoot)
  let modePayload = try canonicalPayloadFixture(at: modeRoot, includeAlias: false)
  let modeFile = modePayload.appendingPathComponent("Library/Application Support/Reach/Host/reachd")
  #expect(chmod(modeFile.path, 0o777) == 0)
  #expect(throws: ReleasePackageError.self) { try PayloadTree.inspect(root: modePayload) }

  let linkRoot = root.appendingPathComponent("link-root")
  try SecureFiles.createPrivateDirectory(linkRoot)
  let linkPayload = try canonicalPayloadFixture(at: linkRoot, includeAlias: false)
  #expect(symlink("/tmp/escape", linkPayload.appendingPathComponent("bad-link").path) == 0)
  #expect(throws: ReleasePackageError.self) { try PayloadTree.inspect(root: linkPayload) }
}

@Test func odcParserRefusesTruncationAndTrailingData() throws {
  let root = try makeTemporaryDirectory("odc-refusal")
  defer { removeTemporaryDirectory(root) }
  let tree = try PayloadTree.inspect(root: canonicalPayloadFixture(at: root))
  let archive = root.appendingPathComponent("archive")
  try tree.writeODC(to: archive, modificationTime: 1_700_000_000)
  let data = try Data(contentsOf: archive)
  #expect(throws: ReleasePackageError.self) { try ODCArchive.parse(Data(data.dropLast())) }
  #expect(throws: ReleasePackageError.self) { try ODCArchive.parse(data + Data([0])) }

  var wrongInode = data
  wrongInode[17] = Character("2").asciiValue!
  #expect(throws: ReleasePackageError.self) { try ODCArchive.parse(wrongInode) }

  var wrongLinkCount = data
  wrongLinkCount[41] = Character("1").asciiValue!
  #expect(throws: ReleasePackageError.self) { try ODCArchive.parse(wrongLinkCount) }
}
