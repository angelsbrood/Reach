import Foundation
import Testing

@testable import ReleasePackageCore

@Test func checkedInReleaseAuthorityIsExact() throws {
  let configuration = try ReleaseConfiguration.load(
    from: repositoryRoot().appendingPathComponent("release/release.json"))
  #expect(configuration.product.version.description == "0.0.1")
  #expect(configuration.components.helper.version.description == "1.0.1")
  #expect(configuration.consumedVersions["systems.reach.meshd"] == [try DottedVersion("1.0.0")])
  #expect(configuration.hostBundles.count == 7)
  #expect(configuration.untrackedAllowlist == ["tasks/"])
}

@Test func dottedVersionsRejectNoncanonicalOrNonTripletValues() throws {
  for value in ["", "1", "1.0", "1.0.0.0", "01.0.0", "1..0", "1.0.x"] {
    #expect(throws: ReleasePackageError.self) { try DottedVersion(value) }
  }
  #expect(try DottedVersion("0.0.1") < DottedVersion("1.0.0"))
}

@Test func releaseAuthorityRejectsUnknownAndConsumedVersionDrift() throws {
  let root = try makeTemporaryDirectory("configuration")
  defer { removeTemporaryDirectory(root) }
  let source = repositoryRoot().appendingPathComponent("release/release.json")
  let unknown = root.appendingPathComponent("unknown.json")
  try mutateJSON(source, { $0["surprise"] = true }, to: unknown)
  #expect(throws: ReleasePackageError.self) { try ReleaseConfiguration.load(from: unknown) }

  let consumed = root.appendingPathComponent("consumed.json")
  try mutateJSON(
    source,
    { object in
      object["consumedVersions"] = [
        "systems.reach.host": [],
        "systems.reach.meshd": ["1.0.0", "1.0.1"],
      ]
    }, to: consumed)
  #expect(throws: ReleasePackageError.self) { try ReleaseConfiguration.load(from: consumed) }

  let nested = root.appendingPathComponent("nested.json")
  try mutateJSON(
    source,
    { object in
      var product = object["product"] as! [String: Any]
      product["channel"] = "private"
      object["product"] = product
    }, to: nested)
  #expect(throws: ReleasePackageError.self) { try ReleaseConfiguration.load(from: nested) }
}

@Test func noticeAuthorityIsCompleteAndStrict() throws {
  let source = repositoryRoot().appendingPathComponent("release/notices.json")
  let authority = try NoticeAuthority.load(from: source)
  #expect(authority.expectedSwiftPins.count == 17)
  #expect(authority.expectedGoModules.count == 10)
  #expect(authority.families.count == 37)

  let root = try makeTemporaryDirectory("notice-authority")
  defer { removeTemporaryDirectory(root) }
  let unknown = root.appendingPathComponent("unknown.json")
  try mutateJSON(source, { $0["legalConclusion"] = "none" }, to: unknown)
  #expect(throws: ReleasePackageError.self) { try NoticeAuthority.load(from: unknown) }

  let nested = root.appendingPathComponent("nested.json")
  try mutateJSON(
    source,
    { object in
      var families = object["families"] as! [[String: Any]]
      families[0]["legalConclusion"] = "none"
      object["families"] = families
    }, to: nested)
  #expect(throws: ReleasePackageError.self) { try NoticeAuthority.load(from: nested) }
}
