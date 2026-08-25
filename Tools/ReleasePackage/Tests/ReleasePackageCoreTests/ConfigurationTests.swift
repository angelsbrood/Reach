import Foundation
import Testing

@testable import ReleasePackageCore

@Test func checkedInReleaseAuthorityIsExact() throws {
  let configuration = try ReleaseConfiguration.load(
    from: repositoryRoot().appendingPathComponent("release/release.json"))
  #expect(configuration.schemaVersion == 2)
  #expect(configuration.product.version.description == "0.0.2")
  #expect(configuration.components.helper.version.description == "1.0.2")
  #expect(configuration.consumedProductVersions == [try DottedVersion("0.0.1")])
  #expect(
    configuration.consumedVersions["systems.reach.meshd"]
      == [try DottedVersion("1.0.0"), try DottedVersion("1.0.1")])
  #expect(
    configuration.lineage?.components
      == .init(host: .changed, helper: .changed))
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
        "systems.reach.host": ["0.0.1", "0.0.2"],
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

@Test func historicalSchemaOneRemainsExactlyReadable() throws {
  let root = try makeTemporaryDirectory("historical-configuration")
  defer { removeTemporaryDirectory(root) }
  let historical = root.appendingPathComponent("release.json")
  let current = repositoryRoot().appendingPathComponent("release/release.json")
  try mutateJSON(
    current,
    { object in
      object["schemaVersion"] = 1
      object.removeValue(forKey: "lineage")
      object.removeValue(forKey: "consumedProductVersions")
      var product = object["product"] as! [String: Any]
      product["version"] = "0.0.1"
      object["product"] = product
      var components = object["components"] as! [String: Any]
      var host = components["host"] as! [String: Any]
      host["version"] = "0.0.1"
      components["host"] = host
      var helper = components["helper"] as! [String: Any]
      helper["version"] = "1.0.1"
      components["helper"] = helper
      object["components"] = components
      var compatibility = object["compatibility"] as! [String: Any]
      compatibility["hostMinimum"] = "0.0.1"
      compatibility["hostMaximum"] = "0.0.1"
      compatibility["helperMinimum"] = "1.0.1"
      compatibility["helperMaximum"] = "1.0.1"
      object["compatibility"] = compatibility
      object["consumedVersions"] = [
        "systems.reach.host": [],
        "systems.reach.meshd": ["1.0.0"],
      ]
    }, to: historical)
  let decoded = try ReleaseConfiguration.load(from: historical)
  #expect(decoded.schemaVersion == 1)
  #expect(decoded.lineage == nil)
  #expect(decoded.product.version.description == "0.0.1")
}

@Test func multiReleaseAuthorityRejectsVersionAndLineageSubstitution() throws {
  let root = try makeTemporaryDirectory("lineage-configuration")
  defer { removeTemporaryDirectory(root) }
  let source = repositoryRoot().appendingPathComponent("release/release.json")

  let unchangedButBumped = root.appendingPathComponent("unchanged-bumped.json")
  try mutateJSON(
    source,
    { object in
      var lineage = object["lineage"] as! [String: Any]
      lineage["components"] = ["host": "changed", "helper": "unchanged"]
      object["lineage"] = lineage
    }, to: unchangedButBumped)
  #expect(throws: ReleasePackageError.self) {
    try ReleaseConfiguration.load(from: unchangedButBumped)
  }

  let wrongHistoricalParent = root.appendingPathComponent("wrong-parent.json")
  try mutateJSON(
    source,
    { object in
      var lineage = object["lineage"] as! [String: Any]
      lineage["historicalP5Reference"] = "invented-full-hash"
      object["lineage"] = lineage
    }, to: wrongHistoricalParent)
  #expect(throws: ReleasePackageError.self) {
    try ReleaseConfiguration.load(from: wrongHistoricalParent)
  }

  let unknownLineageField = root.appendingPathComponent("unknown-lineage.json")
  try mutateJSON(
    source,
    { object in
      var lineage = object["lineage"] as! [String: Any]
      lineage["bypass"] = true
      object["lineage"] = lineage
    }, to: unknownLineageField)
  #expect(throws: ReleasePackageError.self) {
    try ReleaseConfiguration.load(from: unknownLineageField)
  }
}

@Test func successorAllowsOnlyAnExactUnchangedComponentVersion() throws {
  let root = try makeTemporaryDirectory("successor-configuration")
  defer { removeTemporaryDirectory(root) }
  let source = repositoryRoot().appendingPathComponent("release/release.json")
  let successor = root.appendingPathComponent("successor.json")
  try mutateJSON(
    source,
    { object in
      var product = object["product"] as! [String: Any]
      product["version"] = "0.0.3"
      object["product"] = product
      var components = object["components"] as! [String: Any]
      var host = components["host"] as! [String: Any]
      host["version"] = "0.0.3"
      components["host"] = host
      object["components"] = components
      var compatibility = object["compatibility"] as! [String: Any]
      compatibility["hostMinimum"] = "0.0.3"
      compatibility["hostMaximum"] = "0.0.3"
      object["compatibility"] = compatibility
      object["lineage"] = [
        "kind": "successor",
        "parent": ["product": "0.0.2", "host": "0.0.2", "helper": "1.0.2"],
        "parentP5SHA256": String(repeating: "a", count: 64),
        "parentProvenanceSHA256": String(repeating: "b", count: 64),
        "components": ["host": "changed", "helper": "unchanged"],
      ]
      object["consumedProductVersions"] = ["0.0.1", "0.0.2"]
      object["consumedVersions"] = [
        "systems.reach.host": ["0.0.1", "0.0.2"],
        "systems.reach.meshd": ["1.0.0", "1.0.1", "1.0.2"],
      ]
    }, to: successor)
  let decoded = try ReleaseConfiguration.load(from: successor)
  #expect(decoded.product.version.description == "0.0.3")
  #expect(decoded.lineage?.components.helper == .unchanged)

  let drifted = root.appendingPathComponent("successor-drifted.json")
  try mutateJSON(
    successor,
    { object in
      var components = object["components"] as! [String: Any]
      var helper = components["helper"] as! [String: Any]
      helper["version"] = "1.0.3"
      components["helper"] = helper
      object["components"] = components
      var compatibility = object["compatibility"] as! [String: Any]
      compatibility["helperMinimum"] = "1.0.3"
      compatibility["helperMaximum"] = "1.0.3"
      object["compatibility"] = compatibility
    }, to: drifted)
  #expect(throws: ReleasePackageError.self) {
    try ReleaseConfiguration.load(from: drifted)
  }

  let wrongSequence = root.appendingPathComponent("successor-wrong-sequence.json")
  try mutateJSON(
    successor,
    { object in
      var product = object["product"] as! [String: Any]
      product["version"] = "0.0.4"
      object["product"] = product
      var components = object["components"] as! [String: Any]
      var host = components["host"] as! [String: Any]
      host["version"] = "0.0.4"
      components["host"] = host
      object["components"] = components
      var compatibility = object["compatibility"] as! [String: Any]
      compatibility["hostMinimum"] = "0.0.4"
      compatibility["hostMaximum"] = "0.0.4"
      object["compatibility"] = compatibility
    }, to: wrongSequence)
  #expect(throws: ReleasePackageError.self) {
    try ReleaseConfiguration.load(from: wrongSequence)
  }
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
