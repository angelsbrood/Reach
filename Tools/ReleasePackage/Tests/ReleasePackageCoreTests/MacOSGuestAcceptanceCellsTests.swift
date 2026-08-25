import Foundation
import Testing

@testable import ReleasePackageCore

@Test func mandatoryChoiceDocumentIsExactAndTargetsOnlyTheHelper() throws {
  let data = MandatoryChoiceDocument.data()
  try MandatoryChoiceDocument.validate(data)
  let object = try #require(
    PropertyListSerialization.propertyList(from: data, format: nil) as? [[String: Any]])
  #expect(object.count == 1)
  #expect(object[0]["choiceIdentifier"] as? String == "systems.reach.meshd")
  #expect(object[0]["choiceAttribute"] as? String == "selected")
  #expect(object[0]["attributeSetting"] as? Int == 0)
  #expect(!String(decoding: data, as: UTF8.self).contains("systems.reach.host"))

  var changed = data
  let index = try #require(changed.firstIndex(of: UInt8(ascii: "0")))
  changed[index] = UInt8(ascii: "1")
  #expect(throws: ReleasePackageError.self) {
    try MandatoryChoiceDocument.validate(changed)
  }
}
