import Testing

@testable import ReleasePackageCore

@Test func frozenVersionsRemainOrdered() throws {
  #expect(try DottedVersion("1.0.0") < DottedVersion("1.0.1"))
}
