import Testing
@testable import ReachKit

@Test func packageWiresTogether() {
    #expect(ReachKitInfo.wireVersion == 0)
}
