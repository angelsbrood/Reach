import FoundationModels
import Testing
@testable import ReachKit

@Test func packageWiresTogether() {
    #expect(ReachKitInfo.wireVersion == 0)
}

@Test func modelDeclaresOnlyTheCapabilitiesItsExecutorServes() {
    let model = ReachLanguageModel(configuration: .init())
    #expect(model.capabilities.contains(.guidedGeneration))
    #expect(model.capabilities.contains(.toolCalling))
    #expect(!model.capabilities.contains(.vision))
}
