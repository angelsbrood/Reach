import Foundation
import FoundationModels
import ReachIdentity
import Testing
@testable import ReachKit

@Test func packageWiresTogether() {
    #expect(ReachKitInfo.wireVersion == 1)
}

@Test func modelDeclaresOnlyTheCapabilitiesItsExecutorServes() {
    let model = ReachLanguageModel(configuration: .init())
    #expect(model.capabilities.contains(.guidedGeneration))
    #expect(model.capabilities.contains(.toolCalling))
    #expect(!model.capabilities.contains(.vision))
}

@Test func replacingAClusterIdentityRemovesBothRoadStores() throws {
    let label = "reach-test-reset-authority-\(UUID().uuidString)"
    defer { ReachEnrollment.resetStoredClusterAuthority(label: label) }
    try ClusterRoads.save(addrs: ["192.168.8.210"], port: 47_337, for: label)
    try ClusterRelayRoads.save(
        endpoints: [.init(host: "10.87.0.1", port: 47_337)],
        for: label
    )

    ReachEnrollment.resetStoredClusterAuthority(label: label)

    #expect(try ClusterRoads.load(for: label) == nil)
    #expect(try ClusterRelayRoads.load(for: label) == nil)
}
