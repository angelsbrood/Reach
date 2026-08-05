import Foundation
import FoundationModels
import Testing

@testable import ReachKit

/// The blast radius of moving the session open inside the retry loop.
///
/// That move exists so a cold dial firing while the mesh tunnel is still
/// coming up gets the same 120-second budget every other open has. The budget
/// is the point — and it is also the hazard, because an app that was never
/// granted access fails at exactly the same door, and waiting out two minutes
/// to be told so is worse than what it replaced.
@Suite struct UngrantedAppTests {
    @Test func anAppThatWasNeverGrantedIsToldAtOnce() async throws {
        // Never registered with `ReachIdentityRegistry`, so the hub cannot
        // assemble material for it and refuses before any dial.
        let configuration = ReachExecutor.Configuration(
            host: "127.0.0.1",
            port: 47499,
            modelID: "scripted",
            identityLabel: "reach-test-ungranted-\(UUID().uuidString)",
            connectTimeout: 45
        )
        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration),
            instructions: "Scripted."
        )

        let started = ContinuousClock.now
        await #expect(throws: (any Error).self) {
            for try await _ in session.streamResponse(to: "Go.") {}
        }
        let elapsed = ContinuousClock.now - started

        // Not "it eventually failed": the retry budget is 120 seconds and the
        // connect timeout above is 45, so anything that retried this at all
        // would blow straight through a second.
        #expect(elapsed < .seconds(1))
    }
}
