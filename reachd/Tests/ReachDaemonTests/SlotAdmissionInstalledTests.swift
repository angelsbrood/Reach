import Foundation
import FoundationModels
import ReachKit
import Testing
@testable import ReachDaemon

/// A gated acceptance against the installed, supervised daemon. Ordinary test
/// runs never touch canonical state or a live listener; the install guard runs
/// this explicitly after the exact release bytes are in place.
@Suite(.serialized) struct SlotAdmissionInstalledTests {
    private enum Outcome: Sendable {
        case complete
        case busy(String)
        case failed(String)
    }

    @Test(
        .enabled(if: ProcessInfo.processInfo.environment["REACH_SLOT_INSTALLED"] == "1",
                 "installed slot admission is an explicit host acceptance run"),
        .timeLimit(.minutes(5))
    )
    func fiveInstalledClientsFillOneSlotAndThreeWaiters() async throws {
        let state = DaemonInfo.canonicalLoginStateDirectory
        let config = try DaemonConfig.load(from: state)
        let labels = try (0 ..< 5).map { index in
            let label = "reach-slot-installed-\(index)-\(UUID().uuidString)"
            let material = try ClusterDial.mint(stateDirectory: state, label: label)
            return (label, material)
        }
        for (label, material) in labels {
            await ReachIdentityRegistry.shared.register(label: label, material: material)
        }

        let gate = InstalledStartGate(expected: labels.count)
        let prompt = "Write exactly 400 words about a river crossing a plain, then stop."
        let began = ContinuousClock.now
        let outcomes = await withTaskGroup(of: Outcome.self) { group in
            for (label, _) in labels {
                group.addTask {
                    await gate.wait()
                    let model = ReachLanguageModel(configuration: .init(
                        host: "127.0.0.1",
                        port: config.port,
                        modelID: config.modelID,
                        identityLabel: label,
                        connectTimeout: 10
                    ))
                    let session = LanguageModelSession(model: model)
                    do {
                        _ = try await session.respond(
                            to: prompt,
                            options: GenerationOptions(maximumResponseTokens: 768)
                        )
                        return .complete
                    } catch let error as ReachError {
                        if case .remote(let code, let message) = error, code == "cluster-busy" {
                            return .busy(message)
                        }
                        return .failed("\(error)")
                    } catch {
                        return .failed("\(error)")
                    }
                }
            }
            var values: [Outcome] = []
            for await outcome in group { values.append(outcome) }
            return values
        }

        let complete = outcomes.filter { outcome in
            if case .complete = outcome { return true }
            return false
        }
        let busy = outcomes.compactMap { outcome -> String? in
            guard case .busy(let message) = outcome else { return nil }
            return message
        }
        let failed = outcomes.compactMap { outcome -> String? in
            guard case .failed(let message) = outcome else { return nil }
            return message
        }
        #expect(complete.count == 4)
        #expect(busy == [SlotAdmission.AdmissionError.waitingRoomFull.description])
        #expect(failed.isEmpty, "unexpected installed client outcomes: \(failed)")
        print("[S25 installed] complete=\(complete.count) busy=\(busy.count) elapsed=\(began.duration(to: .now))")
    }
}

private actor InstalledStartGate {
    private let expected: Int
    private var arrived = 0
    private var continuations: [CheckedContinuation<Void, Never>] = []

    init(expected: Int) {
        self.expected = expected
    }

    func wait() async {
        arrived += 1
        if arrived == expected {
            let waiting = continuations
            continuations.removeAll()
            for continuation in waiting { continuation.resume() }
            return
        }
        await withCheckedContinuation { continuation in
            continuations.append(continuation)
        }
    }
}
