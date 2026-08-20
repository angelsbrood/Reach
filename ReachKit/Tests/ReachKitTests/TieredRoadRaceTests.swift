import Foundation
import ReachWire
import Testing

@testable import ReachKit

private final class RaceRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String] = []

    func append(_ value: String) {
        lock.lock()
        values.append(value)
        lock.unlock()
    }

    var snapshot: [String] {
        lock.lock()
        defer { lock.unlock() }
        return values
    }
}

@Suite struct TieredRoadRaceTests {
    @Test func relayDeclarationsRespectDialectAndRoadEpoch() {
        let roads = [RoadEndpoint(host: "10.87.0.1", port: 47_337)]
        #expect(RelayRoadPolicy.update(
            from: HelloAck(version: 1, cluster: "studio", models: [], relayRoads: roads),
            replyEpoch: 4,
            currentEpoch: 5
        ) == .stale)
        #expect(RelayRoadPolicy.update(
            from: HelloAck(version: 0, cluster: "studio", models: [], relayRoads: roads),
            replyEpoch: 5,
            currentEpoch: 5
        ) == .preserve)
        #expect(RelayRoadPolicy.update(
            from: HelloAck(version: 1, cluster: "studio", models: []),
            replyEpoch: 5,
            currentEpoch: 5
        ) == .preserve)
        #expect(RelayRoadPolicy.update(
            from: HelloAck(version: 1, cluster: "studio", models: [], relayRoads: []),
            replyEpoch: 5,
            currentEpoch: 5
        ) == .clear)
        #expect(RelayRoadPolicy.update(
            from: HelloAck(version: 1, cluster: "studio", models: [], relayRoads: roads),
            replyEpoch: 5,
            currentEpoch: 5
        ) == .replace(roads))

        #expect(ReachConnectionHub.isCurrentDeclaration(
            roadEpoch: 7,
            activeRoadEpoch: 7,
            replyDeclarationEpoch: 12,
            activeDeclarationEpoch: 12
        ))
        #expect(!ReachConnectionHub.isCurrentDeclaration(
            roadEpoch: 7,
            activeRoadEpoch: 7,
            replyDeclarationEpoch: 11,
            activeDeclarationEpoch: 12
        ))
        #expect(!ReachConnectionHub.isCurrentDeclaration(
            roadEpoch: 6,
            activeRoadEpoch: 7,
            replyDeclarationEpoch: 12,
            activeDeclarationEpoch: 12
        ))

        #expect(!ReachConnectionHub.pathChangeRequiresRedial(
            leaseEpoch: 7,
            activeEpoch: 7,
            sameProbe: true,
            winningTier: .relay
        ))
        #expect(ReachConnectionHub.pathChangeRequiresRedial(
            leaseEpoch: 7,
            activeEpoch: 7,
            sameProbe: true,
            winningTier: .direct
        ))
        #expect(ReachConnectionHub.pathChangeRequiresRedial(
            leaseEpoch: 6,
            activeEpoch: 7,
            sameProbe: false,
            winningTier: .relay
        ))
    }

    @Test func zeroHedgeMeansFastestAuthenticatedRoadRatherThanDirectPreference() async throws {
        let attempts = RaceRecorder()
        let discarded = RaceRecorder()
        let winner = try await TieredRoadRace.run(
            direct: ["direct"],
            relay: ["relay"],
            hedge: .zero,
            deadline: .now + .seconds(1),
            open: { candidate, _ in
                attempts.append(candidate)
                if candidate == "direct" { try await Task.sleep(for: .milliseconds(20)) }
                return candidate
            },
            discard: { discarded.append($0) }
        )
        #expect(winner?.candidate == "relay")
        #expect(winner?.tier == .relay)
        #expect(discarded.snapshot.allSatisfy { $0 == "direct" })
    }

    @Test func selectedPositiveHedgePreservesHealthyDirectAgainstImmediateRelay() async throws {
        let attempts = RaceRecorder()
        let winner = try await TieredRoadRace.run(
            direct: ["direct"],
            relay: ["relay"],
            hedge: ReachConnectionHub.relayHedge,
            deadline: .now + .seconds(1),
            open: { candidate, _ in
                attempts.append(candidate)
                if candidate == "direct" { try await Task.sleep(for: .milliseconds(20)) }
                return candidate
            },
            discard: { _ in }
        )
        #expect(winner?.tier == .direct)
        #expect(attempts.snapshot == ["direct"])
    }

    @Test func stalledDirectStartsRelayInsideTheMeasuredHedge() async throws {
        let starts = RaceRecorder()
        let began = ContinuousClock.now
        let winner = try await TieredRoadRace.run(
            direct: ["direct"],
            relay: ["relay"],
            hedge: ReachConnectionHub.relayHedge,
            deadline: began + .seconds(1),
            open: { candidate, _ in
                starts.append(candidate)
                if candidate == "direct" {
                    try await Task.sleep(for: .seconds(2))
                }
                return candidate
            },
            discard: { _ in }
        )
        let elapsed = began.duration(to: .now)
        #expect(winner?.tier == .relay)
        #expect(starts.snapshot.contains("direct"))
        #expect(starts.snapshot.contains("relay"))
        #expect(elapsed < .milliseconds(500))
    }

    @Test func invalidatedProvenDirectReturnsToTieredRaceBeforeDeadline() async throws {
        #expect(ReachConnectionHub.cachedRoadIsReusable(
            proven: true,
            dirty: false,
            hasSession: true
        ))
        #expect(!ReachConnectionHub.cachedRoadIsReusable(
            proven: true,
            dirty: false,
            hasSession: false
        ))

        let attempts = RaceRecorder()
        let began = ContinuousClock.now
        let deadline = began + .milliseconds(500)
        let winner = try await TieredRoadRace.run(
            direct: ["previous-direct"],
            relay: ["relay"],
            hedge: ReachConnectionHub.relayHedge,
            deadline: deadline,
            open: { candidate, _ in
                attempts.append(candidate)
                if candidate == "previous-direct" {
                    try await Task.sleep(for: .seconds(2))
                }
                return candidate
            },
            discard: { _ in }
        )

        #expect(winner?.tier == .relay)
        #expect(attempts.snapshot.contains("previous-direct"))
        #expect(attempts.snapshot.contains("relay"))
        #expect(began.duration(to: .now) < .milliseconds(500))
    }

    @Test func everyAttemptReceivesOnlyTheRemainingAbsoluteBudget() async throws {
        let attempts = RaceRecorder()
        let began = ContinuousClock.now
        let winner: TieredRoadRace.Winner<String, String>? = try await TieredRoadRace.run(
            direct: ["direct"],
            relay: ["relay"],
            hedge: .milliseconds(60),
            deadline: began + .milliseconds(30),
            open: { candidate, remaining in
                attempts.append(candidate)
                try await Task.sleep(for: remaining)
                throw CancellationError()
            },
            discard: { _ in }
        )
        #expect(winner == nil)
        #expect(attempts.snapshot == ["direct"])
    }

    @Test func parentCancellationLeavesNoDelayedRelayProbe() async {
        let attempts = RaceRecorder()
        let task = Task {
            try await TieredRoadRace.run(
                direct: ["direct"],
                relay: ["relay"],
                hedge: .milliseconds(200),
                deadline: .now + .seconds(2),
                open: { candidate, _ in
                    attempts.append(candidate)
                    try await Task.sleep(for: .seconds(2))
                    return candidate
                },
                discard: { _ in }
            )
        }
        try? await Task.sleep(for: .milliseconds(20))
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("a cancelled race returned normally")
        } catch is CancellationError {
            // Expected.
        } catch {
            Issue.record("unexpected cancellation error: \(error)")
        }
        try? await Task.sleep(for: .milliseconds(250))
        #expect(!attempts.snapshot.contains("relay"))
    }
}
