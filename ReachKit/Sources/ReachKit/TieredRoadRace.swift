import Foundation

/// Privacy-free scheduling for direct-first road attempts.
///
/// The candidate and opened value are generic so timing, cancellation, and
/// absolute-budget behavior can be tested without constructing a transport.
/// Trust is not represented here: every real opener still performs the same
/// pinned cluster mTLS handshake before a value can win.
package enum RoadTier: Sendable, Equatable {
    case direct
    case relay
}

package enum TieredRoadRace {
    package struct Winner<Candidate: Sendable, Opened: Sendable>: Sendable {
        package let candidate: Candidate
        package let opened: Opened
        package let tier: RoadTier
    }

    private struct Outcome<Candidate: Sendable, Opened: Sendable>: Sendable {
        let candidate: Candidate
        let opened: Opened
        let tier: RoadTier
    }

    package static func run<Candidate: Sendable, Opened: Sendable>(
        direct: [Candidate],
        relay: [Candidate],
        hedge: Duration,
        deadline: ContinuousClock.Instant,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
        sleep: @escaping @Sendable (Duration) async throws -> Void = { duration in
            if duration > .zero { try await Task.sleep(for: duration) }
        },
        open: @escaping @Sendable (Candidate, Duration) async throws -> Opened,
        discard: @escaping @Sendable (Opened) -> Void
    ) async throws -> Winner<Candidate, Opened>? {
        try await withThrowingTaskGroup(
            of: Outcome<Candidate, Opened>?.self,
            returning: Winner<Candidate, Opened>?.self
        ) { group in
            func enqueue(
                _ candidate: Candidate,
                tier: RoadTier,
                delay: Duration
            ) {
                group.addTask {
                    do {
                        try await sleep(delay)
                        try Task.checkCancellation()
                        let remaining = now().duration(to: deadline)
                        guard remaining > .zero else { return nil }
                        let opened = try await open(candidate, remaining)
                        if Task.isCancelled {
                            discard(opened)
                            return nil
                        }
                        return Outcome(candidate: candidate, opened: opened, tier: tier)
                    } catch {
                        return nil
                    }
                }
            }

            for candidate in direct {
                enqueue(candidate, tier: .direct, delay: .zero)
            }
            for candidate in relay { enqueue(candidate, tier: .relay, delay: hedge) }

            var winner: Winner<Candidate, Opened>?
            while let outcome = try await group.next() {
                try Task.checkCancellation()
                guard let outcome else { continue }
                if winner == nil {
                    winner = Winner(
                        candidate: outcome.candidate,
                        opened: outcome.opened,
                        tier: outcome.tier
                    )
                    group.cancelAll()
                } else {
                    discard(outcome.opened)
                }
            }
            return winner
        }
    }
}
