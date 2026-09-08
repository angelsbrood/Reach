import Foundation
import Testing
@testable import ReachTransport

@Suite struct ReadinessCancellationTests {
    @Test func cancelledWaiterDrainsWithoutSettlingSharedReadiness() async throws {
        let latch = Latch<Int>()
        let first = Task { try await latch.value() }
        while latch.pendingWaiterCount == 0 { await Task.yield() }
        let start = ContinuousClock.now
        first.cancel()
        let rescue = Task { try await Task.sleep(for: .seconds(2)); latch.settle(.failure(BoundedTransportError.timeout)) }
        defer { rescue.cancel() }
        switch await first.result {
        case .success: Issue.record("cancelled readiness succeeded")
        case .failure(let error): #expect(error is CancellationError)
        }
        #expect(ContinuousClock.now - start < .seconds(1))
        #expect(latch.pendingWaiterCount == 0)
        latch.settle(.success(7))
        #expect(try await latch.value() == 7)
    }
    @Test func timeoutCancelsAndJoinsStalledReadinessWaiter() async throws {
        let latch = Latch<Void>()
        let rescue = Task { try await Task.sleep(for: .seconds(2)); latch.settle(.success(())) }
        defer { rescue.cancel() }
        let start = ContinuousClock.now
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                defer { group.cancelAll() }
                group.addTask { try await latch.value() }
                group.addTask { try await Task.sleep(for: .milliseconds(20)); throw BoundedTransportError.timeout }
                try await group.next()
            }
            Issue.record("timeout returned success")
        } catch { #expect(error is BoundedTransportError) }
        #expect(ContinuousClock.now - start < .seconds(1))
        #expect(latch.pendingWaiterCount == 0)
    }
    @Test func cancellationBeforeRegistrationDrainsAndLateSettlementIsStable() async throws {
        let latch = Latch<Int>()
        let task = Task { withUnsafeCurrentTask { $0?.cancel() }; return try await latch.value() }
        if case .success = await task.result { Issue.record("cancelled task succeeded") }
        #expect(latch.pendingWaiterCount == 0)
        latch.settle(.success(9)); latch.settle(.success(10))
        #expect(try await latch.value() == 9)
    }
}
