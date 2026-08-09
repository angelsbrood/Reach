import Foundation
import Network
import ReachTransport
import ReachWire
import Testing
@testable import ReachKit

@Suite struct GenerationLivenessTests {
    private func raw(_ frame: some WireFrame) throws -> RawFrame {
        RawFrame(type: type(of: frame).frameType, body: try JSONEncoder().encode(frame))
    }

    @Test func aReceivedEventGraduatesRetryToTheResidentDeadline() {
        let now = ContinuousClock.now
        let cold = now + .seconds(10)
        let resident = now + .seconds(120)

        #expect(ReachExecutor.retryDeadline(lastReceived: nil, coldOpen: cold, resident: resident) == cold)
        #expect(ReachExecutor.retryDeadline(lastReceived: 0, coldOpen: cold, resident: resident) == resident)
    }

    @Test func theMeasuredPolicyIsTwoSeconds() {
        #expect(GenerationLivenessPolicy.interval == .seconds(2))
    }

    @Test func anArrivingGenerationFrameResetsSilence() async {
        let frame = Task<FrameEnding, Never> {
            try? await Task.sleep(for: .milliseconds(10))
            return .frame(RawFrame(type: .ev, body: Data()))
        }
        let result = await GenerationLivenessPolicy.waitForFrame(
            frame,
            for: .milliseconds(100)
        )
        guard case .frame(let raw) = result else {
            Issue.record("an arriving generation event was mistaken for silence")
            return
        }
        #expect(raw.type == .ev)
    }

    @Test func silenceArmsTheProbeOnlyAfterItsInterval() async {
        let frame = Task<FrameEnding, Never> {
            try? await Task.sleep(for: .seconds(1))
            return .closed
        }
        let clock = ContinuousClock()
        let began = clock.now
        let result = await GenerationLivenessPolicy.waitForFrame(
            frame,
            for: .milliseconds(30)
        )
        let elapsed = began.duration(to: clock.now)
        frame.cancel()
        #expect(result == nil)
        #expect(elapsed >= .milliseconds(25))
    }

    @Test func aGenerationEventOutweighsAFailedControlProbe() async {
        let frame = Task<FrameEnding, Never> {
            try? await Task.sleep(for: .milliseconds(10))
            return .frame(RawFrame(type: .ev, body: Data()))
        }
        let probe = Task<Bool, Never> {
            try? await Task.sleep(for: .milliseconds(30))
            return false
        }
        guard case .frame(let ending) = await GenerationLivenessPolicy.race(
            frame: frame,
            probe: probe
        ), case .frame(let raw) = ending else {
            Issue.record("a generation event lost its race with a failed probe")
            return
        }
        #expect(raw.type == .ev)
    }

    @Test func aMissingPongWinsBeforeALateGenerationEvent() async {
        let frame = Task<FrameEnding, Never> {
            try? await Task.sleep(for: .milliseconds(80))
            return .frame(RawFrame(type: .ev, body: Data()))
        }
        let probe = Task<Bool, Never> {
            try? await Task.sleep(for: .milliseconds(10))
            return false
        }
        guard case .probe(let alive) = await GenerationLivenessPolicy.race(
            frame: frame,
            probe: probe
        ) else {
            Issue.record("a late event incorrectly beat the bounded missing pong")
            return
        }
        #expect(!alive)
        frame.cancel()
    }

    @Test func aMatchingPongKeepsWaiting() async {
        let frame = Task<FrameEnding, Never> {
            try? await Task.sleep(for: .seconds(1))
            return .closed
        }
        let probe = Task<Bool, Never> { true }
        guard case .probe(let alive) = await GenerationLivenessPolicy.race(
            frame: frame,
            probe: probe
        ) else {
            Issue.record("a matching pong did not settle the health race")
            return
        }
        #expect(alive)
        frame.cancel()
    }

    @Test func onlyTheMatchingNonceProvesHealth() throws {
        let matching = try raw(Pong(nonce: 91))
        let stale = try raw(Pong(nonce: 90))
        let wrongType = try raw(Ping(nonce: 91))

        #expect(ActiveRoadProbe.matches(.frame(matching), nonce: 91, version: 0))
        #expect(!ActiveRoadProbe.matches(.frame(stale), nonce: 91, version: 0))
        #expect(!ActiveRoadProbe.matches(.frame(wrongType), nonce: 91, version: 0))
        #expect(!ActiveRoadProbe.matches(
            .frame(matching),
            nonce: 91,
            version: 0,
            arrivedByDeadline: false
        ))
        #expect(!ActiveRoadProbe.matches(.closed, nonce: 91, version: 0))
    }

    @Test func onlyAQuickRetainedControlClosureAllowsLazyHelloReopening() {
        let clock = ContinuousClock()
        let attempted = clock.now
        let deadline = attempted + .milliseconds(100)

        #expect(ActiveRoadProbe.shouldOpenReplacement(
            attemptedAt: attempted,
            now: attempted + .milliseconds(10),
            deadline: deadline,
            timeout: .milliseconds(100),
            invalidated: false
        ))
        #expect(!ActiveRoadProbe.shouldOpenReplacement(
            attemptedAt: attempted,
            now: deadline,
            deadline: deadline,
            timeout: .milliseconds(100),
            invalidated: false
        ))
        #expect(!ActiveRoadProbe.shouldOpenReplacement(
            attemptedAt: attempted,
            now: attempted + .milliseconds(10),
            deadline: deadline,
            timeout: .milliseconds(100),
            invalidated: true
        ))
    }

    @Test func concurrentGenerationsShareOneRoadProbe() async {
        let counter = ProbeInvocationCounter()
        let probe = ActiveRoadProbe(
            dialer: inertDialer(),
            checkOverride: { _ in
                await counter.increment()
                try? await Task.sleep(for: .milliseconds(30))
                return ActiveRoadProbeResult(alive: true, refreshedHello: nil)
            }
        )

        async let first = probe.check(timeout: .milliseconds(100))
        async let second = probe.check(timeout: .milliseconds(100))
        let results = await [first, second]

        #expect(results[0].alive)
        #expect(results[1].alive)
        #expect(await counter.value == 1)
    }

    @Test func anOlderRoadCannotDirtyItsReplacement() {
        #expect(ReachConnectionHub.isCurrentRoad(
            leaseEpoch: 8,
            activeEpoch: 8,
            sameProbe: true
        ))
        #expect(!ReachConnectionHub.isCurrentRoad(
            leaseEpoch: 7,
            activeEpoch: 8,
            sameProbe: true
        ))
        #expect(!ReachConnectionHub.isCurrentRoad(
            leaseEpoch: 8,
            activeEpoch: 8,
            sameProbe: false
        ))
    }

    @Test func releasingTheLastLeaseDoesNotStartIdleProbing() async {
        let counter = ProbeInvocationCounter()
        let probe = ActiveRoadProbe(
            dialer: inertDialer(),
            checkOverride: { _ in
                await counter.increment()
                return ActiveRoadProbeResult(alive: true, refreshedHello: nil)
            }
        )
        await probe.acquireGenerationLease()
        await probe.releaseGenerationLease()
        try? await Task.sleep(for: .milliseconds(30))
        #expect(await counter.value == 0)
    }

    @Test func cancellationDoesNotWaitForTheSilenceDeadline() async {
        let frame = Task<FrameEnding, Never> {
            try? await Task.sleep(for: .seconds(5))
            return .closed
        }
        let waiting = Task {
            await GenerationLivenessPolicy.waitForFrame(frame, for: .seconds(5))
        }
        try? await Task.sleep(for: .milliseconds(10))
        let clock = ContinuousClock()
        let began = clock.now
        waiting.cancel()
        let result = await waiting.value
        let elapsed = began.duration(to: clock.now)
        frame.cancel()
        #expect(result == nil)
        #expect(elapsed < .milliseconds(100))
    }

    private func inertDialer() -> QUICDialer {
        QUICDialer(
            endpoint: .hostPort(host: "127.0.0.1", port: 9),
            parameters: .udp
        )
    }
}

private actor ProbeInvocationCounter {
    private(set) var value = 0

    func increment() {
        value += 1
    }
}
