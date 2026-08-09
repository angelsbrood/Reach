import Foundation
import ReachTransport
import ReachWire

/// The measured S20 policy. It is internal because liveness is transport
/// behavior, not a knob applications should have to tune.
enum GenerationLivenessPolicy {
    static let interval: Duration = .seconds(2)

    enum ProbeRace: Sendable {
        case frame(FrameEnding)
        case probe(Bool)
    }

    static func waitForFrame(
        _ frame: Task<FrameEnding, Never>,
        for interval: Duration = interval
    ) async -> FrameEnding? {
        let race = LivenessRace<FrameEnding?>()
        let reader = Task { race.resolve(await frame.value) }
        let timer = Task {
            try? await Task.sleep(for: interval)
            race.resolve(nil)
        }
        let result = await withTaskCancellationHandler {
            await race.value()
        } onCancel: {
            race.resolve(nil)
        }
        reader.cancel()
        timer.cancel()
        return result
    }

    static func race(
        frame: Task<FrameEnding, Never>,
        probe: Task<Bool, Never>
    ) async -> ProbeRace {
        let race = LivenessRace<ProbeRace>()
        let reader = Task { race.resolve(.frame(await frame.value)) }
        let prober = Task { race.resolve(.probe(await probe.value)) }
        let result = await withTaskCancellationHandler {
            await race.value()
        } onCancel: {
            race.resolve(.probe(false))
        }
        reader.cancel()
        prober.cancel()
        return result
    }
}

/// Owns the sole iterator for a generation stream. Reads cannot be cancelled
/// and restarted safely: a cancelled iterator can consume the frame that a
/// replacement expected. The watchdog instead races Tasks awaiting this one
/// source, while the source itself remains singular.
final class GenerationFrameSource: @unchecked Sendable {
    private var frames: AsyncThrowingStream<RawFrame, Error>.AsyncIterator
    private var delivered: UInt64 = 0
    private let deliveryLock = NSLock()

    init(stream: ReachTransport.QUICStream) {
        frames = stream.frames.makeAsyncIterator()
    }

    func next() async -> FrameEnding {
        let ending = await FrameEnding.next(from: &frames)
        deliveryLock.withLock { delivered &+= 1 }
        return ending
    }

    func deliveryCount() -> UInt64 {
        deliveryLock.withLock { delivered }
    }
}

/// A tiny one-shot used to race independently owned Tasks without a task
/// group. Cancelling a task-group child awaiting another Task does not cancel
/// that underlying read, but the group still waits for the child; that would
/// delay a newly arrived token by the whole pong deadline.
private final class LivenessRace<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Value?
    private var continuation: CheckedContinuation<Value, Never>?
    private var settled = false

    func resolve(_ value: Value) {
        lock.lock()
        guard !settled else {
            lock.unlock()
            return
        }
        settled = true
        result = value
        if let continuation {
            self.continuation = nil
            lock.unlock()
            continuation.resume(returning: value)
        } else {
            lock.unlock()
        }
    }

    func value() async -> Value {
        await withCheckedContinuation { continuation in
            lock.lock()
            if let result {
                lock.unlock()
                continuation.resume(returning: result)
            } else {
                self.continuation = continuation
                lock.unlock()
            }
        }
    }
}
