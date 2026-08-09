import Foundation
import ReachTransport
import ReachWire

/// The result of one bounded check of the exact QUIC road a generation uses.
/// A newly opened Hello-only channel carries its authenticated calling card
/// back to the hub so road movement is learned from an authenticated peer.
struct ActiveRoadProbeResult: Sendable {
    let alive: Bool
    let refreshedHello: HelloAck?
}

/// One authenticated control channel per dialed road.
///
/// The actor is deliberately road-scoped, not session-scoped. Generations
/// that share a dialer share a probe; a generation leased from an older road
/// keeps its own actor even after the hub has selected a replacement.
actor ActiveRoadProbe {
    private let dialer: QUICDialer
    private let checkOverride: (@Sendable (Duration) async -> ActiveRoadProbeResult)?
    private var control: ReachTransport.QUICStream?
    private var version: UInt8?
    private var invalidated = false
    private var generationLeases = 0
    private var nextNonce = UInt64.random(in: UInt64.min ... UInt64.max)
    private var inFlight: (id: UUID, task: Task<ActiveRoadProbeResult, Never>)?

    init(
        dialer: QUICDialer,
        checkOverride: (@Sendable (Duration) async -> ActiveRoadProbeResult)? = nil
    ) {
        self.dialer = dialer
        self.checkOverride = checkOverride
    }

    /// Retains the already-authenticated session-opening exchange as the
    /// road's initial probe channel. There is no second session open.
    func adopt(control: ReachTransport.QUICStream, version: UInt8) {
        guard !invalidated else {
            control.cancel()
            return
        }
        self.control?.cancel()
        self.control = control
        self.version = version
    }

    func acquireGenerationLease() {
        guard !invalidated else { return }
        generationLeases += 1
    }

    func releaseGenerationLease() {
        guard generationLeases > 0 else { return }
        generationLeases -= 1
        if generationLeases == 0 {
            // No idle keepalive: the channel exists only to distinguish a
            // silent in-flight generation from a dead road. A future
            // generation can lazily authenticate a fresh Hello-only channel.
            control?.cancel()
            control = nil
        }
    }

    func invalidate() {
        invalidated = true
        generationLeases = 0
        control?.cancel()
        control = nil
        inFlight?.task.cancel()
        inFlight = nil
    }

    /// Coalesces concurrent watchdogs on this road into one nonce exchange.
    func check(timeout: Duration) async -> ActiveRoadProbeResult {
        guard !invalidated else {
            return ActiveRoadProbeResult(alive: false, refreshedHello: nil)
        }
        if let inFlight {
            return await inFlight.task.value
        }

        let id = UUID()
        let task = Task {
            if let checkOverride = self.checkOverride {
                return await checkOverride(timeout)
            }
            return await self.performCheck(timeout: timeout)
        }
        inFlight = (id, task)
        let result = await task.value
        if inFlight?.id == id { inFlight = nil }
        return result
    }

    private func performCheck(timeout: Duration) async -> ActiveRoadProbeResult {
        guard !invalidated else {
            return ActiveRoadProbeResult(alive: false, refreshedHello: nil)
        }
        let deadline = ContinuousClock.now + timeout

        // A retained control stream may have been closed normally after the
        // session exchange. A quick closed/error result is permission to open
        // the documented Hello-only replacement on the same dialer. A full
        // missing-pong deadline is not: that is the liveness failure itself.
        if let control, let version {
            let attemptedAt = ContinuousClock.now
            if await ping(control, version: version, deadline: deadline) {
                return ActiveRoadProbeResult(alive: true, refreshedHello: nil)
            }
            self.control = nil
            control.cancel()
            guard Self.shouldOpenReplacement(
                attemptedAt: attemptedAt,
                now: .now,
                deadline: deadline,
                timeout: timeout,
                invalidated: invalidated
            ) else {
                return ActiveRoadProbeResult(alive: false, refreshedHello: nil)
            }
        }

        do {
            let (control, ack) = try await openControl(deadline: deadline)
            guard !invalidated else {
                control.cancel()
                return ActiveRoadProbeResult(alive: false, refreshedHello: nil)
            }
            self.control = control
            version = ack.version
            guard await ping(control, version: ack.version, deadline: deadline) else {
                self.control = nil
                control.cancel()
                return ActiveRoadProbeResult(alive: false, refreshedHello: nil)
            }
            return ActiveRoadProbeResult(alive: true, refreshedHello: ack)
        } catch {
            self.control?.cancel()
            self.control = nil
            return ActiveRoadProbeResult(alive: false, refreshedHello: nil)
        }
    }

    private func openControl(deadline: ContinuousClock.Instant) async throws -> (
        ReachTransport.QUICStream,
        HelloAck
    ) {
        let remaining = ContinuousClock.now.duration(to: deadline)
        guard remaining > .zero else { throw CancellationError() }
        let stream = try await dialer.openStream(timeout: seconds(remaining))
        do {
            let offered = Wire.supportedVersions
            try await stream.send(Hello(versions: offered, client: "ReachKit/\(Wire.version)"))
            var frames = stream.frames.makeAsyncIterator()
            let remaining = ContinuousClock.now.duration(to: deadline)
            guard remaining > .zero else { throw CancellationError() }
            let timeout = Task {
                try? await Task.sleep(for: remaining)
                if !Task.isCancelled { stream.cancel() }
            }
            let ending = await FrameEnding.next(from: &frames)
            timeout.cancel()
            guard case .frame(let raw) = ending else { throw CancellationError() }
            if raw.type == .errorFrame {
                let error = try raw.decode(ErrorFrame.self)
                throw ReachError.sessionRejected("\(error.code): \(error.message)")
            }
            let ack = try raw.decode(HelloAck.self)
            guard offered.contains(ack.version) else {
                throw ReachError.sessionRejected(
                    "wire-version: \(Wire.mismatchMessage(app: offered, cluster: [ack.version]))"
                )
            }
            return (stream, ack)
        } catch {
            stream.cancel()
            throw error
        }
    }

    private func ping(
        _ stream: ReachTransport.QUICStream,
        version: UInt8,
        deadline: ContinuousClock.Instant
    ) async -> Bool {
        guard !invalidated, ContinuousClock.now < deadline else { return false }
        let nonce = nextNonce
        nextNonce &+= 1
        do {
            try await stream.send(Ping(nonce: nonce), for: version)
        } catch {
            return false
        }
        var frames = stream.frames.makeAsyncIterator()
        let remaining = ContinuousClock.now.duration(to: deadline)
        guard remaining > .zero else { return false }
        let timeout = Task {
            try? await Task.sleep(for: remaining)
            if !Task.isCancelled { stream.cancel() }
        }
        let ending = await FrameEnding.next(from: &frames)
        timeout.cancel()
        return Self.matches(
            ending,
            nonce: nonce,
            version: version,
            arrivedByDeadline: ContinuousClock.now <= deadline
        )
    }

    nonisolated static func shouldOpenReplacement(
        attemptedAt: ContinuousClock.Instant,
        now: ContinuousClock.Instant,
        deadline: ContinuousClock.Instant,
        timeout: Duration,
        invalidated: Bool
    ) -> Bool {
        !invalidated && now - attemptedAt < timeout && now < deadline
    }

    nonisolated static func matches(
        _ ending: FrameEnding,
        nonce: UInt64,
        version: UInt8,
        arrivedByDeadline: Bool = true
    ) -> Bool {
        guard arrivedByDeadline,
              case .frame(let raw) = ending,
              (try? raw.requireSupported(by: version)) != nil,
              raw.type == .pong,
              let pong = try? raw.decode(Pong.self) else {
            return false
        }
        return pong.nonce == nonce
    }

    private func seconds(_ duration: Duration) -> Double {
        let components = duration.components
        return max(0.001, Double(components.seconds) + Double(components.attoseconds) / 1e18)
    }
}
