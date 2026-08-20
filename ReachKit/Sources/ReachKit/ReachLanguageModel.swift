import Foundation
import FoundationModels
import Network
import OSLog
import ReachTransport
import ReachWire

private let livenessLogger = Logger(subsystem: "systems.reach.ReachKit", category: "liveness")

/// The Reach model: to an adopting app, a session on it reads identically
/// to one on the system model. `LanguageModelSession(model: reachModel)` is
/// the one-dependency swap.
public struct ReachLanguageModel: FoundationModels.LanguageModel {
    public typealias Executor = ReachExecutor

    public let executorConfiguration: ReachExecutor.Configuration
    public let usage: ReachUsageMonitor

    public var capabilities: LanguageModelCapabilities {
        // This is a gate, not a label. A session handed tools by an app whose
        // model has not declared `.toolCalling` never reaches the executor at
        // all: the framework throws `unsupportedCapability` in its place
        // (spike S6b, where `respond` was provably never called). So the line
        // below is what makes tools possible, and it must never run ahead of
        // the daemon actually serving them — an app told the tools are
        // supported and then quietly ignored is worse off than one refused.
        //
        // Response schemas are served by the daemon's grammar-constrained
        // path. Vision stays undeclared: declaring it would take away the
        // framework's honest refusal without a daemon implementation behind
        // the claim.
        LanguageModelCapabilities([.guidedGeneration, .toolCalling])
    }

    public init(configuration: ReachExecutor.Configuration) {
        executorConfiguration = configuration
        usage = ReachUsageMonitor()
    }
}

/// The client half of the executor bridge: serializes the framework's
/// request onto the wire and forwards wire events back into the channel via
/// the factory surface (the only place framework events are constructed).
/// Owns the reconnect/re-attach loop — a generation survives transport
/// death within the daemon's residency window.
public struct ReachExecutor: FoundationModels.LanguageModelExecutor {
    public typealias Model = ReachLanguageModel

    public struct Configuration: Hashable, Sendable {
        /// A Bonjour service name takes precedence over host/port — the
        /// system resolves it at connect time (the no-configuration path).
        public var serviceName: String?
        public var host: String
        public var port: UInt16
        public var modelID: String
        /// Resolved through `ReachIdentityRegistry`.
        public var identityLabel: String
        public var multipathHandover: Bool
        public var connectTimeout: Double

        public init(
            serviceName: String? = nil,
            host: String = "127.0.0.1",
            port: UInt16 = 47337,
            modelID: String = "default",
            identityLabel: String = "reach-device",
            multipathHandover: Bool = false,
            connectTimeout: Double = 20
        ) {
            self.serviceName = serviceName
            self.host = host
            self.port = port
            self.modelID = modelID
            self.identityLabel = identityLabel
            self.multipathHandover = multipathHandover
            self.connectTimeout = connectTimeout
        }
    }

    private let configuration: Configuration

    public init(configuration: Configuration) throws {
        self.configuration = configuration
    }

    public func respond(
        to request: LanguageModelExecutorGenerationRequest,
        model: ReachLanguageModel,
        streamingInto channel: LanguageModelExecutorGenerationChannel
    ) async throws {
        let wire = WireGenerationRequest(request)
        var session: ReachConnectionHub.SessionHandle?
        let genID = UUID()
        var pendingUsage: ReachGenerationUsage?

        var lastReceived: UInt64?
        var unacked = 0
        // Slides forward on every received event: the retry budget is
        // measured from the last sign of life, matching the daemon's
        // residency window, not from when the generation began.
        var reconnectDeadline = ContinuousClock.now + .seconds(120)
        // A cold open gets its own, much shorter budget. The 120 seconds above
        // is the daemon's residency window: mid-generation there is something
        // resident worth waiting for, and re-attaching recovers it. Before the
        // first session there is nothing resident — the only thing worth
        // waiting for is a mesh tunnel coming up under an on-demand rule,
        // which takes seconds, not minutes. Spending the residency budget here
        // would turn "there is no road to the cluster" into a two-minute hang,
        // which is the opposite of saying so.
        //
        // `var`, and re-armed wherever this call goes back to having nothing
        // resident: as a `let` it was fixed before the event it is meant to
        // budget for, so a reopen inherited a deadline already in the past and
        // got no attempt at all.
        var coldOpenDeadline = ContinuousClock.now + .seconds(10)
        var backoff: Duration = .milliseconds(250)
        // A generation that never started can be re-begun against a fresh
        // session; once tokens are flowing, only re-attach is safe.
        var freshStartRetries = 1

        retry: while true {
            // Which budget applies to the *opens* is decided once per attempt,
            // so both opens below share one bound. The retry decision after
            // those opens is deliberately made again: an attempt can begin
            // cold and then receive its first event, at which point there is
            // a resident generation worth the 120-second recovery window.
            // Reusing that attempt's original ten-second deadline after the
            // first event made a later path change terminal as soon as the
            // generation had been running for ten seconds.
            //
            // The evidence is whether anything is resident to come back to,
            // and the only evidence of that is an event this call has already
            // received. It used to be `session == nil` — but the hub caches a
            // session handle across calls and hands it back without dialling,
            // so a handle for a daemon that is no longer running still read as
            // "connected". A fresh ask with nothing resident therefore spent
            // the full residency window in silence: measured at 118.6 s
            // against a comment promising it could not happen.
            let openingDeadline = lastReceived == nil ? coldOpenDeadline : reconnectDeadline
            do {
                // Epoch read precedes the open: a path change that lands
                // mid-dial still trips the watcher rather than being missed.
                let epoch = await ReachConnectionHub.shared.currentPathEpoch()
                // Opening the session lives inside the loop so the first open
                // takes the same discipline as every later one. It used to sit
                // above, outside the budget: a cold dial that landed while the
                // mesh tunnel was still coming up failed at once, with no
                // backoff and no retry — which is exactly the shape a phone
                // that has just rebooted is in, and the one case "reach it
                // from anywhere" most has to survive.
                let configuration = configuration
                let live: ReachConnectionHub.SessionHandle
                if let session {
                    live = session
                } else {
                    live = try await openingBy(openingDeadline) {
                        try await ReachConnectionHub.shared.generationSession(for: configuration)
                    }
                    session = live
                }
                let lease = try await openingBy(openingDeadline) {
                    try await ReachConnectionHub.shared.openGenerationStream(for: configuration)
                }
                let stream = lease.stream
                defer {
                    Task { await ReachConnectionHub.shared.releaseGenerationStream(lease) }
                }
                defer { stream.cancel() }
                // A path change (an SSID hop, Wi-Fi loss) cancels a direct
                // stream so the retry loop re-dials now. A current relay is
                // deliberately different: the appearance of a direct road is
                // not proof that its live generation stopped. Keep that relay
                // until its nonce liveness probe or stream proves otherwise.
                let watcher = Task {
                    if await ReachConnectionHub.shared.pathChangeRequiresRedial(
                        after: epoch,
                        lease: lease,
                        for: configuration
                    ) {
                        stream.cancel()
                    }
                }
                defer { watcher.cancel() }
                do {
                    if let lastReceived {
                        try await stream.send(GenerateReattach(
                            sessionID: live.sessionID,
                            token: live.token,
                            genID: genID,
                            fromSeq: lastReceived
                        ), for: live.version)
                    } else {
                        try await stream.send(
                            GenerateBegin(sessionID: live.sessionID, genID: genID, request: wire),
                            for: live.version
                        )
                    }
                } catch {
                    await ReachConnectionHub.shared.markRoadUnresponsive(
                        lease,
                        for: configuration
                    )
                    throw error
                }
                let frames = GenerationFrameSource(stream: stream)
                var pendingFrame = Task { await frames.next() }
                var lastGenerationEventAt = ContinuousClock.now

                while true {
                    var ending: FrameEnding
                    if let arrived = await GenerationLivenessPolicy.waitForFrame(pendingFrame) {
                        ending = arrived
                    } else {
                        if Task.isCancelled {
                            try? await stream.send(GenerateCancel(genID: genID), for: live.version)
                            throw CancellationError()
                        }
                        let marker = frames.deliveryCount()
                        let probe = Task {
                            await ReachConnectionHub.shared.activeRoadIsAlive(
                                lease,
                                for: configuration,
                                timeout: GenerationLivenessPolicy.interval
                            )
                        }
                        let probeRace = await GenerationLivenessPolicy.race(
                            frame: pendingFrame,
                            probe: probe
                        )
                        if Task.isCancelled {
                            try? await stream.send(GenerateCancel(genID: genID), for: live.version)
                            throw CancellationError()
                        }
                        switch probeRace {
                        case .frame(let arrived):
                            // Generation delivery outweighs a control-stream
                            // failure: it is direct evidence that this road is
                            // carrying the request that matters.
                            ending = arrived
                        case .probe(true):
                            // The model may be thinking or queued. The exact
                            // road answered its nonce, so keep the same read
                            // pending and arm another silence interval.
                            continue
                        case .probe(false):
                            // Close the race at the probe result. If the source
                            // delivered meanwhile, consume it instead of
                            // dirtying a road that just proved useful.
                            if frames.deliveryCount() > marker {
                                ending = await pendingFrame.value
                            } else {
                                await ReachConnectionHub.shared.markRoadUnresponsive(
                                    lease,
                                    for: configuration
                                )
                                let elapsed = lastGenerationEventAt.duration(to: .now)
                                livenessLogger.notice(
                                    "active-road liveness triggered re-dial elapsed=\(Self.seconds(elapsed), privacy: .public)s roadEpoch=\(lease.roadEpoch, privacy: .public)"
                                )
                                stream.cancel()
                                if lastReceived == nil {
                                    // Duplicate GenerateBegin is idempotent in
                                    // the daemon registry. Give the newly raced
                                    // road the full cold-open budget rather
                                    // than inheriting time spent proving the
                                    // old road dead.
                                    coldOpenDeadline = ContinuousClock.now + .seconds(10)
                                }
                                backoff = .milliseconds(250)
                                continue retry
                            }
                        }
                    }

                    guard case .frame(let raw) = ending else {
                        await ReachConnectionHub.shared.markRoadUnresponsive(
                            lease,
                            for: configuration
                        )
                        throw ReachError.transport(ending.detailing("generation stream ended before finish"))
                    }
                    pendingFrame = Task { await frames.next() }
                    try raw.requireSupported(by: live.version)
                    if Task.isCancelled {
                        try? await stream.send(GenerateCancel(genID: genID), for: live.version)
                        throw CancellationError()
                    }
                    switch raw.type {
                    case .ev:
                        let ev = try raw.decode(Ev.self)
                        // Every generation event is a sign of life, including
                        // a replay duplicate after re-attach.
                        lastGenerationEventAt = .now
                        if let lastReceived, ev.seq <= lastReceived { continue }   // replay dupes
                        lastReceived = ev.seq
                        reconnectDeadline = ContinuousClock.now + .seconds(120)
                        unacked += 1
                        if unacked >= 16 {
                            try? await stream.send(EvAck(seq: ev.seq), for: live.version)
                            unacked = 0
                        }
                        if try await forward(
                            ev.event,
                            requestID: wire.id,
                            pendingUsage: &pendingUsage,
                            monitor: model.usage,
                            into: channel
                        ) {
                            try? await stream.send(EvAck(seq: ev.seq), for: live.version)
                            return
                        }
                    case .errorFrame:
                        let error = try raw.decode(ErrorFrame.self)
                        throw ReachError.remote(code: error.code, message: error.message)
                    default:
                        continue
                    }
                }
            } catch let error as ReachError {
                // A session the daemon no longer knows (it restarted, or the
                // token expired) is recoverable if nothing has streamed yet:
                // drop the stale session, open a fresh one, begin again.
                //
                // Only `begin-rejected` can arrive in that state. A re-attach
                // is sent only under `if let lastReceived`, so pairing
                // `reattach-rejected` with `lastReceived == nil` described a
                // reachable case that is not one — it read as a second
                // recovery path and was none.
                if case .remote(let code, _) = error,
                   code == "begin-rejected",
                   lastReceived == nil, freshStartRetries > 0 {
                    freshStartRetries -= 1
                    await ReachConnectionHub.shared.invalidateSession(for: configuration)
                    // Dropped, not reopened here — the top of the loop opens
                    // it, so the fresh start gets the same budget too. Both
                    // halves of "the same budget" are re-armed here: the
                    // deadline, and the backoff that would otherwise arrive
                    // already doubled and eat it.
                    session = nil
                    coldOpenDeadline = ContinuousClock.now + .seconds(10)
                    backoff = .milliseconds(250)
                    continue
                }
                // An app that was never granted access does not become granted
                // by waiting. Terminal, like `.remote`: without this, moving
                // the open into the loop would make an ungranted app hang for
                // two minutes instead of saying so at once.
                if case .identityNotRegistered = error { throw error }
                // A re-attach is only sent for a generation this call has
                // already taken tokens from, so a refusal to one always means
                // the same thing: what was streaming is gone. Terminal either
                // way — re-beginning is the app's call, never the transport's,
                // because tokens a person has read cannot be un-read and a
                // tool that ran in the app cannot be un-run. What changes is
                // that the ending now says which happened.
                if case .remote(let code, let message) = error, code == "reattach-rejected" {
                    throw ReachError.generationLost(message)
                }
                if case .remote = error { throw error }
                try await waitBeforeRetry(
                    &backoff,
                    deadline: Self.retryDeadline(
                        lastReceived: lastReceived,
                        coldOpen: coldOpenDeadline,
                        resident: reconnectDeadline
                    ),
                    cause: error
                )
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try await waitBeforeRetry(
                    &backoff,
                    deadline: Self.retryDeadline(
                        lastReceived: lastReceived,
                        coldOpen: coldOpenDeadline,
                        resident: reconnectDeadline
                    ),
                    cause: error
                )
            }
        }
    }

    nonisolated static func retryDeadline(
        lastReceived: UInt64?,
        coldOpen: ContinuousClock.Instant,
        resident: ContinuousClock.Instant
    ) -> ContinuousClock.Instant {
        lastReceived == nil ? coldOpen : resident
    }

    /// Returns true when the generation finished.
    private func forward(
        _ event: WireEvent,
        requestID: UUID,
        pendingUsage: inout ReachGenerationUsage?,
        monitor: ReachUsageMonitor,
        into channel: LanguageModelExecutorGenerationChannel
    ) async throws -> Bool {
        switch event {
        case .responseAppend(let entryID, let text, let segmentID, let tokenCount):
            await channel.send(.response(entryID: entryID, action: .appendText(text, segmentID: segmentID, tokenCount: tokenCount)))
        case .responseReplace(let entryID, let text, let segmentID, let tokenCount):
            await channel.send(.response(entryID: entryID, action: .replaceTextSegment(text, segmentID: segmentID, tokenCount: tokenCount)))
        case .toolCallAppendArguments(let entryID, let id, let name, let content, let tokenCount):
            // The only place a framework tool-call event is constructed. The
            // wire case was shaped for this chain when it was still reserved,
            // and it fits it exactly.
            await channel.send(.toolCalls(
                entryID: entryID,
                action: .toolCall(
                    id: id,
                    name: name,
                    action: .appendArguments(content, tokenCount: tokenCount)
                )
            ))
        case .reasoningAppend:
            // Reserved vocabulary; the v0 daemon does not emit this.
            break
        case .usage(let inputTokens, let outputTokens):
            // The event precedes `.finished`; retain it until the cluster says
            // this generation completed so cancellation and error never look
            // like completed usage. An older daemon may omit it entirely.
            pendingUsage = ReachGenerationUsage(
                requestID: requestID,
                inputTokens: inputTokens,
                outputTokens: outputTokens
            )
        case .finished(let reason):
            switch reason {
            case .complete:
                if let pendingUsage {
                    await monitor.record(pendingUsage)
                }
                return true
            case .cancelled:
                throw CancellationError()
            case .error(let message):
                throw ReachError.remote(code: "generation", message: message)
            }
        }
        return false
    }

    private func waitBeforeRetry(
        _ backoff: inout Duration,
        deadline: ContinuousClock.Instant,
        cause: Error
    ) async throws {
        guard !Task.isCancelled, ContinuousClock.now + backoff < deadline else {
            throw cause
        }
        try? await Task.sleep(for: backoff)
        backoff = min(backoff * 2, .seconds(2))
    }

    private static func seconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) + Double(components.attoseconds) / 1e18
    }

    /// Runs `open` and gives up at `deadline`, so the budget bounds the
    /// attempt and not merely the pause before the next one.
    ///
    /// `waitBeforeRetry` above checks the deadline before *sleeping*, which
    /// bounds the gaps between dials and nothing else. This outer gate is what
    /// turns the hub's configured transport timeout into the unchanged ten-
    /// second cold-open contract. Inside the hub, direct and relay attempts now
    /// share one race deadline and each opener receives only its remaining
    /// budget; this gate also includes the control exchange that follows.
    ///
    /// **On expiry the hub's own error is what surfaces, not one invented
    /// here.** Cancelling reaches `NWConnection` (the transport tears a
    /// cancelled open down), the race collects no winner, and the hub throws
    /// `ReachError.unreachable(roads:stored:)` — the sentence that says which
    /// of "never been answered" and "knows the roads" this app is in. Making
    /// one up here would have to guess both.
    ///
    /// This also bounds the control exchange inside `session(for:)`, which no
    /// connect timeout can: those are reads, and a cluster that accepts the
    /// connection and then goes quiet hangs there to the QUIC idle timeout.
    private func openingBy<T: Sendable>(
        _ deadline: ContinuousClock.Instant,
        _ open: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        do {
            return try await withThrowingTaskGroup(of: T?.self) { group in
                group.addTask { try await open() }
                group.addTask {
                    try await Task.sleep(until: deadline, clock: ContinuousClock())
                    return nil
                }
                defer { group.cancelAll() }
                while let next = try await group.next() {
                    if let value = next {
                        return value
                    }
                    // The deadline won. Cancel the open and keep waiting, so
                    // what propagates is its account of why it had not
                    // finished rather than a bare timeout.
                    group.cancelAll()
                }
                // It unwound without throwing and without a stream, which
                // leaves nothing to report but the cancellation itself.
                throw CancellationError()
            }
        } catch {
            // ⚠️ An app that cancelled its own request must not be told there
            // was no road. The hub turns a cancelled dial into `.unreachable`
            // — correct for a dead network, and a lie to someone who just
            // closed the view — and whether that or the timer's own
            // `CancellationError` arrives first is a race. Decided here, where
            // the difference is knowable.
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }
}
