import Foundation
import FoundationModels
import Network
import ReachTransport
import ReachWire

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

        while true {
            // Which budget applies is decided once per attempt, and then
            // bounds both halves of it: the opens below, and the pause before
            // the next iteration. It used to be computed only at the two
            // `waitBeforeRetry` calls, which is why it bounded only the pauses.
            //
            // The evidence is whether anything is resident to come back to,
            // and the only evidence of that is an event this call has already
            // received. It used to be `session == nil` — but the hub caches a
            // session handle across calls and hands it back without dialling,
            // so a handle for a daemon that is no longer running still read as
            // "connected". A fresh ask with nothing resident therefore spent
            // the full residency window in silence: measured at 118.6 s
            // against a comment promising it could not happen.
            let deadline = lastReceived == nil ? coldOpenDeadline : reconnectDeadline
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
                    live = try await openingBy(deadline) {
                        try await ReachConnectionHub.shared.session(for: configuration)
                    }
                    session = live
                }
                let stream = try await openingBy(deadline) {
                    try await ReachConnectionHub.shared.openGenerationStream(for: configuration)
                }
                defer { stream.cancel() }
                // A path change (an SSID hop, Wi-Fi loss) cancels the live
                // stream so the retry loop re-dials now — the hub then races
                // every address the daemon declared, the mesh included.
                // Without this, a dead path surfaces only at the QUIC idle
                // timeout.
                let watcher = Task {
                    await ReachConnectionHub.shared.pathChanged(after: epoch)
                    stream.cancel()
                }
                defer { watcher.cancel() }
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

                for try await raw in stream.frames {
                    try raw.requireSupported(by: live.version)
                    if Task.isCancelled {
                        try? await stream.send(GenerateCancel(genID: genID), for: live.version)
                    }
                    switch raw.type {
                    case .ev:
                        let ev = try raw.decode(Ev.self)
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
                throw ReachError.transport("stream ended before finish")
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
                try await waitBeforeRetry(&backoff, deadline: deadline, cause: error)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try await waitBeforeRetry(&backoff, deadline: deadline, cause: error)
            }
        }
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

    /// Runs `open` and gives up at `deadline`, so the budget bounds the
    /// attempt and not merely the pause before the next one.
    ///
    /// `waitBeforeRetry` above checks the deadline before *sleeping*, which
    /// bounds the gaps between dials and nothing else. A single iteration can
    /// spend far more than the whole budget inside one attempt, and did:
    /// `ReachConnectionHub.openStream` tries the cached dialer for the full
    /// `connectTimeout` and then hands the same timeout to every racer, so a
    /// warm hub pays it twice per call and this function is called twice per
    /// iteration — up to 4× the configured timeout, 80 s at the default 20,
    /// against a 10 s promise. Both existing measurements of this hid it by
    /// choosing a tiny `connectTimeout`.
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
