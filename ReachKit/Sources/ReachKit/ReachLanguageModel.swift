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

    public var capabilities: LanguageModelCapabilities {
        // This is a gate, not a label. A session handed tools by an app whose
        // model has not declared `.toolCalling` never reaches the executor at
        // all: the framework throws `unsupportedCapability` in its place
        // (spike S6b, where `respond` was provably never called). So the line
        // below is what makes tools possible, and it must never run ahead of
        // the daemon actually serving them — an app told the tools are
        // supported and then quietly ignored is worse off than one refused.
        //
        // Guided generation and vision stay undeclared: funded scope, and
        // declaring either would take away the same honest refusal.
        LanguageModelCapabilities([.toolCalling])
    }

    public init(configuration: ReachExecutor.Configuration) {
        executorConfiguration = configuration
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
                let live: ReachConnectionHub.SessionHandle
                if let session {
                    live = session
                } else {
                    live = try await ReachConnectionHub.shared.session(for: configuration)
                    session = live
                }
                let stream = try await ReachConnectionHub.shared.openGenerationStream(for: configuration)
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
                    ))
                } else {
                    try await stream.send(GenerateBegin(sessionID: live.sessionID, genID: genID, request: wire))
                }

                for try await raw in stream.frames {
                    if Task.isCancelled {
                        try? await stream.send(GenerateCancel(genID: genID))
                    }
                    switch raw.type {
                    case .ev:
                        let ev = try raw.decode(Ev.self)
                        if let lastReceived, ev.seq <= lastReceived { continue }   // replay dupes
                        lastReceived = ev.seq
                        reconnectDeadline = ContinuousClock.now + .seconds(120)
                        unacked += 1
                        if unacked >= 16 {
                            try? await stream.send(EvAck(seq: ev.seq))
                            unacked = 0
                        }
                        if try await forward(ev.event, into: channel) {
                            try? await stream.send(EvAck(seq: ev.seq))
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
                if case .remote = error { throw error }
                // Which budget applies is decided by whether anything is
                // resident to come back to, and the only evidence of that is
                // an event this call has already received. It used to be
                // decided by `session == nil` — but the hub caches a session
                // handle across calls and hands it back without dialling, so a
                // handle for a daemon that is no longer running still read as
                // "connected". A fresh ask with nothing resident therefore
                // spent the full residency window in silence: measured at
                // 118.6 s against a comment promising it could not happen.
                try await waitBeforeRetry(
                    &backoff,
                    deadline: lastReceived == nil ? coldOpenDeadline : reconnectDeadline,
                    cause: error
                )
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try await waitBeforeRetry(
                    &backoff,
                    deadline: lastReceived == nil ? coldOpenDeadline : reconnectDeadline,
                    cause: error
                )
            }
        }
    }

    /// Returns true when the generation finished.
    private func forward(
        _ event: WireEvent,
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
        case .reasoningAppend, .usage:
            // Reserved vocabulary; the v0 daemon does not emit these.
            break
        case .finished(let reason):
            switch reason {
            case .complete:
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
}
