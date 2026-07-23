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
        // v0 serves plain text streaming; guided generation, tools, and
        // vision are funded scope and advertise here when they land.
        LanguageModelCapabilities([])
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
        var session = try await ReachConnectionHub.shared.session(for: configuration)
        let genID = UUID()

        var lastReceived: UInt64?
        var unacked = 0
        // Slides forward on every received event: the retry budget is
        // measured from the last sign of life, matching the daemon's
        // residency window, not from when the generation began.
        var reconnectDeadline = ContinuousClock.now + .seconds(120)
        var backoff: Duration = .milliseconds(250)
        // A generation that never started can be re-begun against a fresh
        // session; once tokens are flowing, only re-attach is safe.
        var freshStartRetries = 1

        while true {
            do {
                // Epoch read precedes the open: a path change that lands
                // mid-dial still trips the watcher rather than being missed.
                let epoch = await ReachConnectionHub.shared.currentPathEpoch()
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
                        sessionID: session.sessionID,
                        token: session.token,
                        genID: genID,
                        fromSeq: lastReceived
                    ))
                } else {
                    try await stream.send(GenerateBegin(sessionID: session.sessionID, genID: genID, request: wire))
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
                if case .remote(let code, _) = error,
                   code == "begin-rejected" || code == "reattach-rejected",
                   lastReceived == nil, freshStartRetries > 0 {
                    freshStartRetries -= 1
                    await ReachConnectionHub.shared.invalidateSession(for: configuration)
                    session = try await ReachConnectionHub.shared.session(for: configuration)
                    continue
                }
                if case .remote = error { throw error }
                try await waitBeforeRetry(&backoff, deadline: reconnectDeadline, cause: error)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try await waitBeforeRetry(&backoff, deadline: reconnectDeadline, cause: error)
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
        case .reasoningAppend, .toolCallAppendArguments, .usage:
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
