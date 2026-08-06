import Crypto
import Foundation
import ReachWire

/// Session residency, minimal per the named stub: generations are owned by
/// the registry and decoupled from connections — a transport death leaves
/// the generation running inside its residency window, and a re-attach
/// replays the un-acked buffer then continues live.
///
/// Generations are keyed by genID and nothing caps how many a session holds.
/// A `generationAlreadyRunning` case was declared here and never thrown, so
/// "one in-flight generation per session" was a convention no code kept;
/// enforcing it would have been worse than dropping it, because
/// `begin-rejected` is precisely the client's cue to discard its session and
/// open a fresh one — a well-behaved app would have answered the refusal by
/// silently splitting itself in two.
///
/// Nothing here survives the process. That is deliberate and it is the whole
/// of what a restart costs: the transcript rides the wire on every
/// `GenerateBegin`, so a lost session loses a round trip rather than a
/// conversation, and the only casualty is a generation actually in flight.
public actor SessionRegistry {
    public struct Limits: Sendable {
        public var residencyWindow: Duration = .seconds(120)
        public var completedRetention: Duration = .seconds(600)
        /// How long a session with nothing left in it stays addressable.
        ///
        /// Comfortably past `completedRetention`, so a session is only ever
        /// dropped after its last generation has already aged out. Dropping
        /// one is recoverable rather than fatal: the client re-opens on
        /// `begin-rejected` when nothing has streamed yet, which is exactly
        /// the state an idle session is in.
        public var idleSessionRetention: Duration = .seconds(900)
        public var bufferCapBytes: Int = 4 * 1024 * 1024

        public init() {}
    }

    /// These three cross the wire verbatim — `Daemon` interpolates them into
    /// `ErrorFrame.message`, which the asking app renders on a screen. They
    /// went years as bare case names: `ErrorLegibilityTests` was written to
    /// outlaw exactly that and quotes `unknownSession` as its example, but
    /// held every error type except this one, and stood in a hand-written
    /// message the daemon never sends. So the suite passed while the string a
    /// person actually met after a restart read `unknownSession`.
    ///
    /// The daemon cannot tell a restart from a session that aged out — both
    /// are simply a table with no such row — so none of these claims to know
    /// which. They say what is true either way, and what to do about it.
    public enum RegistryError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
        case unknownSession
        case badToken
        case unknownGeneration

        public var description: String {
            switch self {
            case .unknownSession:
                "the cluster has no session by that name — it was let go after sitting idle, or the daemon holding it restarted"
            case .badToken:
                "that session exists, but the token offered for it is not the one it was opened with"
            case .unknownGeneration:
                "the cluster has no generation by that name on this session — it ended and was let go, or it did not outlive a restart"
            }
        }

        public var errorDescription: String? { description }
    }

    private struct GenerationRecord {
        /// Which connection currently owns `live`.
        ///
        /// A generation outlives the connections that serve it — that is the
        /// whole point of residency — so "the transport died" has to mean
        /// "the transport I was attached to died", not "a transport died".
        /// Without this, the dead LAN connection's pump, which does not learn
        /// it is dead until its own idle timeout ~30 s after a walk-out, ends
        /// the continuation the mesh has been streaming through since.
        /// Monotonic, so an epoch is never reused.
        var epoch: UInt64 = 0
        var buffer: [Ev] = []
        var bufferBytes = 0
        var nextSeq: UInt64 = 0
        var state: WireGenerationState = .streaming
        var task: Task<Void, Never>?
        var live: AsyncStream<Ev>.Continuation?
        var detachedAt: ContinuousClock.Instant?
    }

    private struct SessionRecord {
        var tokenHash: SHA256Digest
        var modelID: String
        var generations: [UUID: GenerationRecord] = [:]
        var lastSeen: ContinuousClock.Instant
    }

    private var sessions: [UUID: SessionRecord] = [:]
    private let limits: Limits
    private let clock = ContinuousClock()

    public init(limits: Limits = Limits()) {
        self.limits = limits
    }

    // MARK: Sessions

    public func openSession(modelID: String) -> (sessionID: UUID, token: String) {
        let sessionID = UUID()
        let token = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) }).base64EncodedString()
        sessions[sessionID] = SessionRecord(
            tokenHash: SHA256.hash(data: Data(token.utf8)),
            modelID: modelID,
            lastSeen: clock.now
        )
        return (sessionID, token)
    }

    public func validate(sessionID: UUID, token: String) throws {
        guard var record = sessions[sessionID] else { throw RegistryError.unknownSession }
        guard record.tokenHash == SHA256.hash(data: Data(token.utf8)) else { throw RegistryError.badToken }
        record.lastSeen = clock.now
        sessions[sessionID] = record
    }

    public func resumeStatus(sessionID: UUID, token: String) throws -> [SessionResumed.GenerationStatus] {
        try validate(sessionID: sessionID, token: token)
        return sessions[sessionID]!.generations.map { id, record in
            SessionResumed.GenerationStatus(
                genID: id,
                state: record.state,
                finalSeq: record.state == .streaming ? nil : record.nextSeq
            )
        }
    }

    // MARK: Generations

    /// Starts a generation fed by `events` and returns the seq-stamped
    /// attachment stream for the connection that began it. Idempotent for
    /// re-sent `GenerateBegin` frames: a known genID re-attaches from 0.
    public func begin(
        sessionID: UUID,
        genID: UUID,
        events: @escaping @Sendable () -> AsyncThrowingStream<WireEvent, Error>
    ) throws -> (stream: AsyncStream<Ev>, epoch: UInt64) {
        guard sessions[sessionID] != nil else { throw RegistryError.unknownSession }
        if sessions[sessionID]!.generations[genID] != nil {
            // First-frame-loss idempotency (ruling 4). This delegates, so it
            // must forward the epoch attach minted rather than invent one —
            // a fresh epoch here would leave the caller holding a number that
            // matches nothing.
            return try attach(sessionID: sessionID, genID: genID, fromSeq: nil)
        }

        var record = GenerationRecord()
        let (stream, continuation) = AsyncStream<Ev>.makeStream()
        record.live = continuation
        sessions[sessionID]!.generations[genID] = record

        let task = Task { [weak self] in
            for await event in Self.terminating(events()) {
                guard let self else { return }
                let finished = await self.ingest(sessionID: sessionID, genID: genID, event: event)
                if finished { break }
            }
        }
        sessions[sessionID]!.generations[genID]!.task = task
        return (stream, record.epoch)
    }

    /// Re-attach a live or buffered generation, replaying from `fromSeq`
    /// (exclusive); nil replays everything still buffered.
    public func attach(sessionID: UUID, genID: UUID, fromSeq: UInt64?) throws -> (stream: AsyncStream<Ev>, epoch: UInt64) {
        guard var session = sessions[sessionID] else { throw RegistryError.unknownSession }
        guard var record = session.generations[genID] else { throw RegistryError.unknownGeneration }

        record.epoch += 1
        record.live?.finish()
        let (stream, continuation) = AsyncStream<Ev>.makeStream()
        for buffered in record.buffer where fromSeq.map({ buffered.seq > $0 }) ?? true {
            continuation.yield(buffered)
        }
        if record.state == .streaming {
            record.live = continuation
            record.detachedAt = nil
        } else {
            continuation.finish()
            record.live = nil
        }
        session.generations[genID] = record
        sessions[sessionID] = session
        return (stream, record.epoch)
    }

    /// Cumulative ack: trim the buffer at and below `seq`.
    public func ack(sessionID: UUID, genID: UUID, seq: UInt64, epoch: UInt64) {
        guard var session = sessions[sessionID],
              var record = session.generations[genID],
              record.epoch == epoch else { return }
        record.buffer.removeAll { $0.seq <= seq }
        record.bufferBytes = record.buffer.reduce(0) { $0 + $1.approximateSize }
        session.generations[genID] = record
        sessions[sessionID] = session
    }

    /// The serving connection died: keep the generation running, start the
    /// residency clock.
    public func detach(sessionID: UUID, genID: UUID, epoch: UInt64) {
        guard var session = sessions[sessionID],
              var record = session.generations[genID],
              // Not mine any more: something newer is attached, and ending
              // its continuation is exactly the freeze this guard exists for.
              record.epoch == epoch else { return }
        record.live?.finish()
        record.live = nil
        record.detachedAt = clock.now
        session.generations[genID] = record
        sessions[sessionID] = session
    }

    public func cancel(sessionID: UUID, genID: UUID, epoch: UInt64) {
        guard let session = sessions[sessionID],
              let record = session.generations[genID],
              record.epoch == epoch else { return }
        record.task?.cancel()
    }

    /// Expiry sweep; call periodically. Returns how many generations were
    /// reaped (for tests and logs).
    @discardableResult
    public func sweep() -> Int {
        var reaped = 0
        let now = clock.now
        for (sessionID, var session) in sessions {
            for (genID, record) in session.generations {
                let expired: Bool
                if record.state == .streaming {
                    expired = record.detachedAt.map { now - $0 > limits.residencyWindow } ?? false
                    if expired { record.task?.cancel() }
                } else {
                    expired = record.detachedAt.map { now - $0 > limits.completedRetention } ?? false
                }
                if expired {
                    session.generations.removeValue(forKey: genID)
                    reaped += 1
                }
            }
            // The generations were being reaped and the session holding them
            // never was, so every session a daemon ever opened stayed
            // resident for the life of the process — including ones
            // abandoned after a `begin-rejected` re-open. `lastSeen` was
            // written on open and on every validate and read nowhere: a TTL
            // with no eviction wired to it.
            if session.generations.isEmpty, now - session.lastSeen > limits.idleSessionRetention {
                sessions.removeValue(forKey: sessionID)
            } else {
                sessions[sessionID] = session
            }
        }
        return reaped
    }

    /// How many sessions are resident. Nothing in the daemon needs this —
    /// it exists so a test can watch the table not grow.
    var residentSessions: Int { sessions.count }

    // MARK: Internals

    private func ingest(sessionID: UUID, genID: UUID, event: WireEvent) -> Bool {
        guard var session = sessions[sessionID],
              var record = session.generations[genID] else { return true }

        let stamped = Ev(seq: record.nextSeq, event: event)
        record.nextSeq += 1
        record.buffer.append(stamped)
        record.bufferBytes += stamped.approximateSize
        if record.bufferBytes > limits.bufferCapBytes {
            // Beyond text-demo scale; drop the oldest un-acked rather than
            // grow without bound. A re-attach past this point restarts.
            record.buffer.removeFirst()
        }
        record.live?.yield(stamped)

        var finished = false
        if case .finished(let reason) = event {
            record.state = switch reason {
            case .complete: .complete
            case .cancelled: .cancelled
            case .error: .failed
            }
            record.live?.finish()
            record.live = nil
            record.detachedAt = clock.now
            finished = true
        }
        session.generations[genID] = record
        sessions[sessionID] = session
        return finished
    }

    /// Guarantees a `.finished` event even if the filling's stream throws
    /// or ends without one.
    private static func terminating(
        _ events: AsyncThrowingStream<WireEvent, Error>
    ) -> AsyncStream<WireEvent> {
        AsyncStream { continuation in
            let task = Task {
                var sawFinish = false
                do {
                    for try await event in events {
                        if case .finished = event { sawFinish = true }
                        continuation.yield(event)
                    }
                } catch {
                    continuation.yield(.finished(.error("\(error)")))
                    sawFinish = true
                }
                if !sawFinish {
                    continuation.yield(.finished(.complete))
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

extension Ev {
    var approximateSize: Int {
        switch event {
        case .responseAppend(_, let text, _, _),
             .responseReplace(_, let text, _, _),
             .reasoningAppend(_, let text, _, _):
            return 64 + text.utf8.count
        case .toolCallAppendArguments(_, _, _, let content, _):
            return 96 + content.utf8.count
        case .usage, .finished:
            return 64
        }
    }
}
