import Crypto
import Foundation
import ReachWire

/// Privacy-safe evidence for the lifecycle of one resident generation.
///
/// The session log remains the source-address record. These receipts join a
/// generation to that session without repeating an address or port, and name
/// the exact wire cursor at both ends without retaining prompt or output data.
package enum GenerationReceipt: Sendable, Equatable {
    package enum Source: String, Sendable, Equatable {
        case loopback
        case reachMesh = "reach-mesh"
        case relayOverlay = "relay-overlay"
        case privateLAN = "private-lan"
        case sharedAddressSpace = "shared-address-space"
        case publicNetwork = "public"
        case unknown

        package init(remoteEndpointDescription: String?, relayNetwork: String? = nil) {
            guard let remoteEndpointDescription,
                  let endpoint = HostEndpoint.split(remoteEndpointDescription),
                  let kind = HostEndpoint.classify(endpoint.host) else {
                self = .unknown
                return
            }
            if kind == .loopback {
                self = .loopback
                return
            }
            if kind == .mesh {
                self = .reachMesh
                return
            }
            if HostEndpoint.isRelayOverlayAddress(endpoint.host, network: relayNetwork) {
                self = .relayOverlay
                return
            }
            self = switch kind {
            case .loopback: .loopback
            case .mesh: .reachMesh
            case .privateNetwork: .privateLAN
            case .sharedAddressSpace: .sharedAddressSpace
            case .publicAddress: .publicNetwork
            case .linkLocal: .unknown
            }
        }
    }

    package enum Ending: String, Sendable, Equatable {
        case complete
        case cancelled
        case error
    }

    case accepted(sessionID: UUID, genID: UUID, source: Source)
    case terminal(sessionID: UUID, genID: UUID, finalSequence: UInt64, ending: Ending)

    /// Stable, grep-friendly copy. UUIDs are random protocol cursors; every
    /// other value is an enum or sequence number. In particular, an error's
    /// associated text never reaches this surface.
    package var message: String {
        switch self {
        case .accepted(let sessionID, let genID, let source):
            "generation \(genID) accepted on session \(sessionID) from \(source.rawValue) at seq 0"
        case .terminal(let sessionID, let genID, let finalSequence, let ending):
            "generation \(genID) on session \(sessionID) finished at seq \(finalSequence) ending \(ending.rawValue)"
        }
    }
}

package typealias GenerationReceiptSink = @Sendable (GenerationReceipt) -> Void
package typealias ReplayEventSink = @Sendable (String) -> Void

/// Session residency, minimal per the named stub: generations are owned by
/// the registry and decoupled from connections — a transport death leaves
/// the generation running inside its residency window, and a re-attach
/// replays the un-acked buffer then continues live.
///
/// Generations are keyed by genID. Provider admission is deliberately not a
/// property of this table: the daemon's package-only `begin` overload binds a
/// resident generation to one volatile provider reservation, while the public
/// registry API remains a pure residency primitive for alternate fillings and
/// tests. A session may own several active generations, but only one of its
/// generations may occupy the global waiting room at a time.
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
        /// Exact framed bytes retained for one generation's unacknowledged
        /// replay. The default is one maximum-size v0 frame, including its
        /// four-byte length prefix.
        public var bufferCapBytes: Int = Int(FrameCodec.maxFrameLength) + 4

        public init() {}
    }

    /// These cross the wire verbatim — `Daemon` interpolates them into
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
        case shuttingDown
        /// The replay this re-attach asked for begins inside a span the buffer
        /// cap dropped, so serving it would hand back an answer with a hole in
        /// the middle and no way to say so.
        ///
        /// Deliberately carries no numbers. How many events went is a fact
        /// about the daemon's bookkeeping, and the person reading this can act
        /// on none of it.
        case replayOutgrewTheBuffer

        public var description: String {
            switch self {
            case .unknownSession:
                "the cluster has no session by that name — it was let go after sitting idle, or the daemon holding it restarted"
            case .badToken:
                "that session exists, but the token offered for it is not the one it was opened with"
            case .unknownGeneration:
                "the cluster has no generation by that name on this session — it ended and was let go, or it did not outlive a restart"
            case .shuttingDown:
                "the cluster is stopping and cannot open or attach session work"
            case .replayOutgrewTheBuffer:
                "it outgrew what the cluster holds for an app that is away — what already arrived is real, but what came after it is gone"
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
        var nextSeq: UInt64 = 0
        var state: WireGenerationState = .streaming
        var task: Task<Void, Never>?
        var live: AsyncStream<Ev>.Continuation?
        var detachedAt: ContinuousClock.Instant?
    }

    private struct SessionRecord {
        var tokenHash: SHA256Digest
        /// The dialect selected on this session's control stream. Generation
        /// streams are separate QUIC streams, so this is the bridge that keeps
        /// their vocabulary inside the agreement.
        var version: UInt8
        var generations: [UUID: GenerationRecord] = [:]
        var lastSeen: ContinuousClock.Instant
    }

    private struct GenerationKey: Hashable, Sendable {
        var sessionID: UUID
        var generationID: UUID
    }

    private var sessions: [UUID: SessionRecord] = [:]
    private let limits: Limits
    private let receiptSink: GenerationReceiptSink
    private let replayEventSink: ReplayEventSink
    private let generationTaskSettlement: @Sendable () async -> Void
    private var replayStore: ReplayStore
    private let clock = ContinuousClock()
    /// Includes tasks whose residency row has already been swept. A row is
    /// protocol state; this table is process ownership and is not cleared
    /// until the corresponding task has actually returned.
    private var generationTasks: [GenerationKey: Task<Void, Never>] = [:]
    private var shuttingDown = false
    private var shutdownComplete = false
    private var shutdownWaiters: [CheckedContinuation<Void, Never>] = []

    public init(limits: Limits = Limits()) {
        self.limits = limits
        receiptSink = { receipt in HostLog.info(receipt.message) }
        replayEventSink = { message in HostLog.info(message) }
        generationTaskSettlement = {}
        replayStore = ReplayStore(policy: Self.replayPolicy(
            perGenerationBytes: limits.bufferCapBytes,
            processBytes: nil
        ))
    }

    /// Test/package seam for observing receipts without intercepting stdout.
    /// The sink is deliberately non-throwing: evidence must not become part of
    /// generation control flow.
    package init(
        limits: Limits = Limits(),
        replayProcessCapBytes: Int? = nil,
        receiptSink: @escaping GenerationReceiptSink,
        replayEventSink: @escaping ReplayEventSink = { message in HostLog.info(message) }
    ) {
        self.limits = limits
        self.receiptSink = receiptSink
        self.replayEventSink = replayEventSink
        generationTaskSettlement = {}
        replayStore = ReplayStore(policy: Self.replayPolicy(
            perGenerationBytes: limits.bufferCapBytes,
            processBytes: replayProcessCapBytes
        ))
    }

    /// Deterministic task-settlement seam. Production uses the initializer
    /// above; tests may hold the last task after its stream has terminated to
    /// prove shutdown's join and concurrent-caller behavior.
    package init(
        limits: Limits = Limits(),
        replayProcessCapBytes: Int? = nil,
        receiptSink: @escaping GenerationReceiptSink,
        replayEventSink: @escaping ReplayEventSink,
        generationTaskSettlement: @escaping @Sendable () async -> Void
    ) {
        self.limits = limits
        self.receiptSink = receiptSink
        self.replayEventSink = replayEventSink
        self.generationTaskSettlement = generationTaskSettlement
        replayStore = ReplayStore(policy: Self.replayPolicy(
            perGenerationBytes: limits.bufferCapBytes,
            processBytes: replayProcessCapBytes
        ))
    }

    // MARK: Sessions

    /// Opens a session and returns what proves it.
    ///
    /// This took a `modelID` and stored it, and nothing ever read the field —
    /// not the registry, not `Daemon`, not a test. Both went, rather than
    /// leaving a public function taking an argument it discards, which is the
    /// worse of the two artefacts. A daemon serves one filling, so a session
    /// has no model to disambiguate.
    ///
    /// ⚠️ What that leaves visible: `SessionOpen.modelID` still crosses the
    /// wire but does not authoritatively select or refuse a model, so a client
    /// asking for a model this daemon does not serve is answered by the one it
    /// does, silently. `HelloAck.models` supplies a catalog without defining
    /// which side owns selection. The unread-wire audit graduated that whole
    /// contract to the Held model-selection-authority design item.
    public func openSession(
        version: UInt8 = Wire.baselineVersion
    ) -> (sessionID: UUID, token: String) {
        makeSession(version: version)
    }

    package func openSessionIfAccepting(
        version: UInt8 = Wire.baselineVersion
    ) throws -> (sessionID: UUID, token: String) {
        guard !shuttingDown else { throw RegistryError.shuttingDown }
        return makeSession(version: version)
    }

    private func makeSession(version: UInt8) -> (sessionID: UUID, token: String) {
        let sessionID = UUID()
        let token = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) }).base64EncodedString()
        sessions[sessionID] = SessionRecord(
            tokenHash: SHA256.hash(data: Data(token.utf8)),
            version: version,
            lastSeen: clock.now
        )
        return (sessionID, token)
    }

    public func validate(sessionID: UUID, token: String) throws {
        guard !shuttingDown else { throw RegistryError.shuttingDown }
        guard var record = sessions[sessionID] else { throw RegistryError.unknownSession }
        guard record.tokenHash == SHA256.hash(data: Data(token.utf8)) else { throw RegistryError.badToken }
        record.lastSeen = clock.now
        sessions[sessionID] = record
    }

    /// What became of each generation in a session.
    ///
    /// This used to return the payload of a `SessionResumed` frame. No client
    /// ever sent the `SessionResume` that asked for one, so both frames are
    /// gone and this is registry-local now — it survives because it is the
    /// only way to observe a generation's terminal state from outside, which
    /// is how `aCancelledGenerationReachesATerminalState` caught `cancel`
    /// leaving records `.streaming` forever.
    public struct GenerationStatus: Sendable, Equatable {
        public var genID: UUID
        public var state: WireGenerationState
        /// The seq of the last event, once there is a last event.
        ///
        /// ⚠️ As a wire cursor this was off by one — `ingest` stamps
        /// `Ev(seq: nextSeq)` and *then* increments, so `nextSeq` is one past
        /// the final event and a client re-attaching from it would have got
        /// nothing. Nobody noticed because nobody read it. Kept as-is and
        /// described honestly: it is "how many events there were", not "the
        /// last one's seq", and only tests read it.
        public var eventsIssued: UInt64?
    }

    public func resumeStatus(sessionID: UUID, token: String) throws -> [GenerationStatus] {
        try validate(sessionID: sessionID, token: token)
        return sessions[sessionID]!.generations.map { id, record in
            GenerationStatus(
                genID: id,
                state: record.state,
                eventsIssued: record.state == .streaming ? nil : record.nextSeq
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
    ) throws -> (stream: AsyncStream<Ev>, epoch: UInt64, version: UInt8) {
        guard !shuttingDown else { throw RegistryError.shuttingDown }
        return try begin(
            sessionID: sessionID,
            genID: genID,
            receiptSource: .unknown,
            events: events
        )
    }

    /// Daemon-only form carrying a category derived from the transport's
    /// remote endpoint. It never stores or logs the endpoint itself.
    package func begin(
        sessionID: UUID,
        genID: UUID,
        receiptSource: GenerationReceipt.Source,
        events: @escaping @Sendable () -> AsyncThrowingStream<WireEvent, Error>
    ) throws -> (stream: AsyncStream<Ev>, epoch: UInt64, version: UInt8) {
        guard !shuttingDown else { throw RegistryError.shuttingDown }
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
        receiptSink(.accepted(sessionID: sessionID, genID: genID, source: receiptSource))

        let key = GenerationKey(sessionID: sessionID, generationID: genID)
        let generationTaskSettlement = self.generationTaskSettlement
        let task = Task { [weak self] in
            guard let self else { return }
            _ = await Self.consume(events()) { [weak self] event in
                guard let self else { return .error }
                return await self.ingest(sessionID: sessionID, genID: genID, event: event)
            }
            await generationTaskSettlement()
            await self.generationTaskDidFinish(key)
        }
        sessions[sessionID]!.generations[genID]!.task = task
        generationTasks[key] = task
        return (stream, record.epoch, sessions[sessionID]!.version)
    }

    /// Daemon-only admitted form. The reservation is acquired before the
    /// filling closure is evaluated, so one lease covers every model pass the
    /// filling performs. The resident record and accepted receipt are created
    /// while the work is queued; a full-room refusal creates neither.
    package func begin(
        sessionID: UUID,
        genID: UUID,
        receiptSource: GenerationReceipt.Source,
        admission: SlotAdmission,
        events: @escaping @Sendable () -> AsyncThrowingStream<WireEvent, Error>
    ) async throws -> (stream: AsyncStream<Ev>, epoch: UInt64, version: UInt8) {
        guard !shuttingDown else { throw RegistryError.shuttingDown }
        guard sessions[sessionID] != nil else { throw RegistryError.unknownSession }
        if sessions[sessionID]!.generations[genID] != nil {
            return try attach(sessionID: sessionID, genID: genID, fromSeq: nil)
        }

        let reservation = try await admission.reserve(.init(
            sessionID: sessionID,
            generationID: genID
        ))

        // `await reserve` is an actor-reentrancy point. A retransmitted begin
        // may have won the race using the same idempotent reservation.
        if sessions[sessionID]?.generations[genID] != nil {
            return try attach(sessionID: sessionID, genID: genID, fromSeq: nil)
        }
        guard !shuttingDown, sessions[sessionID] != nil else {
            await admission.abandon(reservation)
            throw shuttingDown ? RegistryError.shuttingDown : RegistryError.unknownSession
        }

        var record = GenerationRecord()
        let (stream, continuation) = AsyncStream<Ev>.makeStream()
        record.live = continuation
        sessions[sessionID]!.generations[genID] = record
        receiptSink(.accepted(sessionID: sessionID, genID: genID, source: receiptSource))

        let key = GenerationKey(sessionID: sessionID, generationID: genID)
        let generationTaskSettlement = self.generationTaskSettlement
        let task = Task { [weak self] in
            guard let self else { return }
            do {
                let lease = try await admission.acquire(reservation)
                if Task.isCancelled {
                    await admission.release(lease, outcome: .cancelled)
                } else {
                    var outcome = SlotAdmission.ReleaseOutcome.error
                    if let ending = await Self.consume(events(), ingest: { [weak self] event in
                        guard let self else { return .error }
                        return await self.ingest(
                            sessionID: sessionID,
                            genID: genID,
                            event: event
                        )
                    }) {
                        outcome = switch ending {
                        case .complete: .complete
                        case .cancelled: .cancelled
                        case .error: .error
                        }
                    }
                    if Task.isCancelled { outcome = .cancelled }
                    await admission.release(lease, outcome: outcome)
                }
            } catch is CancellationError {
                // `cancel` writes the wire terminal synchronously. The
                // acquisition cancellation only removes a queued reservation.
            } catch let error as SlotAdmission.AdmissionError {
                _ = await self.ingest(
                    sessionID: sessionID,
                    genID: genID,
                    event: .finished(.error(error.description))
                )
            } catch {
                _ = await self.ingest(
                    sessionID: sessionID,
                    genID: genID,
                    event: .finished(.error("\(error)"))
                )
            }
            await generationTaskSettlement()
            await self.generationTaskDidFinish(key)
        }
        sessions[sessionID]!.generations[genID]!.task = task
        generationTasks[key] = task
        return (stream, record.epoch, sessions[sessionID]!.version)
    }

    /// Re-attach a live or buffered generation, replaying from `fromSeq`
    /// (exclusive); nil replays everything still buffered.
    ///
    /// Throws `replayOutgrewTheBuffer` rather than serving a replay that
    /// begins inside a span the cap dropped — see the guard below.
    public func attach(
        sessionID: UUID,
        genID: UUID,
        fromSeq: UInt64?
    ) throws -> (stream: AsyncStream<Ev>, epoch: UInt64, version: UInt8) {
        guard !shuttingDown else { throw RegistryError.shuttingDown }
        guard var session = sessions[sessionID] else { throw RegistryError.unknownSession }
        guard var record = session.generations[genID] else { throw RegistryError.unknownGeneration }
        // Decode and validate the exact stored frames before touching the
        // attachment epoch. A refusal must leave the serving connection's
        // epoch intact so its later detach can still start residency.
        let replay: [Ev]
        do {
            replay = try replayStore.replay(
                for: Self.replayKey(sessionID: sessionID, genID: genID),
                after: fromSeq
            )
        } catch {
            throw RegistryError.replayOutgrewTheBuffer
        }

        record.epoch += 1
        record.live?.finish()
        let (stream, continuation) = AsyncStream<Ev>.makeStream()
        for buffered in replay {
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
        return (stream, record.epoch, session.version)
    }

    /// Cumulative ack: trim the buffer at and below `seq`.
    public func ack(sessionID: UUID, genID: UUID, seq: UInt64, epoch: UInt64) {
        guard let session = sessions[sessionID],
              let record = session.generations[genID],
              record.epoch == epoch else { return }
        replayStore.acknowledge(
            for: Self.replayKey(sessionID: sessionID, genID: genID),
            through: seq
        )
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
        HostLog.lifecycle("generation detached session=\(sessionID) generation=\(genID) epoch=\(epoch)")
    }

    public func cancel(sessionID: UUID, genID: UUID, epoch: UInt64) {
        guard let session = sessions[sessionID],
              let record = session.generations[genID],
              record.epoch == epoch else { return }
        record.task?.cancel()
        // Cancelling the task is not an ending. Its `for await` stops
        // iterating the instant it is cancelled, so the filling's own
        // `.finished` is yielded into a loop that has already stopped
        // reading — nothing ingests it, the record stays `.streaming` for
        // the life of the process, and `resumeStatus` reports a generation
        // that was deliberately stopped as one still running. `wire.md` said
        // "the generation finishes `.cancelled` rather than vanishing"; it
        // did neither. The ending has to be written here, where the decision
        // is actually made.
        _ = ingest(sessionID: sessionID, genID: genID, event: .finished(.cancelled))
    }

    /// Daemon-only cancellation for generations governed by provider
    /// admission. A queued reservation is removed synchronously at the
    /// admission actor before the wire terminal becomes observable. The
    /// public residency-only cancellation surface remains unchanged.
    package func cancel(
        sessionID: UUID,
        genID: UUID,
        epoch: UInt64,
        admission: SlotAdmission
    ) async {
        guard let session = sessions[sessionID],
              let record = session.generations[genID],
              record.epoch == epoch,
              record.state == .streaming
        else { return }

        let queuedCancellationCommitted = await admission.cancelQueued(.init(
            sessionID: sessionID,
            generationID: genID
        ))

        // The await above permits actor re-entry. Revalidate before ending
        // an active generation so a stale connection cannot overwrite a newer
        // attachment. A removed queued reservation is different: cancellation
        // is already irreversible and its acquisition task can no longer
        // finish the generation, so an intervening reattach inherits that
        // committed cancellation rather than orphaning a streaming record.
        guard let refreshedSession = sessions[sessionID],
              let refreshed = refreshedSession.generations[genID],
              refreshed.state == .streaming,
              queuedCancellationCommitted || refreshed.epoch == epoch
        else { return }
        refreshed.task?.cancel()
        _ = ingest(sessionID: sessionID, genID: genID, event: .finished(.cancelled))
    }

    /// Expiry sweep; call periodically. Returns how many generations were
    /// reaped (for tests and logs).
    @discardableResult
    public func sweep() -> Int {
        guard !shuttingDown else { return 0 }
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
                    let age = record.detachedAt.map { now - $0 } ?? .zero
                    let parts = age.components
                    HostLog.lifecycle(
                        "generation expired session=\(sessionID) generation=\(genID) " +
                        "state=\(record.state.rawValue) detached_age_seconds=\(parts.seconds) " +
                        "detached_age_attoseconds=\(parts.attoseconds)"
                    )
                    session.generations.removeValue(forKey: genID)
                    replayStore.remove(Self.replayKey(sessionID: sessionID, genID: genID))
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
    package var residentSessions: Int { sessions.count }

    /// Privacy-safe operator copy: policy only, never live usage.
    package var replayStartupMessage: String {
        let expected = Int(FrameCodec.maxFrameLength) + 4
        if replayStore.policy.perGenerationBytes == expected,
           replayStore.policy.processBytes == expected * 4 {
            return "replay store ready: exact framed bytes, one maximum-frame window per generation, four-window process budget, volatile across daemon restart"
        }
        return "replay store ready: exact framed bytes with configured per-generation and process budgets, volatile across daemon restart"
    }

    package var replayCounters: ReplayStore.Counters { replayStore.counters }

    package var activeGenerationTasks: Int { generationTasks.count }

    /// Process shutdown owns the final cleanup edge. No terminal is invented:
    /// clients already name daemon restart separately from a wire completion.
    package func shutdown() async {
        if shuttingDown {
            if shutdownComplete { return }
            await withCheckedContinuation { shutdownWaiters.append($0) }
            return
        }
        shuttingDown = true
        for session in sessions.values {
            for record in session.generations.values {
                record.task?.cancel()
                record.live?.finish()
            }
        }
        let tasks = Array(generationTasks.values)
        tasks.forEach { $0.cancel() }
        sessions.removeAll(keepingCapacity: false)
        replayStore.removeAll()
        for task in tasks { await task.value }
        generationTasks.removeAll(keepingCapacity: false)

        shutdownComplete = true
        let resumed = shutdownWaiters
        shutdownWaiters.removeAll()
        resumed.forEach { $0.resume() }
    }

    // MARK: Internals

    /// Stamps and publishes one filling event. The returned ending is derived
    /// from the event actually put on the wire, including a synthesized error
    /// terminal when the original event could not be encoded.
    private func ingest(
        sessionID: UUID,
        genID: UUID,
        event: WireEvent
    ) -> GenerationReceipt.Ending? {
        guard var session = sessions[sessionID],
              var record = session.generations[genID] else { return .error }
        // Nothing follows the ending. `cancel` writes a `.finished` while the
        // filling may still have one of its own in flight, and two endings on
        // one generation would hand a re-attaching client two different final
        // sequences for the same answer.
        guard record.state == .streaming else {
            return switch record.state {
            case .streaming: nil
            case .complete: .complete
            case .cancelled: .cancelled
            case .failed: .error
            }
        }

        let key = Self.replayKey(sessionID: sessionID, genID: genID)
        var stamped = Ev(seq: record.nextSeq, event: event)
        let append: ReplayStore.AppendResult
        do {
            append = try replayStore.append(stamped, for: key)
        } catch let error as WireError {
            // A peer would reject an over-limit envelope before it could read
            // the event. Replace it at the same sequence with a small terminal
            // so the stream ends legibly instead of becoming malformed.
            replayEventSink("generation event exceeded the wire frame limit; ending generation")
            let copy = switch error {
            case .frameTooLarge:
                "the cluster produced a generation event larger than the wire's 16 MiB frame limit"
            default:
                "the cluster could not encode one generation event for the wire"
            }
            stamped = Ev(seq: record.nextSeq, event: .finished(.error(copy)))
            do {
                append = try replayStore.append(stamped, for: key)
            } catch {
                replayStore.recordLiveOnly(sequence: stamped.seq, for: key)
                append = .init(stored: false, newlyExhausted: [])
            }
        } catch {
            replayEventSink("generation event could not be encoded; ending generation")
            stamped = Ev(
                seq: record.nextSeq,
                event: .finished(.error("the cluster could not encode one generation event for the wire"))
            )
            do {
                append = try replayStore.append(stamped, for: key)
            } catch {
                replayStore.recordLiveOnly(sequence: stamped.seq, for: key)
                append = .init(stored: false, newlyExhausted: [])
            }
        }
        record.nextSeq += 1
        for exhaustion in append.newlyExhausted {
            switch exhaustion {
            case .perGeneration:
                replayEventSink("replay capacity exhausted for one generation; live delivery continues and future replay may refuse")
            case .processWide:
                replayEventSink("replay process budget unavailable to the appending generation; live delivery continues and future replay may refuse")
            }
        }
        let live = record.live
        var receiptEnding: GenerationReceipt.Ending?
        if case .finished(let reason) = stamped.event {
            record.state = switch reason {
            case .complete: .complete
            case .cancelled: .cancelled
            case .error: .failed
            }
            receiptEnding = switch reason {
            case .complete: .complete
            case .cancelled: .cancelled
            case .error: .error
            }
            record.live = nil
            record.detachedAt = clock.now
        }
        session.generations[genID] = record
        sessions[sessionID] = session
        if let receiptEnding {
            receiptSink(.terminal(
                sessionID: sessionID,
                genID: genID,
                finalSequence: stamped.seq,
                ending: receiptEnding
            ))
        }
        // A client may resume immediately when `yield` wakes it. Publish the
        // state and its privacy-safe receipt first so a visible terminal event
        // can never outrun the daemon evidence that names the same sequence.
        live?.yield(stamped)
        if receiptEnding != nil {
            live?.finish()
        }
        return receiptEnding
    }

    private static func replayKey(sessionID: UUID, genID: UUID) -> ReplayStore.Key {
        ReplayStore.Key(sessionID: sessionID, generationID: genID)
    }

    private static func replayPolicy(
        perGenerationBytes: Int,
        processBytes configuredProcessBytes: Int?
    ) -> ReplayStore.Policy {
        let processBytes: Int
        if let configured = configuredProcessBytes {
            processBytes = configured
        } else {
            let (fourWindows, overflow) = perGenerationBytes.multipliedReportingOverflow(by: 4)
            processBytes = overflow ? Int.max : fourWindows
        }
        return ReplayStore.Policy(
            perGenerationBytes: perGenerationBytes,
            processBytes: processBytes
        )
    }

    private func generationTaskDidFinish(_ key: GenerationKey) {
        generationTasks.removeValue(forKey: key)
    }

    /// Consumes the filling directly in the one registry-owned task. This
    /// keeps shutdown's task table exhaustive while preserving the historical
    /// synthesized terminal for a throwing or prematurely ending filling.
    private static func consume(
        _ events: AsyncThrowingStream<WireEvent, Error>,
        ingest: @escaping @Sendable (WireEvent) async -> GenerationReceipt.Ending?
    ) async -> GenerationReceipt.Ending? {
        do {
            for try await event in events {
                if Task.isCancelled { return nil }
                if let ending = await ingest(event) { return ending }
            }
        } catch {
            guard !Task.isCancelled else { return nil }
            return await ingest(.finished(.error("\(error)")))
        }
        guard !Task.isCancelled else { return nil }
        return await ingest(.finished(.complete))
    }
}
