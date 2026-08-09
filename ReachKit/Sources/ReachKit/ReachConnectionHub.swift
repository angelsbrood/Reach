import Foundation
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Security

public enum ReachError: Error, Sendable, CustomStringConvertible, LocalizedError {
    case identityNotRegistered(String)
    case sessionRejected(String)
    case remote(code: String, message: String)
    case transport(String)
    /// Every road dialed and none of them led anywhere. `stored` is what the
    /// calling card an earlier session left had to say, and it is what makes
    /// the sentence actionable: an app that has never been answered needs the
    /// cluster's own network once, and an app that knows the roads and cannot
    /// use them needs its tunnel up. Those are different next actions and the
    /// coarse prefix could tell neither.
    case unreachable(roads: Int, stored: StoredRoads)
    /// An answer that had already begun arriving cannot be picked up again.
    ///
    /// Separate from `.remote` because a re-attach is only ever sent for a
    /// generation this call has already taken tokens from, so a refusal to
    /// one is not the cluster declining a request — it is the cluster no
    /// longer holding what was mid-flight. Rendered as "the cluster refused
    /// this (reattach-rejected)" it described the wrong event to the only
    /// person who would read it, and left out the one thing they can act on.
    /// The cluster's own reason travels through unaltered; what is added is
    /// what it means and what to do about it.
    case generationLost(String)

    public var description: String {
        switch self {
        case .identityNotRegistered(let label):
            "no identity is registered under \"\(label)\" — this app has not been granted access to the cluster yet"
        case .sessionRejected(let detail):
            "the cluster refused to open a session: \(detail)"
        case .remote(let code, let message):
            // The daemon's own words, and they are the useful half — a
            // reason that travelled the wire beats a reason invented here.
            "the cluster refused this (\(code)): \(message)"
        case .transport(let detail):
            "could not reach the cluster: \(detail)"
        case .generationLost(let reason):
            "the answer stopped partway and cannot be picked up again: \(reason). Asking again starts a new one."
        case .unreachable(let roads, let stored):
            switch stored {
            case .known:
                "no road reached the cluster — nothing answered on \(Self.roads(roads)), and those are the addresses it last answered on. The cluster may be off, or this device may need its mesh tunnel up."
            case .none:
                "no road reached the cluster — nothing answered on \(Self.roads(roads)), and this app has not been answered before, so it knows no way there but the one it was configured with. Open it once on the cluster's own network and it will keep the way back."
            case .unreadable:
                "no road reached the cluster — nothing answered on \(Self.roads(roads)). This app has been answered before, but the roads it wrote down will not read back: the keychain holding them is locked or the entry is damaged. Opening it on the cluster's own network again will not help until that is sorted, because that is where the next set would be written too."
            }
        }
    }

    private static func roads(_ count: Int) -> String {
        count == 1 ? "the one road it knows" : "any of the \(count) roads it knows"
    }

    public var errorDescription: String? { description }
}

/// What the app's road store had to say — three answers, not two.
///
/// `ClusterRoads.load` goes to deliberate trouble to tell *absent* from
/// *unreadable*, for the reason its own note gives; the hub then collapsed
/// them with a `try?` and a `Bool`. The dialing was right to collapse them —
/// there is nothing dialable either way — but the refusal is not. Read as
/// `none`, an unreadable store makes the app say "has not been answered
/// before" and tell the person to open it once on the cluster's network. Both
/// halves are false, and the instruction loops: the next set of roads would
/// be written to the same store that will not read back.
public enum StoredRoads: Sendable, Equatable {
    /// Nothing has ever been written down for this app.
    case none
    /// Roads read back, or the cluster has answered this process.
    case known
    /// Something is stored and will not read back — a locked keychain, or an
    /// entry that no longer decodes.
    case unreadable
}

/// One hub per executor configuration: the shared `NWParameters` (one QUIC
/// tunnel), the daemon session, and stream opening. Sessions outlive
/// connections — the (sessionID, token) pair survives transport death and
/// re-attaches generations across path changes.
///
/// The hub also owns the away machinery. The daemon's `HelloAck` declares
/// every address it answers on — the mesh address included — and once the
/// dialed path dies or the device's network path changes, stream opening
/// races every candidate and keeps whichever connects first. A session that
/// began over LAN discovery falls to the mesh without the app ever having
/// been configured with either address.
public actor ReachConnectionHub {
    public static let shared = ReachConnectionHub()

    public struct SessionHandle: Sendable {
        public let sessionID: UUID
        public let token: String
        public let capabilities: [String]
        public let version: UInt8
    }

    struct GenerationStreamLease: Sendable {
        let stream: ReachTransport.QUICStream
        let roadEpoch: UInt64
        fileprivate let probe: ActiveRoadProbe
    }

    private struct RoadStream: Sendable {
        let stream: ReachTransport.QUICStream
        let roadEpoch: UInt64
        let probe: ActiveRoadProbe
    }

    private struct Entry {
        var dialer: QUICDialer
        var roadEpoch: UInt64 = 0
        var probe: ActiveRoadProbe?
        var reservedGenerationLeases = 0
        var session: SessionHandle?
        /// Redial candidates the daemon declared in its HelloAck.
        var candidates: [NWEndpoint] = []
        /// Set when the path changed or an open failed — the next open
        /// races candidates instead of trusting the cached dialer.
        var dirty = false
        /// False until a dial through this entry has actually opened a
        /// stream. A fresh entry's `dialer` is the configured primary and
        /// nothing more — trying it alone first is not a fast path, it is the
        /// race's first endpoint run alone for the whole connect timeout. Off
        /// the LAN with a name that will never resolve, that is the connect
        /// timeout spent twice: once alone, once again inside the race.
        ///
        /// Not folded into `dirty`, whose meaning above is "the path changed
        /// or an open failed". A fresh entry is neither of those things.
        var proven = false
        /// What the store said when this entry was seeded. Only the refusal
        /// reads it, and only to tell "never been answered" apart from "knows
        /// the roads and none of them worked" apart from "wrote roads down and
        /// cannot read them back".
        var storedRoads: StoredRoads = .none
    }

    private var entries: [ReachExecutor.Configuration: Entry] = [:]

    // MARK: - Path changes

    private var pathMonitor: NWPathMonitor?
    private var sawFirstPath = false
    private var pathEpoch: UInt64 = 0
    private var pathWaiters: [UUID: CheckedContinuation<Void, Never>] = [:]

    public func currentPathEpoch() -> UInt64 { pathEpoch }

    /// Suspends until the network path changes past the given epoch.
    /// Executors race this against a live stream so a path change surfaces
    /// immediately instead of at the QUIC idle timeout.
    public func pathChanged(after epoch: UInt64) async {
        guard pathEpoch <= epoch else { return }
        let id = UUID()
        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                if pathEpoch > epoch {
                    continuation.resume()
                } else {
                    pathWaiters[id] = continuation
                }
            }
        } onCancel: {
            Task { await self.dropPathWaiter(id) }
        }
    }

    /// What a real interface change does — public so an app that knows its
    /// environment moved (a scene returning to foreground, a user toggling
    /// networks) can prod the hub instead of waiting for the monitor.
    public func notePathPossiblyChanged() {
        pathEpoch += 1
        for key in entries.keys {
            entries[key]?.dirty = true
            entries[key]?.reservedGenerationLeases = 0
            if let probe = entries[key]?.probe {
                Task { await probe.invalidate() }
            }
        }
        let waiters = pathWaiters
        pathWaiters.removeAll()
        for (_, continuation) in waiters { continuation.resume() }
    }

    private func dropPathWaiter(_ id: UUID) {
        pathWaiters.removeValue(forKey: id)?.resume()
    }

    private func startPathMonitorIfNeeded() {
        guard pathMonitor == nil else { return }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] _ in
            guard let self else { return }
            Task { await self.notePathUpdate() }
        }
        monitor.start(queue: DispatchQueue(label: "reach.pathmonitor"))
        pathMonitor = monitor
    }

    private func notePathUpdate() {
        // The monitor reports the current path immediately on start; only
        // what comes after that is a change.
        guard sawFirstPath else {
            sawFirstPath = true
            return
        }
        notePathPossiblyChanged()
    }

    // MARK: - Sessions and streams

    /// The daemon session for a configuration, opening the tunnel and the
    /// control exchange on first use.
    public func session(for configuration: ReachExecutor.Configuration) async throws -> SessionHandle {
        try await openSession(for: configuration, retainingProbeForGeneration: false)
    }

    func generationSession(for configuration: ReachExecutor.Configuration) async throws -> SessionHandle {
        try await openSession(for: configuration, retainingProbeForGeneration: true)
    }

    private func openSession(
        for configuration: ReachExecutor.Configuration,
        retainingProbeForGeneration: Bool
    ) async throws -> SessionHandle {
        if let session = entries[configuration]?.session {
            return session
        }
        let road = try await openRoadStream(for: configuration)
        let control = road.stream
        var retainedControl = false
        defer { if !retainedControl { control.cancel() } }
        var frames = control.frames.makeAsyncIterator()
        let offeredVersions = Wire.supportedVersions
        try await control.send(Hello(versions: offeredVersions, client: "ReachKit/\(Wire.version)"))
        // `.closed` reached the old `else`; `.broke` did not, and left as
        // `TransportError.connectionFailed` — "could not open a connection to
        // the cluster" for a tunnel that had already opened, which is the
        // false sentence this shape exists to stop producing.
        let acked = await FrameEnding.next(from: &frames)
        guard case .frame(let ackRaw) = acked else {
            throw ReachError.transport(acked.detailing("the cluster's hello ack never came"))
        }
        if ackRaw.type == .errorFrame {
            let error = try ackRaw.decode(ErrorFrame.self)
            throw ReachError.sessionRejected("\(error.code): \(error.message)")
        }
        let ack = try ackRaw.decode(HelloAck.self)
        guard offeredVersions.contains(ack.version) else {
            throw ReachError.sessionRejected(
                "wire-version: \(Wire.mismatchMessage(app: offeredVersions, cluster: [ack.version]))"
            )
        }
        noteCandidates(from: ack, for: configuration)
        try await control.send(SessionOpen(modelID: configuration.modelID), for: ack.version)
        let answered = await FrameEnding.next(from: &frames)
        guard case .frame(let openedRaw) = answered else {
            throw ReachError.transport(answered.detailing(
                "the cluster never answered the session request for \(configuration.modelID)"
            ))
        }
        if openedRaw.type == .errorFrame {
            let error = try openedRaw.decode(ErrorFrame.self)
            throw ReachError.sessionRejected("\(error.code): \(error.message)")
        }
        try openedRaw.requireSupported(by: ack.version)
        let opened = try openedRaw.decode(SessionOpened.self)
        let handle = SessionHandle(
            sessionID: opened.sessionID,
            token: opened.token,
            capabilities: opened.capabilities,
            version: ack.version
        )
        entries[configuration]?.session = handle
        if retainingProbeForGeneration {
            await road.probe.adopt(control: control, version: ack.version)
            if entries[configuration]?.roadEpoch == road.roadEpoch,
               entries[configuration]?.probe === road.probe {
                await road.probe.acquireGenerationLease()
                entries[configuration]?.reservedGenerationLeases += 1
                retainedControl = true
            } else {
                await road.probe.invalidate()
            }
        }
        return handle
    }

    func openGenerationStream(for configuration: ReachExecutor.Configuration) async throws -> GenerationStreamLease {
        let road = try await openRoadStream(for: configuration)
        if entries[configuration]?.roadEpoch == road.roadEpoch,
           entries[configuration]?.probe === road.probe,
           (entries[configuration]?.reservedGenerationLeases ?? 0) > 0 {
            entries[configuration]?.reservedGenerationLeases -= 1
        } else {
            await road.probe.acquireGenerationLease()
        }
        return GenerationStreamLease(
            stream: road.stream,
            roadEpoch: road.roadEpoch,
            probe: road.probe
        )
    }

    func releaseGenerationStream(_ lease: GenerationStreamLease) async {
        await lease.probe.releaseGenerationLease()
    }

    func activeRoadIsAlive(
        _ lease: GenerationStreamLease,
        for configuration: ReachExecutor.Configuration,
        timeout: Duration
    ) async -> Bool {
        let result = await lease.probe.check(timeout: timeout)
        if result.alive,
           let ack = result.refreshedHello,
           Self.isCurrentRoad(
               leaseEpoch: lease.roadEpoch,
               activeEpoch: entries[configuration]?.roadEpoch,
               sameProbe: entries[configuration]?.probe === lease.probe
           ) {
            noteCandidates(from: ack, for: configuration)
        }
        return result.alive
    }

    /// Marks only the road that was actually probed. A late failure from a
    /// lease on an older road can end that generation stream, but it can never
    /// dirty the newer winner now cached by the hub.
    func markRoadUnresponsive(
        _ lease: GenerationStreamLease,
        for configuration: ReachExecutor.Configuration
    ) async {
        guard Self.isCurrentRoad(
            leaseEpoch: lease.roadEpoch,
            activeEpoch: entries[configuration]?.roadEpoch,
            sameProbe: entries[configuration]?.probe === lease.probe
        ) else { return }
        entries[configuration]?.dirty = true
        entries[configuration]?.reservedGenerationLeases = 0
        await lease.probe.invalidate()
    }

    nonisolated static func isCurrentRoad(
        leaseEpoch: UInt64,
        activeEpoch: UInt64?,
        sameProbe: Bool
    ) -> Bool {
        activeEpoch == leaseEpoch && sameProbe
    }

    /// Drops the session (not the material) — the next use opens fresh.
    public func invalidateSession(for configuration: ReachExecutor.Configuration) {
        entries[configuration]?.session = nil
    }

    private func noteCandidates(from ack: HelloAck, for configuration: ReachExecutor.Configuration) {
        let roads: [RoadEndpoint]
        if let declared = ack.roads {
            roads = declared
        } else if let addrs = ack.addrs, let port = ack.port {
            roads = addrs.map { RoadEndpoint(host: $0, port: port) }
        } else {
            return
        }
        entries[configuration]?.candidates = endpoints(from: roads, for: configuration)
        // Being answered is exactly what `storedRoads` is asking about, and it
        // was only ever set when an entry was seeded from disk. So an app that
        // had just been answered — that had streamed tokens — was still told,
        // when its cluster later went away, that it "has not been answered
        // before" and should go and open it once on the cluster's own network.
        // False, and it points at the wrong next action. A restart mid-answer
        // is how that sentence gets read most. This also correctly overrides
        // `.unreadable`: whatever the store can or cannot do, being answered
        // is the stronger fact about the roads now in hand.
        entries[configuration]?.storedRoads = .known
        // Writing them down is what lets the next cold launch dial at all —
        // this is the one moment the app is certainly being answered, so it is
        // the only moment the roads are certainly true. Failing to write them
        // is not a reason to fail a session that is working, and ReachKit has
        // no channel to say so on; a store that will not write surfaces later
        // as an app that cannot start away.
        try? ClusterRoads.save(
            endpoints: roads.map { .init(host: $0.host, port: $0.port) },
            for: configuration.identityLabel
        )
    }

    /// The declared addresses as endpoints, minus whatever is already the
    /// primary — the same conversion whether they arrived in a `HelloAck` or
    /// came back out of the store.
    private func endpoints(from roads: [RoadEndpoint], for configuration: ReachExecutor.Configuration) -> [NWEndpoint] {
        var seen: Set<NWEndpoint> = [primaryEndpoint(for: configuration)]
        var candidates: [NWEndpoint] = []
        for road in roads {
            guard let port = NWEndpoint.Port(rawValue: road.port) else { continue }
            let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(road.host), port: port)
            if seen.insert(endpoint).inserted {
                candidates.append(endpoint)
            }
        }
        return candidates
    }

    private func openRoadStream(for configuration: ReachExecutor.Configuration) async throws -> RoadStream {
        let entry = try await ensureEntry(for: configuration)
        if entry.proven && !entry.dirty {
            do {
                let stream = try await entry.dialer.openStream(timeout: configuration.connectTimeout)
                let probe: ActiveRoadProbe
                if let existing = entries[configuration]?.probe {
                    probe = existing
                } else {
                    probe = ActiveRoadProbe(dialer: entry.dialer)
                    entries[configuration]?.probe = probe
                }
                return RoadStream(stream: stream, roadEpoch: entry.roadEpoch, probe: probe)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                // The cached path just failed — fall through to the race.
            }
        }
        return try await racedStream(for: configuration)
    }

    /// Dials every known address at once and keeps the first stream that
    /// opens; its dialer becomes the cached one. Losers are cancelled (the
    /// transport tears a cancelled open down promptly), and a second late
    /// success is surplus — one tunnel is the contract.
    private func racedStream(for configuration: ReachExecutor.Configuration) async throws -> RoadStream {
        guard let material = await ReachIdentityRegistry.shared.material(for: configuration.identityLabel) else {
            throw ReachError.identityNotRegistered(configuration.identityLabel)
        }
        var endpoints = [primaryEndpoint(for: configuration)]
        for candidate in entries[configuration]?.candidates ?? [] where !endpoints.contains(candidate) {
            endpoints.append(candidate)
        }
        let dialers = endpoints.map { endpoint in
            let options = TLSBuilder.clientOptions(
                alpn: Wire.alpn,
                identity: material.identity,
                serverTrustRoots: [material.caCertificate]
            )
            let parameters = NWParameters.reachQUIC(options: options, handover: configuration.multipathHandover)
            return QUICDialer(endpoint: endpoint, parameters: parameters)
        }
        let timeout = configuration.connectTimeout
        let winner: (Int, ReachTransport.QUICStream)? = await withTaskGroup(
            of: (Int, ReachTransport.QUICStream)?.self
        ) { group in
            for (index, dialer) in dialers.enumerated() {
                group.addTask {
                    guard let stream = try? await dialer.openStream(timeout: timeout) else { return nil }
                    return (index, stream)
                }
            }
            var won: (Int, ReachTransport.QUICStream)?
            while let result = await group.next() {
                if let (index, stream) = result {
                    if won == nil {
                        won = (index, stream)
                        group.cancelAll()
                    } else {
                        stream.cancel()
                    }
                }
            }
            return won
        }
        guard let (index, stream) = winner else {
            entries[configuration]?.dirty = true
            throw ReachError.unreachable(
                roads: endpoints.count,
                stored: entries[configuration]?.storedRoads ?? .none
            )
        }
        if let previous = entries[configuration]?.probe {
            await previous.invalidate()
        }
        let epoch = (entries[configuration]?.roadEpoch ?? 0) &+ 1
        let probe = ActiveRoadProbe(dialer: dialers[index])
        entries[configuration]?.dialer = dialers[index]
        entries[configuration]?.roadEpoch = epoch
        entries[configuration]?.probe = probe
        entries[configuration]?.reservedGenerationLeases = 0
        entries[configuration]?.dirty = false
        // The only place a dial is ever proven: it opened a stream.
        entries[configuration]?.proven = true
        return RoadStream(stream: stream, roadEpoch: epoch, probe: probe)
    }

    private func ensureEntry(for configuration: ReachExecutor.Configuration) async throws -> Entry {
        if let entry = entries[configuration] { return entry }
        guard let material = await ReachIdentityRegistry.shared.material(for: configuration.identityLabel) else {
            throw ReachError.identityNotRegistered(configuration.identityLabel)
        }
        startPathMonitorIfNeeded()
        let options = TLSBuilder.clientOptions(
            alpn: Wire.alpn,
            identity: material.identity,
            serverTrustRoots: [material.caCertificate]
        )
        let parameters = NWParameters.reachQUIC(options: options, handover: configuration.multipathHandover)
        let dialer = QUICDialer(endpoint: primaryEndpoint(for: configuration), parameters: parameters)
        var entry = Entry(dialer: dialer, session: nil)
        // A fresh entry is a cold start: nothing in this process has been
        // answered yet, so the only roads it knows are the ones an earlier
        // process wrote down. Because the entry is not yet `proven`, the very
        // first dial goes through the race — these join the primary in it,
        // which is what makes a session born away possible. On the LAN the
        // LAN wins that race on latency without being told to; away, the mesh
        // does.
        //
        // A store that will not read back yields nothing dialable, exactly as
        // an empty one does — so the candidate set is the same either way, and
        // claiming the refusal tried "the addresses it last answered on" would
        // be false. But the two are not the same thing to *say*, and reading
        // the second as the first is what made the app tell a person to go and
        // pair it again over a keychain it cannot open. The dial collapses
        // them; the sentence must not.
        do {
            if let roads = try ClusterRoads.load(for: configuration.identityLabel) {
                let stored = endpoints(
                    from: roads.endpoints.map { RoadEndpoint(host: $0.host, port: $0.port) },
                    for: configuration
                )
                if !stored.isEmpty {
                    entry.candidates = stored
                    entry.storedRoads = .known
                }
            }
        } catch {
            entry.storedRoads = .unreadable
        }
        entries[configuration] = entry
        return entry
    }

    private func primaryEndpoint(for configuration: ReachExecutor.Configuration) -> NWEndpoint {
        if let serviceName = configuration.serviceName {
            .service(name: serviceName, type: Wire.bonjourService, domain: "local.", interface: nil)
        } else {
            .hostPort(
                host: NWEndpoint.Host(configuration.host),
                port: NWEndpoint.Port(rawValue: configuration.port)!
            )
        }
    }
}
