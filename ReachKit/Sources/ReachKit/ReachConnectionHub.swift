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
        }
    }

    public var errorDescription: String? { description }
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
    }

    private struct Entry {
        var dialer: QUICDialer
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
        /// Whether this entry started from roads a previous process wrote
        /// down. Only the refusal reads it, and only to tell "never been
        /// answered" apart from "knows the roads and none of them worked".
        var knewStoredRoads = false
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
        for key in entries.keys { entries[key]?.dirty = true }
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
        if let session = entries[configuration]?.session {
            return session
        }
        let control = try await openStream(for: configuration)
        defer { control.cancel() }
        var frames = control.frames.makeAsyncIterator()
        try await control.send(Hello(client: "ReachKit/\(Wire.version)"))
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
        noteCandidates(from: ack, for: configuration)
        try await control.send(SessionOpen(modelID: configuration.modelID))
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
        let opened = try openedRaw.decode(SessionOpened.self)
        let handle = SessionHandle(sessionID: opened.sessionID, token: opened.token, capabilities: opened.capabilities)
        entries[configuration]?.session = handle
        return handle
    }

    public func openGenerationStream(for configuration: ReachExecutor.Configuration) async throws -> ReachTransport.QUICStream {
        try await openStream(for: configuration)
    }

    /// Drops the session (not the material) — the next use opens fresh.
    public func invalidateSession(for configuration: ReachExecutor.Configuration) {
        entries[configuration]?.session = nil
    }

    private func noteCandidates(from ack: HelloAck, for configuration: ReachExecutor.Configuration) {
        guard let addrs = ack.addrs, let port = ack.port,
              let nwPort = NWEndpoint.Port(rawValue: port) else { return }
        entries[configuration]?.candidates = endpoints(from: addrs, port: nwPort, for: configuration)
        // Writing them down is what lets the next cold launch dial at all —
        // this is the one moment the app is certainly being answered, so it is
        // the only moment the roads are certainly true. Failing to write them
        // is not a reason to fail a session that is working, and ReachKit has
        // no channel to say so on; a store that will not write surfaces later
        // as an app that cannot start away.
        try? ClusterRoads.save(addrs: addrs, port: port, for: configuration.identityLabel)
    }

    /// The declared addresses as endpoints, minus whatever is already the
    /// primary — the same conversion whether they arrived in a `HelloAck` or
    /// came back out of the store.
    private func endpoints(
        from addrs: [String],
        port: NWEndpoint.Port,
        for configuration: ReachExecutor.Configuration
    ) -> [NWEndpoint] {
        var seen: Set<NWEndpoint> = [primaryEndpoint(for: configuration)]
        var candidates: [NWEndpoint] = []
        for addr in addrs {
            let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(addr), port: port)
            if seen.insert(endpoint).inserted {
                candidates.append(endpoint)
            }
        }
        return candidates
    }

    private func openStream(for configuration: ReachExecutor.Configuration) async throws -> ReachTransport.QUICStream {
        let entry = try await ensureEntry(for: configuration)
        if entry.proven && !entry.dirty {
            do {
                return try await entry.dialer.openStream(timeout: configuration.connectTimeout)
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
    private func racedStream(for configuration: ReachExecutor.Configuration) async throws -> ReachTransport.QUICStream {
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
            throw ReachError.transport("no reachable cluster address (\(endpoints.count) dialed)")
        }
        entries[configuration]?.dialer = dialers[index]
        entries[configuration]?.dirty = false
        // The only place a dial is ever proven: it opened a stream.
        entries[configuration]?.proven = true
        return stream
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
        // A store that will not read back is treated as a store that holds
        // nothing: there is nothing dialable either way, and claiming the
        // refusal tried "the addresses it last answered on" would then be
        // false.
        if let roads = try? ClusterRoads.load(for: configuration.identityLabel),
           let nwPort = NWEndpoint.Port(rawValue: roads.port) {
            let stored = endpoints(from: roads.addrs, port: nwPort, for: configuration)
            if !stored.isEmpty {
                entry.candidates = stored
                entry.knewStoredRoads = true
            }
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
