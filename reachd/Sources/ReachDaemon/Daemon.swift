import Crypto
import Foundation
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Security

public enum DaemonInfo {
    public static let version = "0.0.1"
    public static let wireVersion = Wire.version
    public static let stateEnvironmentKey = "REACH_STATE_DIR"

    /// The one state root a persistent login-owned service may name.
    ///
    /// This deliberately ignores the runtime environment. A command-scoped
    /// override remains useful for foreground and scratch work, but allowing
    /// it to enter the LaunchAgent plist would permanently attach the service
    /// to a different cluster.
    package static var canonicalLoginStateDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Reach", isDirectory: true)
    }

    /// Runtime state root; never inside the repository. `REACH_STATE_DIR`
    /// overrides it for foreground commands and controlled scratch/system
    /// work. It is not a persistent service-relocation mechanism.
    ///
    /// It is not how tests reach throwaway state — they pass a path through
    /// `HostCheck.examine(stateDirectory:)`, `DaemonConfig`'s
    /// `in:`/`from:`/`to:`, and `reachd doctor --state`. The generated
    /// LaunchAgent sets this variable from `canonicalLoginStateDirectory`,
    /// making the service's identity explicit without inheriting a shell's
    /// override. Root serve is accepted only when this variable names an
    /// explicit path.
    public static var stateDirectory: URL {
        if let override = ProcessInfo.processInfo.environment[stateEnvironmentKey], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        return canonicalLoginStateDirectory
    }
}

/// The daemon: QUIC listener with mutual TLS, Bonjour advertisement, and
/// the slot behind it. Grant model: any certificate issued by the cluster
/// CA may open sessions — the grant governs ISSUANCE (the keeper's sheet
/// stands between an app and its certificate); revocation and the ledger
/// are funded scope (M2).
public final class Daemon: Sendable {
    struct RoadAdvertisement: Sendable, Equatable {
        var roads: [RoadEndpoint]
        var legacyAddresses: [String]
    }

    static func roadAdvertisement(
        localAddresses: [String],
        port: UInt16,
        mapped: RoadEndpoint?
    ) -> RoadAdvertisement {
        var roads = localAddresses.map { RoadEndpoint(host: $0, port: port) }
        if let mapped, !roads.contains(mapped) { roads.append(mapped) }
        var legacyAddresses = localAddresses
        if let mapped, mapped.port == port, !legacyAddresses.contains(mapped.host) {
            legacyAddresses.append(mapped.host)
        }
        return RoadAdvertisement(roads: roads, legacyAddresses: legacyAddresses)
    }

    public struct ListenerIdentity: @unchecked Sendable {
        public let identity: SecIdentity
        public let caCertificate: SecCertificate

        public init(identity: SecIdentity, caCertificate: SecCertificate) {
            self.identity = identity
            self.caCertificate = caCertificate
        }
    }

    /// The grant organ, when this daemon rules per-app access: the desk
    /// where requests park, and the registry that says which peer
    /// certificate is the admin device.
    public struct GrantWiring: Sendable {
        public let desk: GrantDesk
        public let devices: DeviceRegistry

        public init(desk: GrantDesk, devices: DeviceRegistry) {
            self.desk = desk
            self.devices = devices
        }
    }

    /// Starts the ceremony's listener: server-auth-only TLS (clients have
    /// no certificate yet), the issuing chain presented so the QR's CA-hash
    /// pin — or the TXT-carried pin an app discovered — can verify it.
    public func startEnrollment(service: EnrollmentService, advertise: Bool = true) async throws {
        let options = TLSBuilder.serverOptions(
            alpn: Wire.enrollALPN,
            identity: tls.identity,
            clientTrustRoots: [],
            presentedChain: [tls.caCertificate],
            // A parked app request idles for up to the grant window; QUIC's
            // effective idle timeout is the min of both ends, so the server
            // must stretch too.
            idleMilliseconds: 180_000
        )
        let listener = try QUICListener(port: config.enrollPort, parameters: .reachQUIC(options: options))
        // Same reason as the session listener: a held port fails later and
        // silently, and here the symptom is a ceremony that never reaches
        // the phone with nothing on the Mac to say why.
        try await listener.waitUntilReady()
        if advertise {
            listener.advertise(name: config.clusterName, type: Wire.bonjourEnrollService)
        }
        let accept = Task { [state] in
            do {
                for try await tunnel in listener.tunnels {
                    Task {
                        let id = await state.track(tunnel)
                        for await stream in tunnel.inboundStreams {
                            Task { await service.serve(stream: stream) }
                        }
                        await state.untrack(id)
                    }
                }
            } catch {
                Log.error("enrollment listener terminated: \(error)")
            }
        }
        Task { await state.store(enrollListener: listener, task: accept) }
    }

    private let config: DaemonConfig
    private let filling: any SlotFilling
    private let registry: SessionRegistry
    private let tls: ListenerIdentity
    private let grants: GrantWiring?
    private let reachability: ReachabilityCoordinator?
    private let currentAddresses: @Sendable () -> [[UInt8]]
    private let state = StateBox()

    public init(
        config: DaemonConfig,
        filling: any SlotFilling,
        identity: ListenerIdentity,
        registry: SessionRegistry = SessionRegistry(),
        grants: GrantWiring? = nil,
        reachability: ReachabilityCoordinator? = nil
    ) {
        self.config = config
        self.filling = filling
        self.registry = registry
        self.tls = identity
        self.grants = grants
        self.reachability = reachability
        self.currentAddresses = LocalAddresses.ipv4
    }

    /// Test-only/package seam for the fact authenticated hellos read the
    /// address set *now*, not the set that existed when the listener started.
    /// The public initializer above is intentionally unchanged.
    package init(
        config: DaemonConfig,
        filling: any SlotFilling,
        identity: ListenerIdentity,
        registry: SessionRegistry = SessionRegistry(),
        grants: GrantWiring? = nil,
        reachability: ReachabilityCoordinator? = nil,
        currentAddresses: @escaping @Sendable () -> [[UInt8]]
    ) {
        self.config = config
        self.filling = filling
        self.registry = registry
        self.tls = identity
        self.grants = grants
        self.reachability = reachability
        self.currentAddresses = currentAddresses
    }

    /// Starts listening (and advertising, unless disabled for tests).
    public func start(advertise: Bool = true) async throws {
        let options = TLSBuilder.serverOptions(
            alpn: Wire.alpn,
            identity: tls.identity,
            clientTrustRoots: [tls.caCertificate]
        )
        let listener = try QUICListener(port: config.port, parameters: .reachQUIC(options: options))
        // Before advertising, and before anything prints that we are serving.
        // A listener whose port is already held does not fail here — it fails
        // later, on the network queue, and the failure used to arrive at the
        // accept task as one line on stderr while `start()` had already
        // returned successfully. The operator's terminal said the cluster was
        // serving and every client said no road reached it; both were on
        // screen at once and one of them was a lie. Racing a dying process
        // for its port is exactly what a restart is, so this is the shape the
        // daemon meets most.
        try await listener.waitUntilReady()
        // The system request is deliberately long-lived: it renews mappings
        // and follows primary-network changes, calling us again whenever the
        // assigned address or port moves.
        reachability?.start()
        if advertise {
            // The CA-hash pin rides the TXT record: an identity-less app
            // reads it here and holds the enrollment channel to it.
            let caHash = Wire.base64URL(Data(SHA256.hash(data: IdentityStore.der(of: tls.caCertificate))))
            listener.advertise(name: config.clusterName, txt: [
                Wire.txtVersionsKey: Wire.txtVersionsValue,
                "model": filling.modelID,
                Wire.txtCAHashKey: caHash,
            ])
        }
        let accept = Task { [weak self] in
            guard let tunnels = await self?.stateStore(listener: listener) else { return }
            do {
                for try await tunnel in tunnels {
                    guard let self else { return }
                    Task { await self.serve(tunnel: tunnel) }
                }
            } catch {
                Log.error("listener terminated: \(error)")
            }
        }
        // The desk sweeps on the same tick as the registry. It was left out
        // when this was written, and being the one organ with nothing on
        // disk, there was no artifact anywhere that would have shown it.
        let sweeper = Task { [registry, grants] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                await registry.sweep()
                await grants?.desk.sweep()
            }
        }
        await state.store(accept: accept, sweeper: sweeper)
    }

    private func stateStore(listener: QUICListener) async -> AsyncThrowingStream<QUICTunnel, Error> {
        await state.store(listener: listener)
        return listener.tunnels
    }

    public func stop() async {
        reachability?.stop()
        await state.stop()
    }

    // MARK: Streams

    /// One accepted tunnel, held for as long as it is being served so that
    /// `stop()` has something to reach. See `StateBox.tunnels`.
    private func serve(tunnel: ReachTransport.QUICTunnel) async {
        let id = await state.track(tunnel)
        await handle(tunnel: tunnel)
        await state.untrack(id)
    }

    private func handle(tunnel: ReachTransport.QUICTunnel) async {
        for await stream in tunnel.inboundStreams {
            Task { await self.serve(stream: stream) }
        }
    }

    private func serve(stream: ReachTransport.QUICStream) async {
        var iterator = stream.frames.makeAsyncIterator()
        do {
            // A stream that opens and never speaks is not a fault: a dial the
            // client cancelled, an app that went away between connect and
            // send, a probe. Both silent endings are that — and the reset one
            // arrived here as a THROW, past this guard into the catch below,
            // where it printed `stream ended: POSIXErrorCode 57` at error
            // level for a session that never existed. That is 7f's reading, on
            // the one listener 7f did not reach.
            //
            // Nothing was served, so there is nothing to say. The cancel is
            // what the catch was already doing for that path and still has to
            // happen — and the clean close, which used to fall out of here
            // without one, was leaking the connection.
            let opening = await FrameEnding.next(from: &iterator)
            guard case .frame(let first) = opening else {
                stream.cancel()
                return
            }
            switch first.type {
            case .hello:
                let hello = try first.decode(Hello.self)
                guard let version = Wire.negotiate(offered: hello.versions) else {
                    try await stream.send(ErrorFrame(
                        code: "wire-version",
                        message: Wire.mismatchMessage(app: hello.versions, cluster: Wire.supportedVersions)
                    ))
                    stream.finishSending()
                    return
                }
                let ending = try await controlLoop(stream: stream, iterator: &iterator, version: version)
                // How a control stream ends is a decision, so it is made where
                // the decision belongs and logged from the answer — not left
                // to fall into the catch below, which is where it used to go.
                if ending.peerWentAway {
                    Log.info(ending.accountOfAControlStream)
                } else {
                    Log.error(ending.accountOfAControlStream)
                }
                stream.cancel()
            case .generateBegin:
                let begin = try first.decode(GenerateBegin.self)
                try await generationLoop(stream: stream, iterator: &iterator, begin: begin)
            case .generateReattach:
                let reattach = try first.decode(GenerateReattach.self)
                try await reattachLoop(stream: stream, iterator: &iterator, frame: reattach)
            default:
                try await stream.send(ErrorFrame(code: "unexpected-frame", message: "stream must open with hello or generate"))
                stream.cancel()
            }
        } catch {
            Log.error("stream ended: \(error)")
            stream.cancel()
        }
    }

    /// Serves the control stream until it ends, and returns **how** it ended.
    ///
    /// The ending is a return value rather than a throw for the reason
    /// `FrameEnding` exists at all: `while let raw = try await iterator.next()`
    /// handles a clean close and lets a reset throw straight past, into
    /// `serve`'s catch, which logged `stream ended: <socket error>` at error
    /// level. An app quitting with a live control stream is the most ordinary
    /// traffic this daemon sees, and it is the traffic a restart generates
    /// most — so the log filled with errors for nothing going wrong. That is
    /// 7f's reading again, one shape over.
    ///
    /// It still throws for what genuinely fails: a send that will not go, a
    /// frame that will not decode. Those are faults and belong in the catch.
    private func controlLoop(
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator,
        version: UInt8
    ) async throws -> FrameEnding {
        let localAddresses = currentAddresses().map { $0.map(String.init).joined(separator: ".") }
        let advertisement = Self.roadAdvertisement(
            localAddresses: localAddresses,
            port: config.port,
            mapped: reachability?.sessionEndpoint
        )
        try await stream.send(HelloAck(
            version: version,
            cluster: config.clusterName,
            models: [ModelDescriptor(id: filling.modelID, displayName: filling.displayName, capabilities: filling.capabilities)],
            addrs: advertisement.legacyAddresses,
            port: config.port,
            roads: advertisement.roads
        ), for: version)
        // The admin device, once this stream proves it is one; grant events
        // ride back on this same stream while the loop keeps consuming.
        var admin: DeviceRegistry.Device?
        var forwarder: Task<Void, Never>?
        defer { forwarder?.cancel() }
        while true {
            let next = await FrameEnding.next(from: &iterator)
            guard case .frame(let raw) = next else { return next }
            try raw.requireSupported(by: version)
            switch raw.type {
            case .sessionOpen:
                // Decoded so a malformed frame is still refused here; its
                // `modelID` is not authoritative yet — the unread-wire audit
                // graduated catalog meaning, selection ownership, and
                // mismatch refusal together rather than inventing one here.
                _ = try raw.decode(SessionOpen.self)
                let (sessionID, token) = await registry.openSession(version: version)
                try await stream.send(
                    SessionOpened(sessionID: sessionID, token: token, capabilities: filling.capabilities),
                    for: version
                )
                // Which road the session was *born* on. The re-attach below
                // has said this since the walk-out take, for a reason that
                // applies here word for word — a 10.86.0.x on the Mac's
                // terminal, in shot, is the difference between the claim and
                // the evidence for it — and a cold open is the half the away
                // claim actually rests on. It was never written, so the one
                // scenario nobody could photograph was the headline one.
                //
                // It matters because the client *races* its stored roads and
                // keeps whichever answers: a session that came over the
                // tailnet and one that came over the mesh are indistinguishable
                // from every other line in this log, and only one of them is
                // the claim.
                Log.info(Log.sessionOpened(sessionID, from: stream.remoteEndpointDescription() ?? "an unnamed path"))
            case .grantSubscribe:
                _ = try raw.decode(GrantSubscribe.self)
                guard let grants, let device = await adminDevice(on: stream, grants: grants) else {
                    try await stream.send(ErrorFrame(code: "grant-denied", message: "admin device certificate required"), for: version)
                    continue
                }
                admin = device
                forwarder?.cancel()
                let events = await grants.desk.subscribe()
                forwarder = Task {
                    for await event in events {
                        try? await stream.send(event, for: version)
                    }
                }
            case .grantRule:
                let rule = try raw.decode(GrantRule.self)
                if admin == nil, let grants {
                    admin = await adminDevice(on: stream, grants: grants)
                }
                guard let grants, let device = admin else {
                    try await stream.send(ErrorFrame(code: "grant-denied", message: "admin device certificate required"), for: version)
                    continue
                }
                if await !grants.desk.rule(requestID: rule.requestID, allow: rule.allow, ruler: device.id) {
                    try await stream.send(ErrorFrame(code: "grant-unknown", message: "no pending request \(rule.requestID)"), for: version)
                }
            case .ping:
                let ping = try raw.decode(Ping.self)
                try await stream.send(Pong(nonce: ping.nonce), for: version)
            default:
                try await stream.send(ErrorFrame(code: "unexpected-frame", message: "\(raw.type) on control stream"), for: version)
            }
        }
    }

    /// The peer is an admin device iff its leaf's SAN URI names an active
    /// enrolled device holding the admin grant.
    private func adminDevice(on stream: ReachTransport.QUICStream, grants: GrantWiring) async -> DeviceRegistry.Device? {
        guard let der = stream.peerCertificateDER(),
              let uri = PeerIdentity.uri(fromDER: der),
              let id = PeerIdentity.deviceID(fromURI: uri),
              let device = await grants.devices.device(id: id),
              device.admin, device.active
        else { return nil }
        return device
    }

    private func generationLoop(
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator,
        begin: GenerateBegin
    ) async throws {
        let filling = self.filling
        let events: AsyncStream<Ev>
        let epoch: UInt64
        let version: UInt8
        do {
            (events, epoch, version) = try await registry.begin(
                sessionID: begin.sessionID,
                genID: begin.genID,
                events: { filling.generate(begin.request) }
            )
        } catch {
            try await stream.send(ErrorFrame(code: "begin-rejected", message: "\(error)"))
            // Cancelled for the same reason the silent-opening path above
            // cancels: a stream this side is done with and does not close
            // leaks the connection. Refusals are the traffic a restart
            // generates most, so this is the leak that would grow fastest.
            stream.cancel()
            return
        }
        try await pump(
            events: events,
            stream: stream,
            iterator: &iterator,
            sessionID: begin.sessionID,
            genID: begin.genID,
            epoch: epoch,
            version: version
        )
    }

    private func reattachLoop(
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator,
        frame: GenerateReattach
    ) async throws {
        let events: AsyncStream<Ev>
        let epoch: UInt64
        let version: UInt8
        do {
            try await registry.validate(sessionID: frame.sessionID, token: frame.token)
            (events, epoch, version) = try await registry.attach(
                sessionID: frame.sessionID,
                genID: frame.genID,
                fromSeq: frame.fromSeq
            )
        } catch {
            try await stream.send(ErrorFrame(code: "reattach-rejected", message: "\(error)"))
            stream.cancel()
            return
        }
        // Which road the generation came back on. Nothing else records it:
        // the session is road-agnostic by design, and a walk-out at a venue
        // whose Wi-Fi reaches past the door can complete without the mesh
        // ever being used — a take that looks perfect while demonstrating
        // nothing. A 10.86.0.x here, on the Mac's terminal and in shot, is
        // the difference between the claim and the evidence for it.
        Log.info("generation \(frame.genID) re-attached from \(stream.remoteEndpointDescription() ?? "an unnamed path") at seq \(frame.fromSeq)")
        try await pump(
            events: events,
            stream: stream,
            iterator: &iterator,
            sessionID: frame.sessionID,
            genID: frame.genID,
            epoch: epoch,
            version: version
        )
    }

    /// Sends seq-stamped events while consuming acks/cancels, detaching the
    /// generation if the transport dies before the stream completes.
    private func pump(
        events: AsyncStream<Ev>,
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator,
        sessionID: UUID,
        genID: UUID,
        epoch: UInt64,
        version: UInt8
    ) async throws {
        let registry = self.registry
        let sender = Task {
            var clean = true
            for await ev in events {
                do {
                    try await stream.send(ev, for: version)
                } catch {
                    clean = false
                    break
                }
            }
            if clean {
                stream.finishSending()
            } else {
                await registry.detach(sessionID: sessionID, genID: genID, epoch: epoch)
            }
        }
        do {
            while let raw = try await iterator.next() {
                try raw.requireSupported(by: version)
                switch raw.type {
                case .evAck:
                    let ack = try raw.decode(EvAck.self)
                    await registry.ack(sessionID: sessionID, genID: genID, seq: ack.seq, epoch: epoch)
                case .generateCancel:
                    await registry.cancel(sessionID: sessionID, genID: genID, epoch: epoch)
                default:
                    break
                }
            }
        } catch {
            await registry.detach(sessionID: sessionID, genID: genID, epoch: epoch)
        }
        _ = await sender.value
    }
}

private actor StateBox {
    private var listener: QUICListener?
    private var enrollListener: QUICListener?
    private var tasks: [Task<Void, Never>] = []

    /// Tunnels this daemon accepted and is still serving.
    ///
    /// ⚠️ **`stop()` did not stop the daemon, and this is what it was
    /// missing.** It cancelled the listener and the accept task — but the
    /// per-tunnel work is spawned as a bare `Task {}` inside the accept
    /// loop's body, and an unstructured task does not care that the task it
    /// was created from was cancelled. So a stopped daemon went on serving
    /// every tunnel a client had already established, and a client whose hub
    /// entry was `proven` reused that tunnel rather than dialing the listener
    /// that was gone.
    ///
    /// Invisible in production, where `stop()` is only called by `selftest` in
    /// a process about to exit. Visible in `RestartBudgetTests` as **"a
    /// stopped daemon answered"** — intermittently, on runs with enough
    /// concurrent load to keep the old tunnel warm, and moving between three
    /// tests that all depended on the guarantee and none of which asserted it.
    /// `DialTests.aStoppedDaemonStopsAnsweringClients` now does, in 0.07 s.
    ///
    /// Cancelling the *tunnel* rather than the task is both smaller and truer:
    /// it closes the connection, which ends the stream iteration in `handle`
    /// and the frame iteration in every `serve` below it, instead of
    /// abandoning tasks that still hold a live socket. Each entry removes
    /// itself when its tunnel finishes, so a daemon serving for weeks holds
    /// one entry per *live* connection rather than per connection it ever had.
    private var tunnels: [UUID: ReachTransport.QUICTunnel] = [:]

    func track(_ tunnel: ReachTransport.QUICTunnel) -> UUID {
        let id = UUID()
        tunnels[id] = tunnel
        return id
    }

    func untrack(_ id: UUID) {
        tunnels[id] = nil
    }

    func store(listener: QUICListener) {
        self.listener = listener
    }

    func store(enrollListener: QUICListener, task: Task<Void, Never>) {
        self.enrollListener = enrollListener
        tasks.append(task)
    }

    func store(accept: Task<Void, Never>, sweeper: Task<Void, Never>) {
        tasks = [accept, sweeper]
    }

    func stop() {
        listener?.cancel()
        enrollListener?.cancel()
        tasks.forEach { $0.cancel() }
        tasks = []
        // Established connections, which the two lines above never reached.
        for tunnel in tunnels.values { tunnel.cancel() }
        tunnels = [:]
    }
}

/// How a served control stream ended, and whether that is news or a fault.
///
/// The same move `EnrollmentService` makes with `appHalfConverges` and
/// `reason(waitingFor:)`, for the same reason: the level has to *follow* from
/// a decision, and a decision that lives in a log line cannot be tested. Both
/// of these are values, and the tests read the values.
extension FrameEnding {
    /// Whether this ending is just a peer going away.
    ///
    /// Two of the three are. A control stream closes cleanly when an app is
    /// done with it, and it resets when the app is killed, suspended past its
    /// keepalive, or loses its network — an app quitting mid-session is the
    /// single most common thing that happens to this daemon, and after a
    /// restart it is nearly all of the traffic. Neither is a fault and neither
    /// costs anything: the session outlives the connection by design.
    ///
    /// A `WireError` is the exception, and it is the reason this is not simply
    /// "the loop stopped". A peer whose bytes will not parse as frames is not
    /// leaving, it is speaking something this daemon does not know — no
    /// version negotiation exists to have refused it earlier, so this line is
    /// where it surfaces.
    ///
    /// `.frame` cannot arrive here — the loop only returns on a non-frame —
    /// but if it ever did it would mean a frame was read and dropped, which is
    /// a fault by any reading.
    var peerWentAway: Bool {
        switch self {
        case .frame: false
        case .closed: true
        case .broke(let error): error is TransportError
        }
    }

    /// What to write down about it. Carries the transport's own words in the
    /// reset case, because that is the part naming what actually happened.
    var accountOfAControlStream: String {
        switch self {
        case .frame(let raw):
            "a control stream ended holding an unread \(raw.type) — that is a fault in the loop, not in the peer"
        case .closed:
            "an app closed its control stream"
        case .broke(let error) where error is TransportError:
            "an app's control stream went away: \(error). It quit, slept, or lost its network; anything it had running is held for the residency window"
        case .broke(let error):
            "a control stream carried something this daemon could not read as a frame: \(error)"
        }
    }
}

enum Log {
    static func error(_ message: String) {
        FileHandle.standardError.write(Data("[reachd] \(message)\n".utf8))
    }

    static func info(_ message: String) {
        print("[reachd] \(message)")
    }

    /// The road a session was born on: written here, read by `ClusterDial`,
    /// and the two must not drift.
    ///
    /// This is a log line that something greps, which makes its wording a
    /// contract rather than prose. The reader's needle is `roadPrefix` and
    /// the writer's line is defined in terms of it, so a reworded line moves
    /// both at once — a test holding a hand-written copy of this format would
    /// have gone on passing while `doctor --dial` quietly stopped finding the
    /// road, which is precisely the shape of defect R2's second corollary is
    /// about.
    static func roadPrefix(session: UUID) -> String {
        "session \(session) opened from "
    }

    static func sessionOpened(_ session: UUID, from road: String) -> String {
        roadPrefix(session: session) + road
    }
}
