import Crypto
import Foundation
import Network
import ReachHost
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

// Preserve the Apple shell's diagnostic/test vocabulary while routing the
// classification and operator copy through the shared host implementation.
// `FrameEnding` remains ReachTransport's read result; no transport type enters
// the Linux host closure.
extension FrameEnding {
    private var hostEnding: HostFrameEnding {
        switch self {
        case .frame(let frame): .frame(frame)
        case .closed: .closed
        case .broke(let error): .broke(error)
        }
    }

    var peerWentAway: Bool {
        hostEnding.peerWentAway { $0 is TransportError }
    }

    var accountOfAControlStream: String {
        hostEnding.controlAccount { $0 is TransportError }
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
    private let host: SessionHost
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
        self.tls = identity
        self.grants = grants
        self.reachability = reachability
        self.currentAddresses = { DirectAddressSelector.current() }
        let relayDeclaration: @Sendable (UInt8, UInt16) -> RelayRoadDeclaration = { version, port in
            RelayRoadDeclarationProvider.current(version: version, port: port)
        }
        let relayNetwork: @Sendable () -> String? = {
            try? MeshIntentStore.load(in: DaemonInfo.stateDirectory).relay?.network
        }
        let addressProvider = self.currentAddresses
        self.host = SessionHost(
            filling: filling,
            registry: registry,
            helloAck: { version in
                let localAddresses = addressProvider().map { $0.map(String.init).joined(separator: ".") }
                let advertisement = Self.roadAdvertisement(
                    localAddresses: localAddresses,
                    port: config.port,
                    mapped: reachability?.sessionEndpoint
                )
                return HelloAck(
                    version: version,
                    cluster: config.clusterName,
                    models: [ModelDescriptor(id: filling.modelID, displayName: filling.displayName, capabilities: filling.capabilities)],
                    addrs: advertisement.legacyAddresses,
                    port: config.port,
                    roads: advertisement.roads,
                    relayRoads: relayDeclaration(version, config.port).wireValue
                )
            },
            relayNetwork: relayNetwork,
            sessionOpened: { Log.sessionOpened($0, from: $1) },
            info: { Log.info($0) },
            error: { Log.error($0) },
            isOrdinaryPeerDeparture: { $0 is TransportError },
            controlExtension: { GrantControl(grants: grants, peerCertificateDER: $0) }
        )
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
        admission: SlotAdmission? = nil,
        currentAddresses: @escaping @Sendable () -> [[UInt8]],
        relayRoadDeclaration: @escaping @Sendable (UInt8, UInt16) -> RelayRoadDeclaration = { version, port in
            RelayRoadDeclarationProvider.current(version: version, port: port)
        },
        currentRelayNetwork: @escaping @Sendable () -> String? = {
            try? MeshIntentStore.load(in: DaemonInfo.stateDirectory).relay?.network
        }
    ) {
        self.config = config
        self.filling = filling
        self.tls = identity
        self.grants = grants
        self.reachability = reachability
        self.currentAddresses = currentAddresses
        let addressProvider = currentAddresses
        self.host = SessionHost(
            filling: filling,
            registry: registry,
            admission: admission,
            helloAck: { version in
                let localAddresses = addressProvider().map { $0.map(String.init).joined(separator: ".") }
                let advertisement = Self.roadAdvertisement(
                    localAddresses: localAddresses,
                    port: config.port,
                    mapped: reachability?.sessionEndpoint
                )
                return HelloAck(
                    version: version,
                    cluster: config.clusterName,
                    models: [ModelDescriptor(id: filling.modelID, displayName: filling.displayName, capabilities: filling.capabilities)],
                    addrs: advertisement.legacyAddresses,
                    port: config.port,
                    roads: advertisement.roads,
                    relayRoads: relayRoadDeclaration(version, config.port).wireValue
                )
            },
            relayNetwork: currentRelayNetwork,
            sessionOpened: { Log.sessionOpened($0, from: $1) },
            info: { Log.info($0) },
            error: { Log.error($0) },
            isOrdinaryPeerDeparture: { $0 is TransportError },
            controlExtension: { GrantControl(grants: grants, peerCertificateDER: $0) }
        )
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
        let startup = await host.startupMessages
        Log.info(startup.admission)
        Log.info(startup.replay)
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
        let sweeper = Task { [host, grants] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                await host.sweep()
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
        await host.shutdown()
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
        await host.serve(stream)
    }

}

extension ReachTransport.QUICStream: SessionHostStream {}

private actor GrantControl: HostControlExtension {
    private let grants: Daemon.GrantWiring?
    private let peerCertificateDER: Data?
    private var admin: DeviceRegistry.Device?

    init(grants: Daemon.GrantWiring?, peerCertificateDER: Data?) {
        self.grants = grants
        self.peerCertificateDER = peerCertificateDER
    }

    package func handle(_ frame: RawFrame) async throws -> HostControlAction {
        switch frame.type {
        case .grantSubscribe:
            _ = try frame.decode(GrantSubscribe.self)
            guard let grants, let device = await adminDevice(grants: grants) else {
                return .send(ErrorFrame(code: "grant-denied", message: "admin device certificate required"))
            }
            admin = device
            return .subscribe(await grants.desk.subscribe())
        case .grantRule:
            let rule = try frame.decode(GrantRule.self)
            if admin == nil, let grants {
                admin = await adminDevice(grants: grants)
            }
            guard let grants, let device = admin else {
                return .send(ErrorFrame(code: "grant-denied", message: "admin device certificate required"))
            }
            if await !grants.desk.rule(requestID: rule.requestID, allow: rule.allow, ruler: device.id) {
                return .send(ErrorFrame(code: "grant-unknown", message: "no pending request \(rule.requestID)"))
            }
            return .handled
        default:
            return .unhandled
        }
    }

    private func adminDevice(grants: Daemon.GrantWiring) async -> DeviceRegistry.Device? {
        guard let peerCertificateDER,
              let uri = PeerIdentity.uri(fromDER: peerCertificateDER),
              let id = PeerIdentity.deviceID(fromURI: uri),
              let device = await grants.devices.device(id: id),
              device.admin, device.active
        else { return nil }
        return device
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
