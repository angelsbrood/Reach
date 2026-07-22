import Foundation
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Security

public enum DaemonInfo {
    public static let version = "0.0.1"
    public static let wireVersion = Wire.version

    /// Runtime state root; never inside the repository.
    public static var stateDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Reach", isDirectory: true)
    }
}

/// The daemon: QUIC listener with mutual TLS, Bonjour advertisement, and
/// the slot behind it. Phase 1 grant model: any certificate issued by the
/// cluster CA may open sessions (per-app grants arrive with the ceremony,
/// which also binds sessions to the peer certificate).
public final class Daemon: Sendable {
    public struct ListenerIdentity: @unchecked Sendable {
        public let identity: SecIdentity
        public let caCertificate: SecCertificate

        public init(identity: SecIdentity, caCertificate: SecCertificate) {
            self.identity = identity
            self.caCertificate = caCertificate
        }
    }

    private let config: DaemonConfig
    private let filling: any SlotFilling
    private let registry: SessionRegistry
    private let tls: ListenerIdentity
    private let state = StateBox()

    public init(
        config: DaemonConfig,
        filling: any SlotFilling,
        identity: ListenerIdentity,
        registry: SessionRegistry = SessionRegistry()
    ) {
        self.config = config
        self.filling = filling
        self.registry = registry
        self.tls = identity
    }

    /// Starts listening (and advertising, unless disabled for tests).
    public func start(advertise: Bool = true) async throws {
        let options = TLSBuilder.serverOptions(
            alpn: Wire.alpn,
            identity: tls.identity,
            clientTrustRoots: [tls.caCertificate]
        )
        let listener = try QUICListener(port: config.port, parameters: .reachQUIC(options: options))
        if advertise {
            listener.advertise(name: config.clusterName, txt: [
                "v": "\(Wire.version)",
                "model": filling.modelID,
            ])
        }
        let accept = Task { [weak self] in
            guard let tunnels = await self?.stateStore(listener: listener) else { return }
            do {
                for try await tunnel in tunnels {
                    guard let self else { return }
                    Task { await self.handle(tunnel: tunnel) }
                }
            } catch {
                Log.error("listener terminated: \(error)")
            }
        }
        let sweeper = Task { [registry] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                await registry.sweep()
            }
        }
        await state.store(accept: accept, sweeper: sweeper)
    }

    private func stateStore(listener: QUICListener) async -> AsyncThrowingStream<QUICTunnel, Error> {
        await state.store(listener: listener)
        return listener.tunnels
    }

    public func stop() async {
        await state.stop()
    }

    // MARK: Streams

    private func handle(tunnel: ReachTransport.QUICTunnel) async {
        for await stream in tunnel.inboundStreams {
            Task { await self.serve(stream: stream) }
        }
    }

    private func serve(stream: ReachTransport.QUICStream) async {
        var iterator = stream.frames.makeAsyncIterator()
        do {
            guard let first = try await iterator.next() else { return }
            switch first.type {
            case .hello:
                _ = try first.decode(Hello.self)
                try await controlLoop(stream: stream, iterator: &iterator)
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

    private func controlLoop(
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator
    ) async throws {
        try await stream.send(HelloAck(
            cluster: config.clusterName,
            models: [ModelDescriptor(id: filling.modelID, displayName: filling.displayName, capabilities: filling.capabilities)]
        ))
        while let raw = try await iterator.next() {
            switch raw.type {
            case .sessionOpen:
                let open = try raw.decode(SessionOpen.self)
                let (sessionID, token) = await registry.openSession(modelID: open.modelID)
                try await stream.send(SessionOpened(sessionID: sessionID, token: token, capabilities: filling.capabilities))
            case .sessionResume:
                let resume = try raw.decode(SessionResume.self)
                do {
                    let status = try await registry.resumeStatus(sessionID: resume.sessionID, token: resume.token)
                    try await stream.send(SessionResumed(generations: status))
                } catch {
                    try await stream.send(ErrorFrame(code: "resume-rejected", message: "\(error)"))
                }
            case .ping:
                let ping = try raw.decode(Ping.self)
                try await stream.send(Pong(nonce: ping.nonce))
            default:
                try await stream.send(ErrorFrame(code: "unexpected-frame", message: "\(raw.type) on control stream"))
            }
        }
    }

    private func generationLoop(
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator,
        begin: GenerateBegin
    ) async throws {
        let filling = self.filling
        let events: AsyncStream<Ev>
        do {
            events = try await registry.begin(
                sessionID: begin.sessionID,
                genID: begin.genID,
                events: { filling.generate(begin.request) }
            )
        } catch {
            try await stream.send(ErrorFrame(code: "begin-rejected", message: "\(error)"))
            return
        }
        try await pump(events: events, stream: stream, iterator: &iterator, sessionID: begin.sessionID, genID: begin.genID)
    }

    private func reattachLoop(
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator,
        frame: GenerateReattach
    ) async throws {
        let events: AsyncStream<Ev>
        do {
            try await registry.validate(sessionID: frame.sessionID, token: frame.token)
            events = try await registry.attach(sessionID: frame.sessionID, genID: frame.genID, fromSeq: frame.fromSeq)
        } catch {
            try await stream.send(ErrorFrame(code: "reattach-rejected", message: "\(error)"))
            return
        }
        try await pump(events: events, stream: stream, iterator: &iterator, sessionID: frame.sessionID, genID: frame.genID)
    }

    /// Sends seq-stamped events while consuming acks/cancels, detaching the
    /// generation if the transport dies before the stream completes.
    private func pump(
        events: AsyncStream<Ev>,
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator,
        sessionID: UUID,
        genID: UUID
    ) async throws {
        let registry = self.registry
        let sender = Task {
            var clean = true
            for await ev in events {
                do {
                    try await stream.send(ev)
                } catch {
                    clean = false
                    break
                }
            }
            if clean {
                stream.finishSending()
            } else {
                await registry.detach(sessionID: sessionID, genID: genID)
            }
        }
        do {
            while let raw = try await iterator.next() {
                switch raw.type {
                case .evAck:
                    let ack = try raw.decode(EvAck.self)
                    await registry.ack(sessionID: sessionID, genID: genID, seq: ack.seq)
                case .generateCancel:
                    await registry.cancel(sessionID: sessionID, genID: genID)
                default:
                    break
                }
            }
        } catch {
            await registry.detach(sessionID: sessionID, genID: genID)
        }
        _ = await sender.value
    }
}

private actor StateBox {
    private var listener: QUICListener?
    private var tasks: [Task<Void, Never>] = []

    func store(listener: QUICListener) {
        self.listener = listener
    }

    func store(accept: Task<Void, Never>, sweeper: Task<Void, Never>) {
        tasks = [accept, sweeper]
    }

    func stop() {
        listener?.cancel()
        tasks.forEach { $0.cancel() }
        tasks = []
    }
}

enum Log {
    static func error(_ message: String) {
        FileHandle.standardError.write(Data("[reachd] \(message)\n".utf8))
    }

    static func info(_ message: String) {
        print("[reachd] \(message)")
    }
}
