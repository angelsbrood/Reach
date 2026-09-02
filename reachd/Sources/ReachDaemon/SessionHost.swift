import Foundation
import ReachWire

/// The bounded transport seam consumed by the shared state machine. Darwin's
/// QUIC stream conforms in the Apple shell; Linux tests use an in-memory
/// implementation and earn no listener or identity claim.
public protocol SessionHostStream: Sendable {
    var frames: AsyncThrowingStream<RawFrame, any Error> { get }
    func send(_ frame: some WireFrame, for negotiatedVersion: UInt8) async throws
    func finishSending()
    func cancel()
    func remoteEndpointDescription() -> String?
    func peerCertificateDER() -> Data?
}

public extension SessionHostStream {
    func peerCertificateDER() -> Data? { nil }
}

package enum HostControlAction: Sendable {
    case unhandled
    case handled
    case send(ErrorFrame)
    case subscribe(AsyncStream<GrantEvent>)
}

package protocol HostControlExtension: Sendable {
    func handle(_ frame: RawFrame) async throws -> HostControlAction
}

private struct NoControlExtension: HostControlExtension {
    func handle(_ frame: RawFrame) async throws -> HostControlAction { .unhandled }
}

package typealias HostControlExtensionFactory = @Sendable (Data?) -> any HostControlExtension

/// The one provider-neutral control/generation state machine. It owns no
/// listener, certificate, discovery, service, or platform lifecycle object.
public final class SessionHost: Sendable {
    public typealias HelloAckFactory = @Sendable (UInt8) -> HelloAck
    public typealias RelayNetworkProvider = @Sendable () -> String?
    public typealias SessionOpenedFormatter = @Sendable (UUID, String) -> String

    private let filling: any SlotFilling
    private let registry: SessionRegistry
    private let admission: SlotAdmission
    private let helloAck: HelloAckFactory
    private let relayNetwork: RelayNetworkProvider
    private let sessionOpened: SessionOpenedFormatter
    private let info: @Sendable (String) -> Void
    private let error: @Sendable (String) -> Void
    private let isOrdinaryPeerDeparture: @Sendable (any Error) -> Bool
    private let controlExtension: HostControlExtensionFactory

    public init(
        filling: any SlotFilling,
        registry: SessionRegistry = SessionRegistry(),
        helloAck: @escaping HelloAckFactory,
        relayNetwork: @escaping RelayNetworkProvider = { nil },
        sessionOpened: @escaping SessionOpenedFormatter
    ) {
        self.filling = filling
        self.registry = registry
        admission = SlotAdmission(policy: .init(capacity: filling.maximumConcurrentGenerations))
        self.helloAck = helloAck
        self.relayNetwork = relayNetwork
        self.sessionOpened = sessionOpened
        info = { HostLog.info($0) }
        error = { HostLog.error($0) }
        isOrdinaryPeerDeparture = { _ in false }
        controlExtension = { _ in NoControlExtension() }
    }

    package init(
        filling: any SlotFilling,
        registry: SessionRegistry = SessionRegistry(),
        admission: SlotAdmission? = nil,
        helloAck: @escaping HelloAckFactory,
        relayNetwork: @escaping RelayNetworkProvider = { nil },
        sessionOpened: @escaping SessionOpenedFormatter,
        info: @escaping @Sendable (String) -> Void = { HostLog.info($0) },
        error: @escaping @Sendable (String) -> Void = { HostLog.error($0) },
        isOrdinaryPeerDeparture: @escaping @Sendable (any Error) -> Bool = { _ in false },
        controlExtension: @escaping HostControlExtensionFactory = { _ in NoControlExtension() }
    ) {
        self.filling = filling
        self.registry = registry
        self.admission = admission ?? SlotAdmission(policy: .init(capacity: filling.maximumConcurrentGenerations))
        self.helloAck = helloAck
        self.relayNetwork = relayNetwork
        self.sessionOpened = sessionOpened
        self.info = info
        self.error = error
        self.isOrdinaryPeerDeparture = isOrdinaryPeerDeparture
        self.controlExtension = controlExtension
    }

    package var startupMessages: (admission: String, replay: String) {
        get async {
            (await admission.startupMessage, await registry.replayStartupMessage)
        }
    }

    public func shutdown() async {
        await admission.shutdown()
        await registry.shutdown()
    }

    package func sweep() async {
        await registry.sweep()
    }

    public func serve<Stream: SessionHostStream>(_ stream: Stream) async {
        var iterator = stream.frames.makeAsyncIterator()
        do {
            let opening = await HostFrameEnding.next(from: &iterator)
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
                    ), for: Wire.baselineVersion)
                    stream.finishSending()
                    return
                }
                let ending = try await controlLoop(stream: stream, iterator: &iterator, version: version)
                if ending.peerWentAway(using: isOrdinaryPeerDeparture) {
                    info(ending.controlAccount(using: isOrdinaryPeerDeparture))
                } else {
                    error(ending.controlAccount(using: isOrdinaryPeerDeparture))
                }
                stream.cancel()
            case .generateBegin:
                try await generationLoop(
                    stream: stream,
                    iterator: &iterator,
                    begin: first.decode(GenerateBegin.self)
                )
            case .generateReattach:
                try await reattachLoop(
                    stream: stream,
                    iterator: &iterator,
                    frame: first.decode(GenerateReattach.self)
                )
            default:
                try await stream.send(
                    ErrorFrame(code: "unexpected-frame", message: "stream must open with hello or generate"),
                    for: Wire.baselineVersion
                )
                stream.cancel()
            }
        } catch {
            self.error("stream ended: \(error)")
            stream.cancel()
        }
    }

    private func controlLoop<Stream: SessionHostStream>(
        stream: Stream,
        iterator: inout AsyncThrowingStream<RawFrame, any Error>.AsyncIterator,
        version: UInt8
    ) async throws -> HostFrameEnding {
        try await stream.send(helloAck(version), for: version)
        let extensionHandler = controlExtension(stream.peerCertificateDER())
        var forwarder: Task<Void, Never>?
        defer { forwarder?.cancel() }
        while true {
            let next = await HostFrameEnding.next(from: &iterator)
            guard case .frame(let raw) = next else { return next }
            try raw.requireSupported(by: version)
            switch raw.type {
            case .sessionOpen:
                _ = try raw.decode(SessionOpen.self)
                let (sessionID, token) = await registry.openSession(version: version)
                try await stream.send(
                    SessionOpened(sessionID: sessionID, token: token, capabilities: filling.capabilities),
                    for: version
                )
                info(sessionOpened(
                    sessionID,
                    stream.remoteEndpointDescription() ?? "an unnamed path"
                ))
                let source = GenerationReceipt.Source(
                    remoteEndpointDescription: stream.remoteEndpointDescription(),
                    relayNetwork: relayNetwork()
                )
                info("session \(sessionID) source category \(source.rawValue)")
            case .ping:
                let ping = try raw.decode(Ping.self)
                try await stream.send(Pong(nonce: ping.nonce), for: version)
            default:
                switch try await extensionHandler.handle(raw) {
                case .unhandled:
                    try await stream.send(
                        ErrorFrame(code: "unexpected-frame", message: "\(raw.type) on control stream"),
                        for: version
                    )
                case .handled:
                    break
                case .send(let response):
                    try await stream.send(response, for: version)
                case .subscribe(let events):
                    forwarder?.cancel()
                    forwarder = Task {
                        for await event in events {
                            try? await stream.send(event, for: version)
                        }
                    }
                }
            }
        }
    }

    private func generationLoop<Stream: SessionHostStream>(
        stream: Stream,
        iterator: inout AsyncThrowingStream<RawFrame, any Error>.AsyncIterator,
        begin: GenerateBegin
    ) async throws {
        let events: AsyncStream<Ev>
        let epoch: UInt64
        let version: UInt8
        do {
            (events, epoch, version) = try await registry.begin(
                sessionID: begin.sessionID,
                genID: begin.genID,
                receiptSource: GenerationReceipt.Source(
                    remoteEndpointDescription: stream.remoteEndpointDescription(),
                    relayNetwork: relayNetwork()
                ),
                admission: admission,
                events: { self.filling.generate(begin.request) }
            )
        } catch let failure as SlotAdmission.AdmissionError where failure.isImmediateRefusal {
            try await stream.send(
                ErrorFrame(code: "cluster-busy", message: failure.description),
                for: Wire.baselineVersion
            )
            stream.cancel()
            return
        } catch {
            try await stream.send(
                ErrorFrame(code: "begin-rejected", message: "\(error)"),
                for: Wire.baselineVersion
            )
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

    private func reattachLoop<Stream: SessionHostStream>(
        stream: Stream,
        iterator: inout AsyncThrowingStream<RawFrame, any Error>.AsyncIterator,
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
            try await stream.send(
                ErrorFrame(code: "reattach-rejected", message: "\(error)"),
                for: Wire.baselineVersion
            )
            stream.cancel()
            return
        }
        let source = GenerationReceipt.Source(
            remoteEndpointDescription: stream.remoteEndpointDescription(),
            relayNetwork: relayNetwork()
        )
        info("generation \(frame.genID) re-attached from \(stream.remoteEndpointDescription() ?? "an unnamed path") at seq \(frame.fromSeq)")
        info("generation \(frame.genID) re-attachment source category \(source.rawValue) at seq \(frame.fromSeq)")
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

    private func pump<Stream: SessionHostStream>(
        events: AsyncStream<Ev>,
        stream: Stream,
        iterator: inout AsyncThrowingStream<RawFrame, any Error>.AsyncIterator,
        sessionID: UUID,
        genID: UUID,
        epoch: UInt64,
        version: UInt8
    ) async throws {
        let registry = self.registry
        let sender = Task {
            var clean = true
            for await event in events {
                do {
                    try await stream.send(event, for: version)
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
                    await registry.cancel(
                        sessionID: sessionID,
                        genID: genID,
                        epoch: epoch,
                        admission: admission
                    )
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

package enum HostFrameEnding: Sendable {
    case frame(RawFrame)
    case closed
    case broke(any Error)

    package static func next(
        from iterator: inout AsyncThrowingStream<RawFrame, any Error>.AsyncIterator
    ) async -> HostFrameEnding {
        do {
            guard let frame = try await iterator.next() else { return .closed }
            return .frame(frame)
        } catch {
            return .broke(error)
        }
    }

    package func peerWentAway(using classifier: (any Error) -> Bool) -> Bool {
        switch self {
        case .frame: false
        case .closed: true
        case .broke(let error): classifier(error)
        }
    }

    package func controlAccount(using classifier: (any Error) -> Bool) -> String {
        switch self {
        case .frame(let raw):
            "a control stream ended holding an unread \(raw.type) — that is a fault in the loop, not in the peer"
        case .closed:
            "an app closed its control stream"
        case .broke(let error) where classifier(error):
            "an app's control stream went away: \(error). It quit, slept, or lost its network; anything it had running is held for the residency window"
        case .broke(let error):
            "a control stream carried something this daemon could not read as a frame: \(error)"
        }
    }
}

enum HostLog {
    static func error(_ message: String) {
        FileHandle.standardError.write(Data("[reachd] \(message)\n".utf8))
    }

    static func info(_ message: String) {
        print("[reachd] \(message)")
    }
}

// Shared-source compatibility for SlotAdmission's unchanged default sink.
// ReachDaemon's own `Log` remains a separate Apple-shell type.
typealias Log = HostLog

// `Counters` keeps its deliberately narrow package surface while the Apple
// composition's existing tests retain their former same-module expected-value
// spelling. The implicit memberwise initializer is available only here, in
// ReachHost; ReachHostExports.swift delegates to this factory.
package extension SlotAdmission.Counters {
    static func expectedValue(
        active: Int = 0,
        waiting: Int = 0,
        admitted: UInt64 = 0,
        refused: UInt64 = 0,
        cancelled: UInt64 = 0,
        timedOut: UInt64 = 0
    ) -> Self {
        .init(
            active: active,
            waiting: waiting,
            admitted: admitted,
            refused: refused,
            cancelled: cancelled,
            timedOut: timedOut
        )
    }
}
