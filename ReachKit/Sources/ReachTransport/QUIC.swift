import Foundation
import Network
import ReachWire
import Security

public enum TransportError: Error, Sendable {
    case connectionFailed(String)
    case streamClosed
    case sendFailed(String)
    case listenerFailed(String)
}

let transportQueue = DispatchQueue(label: "reach.transport.net", qos: .userInitiated)

// MARK: - Stream

/// One QUIC stream carrying wire frames. Wraps an `NWConnection` in the
/// per-stream model both ends share (spike S1a: servers accept streams via
/// the connection group's `newConnectionHandler`; clients extract them).
public final class QUICStream: Sendable {
    private let connection: NWConnection
    private let incoming: AsyncThrowingStream<RawFrame, Error>

    init(connection: NWConnection, started: Bool) {
        self.connection = connection

        let (stream, continuation) = AsyncThrowingStream<RawFrame, Error>.makeStream()
        incoming = stream

        connection.stateUpdateHandler = { state in
            switch state {
            case .failed(let error):
                continuation.finish(throwing: TransportError.connectionFailed("\(error)"))
            case .cancelled:
                continuation.finish()
            default:
                break
            }
        }
        if !started {
            connection.start(queue: transportQueue)
        }
        Self.pump(connection: connection, continuation: continuation)
    }

    /// Opens a client-side stream: starts the connection, waits for
    /// readiness, then wraps it. Plain QUIC connections sharing one
    /// `NWParameters` instance ride one tunnel (verified against the
    /// group-accepting listener: one server-side group, N streams).
    static func open(
        connection: NWConnection,
        timeout: Double
    ) async throws -> QUICStream {
        try await withCheckedThrowingContinuation { continuation in
            let box = ResumeOnce(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    box.resume(.success(QUICStream(connection: connection, started: true)))
                case .failed(let error):
                    box.resume(.failure(TransportError.connectionFailed("\(error)")))
                case .cancelled:
                    box.resume(.failure(TransportError.streamClosed))
                default:
                    break
                }
            }
            connection.start(queue: transportQueue)
            transportQueue.asyncAfter(deadline: .now() + timeout) {
                box.resume(.failure(TransportError.connectionFailed("stream open timeout")))
                connection.cancel()
            }
        }
    }

    private static func pump(
        connection: NWConnection,
        continuation: AsyncThrowingStream<RawFrame, Error>.Continuation,
        reassembler: FrameReassembler = FrameReassembler()
    ) {
        var reassembler = reassembler
        connection.receive(minimumIncompleteLength: 1, maximumLength: 128 * 1024) { data, _, isComplete, error in
            if let data, !data.isEmpty {
                do {
                    for frame in try reassembler.feed(data) {
                        continuation.yield(frame)
                    }
                } catch {
                    continuation.finish(throwing: error)
                    connection.cancel()
                    return
                }
            }
            if let error {
                continuation.finish(throwing: TransportError.connectionFailed("\(error)"))
                return
            }
            if isComplete {
                continuation.finish()
                return
            }
            pump(connection: connection, continuation: continuation, reassembler: reassembler)
        }
    }

    /// Frames as they arrive, in order, until FIN or failure.
    public var frames: AsyncThrowingStream<RawFrame, Error> { incoming }

    public func send(_ frame: some WireFrame) async throws {
        let data = try FrameCodec.encode(frame)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: TransportError.sendFailed("\(error)"))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    /// Half-close: our side is done sending.
    public func finishSending() {
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
    }

    public func cancel() {
        connection.cancel()
    }

    /// DER of the peer's leaf certificate, when the stream rode a
    /// mutually-authenticated tunnel. The daemon keys grants off this.
    public func peerCertificateDER() -> Data? {
        guard let metadata = connection.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata else {
            return nil
        }
        let sec = metadata.securityProtocolMetadata
        var der: Data?
        sec_protocol_metadata_access_peer_certificate_chain(sec) { certificate in
            if der == nil {
                let secCert = sec_certificate_copy_ref(certificate).takeRetainedValue()
                der = SecCertificateCopyData(secCert) as Data
            }
        }
        return der
    }
}

// MARK: - Tunnel

/// One QUIC connection (tunnel) to a peer; streams multiplex over it.
public final class QUICTunnel: Sendable {
    private let group: NWConnectionGroup
    private let inboundContinuation: AsyncStream<QUICStream>.Continuation
    /// Streams the peer opens toward us.
    public let inboundStreams: AsyncStream<QUICStream>

    /// Wrap a server-accepted connection group.
    init(accepted group: NWConnectionGroup) {
        self.group = group
        (inboundStreams, inboundContinuation) = AsyncStream<QUICStream>.makeStream()
        let continuation = inboundContinuation
        group.newConnectionHandler = { connection in
            connection.start(queue: transportQueue)
            continuation.yield(QUICStream(connection: connection, started: true))
        }
        group.stateUpdateHandler = { state in
            switch state {
            case .failed, .cancelled:
                continuation.finish()
            default:
                break
            }
        }
        group.start(queue: transportQueue)
    }

    public func cancel() {
        group.cancel()
    }
}

/// Client side of a tunnel: opens streams as plain QUIC connections over a
/// single shared `NWParameters` instance, which the system coalesces onto
/// one QUIC tunnel. (Group-based dialing never reaches readiness on the
/// current OS; the shared-parameters path is verified — one server-side
/// group, N streams.)
public final class QUICDialer: Sendable {
    private let endpoint: NWEndpoint
    private let parameters: NWParameters

    public init(endpoint: NWEndpoint, parameters: NWParameters) {
        self.endpoint = endpoint
        self.parameters = parameters
    }

    public func openStream(timeout: Double = 20) async throws -> QUICStream {
        let connection = NWConnection(to: endpoint, using: parameters)
        return try await QUICStream.open(connection: connection, timeout: timeout)
    }
}

/// Continuation guarded against double resume.
final class ResumeOnce<T: Sendable>: @unchecked Sendable {
    private var continuation: CheckedContinuation<T, Error>?
    private let lock = NSLock()

    init(_ continuation: CheckedContinuation<T, Error>) {
        self.continuation = continuation
    }

    func resume(_ result: Result<T, Error>) {
        lock.lock()
        defer { lock.unlock() }
        continuation?.resume(with: result)
        continuation = nil
    }
}

// MARK: - Listener

/// The daemon's QUIC listener: yields one tunnel per inbound connection.
public final class QUICListener: Sendable {
    private let listener: NWListener
    public let tunnels: AsyncThrowingStream<QUICTunnel, Error>
    public let port: UInt16

    public init(
        port: UInt16,
        parameters: NWParameters
    ) throws {
        let nwPort = NWEndpoint.Port(rawValue: port)!
        listener = try NWListener(using: parameters, on: nwPort)
        self.port = port

        let (stream, continuation) = AsyncThrowingStream<QUICTunnel, Error>.makeStream()
        tunnels = stream
        listener.newConnectionGroupHandler = { group in
            continuation.yield(QUICTunnel(accepted: group))
        }
        listener.stateUpdateHandler = { state in
            switch state {
            case .failed(let error):
                continuation.finish(throwing: TransportError.listenerFailed("\(error)"))
            case .cancelled:
                continuation.finish()
            default:
                break
            }
        }
        listener.start(queue: transportQueue)
    }

    /// Attach a Bonjour advertisement to this listener.
    public func advertise(name: String, txt: [String: String] = [:]) {
        var record = NWTXTRecord()
        for (key, value) in txt {
            record[key] = value
        }
        listener.service = NWListener.Service(
            name: name,
            type: Wire.bonjourService,
            domain: nil,
            txtRecord: record.data
        )
    }

    public func cancel() {
        listener.cancel()
    }
}
