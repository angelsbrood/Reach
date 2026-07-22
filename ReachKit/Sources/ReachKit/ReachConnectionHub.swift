import Foundation
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Security

public enum ReachError: Error, Sendable {
    case identityNotRegistered(String)
    case sessionRejected(String)
    case remote(code: String, message: String)
    case transport(String)
}

/// One hub per executor configuration: the shared `NWParameters` (one QUIC
/// tunnel), the daemon session, and stream opening. Sessions outlive
/// connections — the (sessionID, token) pair survives transport death and
/// re-attaches generations across path changes.
public actor ReachConnectionHub {
    public static let shared = ReachConnectionHub()

    public struct SessionHandle: Sendable {
        public let sessionID: UUID
        public let token: String
        public let capabilities: [String]
    }

    private struct Entry {
        let dialer: QUICDialer
        var session: SessionHandle?
    }

    private var entries: [ReachExecutor.Configuration: Entry] = [:]

    /// The daemon session for a configuration, opening the tunnel and the
    /// control exchange on first use.
    public func session(for configuration: ReachExecutor.Configuration) async throws -> SessionHandle {
        if let session = entries[configuration]?.session {
            return session
        }
        let dialer = try await dialer(for: configuration)
        let control = try await dialer.openStream(timeout: configuration.connectTimeout)
        defer { control.cancel() }
        var frames = control.frames.makeAsyncIterator()
        try await control.send(Hello(client: "ReachKit/\(Wire.version)"))
        guard let ackRaw = try await frames.next() else { throw ReachError.transport("no hello ack") }
        if ackRaw.type == .errorFrame {
            let error = try ackRaw.decode(ErrorFrame.self)
            throw ReachError.sessionRejected("\(error.code): \(error.message)")
        }
        _ = try ackRaw.decode(HelloAck.self)
        try await control.send(SessionOpen(modelID: configuration.modelID))
        guard let openedRaw = try await frames.next() else { throw ReachError.transport("no session response") }
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
        let dialer = try await dialer(for: configuration)
        return try await dialer.openStream(timeout: configuration.connectTimeout)
    }

    /// Drops the session (not the material) — the next use opens fresh.
    public func invalidateSession(for configuration: ReachExecutor.Configuration) {
        entries[configuration]?.session = nil
    }

    private func dialer(for configuration: ReachExecutor.Configuration) async throws -> QUICDialer {
        if let entry = entries[configuration] {
            return entry.dialer
        }
        guard let material = await ReachIdentityRegistry.shared.material(for: configuration.identityLabel) else {
            throw ReachError.identityNotRegistered(configuration.identityLabel)
        }
        let options = TLSBuilder.clientOptions(
            alpn: Wire.alpn,
            identity: material.identity,
            serverTrustRoots: [material.caCertificate]
        )
        let parameters = NWParameters.reachQUIC(options: options, handover: configuration.multipathHandover)
        let dialer = QUICDialer(
            endpoint: .hostPort(
                host: NWEndpoint.Host(configuration.host),
                port: NWEndpoint.Port(rawValue: configuration.port)!
            ),
            parameters: parameters
        )
        entries[configuration] = Entry(dialer: dialer, session: nil)
        return dialer
    }
}
