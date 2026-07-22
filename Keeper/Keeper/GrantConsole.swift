import Foundation
import Network
import Observation
import ReachIdentity
import ReachTransport
import ReachWire
import SwiftUI

/// The cluster as the ceremony recorded it — the console's dialing card.
struct ClusterRecord: Codable {
    var name: String
    var addrs: [String]
    var sessionPort: UInt16
    var caCertDER: Data

    static var url: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("cluster.json")
    }

    static func load() -> ClusterRecord? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(ClusterRecord.self, from: data)
    }

    func save() {
        if let data = try? JSONEncoder().encode(self) {
            try? data.write(to: Self.url, options: [.atomic])
        }
    }
}

/// The keeper's live half of the grant sheet: a control stream opened with
/// the device certificate, subscribed to the daemon's desk. Requests appear
/// as they park; a tap rules them. The real console — ledger, revocation,
/// the admin grammar — is funded scope; this is the sheet and nothing else.
@Observable @MainActor
final class GrantConsole {
    enum State: Equatable {
        case idle            // not enrolled yet — no cluster record
        case connecting
        case watching(cluster: String)
        case notAdmin
        case unavailable(String)
    }

    var state: State = .idle
    var pending: [GrantEvent] = []
    var ruledLog: [String] = []

    private var loop: Task<Void, Never>?
    private var control: ReachTransport.QUICStream?

    func start() {
        guard loop == nil else { return }
        loop = Task { await run() }
    }

    func rule(_ event: GrantEvent, allow: Bool) {
        pending.removeAll { $0.requestID == event.requestID }
        ruledLog.append("\(allow ? "allowed" : "denied") \(event.displayName) (\(event.bundleID))")
        let control = self.control
        Task {
            try? await control?.send(GrantRule(requestID: event.requestID, allow: allow))
        }
    }

    private func run() async {
        while !Task.isCancelled {
            guard let record = ClusterRecord.load() else {
                state = .idle
                try? await Task.sleep(for: .seconds(3))
                continue
            }
            do {
                state = .connecting
                try await watch(record)
            } catch is NotAdmin {
                // The daemon said this device may not rule; that will not
                // change by retrying.
                state = .notAdmin
                return
            } catch {
                state = .unavailable("cluster unreachable — retrying")
            }
            control = nil
            try? await Task.sleep(for: .seconds(3))
        }
    }

    private struct NotAdmin: Error {}

    private func watch(_ record: ClusterRecord) async throws {
        let identity = try KeychainIdentity.find(label: DeviceKey.label)
        let ca = try IdentityStore.certificate(fromDER: record.caCertDER)
        let options = TLSBuilder.clientOptions(alpn: Wire.alpn, identity: identity, serverTrustRoots: [ca])

        var stream: ReachTransport.QUICStream?
        for addr in record.addrs {
            let dialer = QUICDialer(
                endpoint: .hostPort(host: NWEndpoint.Host(addr), port: NWEndpoint.Port(rawValue: record.sessionPort)!),
                parameters: .reachQUIC(options: options)
            )
            if let opened = try? await dialer.openStream(timeout: 10) {
                stream = opened
                break
            }
        }
        guard let stream else { throw TransportError.connectionFailed("no address reachable") }
        control = stream
        var frames = stream.frames.makeAsyncIterator()

        try await stream.send(Hello(client: "Keeper/\(Wire.version)"))
        guard let ack = try await frames.next(), ack.type == .helloAck else {
            throw TransportError.streamClosed
        }
        try await stream.send(GrantSubscribe())
        state = .watching(cluster: record.name)

        // The session tunnel idles out at 30 s; the console holds it open.
        let pinger = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(10))
                try? await stream.send(Ping(nonce: UInt64.random(in: .min ... .max)))
            }
        }
        defer {
            pinger.cancel()
            stream.cancel()
        }

        while let raw = try await frames.next() {
            switch raw.type {
            case .grantEvent:
                let event = try raw.decode(GrantEvent.self)
                if !pending.contains(where: { $0.requestID == event.requestID }) {
                    pending.append(event)
                }
            case .errorFrame:
                let error = try raw.decode(ErrorFrame.self)
                if error.code == "grant-denied" { throw NotAdmin() }
            default:
                break   // pongs
            }
        }
        throw TransportError.streamClosed
    }
}

/// The sheet: an app asks, a human rules. This surface IS the trust
/// decision in v0 — the named App-Attest stub.
struct GrantConsoleView: View {
    @Bindable var console: GrantConsole

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Grants", systemImage: "checkmark.shield")
                .font(.title3.weight(.semibold))
            statusLine
            ForEach(console.pending, id: \.requestID) { event in
                requestCard(event)
            }
            ForEach(console.ruledLog.suffix(3).reversed(), id: \.self) { line in
                Text(line)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private var statusLine: some View {
        switch console.state {
        case .idle:
            Text("Pair with a cluster first — grants surface here.")
                .font(.callout).foregroundStyle(.secondary)
        case .connecting:
            HStack(spacing: 8) {
                ProgressView()
                Text("Reaching the cluster…").font(.callout).foregroundStyle(.secondary)
            }
        case .watching(let cluster):
            Label("Watching \(cluster) — app requests appear here.", systemImage: "eye")
                .font(.callout).foregroundStyle(.secondary)
        case .notAdmin:
            Label("This device does not hold the admin grant.", systemImage: "lock")
                .font(.callout).foregroundStyle(.orange)
        case .unavailable(let message):
            Label(message, systemImage: "wifi.exclamationmark")
                .font(.callout).foregroundStyle(.orange)
        }
    }

    private func requestCard(_ event: GrantEvent) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("“\(event.displayName)” asks to use this cluster")
                .font(.headline)
            Text(event.bundleID)
                .font(.caption.monospaced())
            Text("key \(event.appKeyFingerprint.prefix(16))… · from \(event.deviceID)")
                .font(.caption2)
                .foregroundStyle(.secondary)
            HStack {
                Button("Allow") { console.rule(event, allow: true) }
                    .buttonStyle(.borderedProminent)
                Button("Deny", role: .destructive) { console.rule(event, allow: false) }
                    .buttonStyle(.bordered)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quinary, in: RoundedRectangle(cornerRadius: 12))
    }
}
