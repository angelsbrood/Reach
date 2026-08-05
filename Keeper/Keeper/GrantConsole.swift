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

    /// Re-dial, because coming back to the foreground is the one moment we
    /// know a card may be waiting and unseen.
    ///
    /// The desk announces a request **exactly once**, to whoever is
    /// subscribed at that instant (`GrantDesk.park`), and replays what is
    /// still parked only to a **new** subscriber (`GrantDesk.subscribe`). A
    /// console that is subscribed but SUSPENDED is neither: iOS is not
    /// draining its stream, so the yield lands in a buffer nothing reads,
    /// and it never re-subscribes on its own. That is the ordinary case and
    /// not an edge one — the operator is necessarily in the asking app at
    /// the moment they Send, which is exactly when the request parks.
    ///
    /// Re-dialling makes this console a new subscriber, which replays
    /// everything outstanding. Until this existed, the only thing that
    /// recovered the card was the operator backgrounding and foregrounding
    /// the app by hand — the same mechanism, performed manually, and only
    /// by someone who knew to.
    func refresh() {
        guard let existing = loop else { return }   // never started — start() owns that
        // Cancelling the task does not by itself unblock `frames.next()`;
        // closing the stream underneath it does, and watch()'s `defer` then
        // tidies up the pinger.
        control?.cancel()
        existing.cancel()
        dropConnection()
        // Let the old loop finish unwinding before the new one dials, so two
        // watches can never interleave their writes to `state` and `pending`.
        loop = Task { [weak self] in
            _ = await existing.value
            await self?.run()
        }
    }

    /// Send first, then say it happened. The card disappearing and the line
    /// in the log are the keeper's whole account of a ruling, and they were
    /// written before anything left the phone — so a control stream that had
    /// dropped (it is nil'd whenever the watch loop returns, and the send was
    /// a `try?`) produced a sheet that read as ruled while the asking app sat
    /// parked until its grant window expired. The one place the operator
    /// looks would have been the one place that could not tell them.
    func rule(_ event: GrantEvent, allow: Bool) {
        guard let control else {
            state = .unavailable("not connected to the cluster — the ruling was not sent")
            return
        }
        Task { [weak self] in
            do {
                try await control.send(GrantRule(requestID: event.requestID, allow: allow))
                guard let self else { return }
                self.pending.removeAll { $0.requestID == event.requestID }
                self.ruledLog.append("\(allow ? "allowed" : "denied") \(event.displayName) (\(event.bundleID))")
            } catch {
                guard let self else { return }
                // The card stays, so the ruling can be made again.
                self.state = .unavailable("the ruling did not reach the cluster — try again")
            }
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
                // The daemon said this device may not rule. That will not
                // change by retrying quickly — but it can change: the admin
                // flag lives in a device record the host can re-issue, and a
                // re-pair restores it. Returning here left the loop dead with
                // `loop` still non-nil, so start() could never restart it and
                // only relaunching the app recovered — a permanent blank sheet
                // reported as a statement about authority, which sends the
                // repair toward the device record rather than the loop.
                state = .notAdmin
                dropConnection()
                try? await Task.sleep(for: .seconds(30))
                continue
            } catch {
                // A deliberate re-dial (refresh) tears the stream down on
                // purpose, and the error it produces is not news — saying
                // "cluster unreachable" on the way out would put a fault on
                // screen for the one gesture that is fixing things.
                if !Task.isCancelled {
                    state = .unavailable("cluster unreachable — retrying")
                }
            }
            dropConnection()
            try? await Task.sleep(for: .seconds(3))
        }
    }

    /// A card outliving the stream that delivered it is a button that cannot
    /// work: rule() has nothing to send on. The desk replays everything still
    /// parked to each new subscriber, so anything genuinely outstanding comes
    /// straight back when the watch reconnects.
    private func dropConnection() {
        control = nil
        pending.removeAll()
    }

    private struct NotAdmin: Error {}

    /// The console's control stream ended before the cluster's hello ack.
    ///
    /// It is its own type because both transport cases that could carry it are
    /// false here: `connectionFailed` renders as "could not open a connection
    /// to the cluster" and the connection *did* open — the same sentence the
    /// ceremony's catch used to put on the phone — and `streamClosed` is true
    /// of one of the three endings and a lie about the other two.
    ///
    /// `run()` renders all three as "cluster unreachable — retrying", which is
    /// right: all three are fixed by re-dialling, which is what the loop does.
    /// So this text is for the next reader and a crash log, not the sheet, and
    /// the defect it closes is a value being false rather than a sentence.
    private struct NoHelloAck: Error, CustomStringConvertible {
        let ending: FrameEnding
        var description: String {
            switch ending {
            case .frame(let raw): "the cluster answered the console's hello with \(raw.type)"
            case .closed: "the cluster closed the console's stream before its hello ack"
            case .broke(let error): "the console's stream broke before the hello ack: \(error)"
            }
        }
    }

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
        let acked = await FrameEnding.next(from: &frames)
        guard case .frame(let ack) = acked, ack.type == .helloAck else {
            throw NoHelloAck(ending: acked)
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
