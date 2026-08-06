import Foundation
import ReachWire
import X509

/// Where app requests wait for a human — keyed by the app KEY, not the
/// stream, because the asking app is usually suspended while the human
/// rules (same phone: opening the keeper backgrounds the app and iOS
/// tears its parked connection down). Ask and collect are separable: a
/// ruled-but-undelivered verdict is held, and a re-knock with the same
/// key collects it. Events fan out to every live subscriber and replay
/// to late ones.
public actor GrantDesk {
    public enum Verdict: Sendable, Equatable {
        case allowed(rulerDeviceID: UUID)
        case denied
        case timedOut
        /// A newer knock for the same key took over this park — close
        /// quietly; the newer stream carries the outcome.
        case superseded
    }

    private struct Pending {
        let event: GrantEvent
        let ticket: UUID
        let continuation: CheckedContinuation<Verdict, Never>
    }

    private let window: Duration
    private let holdWindow: TimeInterval
    /// Keyed by app-key fingerprint — the stable name of an asking app.
    private var pending: [String: Pending] = [:]
    /// Ruled but not yet delivered (the asker's stream died first).
    private var ruled: [String: (verdict: Verdict, at: Date)] = [:]
    /// requestID → fingerprint, so a ruling can land after the park expired.
    /// Dated, because that is the only thing that can ever retire an entry
    /// whose knock timed out or was superseded: neither path reaches
    /// `collected`, so both used to leave one behind permanently.
    private var requestIndex: [UUID: (fingerprint: String, at: Date)] = [:]
    private var subscribers: [UUID: AsyncStream<GrantEvent>.Continuation] = [:]

    public init(window: Duration = .seconds(120), holdWindow: TimeInterval = 600) {
        self.window = window
        self.holdWindow = holdWindow
    }

    /// Parks a knock; resumes with the ruling, a held verdict from an
    /// earlier knock, a timeout, or supersession by a newer knock.
    public func park(_ event: GrantEvent) async -> Verdict {
        let fingerprint = event.appKeyFingerprint
        // Collect first: the human may have ruled while the asker was away.
        if let held = ruled[fingerprint] {
            if Date().timeIntervalSince(held.at) < holdWindow {
                return held.verdict
            }
            ruled[fingerprint] = nil
        }
        // A re-knock keeps the first knock's requestID — keepers dedupe on
        // it — and does not re-announce.
        let event = pending[fingerprint]?.event ?? event
        if pending[fingerprint] == nil {
            for subscriber in subscribers.values {
                subscriber.yield(event)
            }
        }
        requestIndex[event.requestID] = (fingerprint, Date())
        let ticket = UUID()
        return await withCheckedContinuation { continuation in
            if let previous = pending[fingerprint] {
                previous.continuation.resume(returning: .superseded)
            }
            pending[fingerprint] = Pending(event: event, ticket: ticket, continuation: continuation)
            Task {
                try? await Task.sleep(for: window)
                self.expire(fingerprint, ticket)
            }
        }
    }

    /// Records the ruling and resumes the parked knock when one is live.
    /// The verdict is held either way — delivery is the asker's problem,
    /// and `collected` clears it once the grant lands.
    public func rule(requestID: UUID, allow: Bool, ruler: UUID) -> Bool {
        guard let fingerprint = requestIndex[requestID]?.fingerprint else { return false }
        let verdict: Verdict = allow ? .allowed(rulerDeviceID: ruler) : .denied
        ruled[fingerprint] = (verdict, Date())
        if let entry = pending.removeValue(forKey: fingerprint) {
            entry.continuation.resume(returning: verdict)
        }
        return true
    }

    /// The verdict reached its app; forget it.
    public func collected(_ fingerprint: String) {
        ruled[fingerprint] = nil
        requestIndex = requestIndex.filter { $0.value.fingerprint != fingerprint }
    }

    /// Retires what the happy path never returns for; call periodically.
    ///
    /// The desk keeps nothing on disk — the session registry is the same
    /// (`docs/wire.md`: "Nothing in the session registry survives the daemon
    /// exiting"), so the desk is one of two such organs, not the only one.
    /// That is exactly why nothing ever noticed it growing: there is no
    /// file to look at. Two tables outlived their own stated window. A
    /// verdict the human allowed is cleared by `collected`, or lazily by a
    /// later knock from the same app — and an app that crashed, was
    /// uninstalled, or simply never came back sends no later knock, so its
    /// verdict stayed resident for the life of the process. An index entry
    /// is cleared only by `collected` too, so every knock that timed out or
    /// was superseded left one.
    ///
    /// `holdWindow` is the desk's one retention rule and both tables now
    /// obey it: a verdict is *held* ten minutes, not kept forever. That rule
    /// is the desk's own and is written down nowhere else — `docs/wire.md`
    /// names `GrantRule` in its frame table and says nothing about how long
    /// the desk keeps one. `docs/ceremony.md` is where the promise is made
    /// to a reader, so it is where the ten minutes has to appear.
    @discardableResult
    public func sweep() -> Int {
        let now = Date()
        var retired = 0
        for (fingerprint, held) in ruled where now.timeIntervalSince(held.at) >= holdWindow {
            ruled[fingerprint] = nil
            retired += 1
        }
        for (requestID, entry) in requestIndex where now.timeIntervalSince(entry.at) >= holdWindow {
            // A knock still parked keeps its index entry: the keeper can
            // rule on it, and that ruling has to find its fingerprint.
            guard pending[entry.fingerprint] == nil else { continue }
            requestIndex[requestID] = nil
            retired += 1
        }
        return retired
    }

    /// The sizes of the desk's tables, for tests that watch them not grow.
    var footprint: (pending: Int, ruled: Int, index: Int) {
        (pending.count, ruled.count, requestIndex.count)
    }

    /// A keeper's live view: currently pending requests replay first, then
    /// new ones as they arrive. Terminating the stream unsubscribes.
    public func subscribe() -> AsyncStream<GrantEvent> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<GrantEvent>.makeStream()
        continuation.onTermination = { _ in
            Task { await self.unsubscribe(id) }
        }
        subscribers[id] = continuation
        for entry in pending.values {
            continuation.yield(entry.event)
        }
        return stream
    }

    private func unsubscribe(_ id: UUID) {
        subscribers[id] = nil
    }

    private func expire(_ fingerprint: String, _ ticket: UUID) {
        // Only the timer that belongs to the CURRENT park may expire it —
        // a re-knock re-arms, and the old timer must miss.
        guard let entry = pending[fingerprint], entry.ticket == ticket else { return }
        pending[fingerprint] = nil
        entry.continuation.resume(returning: .timedOut)
    }
}

/// Reads who a mutually-authenticated peer is from its leaf certificate —
/// the SAN URI the cluster CA issued (`reach://device/<uuid>`, or
/// `reach://app/<device>/<bundleID>`).
public enum PeerIdentity {
    public static func uri(fromDER der: Data) -> String? {
        guard let certificate = try? Certificate(derEncoded: Array(der)),
              let names = try? certificate.extensions.subjectAlternativeNames
        else { return nil }
        for name in names {
            if case .uniformResourceIdentifier(let uri) = name {
                return uri
            }
        }
        return nil
    }

    /// The device UUID out of a `reach://device/<uuid>` URI.
    public static func deviceID(fromURI uri: String) -> UUID? {
        guard uri.hasPrefix("reach://device/") else { return nil }
        return UUID(uuidString: String(uri.dropFirst("reach://device/".count)))
    }
}
