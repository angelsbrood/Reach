import Foundation
import ReachWire
import X509

/// Where app requests wait for a human. `park` suspends the enrollment
/// stream until an admin rules the request over the keeper's authenticated
/// control stream, or the window closes. Events fan out to every live
/// subscriber and replay to late ones — the keeper may open after the app
/// knocks.
public actor GrantDesk {
    public enum Verdict: Sendable, Equatable {
        case allowed(rulerDeviceID: UUID)
        case denied
        case timedOut
    }

    private struct Pending {
        let event: GrantEvent
        let continuation: CheckedContinuation<Verdict, Never>
    }

    private let window: Duration
    private var pending: [UUID: Pending] = [:]
    private var subscribers: [UUID: AsyncStream<GrantEvent>.Continuation] = [:]

    public init(window: Duration = .seconds(120)) {
        self.window = window
    }

    /// Parks a request; resumes with the ruling or a timeout.
    public func park(_ event: GrantEvent) async -> Verdict {
        for subscriber in subscribers.values {
            subscriber.yield(event)
        }
        let requestID = event.requestID
        return await withCheckedContinuation { continuation in
            pending[requestID] = Pending(event: event, continuation: continuation)
            Task {
                try? await Task.sleep(for: window)
                self.expire(requestID)
            }
        }
    }

    public func rule(requestID: UUID, allow: Bool, ruler: UUID) -> Bool {
        guard let entry = pending.removeValue(forKey: requestID) else { return false }
        entry.continuation.resume(returning: allow ? .allowed(rulerDeviceID: ruler) : .denied)
        return true
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

    private func expire(_ requestID: UUID) {
        guard let entry = pending.removeValue(forKey: requestID) else { return }
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
