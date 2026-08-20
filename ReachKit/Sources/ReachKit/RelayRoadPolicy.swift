import ReachWire

/// Pure authority gate between a negotiated Hello and relay persistence.
package enum AuthenticatedRelayUpdate: Sendable, Equatable {
    case stale
    case preserve
    case clear
    case replace([RoadEndpoint])
}

package enum RelayRoadPolicy {
    package static func update(
        from ack: HelloAck,
        replyEpoch: UInt64,
        currentEpoch: UInt64
    ) -> AuthenticatedRelayUpdate {
        guard replyEpoch == currentEpoch else { return .stale }
        guard ack.version == 1 else { return .preserve }
        switch ack.relayRoads {
        case .none: return .preserve
        case .some(let roads) where roads.isEmpty: return .clear
        case .some(let roads): return .replace(roads)
        }
    }
}
