import Foundation
import ReachWire

/// The three authenticated meanings of `HelloAck.relayRoads` in dialect v1.
package enum RelayRoadDeclaration: Sendable, Equatable {
    case preserve
    case clear
    case replace([RoadEndpoint])

    package var wireValue: [RoadEndpoint]? {
        switch self {
        case .preserve: nil
        case .clear: []
        case .replace(let roads): roads
        }
    }
}

/// Reads host relay authority at Hello time. A declaration is a calling card,
/// not trust: the client still accepts only the pinned cluster mTLS identity.
package enum RelayRoadDeclarationProvider {
    package static func current(
        version: UInt8,
        port: UInt16,
        stateDirectory: URL = DaemonInfo.stateDirectory
    ) -> RelayRoadDeclaration {
        guard version == 1 else { return .preserve }
        let intent: MeshIntent
        do {
            intent = try MeshIntentStore.load(in: stateDirectory)
        } catch {
            return .preserve
        }
        guard let relay = intent.relay else { return .clear }
        let path: MeshOwner.PathInspection
        do {
            path = .available(try MeshOwner.PathEvidence.current())
        } catch {
            path = .unavailable
        }
        return resolve(
            version: version,
            port: port,
            intent: intent,
            evidence: MeshOwner.inspect(),
            addresses: LocalAddresses.ipv4(),
            pathEvidence: path,
            relay: relay
        )
    }

    /// Pure package seam for the declaration truth table.
    package static func resolve(
        version: UInt8,
        port: UInt16,
        intent: MeshIntent,
        evidence: MeshOwner.Evidence,
        addresses: [[UInt8]],
        pathEvidence: MeshOwner.PathInspection,
        relay: MeshIntent.Relay? = nil
    ) -> RelayRoadDeclaration {
        guard version == 1 else { return .preserve }
        guard let relay = relay ?? intent.relay else { return .clear }
        let finding = MeshOwner.verdict(
            intent: .success(intent),
            addresses: addresses,
            evidence: evidence,
            pathEvidence: pathEvidence
        )
        guard finding.level == .pass || finding.level == .warn,
              relay.address.hasSuffix("/32"),
              port != 0
        else { return .preserve }
        return .replace([
            RoadEndpoint(host: String(relay.address.dropLast(3)), port: port),
        ])
    }
}
