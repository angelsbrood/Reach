import Foundation

/// The addresses wire-v0 may advertise as ordinary direct candidates.
/// Listener certificates continue to include every local address; this only
/// prevents a same-interface relay alias from being misnamed as a direct road.
package enum DirectAddressSelector {
    package static let directHost: [UInt8] = [10, 86, 0, 1]

    package static func select(
        entries: [LocalAddresses.IPv4Entry],
        desiredRelayAddress: String? = nil,
        appliedRelayAddress: String? = nil
    ) -> [[UInt8]] {
        let meshInterfaces = Set(entries.filter { $0.address == directHost }.map(\.interface))
        let namedRelay = Set(
            [desiredRelayAddress, appliedRelayAddress]
                .compactMap { $0 }
                .compactMap(relayOctets)
        )
        var result: [[UInt8]] = [[127, 0, 0, 1]]
        for entry in entries {
            guard entry.address != [127, 0, 0, 1], !namedRelay.contains(entry.address) else { continue }
            if meshInterfaces.contains(entry.interface), entry.address != directHost {
                continue
            }
            if !result.contains(entry.address) { result.append(entry.address) }
        }
        return result
    }

    package static func current(stateDirectory: URL = DaemonInfo.stateDirectory) -> [[UInt8]] {
        let desired = try? MeshIntentStore.load(in: stateDirectory).relay?.address
        return select(
            entries: LocalAddresses.ipv4Entries(),
            desiredRelayAddress: desired,
            appliedRelayAddress: MeshOwner.appliedRelayAddress()
        )
    }

    private static func relayOctets(_ address: String) -> [UInt8]? {
        guard address.hasSuffix("/32") else { return nil }
        let host = address.dropLast(3)
        let pieces = host.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count == 4 else { return nil }
        var result: [UInt8] = []
        for piece in pieces {
            guard let value = UInt8(piece), String(value) == piece else { return nil }
            result.append(value)
        }
        return result
    }
}
