import Foundation

/// The address-only portion of Reach's source classification. It belongs to
/// the shared host because receipts are host state, while endpoint selection
/// and interface ownership remain in the Apple shell.
package enum HostEndpoint {
    package enum AddressKind: Sendable, Equatable {
        case loopback
        case mesh
        case sharedAddressSpace
        case privateNetwork
        case linkLocal
        case publicAddress
    }

    package static func split(_ endpoint: String) -> (host: String, port: UInt16)? {
        guard let colon = endpoint.lastIndex(of: ":") else { return nil }
        let host = String(endpoint[endpoint.startIndex ..< colon])
        let portText = String(endpoint[endpoint.index(after: colon)...])
        guard !host.isEmpty, let port = UInt16(portText) else { return nil }
        return (host, port)
    }

    package static func classify(_ host: String) -> AddressKind? {
        guard let octets = ipv4(host) else { return nil }
        if octets[0] == 127 { return .loopback }
        if isReachMeshAddress(octets) { return .mesh }
        if octets[0] == 169, octets[1] == 254 { return .linkLocal }
        if octets[0] == 100, (64 ... 127).contains(octets[1]) { return .sharedAddressSpace }
        if octets[0] == 10 { return .privateNetwork }
        if octets[0] == 172, (16 ... 31).contains(octets[1]) { return .privateNetwork }
        if octets[0] == 192, octets[1] == 168 { return .privateNetwork }
        return .publicAddress
    }

    package static func isRelayOverlayAddress(_ host: String, network: String?) -> Bool {
        guard let network,
              let address = ipv4(host),
              !isReachMeshAddress(address),
              let slash = network.lastIndex(of: "/"),
              network[network.index(after: slash)...] == "24",
              let base = ipv4(String(network[..<slash]))
        else { return false }
        return address.prefix(3).elementsEqual(base.prefix(3))
    }

    package static func isReachMeshAddress(_ address: [UInt8]) -> Bool {
        address.count == 4 && Array(address.prefix(3)) == [10, 86, 0]
    }

    private static func ipv4(_ host: String) -> [UInt8]? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [UInt8] = []
        for part in parts {
            guard let value = UInt8(part) else { return nil }
            octets.append(value)
        }
        return octets
    }
}
