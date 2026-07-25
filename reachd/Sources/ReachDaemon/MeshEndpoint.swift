import Foundation

/// Where the phone is told to send WireGuard packets — and, just as
/// importantly, where that answer came from.
///
/// A pinned endpoint and a derived one look identical once they are a string,
/// which is how a daemon comes up looking healthy while handing out an address
/// no phone off this LAN can reach. Everything here exists so the two can be
/// told apart by a human reading one line of output.
public enum MeshEndpoint {
    /// WireGuard's listen port on the host, fixed across the rig.
    public static let port: UInt16 = 51820

    /// Reach's own mesh subnet. Deriving an endpoint from an address inside it
    /// would tell a phone to reach the mesh by way of the mesh.
    static let meshPrefix: [UInt8] = [10, 86, 0]

    public enum Source: Sendable, Equatable {
        /// Read from `meshEndpoint` in config.json.
        case pinned
        /// Guessed from a local address. LAN-only: correct for rehearsals on
        /// one network, useless the moment the phone leaves it.
        case derived
        /// Nothing suitable to derive from; loopback stands in.
        case unavailable
    }

    public struct Resolution: Sendable, Equatable {
        public let endpoint: String
        public let source: Source

        public init(endpoint: String, source: Source) {
            self.endpoint = endpoint
            self.source = source
        }

        /// The one line `reachd serve` prints, and the reason step 8's
        /// "confirm the startup line" is a check rather than a glance.
        public var summary: String {
            switch source {
            case .pinned:
                "mesh endpoint \(endpoint) (pinned)"
            case .derived:
                "mesh endpoint \(endpoint) (DERIVED — LAN-only; pin meshEndpoint in config.json for the away leg)"
            case .unavailable:
                "mesh endpoint \(endpoint) (NO USABLE ADDRESS — pin meshEndpoint in config.json)"
            }
        }
    }

    public static func resolve(config: DaemonConfig, addresses: [[UInt8]]) -> Resolution {
        if let pinned = config.meshEndpoint, !pinned.isEmpty {
            return Resolution(endpoint: pinned, source: .pinned)
        }
        let candidate = addresses.first { address in
            address.count == 4
                && address != [127, 0, 0, 1]
                && Array(address.prefix(3)) != meshPrefix
        }
        guard let candidate else {
            return Resolution(endpoint: "127.0.0.1:\(port)", source: .unavailable)
        }
        return Resolution(endpoint: "\(string(from: candidate)):\(port)", source: .derived)
    }

    public static func string(from address: [UInt8]) -> String {
        address.map(String.init).joined(separator: ".")
    }

    /// Split `host:port`. Rightmost colon wins, so a bracketed IPv6 literal
    /// fails cleanly rather than being silently mangled.
    public static func split(_ endpoint: String) -> (host: String, port: UInt16)? {
        guard let colon = endpoint.lastIndex(of: ":") else { return nil }
        let host = String(endpoint[endpoint.startIndex..<colon])
        let portText = String(endpoint[endpoint.index(after: colon)...])
        guard !host.isEmpty, let port = UInt16(portText) else { return nil }
        return (host, port)
    }

    /// What kind of address a host is, and therefore who can reach it.
    public enum AddressKind: Sendable, Equatable {
        case loopback
        /// Inside Reach's own mesh — circular as an endpoint.
        case mesh
        /// 100.64/10: carrier-grade NAT, and also where tailnets live.
        case sharedAddressSpace
        /// RFC1918. Dialable only from that network, or through a forward.
        case privateNetwork
        case linkLocal
        case publicAddress
    }

    public static func classify(_ host: String) -> AddressKind? {
        guard let octets = ipv4(host) else { return nil }
        if octets[0] == 127 { return .loopback }
        if Array(octets.prefix(3)) == meshPrefix { return .mesh }
        if octets[0] == 169, octets[1] == 254 { return .linkLocal }
        if octets[0] == 100, (64...127).contains(octets[1]) { return .sharedAddressSpace }
        if octets[0] == 10 { return .privateNetwork }
        if octets[0] == 172, (16...31).contains(octets[1]) { return .privateNetwork }
        if octets[0] == 192, octets[1] == 168 { return .privateNetwork }
        return .publicAddress
    }

    static func ipv4(_ host: String) -> [UInt8]? {
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
