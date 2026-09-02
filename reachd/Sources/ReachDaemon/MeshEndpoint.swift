import Foundation
import ReachWire

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

    /// The complete address predicate shared by endpoint selection and host
    /// readiness. A prefix match on a malformed or longer byte array is not a
    /// Reach mesh address.
    static func isReachMeshAddress(_ address: [UInt8]) -> Bool {
        HostEndpoint.isReachMeshAddress(address)
    }

    public enum Source: Sendable, Equatable {
        /// Read from `meshEndpoint` in config.json.
        case pinned
        /// Assigned by the active system port-mapping broker.
        case mapped
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
            case .mapped:
                "mesh endpoint \(endpoint) (automatically mapped)"
            case .derived:
                "mesh endpoint \(endpoint) (DERIVED — LAN-only; pin meshEndpoint in config.json for the away leg)"
            case .unavailable:
                "mesh endpoint \(endpoint) (NO USABLE ADDRESS — pin meshEndpoint in config.json)"
            }
        }
    }

    public static func resolve(
        config: DaemonConfig,
        mapped: RoadEndpoint? = nil,
        addresses: [[UInt8]]
    ) -> Resolution {
        if let pinned = config.meshEndpoint, !pinned.isEmpty {
            return Resolution(endpoint: pinned, source: .pinned)
        }
        if let mapped {
            return Resolution(endpoint: "\(mapped.host):\(mapped.port)", source: .mapped)
        }
        let candidate = addresses.first { address in
            address.count == 4
                && address != [127, 0, 0, 1]
                && !isReachMeshAddress(address)
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
        HostEndpoint.split(endpoint)
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
        switch HostEndpoint.classify(host) {
        case .loopback: .loopback
        case .mesh: .mesh
        case .sharedAddressSpace: .sharedAddressSpace
        case .privateNetwork: .privateNetwork
        case .linkLocal: .linkLocal
        case .publicAddress: .publicAddress
        case nil: nil
        }
    }

    /// Whether `host` belongs to the operator-configured relay overlay.
    /// Direct mesh classification always takes precedence at the caller.
    package static func isRelayOverlayAddress(_ host: String, network: String?) -> Bool {
        HostEndpoint.isRelayOverlayAddress(host, network: network)
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
