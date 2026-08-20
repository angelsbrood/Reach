import Crypto
import Darwin
import Foundation

package enum MeshIntentError: Error, Sendable, CustomStringConvertible, LocalizedError {
    case refused(String)

    package var description: String {
        switch self {
        case .refused(let reason): reason
        }
    }

    package var errorDescription: String? { description }
}

/// The login-owned, non-secret description of the mesh Reach intends the
/// privileged owner to hold. The private host key deliberately lives only in
/// `wg/server.key` and in the one mode-0600 staging file compiled on demand.
package struct MeshIntent: Sendable, Equatable {
    package static let version = 1
    package static let relayVersion = 2
    package static let address = "10.86.0.1/24"
    package static let port = 51_820
    package static let mtu = 1_280
    package static let maximumPeers = 253
    package static let maximumKeepalive = 3_600
    package static let relayKeepalive = 25
    package static let fileName = "mesh-intent.json"
    package static let stagingDirectoryName = "mesh-stage"

    package struct Peer: Sendable, Equatable {
        package var publicKey: String
        package var allowedIP: String
        package var keepalive: Int

        package init(publicKey: String, allowedIP: String, keepalive: Int = 0) {
            self.publicKey = publicKey
            self.allowedIP = allowedIP
            self.keepalive = keepalive
        }
    }

    package struct Relay: Sendable, Equatable {
        package var network: String
        package var address: String
        package var hubPublicKey: String
        package var endpoint: String
        package var keepalive: Int
        package var routes: [String]

        package init(
            network: String,
            hubPublicKey: String,
            endpoint: String,
            directPeers: [Peer]
        ) throws {
            let prefix = try MeshIntent.relayPrefix(network)
            self.network = network
            address = "\(prefix.0).\(prefix.1).\(prefix.2).1/32"
            self.hubPublicKey = hubPublicKey
            self.endpoint = try MeshIntent.canonicalRelayEndpoint(endpoint, relayPrefix: prefix)
            keepalive = MeshIntent.relayKeepalive
            routes = try directPeers.map { peer in
                guard let ordinal = MeshIntent.peerOrdinal(peer.allowedIP) else {
                    throw MeshIntentError.refused("relay routes require canonical direct peer ordinals")
                }
                return "\(prefix.0).\(prefix.1).\(prefix.2).\(ordinal)/32"
            }
        }

        package init(
            network: String,
            address: String,
            hubPublicKey: String,
            endpoint: String,
            keepalive: Int,
            routes: [String]
        ) {
            self.network = network
            self.address = address
            self.hubPublicKey = hubPublicKey
            self.endpoint = endpoint
            self.keepalive = keepalive
            self.routes = routes
        }

        package func rederived(for directPeers: [Peer]) throws -> Relay {
            try Relay(
                network: network,
                hubPublicKey: hubPublicKey,
                endpoint: endpoint,
                directPeers: directPeers
            )
        }
    }

    package var generation: UInt64
    package var publicKey: String
    package var peers: [Peer]
    package var relay: Relay?

    package init(generation: UInt64, publicKey: String, peers: [Peer], relay: Relay? = nil) throws {
        self.generation = generation
        self.publicKey = publicKey
        self.peers = peers
        self.relay = relay
        try validate(allowEmpty: true)
    }

    package func validate(allowEmpty: Bool) throws {
        guard generation > 0 else { throw MeshIntentError.refused("mesh generation must be positive") }
        _ = try Self.decodeKey(publicKey, role: "host public key")
        guard peers.count <= Self.maximumPeers, allowEmpty || !peers.isEmpty else {
            throw MeshIntentError.refused("mesh peer count is outside 1...\(Self.maximumPeers)")
        }
        var keys = Set<String>()
        var routes = Set<String>()
        var previousOrdinal = 1
        for peer in peers {
            _ = try Self.decodeKey(peer.publicKey, role: "peer public key")
            guard keys.insert(peer.publicKey).inserted else {
                throw MeshIntentError.refused("mesh intent repeats a peer key")
            }
            guard let ordinal = Self.peerOrdinal(peer.allowedIP) else {
                throw MeshIntentError.refused("mesh peer route is outside 10.86.0.2...254/32")
            }
            guard routes.insert(peer.allowedIP).inserted else {
                throw MeshIntentError.refused("mesh intent repeats a peer route")
            }
            guard ordinal > previousOrdinal else {
                throw MeshIntentError.refused("mesh peers are not in ascending route order")
            }
            previousOrdinal = ordinal
            guard (0...Self.maximumKeepalive).contains(peer.keepalive) else {
                throw MeshIntentError.refused("mesh peer keepalive is outside 0...\(Self.maximumKeepalive)")
            }
        }
        if let relay {
            guard !peers.isEmpty else {
                throw MeshIntentError.refused("relay intent requires 1...\(Self.maximumPeers) direct peers")
            }
            let prefix = try Self.relayPrefix(relay.network)
            guard relay.address == "\(prefix.0).\(prefix.1).\(prefix.2).1/32" else {
                throw MeshIntentError.refused("relay host address is not the selected network's .1/32")
            }
            _ = try Self.decodeKey(relay.hubPublicKey, role: "relay hub public key")
            guard relay.hubPublicKey != publicKey,
                  !peers.contains(where: { $0.publicKey == relay.hubPublicKey })
            else {
                throw MeshIntentError.refused("relay hub key is reused by the host or a device")
            }
            guard relay.endpoint == (try Self.canonicalRelayEndpoint(relay.endpoint, relayPrefix: prefix)) else {
                throw MeshIntentError.refused("relay endpoint is not canonical")
            }
            guard relay.keepalive == Self.relayKeepalive else {
                throw MeshIntentError.refused("relay keepalive must be \(Self.relayKeepalive)")
            }
            let expectedRoutes = try peers.map { peer -> String in
                guard let ordinal = Self.peerOrdinal(peer.allowedIP) else {
                    throw MeshIntentError.refused("relay routes require canonical direct peer ordinals")
                }
                return "\(prefix.0).\(prefix.1).\(prefix.2).\(ordinal)/32"
            }
            guard relay.routes == expectedRoutes else {
                throw MeshIntentError.refused("relay routes do not match the ordered direct peer ordinals")
            }
        }
    }

    package static func decode(_ data: Data) throws -> MeshIntent {
        let root = try StrictJSON.parse(data)
        guard case .object(let raw) = root else {
            throw MeshIntentError.refused("mesh JSON object expected")
        }
        let decodedVersion = try raw.integer("version")
        let keys = Set(["version", "generation", "publicKey", "address", "port", "mtu", "peers"])
        let object: [String: StrictJSONValue]
        switch decodedVersion {
        case version:
            object = try root.object(exactly: keys)
        case relayVersion:
            let actual = Set(raw.keys)
            guard actual == keys || actual == keys.union(["relay"]) else {
                throw MeshIntentError.refused("mesh JSON has missing or unknown fields")
            }
            object = raw
        default:
            throw MeshIntentError.refused("unsupported mesh intent version")
        }
        guard try object.string("address") == address,
              try object.integer("port") == port,
              try object.integer("mtu") == mtu
        else {
            throw MeshIntentError.refused("mesh intent interface policy is not Reach's fixed interface")
        }
        let generation = try object.unsigned("generation")
        let publicKey = try object.string("publicKey")
        let peers = try object.array("peers").map { value in
            let peer = try value.object(exactly: ["publicKey", "allowedIP", "keepalive"])
            return Peer(
                publicKey: try peer.string("publicKey"),
                allowedIP: try peer.string("allowedIP"),
                keepalive: try peer.integer("keepalive")
            )
        }
        let relay: Relay?
        if decodedVersion == relayVersion, object["relay"] != nil {
            let value = try object.value("relay").object(exactly: [
                "network", "address", "hubPublicKey", "endpoint", "keepalive", "routes",
            ])
            relay = Relay(
                network: try value.string("network"),
                address: try value.string("address"),
                hubPublicKey: try value.string("hubPublicKey"),
                endpoint: try value.string("endpoint"),
                keepalive: try value.integer("keepalive"),
                routes: try value.array("routes").map { route in
                    guard case .string(let text) = route else {
                        throw MeshIntentError.refused("mesh JSON relay route must be a string")
                    }
                    return text
                }
            )
        } else {
            relay = nil
        }
        return try MeshIntent(generation: generation, publicKey: publicKey, peers: peers, relay: relay)
    }

    package func encoded() throws -> Data {
        try validate(allowEmpty: true)
        let peersJSON = try peers.map { peer in
            """
                {
                  "publicKey": \(try Self.jsonString(peer.publicKey)),
                  "allowedIP": \(try Self.jsonString(peer.allowedIP)),
                  "keepalive": \(peer.keepalive)
                }
            """
        }.joined(separator: ",\n")
        guard let relay else {
            return Data("""
                {
                  "version": \(Self.version),
                  "generation": \(generation),
                  "publicKey": \(try Self.jsonString(publicKey)),
                  "address": \(try Self.jsonString(Self.address)),
                  "port": \(Self.port),
                  "mtu": \(Self.mtu),
                  "peers": [
                \(peersJSON)
                  ]
                }

                """.utf8)
        }
        let routesJSON = try relay.routes.map(Self.jsonString).joined(separator: ", ")
        return Data("""
            {
              "version": \(Self.relayVersion),
              "generation": \(generation),
              "publicKey": \(try Self.jsonString(publicKey)),
              "address": \(try Self.jsonString(Self.address)),
              "port": \(Self.port),
              "mtu": \(Self.mtu),
              "peers": [
            \(peersJSON)
              ],
              "relay": {
                "network": \(try Self.jsonString(relay.network)),
                "address": \(try Self.jsonString(relay.address)),
                "hubPublicKey": \(try Self.jsonString(relay.hubPublicKey)),
                "endpoint": \(try Self.jsonString(relay.endpoint)),
                "keepalive": \(relay.keepalive),
                "routes": [\(routesJSON)]
              }
            }

            """.utf8)
    }

    package var publicDigest: String {
        guard let relay else { return Self.digest(v1PublicSource) }
        var source = "reach-mesh-public-v2\n"
        source += "version=\(Self.relayVersion)\n"
        source += "generation=\(generation)\n"
        source += "directDigest=\(directDigest)\n"
        source += "relayDigest=\(Self.relayDigest(relay))\n"
        return Self.digest(source)
    }

    package var directDigest: String {
        var source = "reach-mesh-direct-v1\n"
        source += "publicKey=\(publicKey)\n"
        source += "address=\(Self.address)\n"
        source += "port=\(Self.port)\n"
        source += "mtu=\(Self.mtu)\n"
        source += "peerCount=\(peers.count)\n"
        for (index, peer) in peers.enumerated() {
            source += "peer.\(index).publicKey=\(peer.publicKey)\n"
            source += "peer.\(index).allowedIP=\(peer.allowedIP)\n"
            source += "peer.\(index).keepalive=\(peer.keepalive)\n"
        }
        return Self.digest(source)
    }

    package var relayDigest: String? {
        relay.map(Self.relayDigest)
    }

    private var v1PublicSource: String {
        var source = "reach-mesh-public-v1\n"
        source += "version=\(Self.version)\n"
        source += "generation=\(generation)\n"
        source += "publicKey=\(publicKey)\n"
        source += "address=\(Self.address)\n"
        source += "port=\(Self.port)\n"
        source += "mtu=\(Self.mtu)\n"
        source += "peerCount=\(peers.count)\n"
        for (index, peer) in peers.enumerated() {
            source += "peer.\(index).publicKey=\(peer.publicKey)\n"
            source += "peer.\(index).allowedIP=\(peer.allowedIP)\n"
            source += "peer.\(index).keepalive=\(peer.keepalive)\n"
        }
        return source
    }

    private static func relayDigest(_ relay: Relay) -> String {
        var source = "reach-mesh-relay-v1\n"
        source += "network=\(relay.network)\n"
        source += "address=\(relay.address)\n"
        source += "hubPublicKey=\(relay.hubPublicKey)\n"
        source += "endpoint=\(relay.endpoint)\n"
        source += "keepalive=\(relay.keepalive)\n"
        source += "routeCount=\(relay.routes.count)\n"
        for (index, route) in relay.routes.enumerated() {
            source += "route.\(index)=\(route)\n"
        }
        return digest(source)
    }

    private static func digest(_ source: String) -> String {
        SHA256.hash(data: Data(source.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    package static func importLegacy(
        _ text: String,
        privateKey: String,
        publicKey: String
    ) throws -> MeshIntent {
        enum Section { case none, interface, peer }
        let allowedInterface = Set(["privatekey", "address", "listenport", "mtu"])
        let allowedPeer = Set(["publickey", "allowedips", "persistentkeepalive"])
        var section = Section.none
        var interface: [String: String] = [:]
        var interfaceCount = 0
        var peers: [[String: String]] = []

        for raw in text.split(omittingEmptySubsequences: false, whereSeparator: \Character.isNewline) {
            let withoutComment = raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
            let line = withoutComment.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty else { continue }
            if line.hasPrefix("[") {
                switch line.lowercased() {
                case "[interface]":
                    interfaceCount += 1
                    section = .interface
                case "[peer]":
                    peers.append([:])
                    section = .peer
                default:
                    throw MeshIntentError.refused("legacy WireGuard config contains an unknown section")
                }
                continue
            }
            guard let equals = line.firstIndex(of: "="), section != .none else {
                throw MeshIntentError.refused("legacy WireGuard config contains text outside a section")
            }
            let key = line[..<equals].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespacesAndNewlines)
            switch section {
            case .interface:
                guard allowedInterface.contains(key), interface[key] == nil else {
                    throw MeshIntentError.refused("legacy WireGuard config contains an unknown or duplicate interface field")
                }
                interface[key] = value
            case .peer:
                guard allowedPeer.contains(key), peers[peers.count - 1][key] == nil else {
                    throw MeshIntentError.refused("legacy WireGuard config contains an unknown or duplicate peer field")
                }
                peers[peers.count - 1][key] = value
            case .none:
                throw MeshIntentError.refused("legacy WireGuard config contains text outside a section")
            }
        }
        guard interfaceCount == 1 else {
            throw MeshIntentError.refused("legacy WireGuard config must contain one interface section")
        }
        guard interface["privatekey"] == privateKey,
              interface["address"] == address,
              interface["listenport"] == String(port),
              interface["mtu"].map({ $0 == String(mtu) }) ?? true
        else {
            throw MeshIntentError.refused("legacy WireGuard interface does not match Reach's fixed policy or host key")
        }
        var importedPeers = try peers.map { peer -> Peer in
            guard let key = peer["publickey"], let route = peer["allowedips"] else {
                throw MeshIntentError.refused("legacy WireGuard peer is incomplete")
            }
            guard !route.contains(",") else {
                throw MeshIntentError.refused("legacy WireGuard peer has more than one route")
            }
            let keepalive: Int
            if let value = peer["persistentkeepalive"] {
                guard let parsed = Int(value) else {
                    throw MeshIntentError.refused("legacy WireGuard peer keepalive is not an integer")
                }
                keepalive = parsed
            } else {
                keepalive = 0
            }
            return Peer(publicKey: key, allowedIP: route, keepalive: keepalive)
        }
        importedPeers.sort {
            (peerOrdinal($0.allowedIP) ?? Int.max) < (peerOrdinal($1.allowedIP) ?? Int.max)
        }
        return try MeshIntent(generation: 1, publicKey: publicKey, peers: importedPeers)
    }

    package static func peerOrdinal(_ route: String) -> Int? {
        let prefix = "10.86.0."
        guard route.hasPrefix(prefix), route.hasSuffix("/32") else { return nil }
        let start = route.index(route.startIndex, offsetBy: prefix.count)
        let end = route.index(route.endIndex, offsetBy: -3)
        guard start < end, let value = Int(route[start..<end]), (2...254).contains(value), route == "\(prefix)\(value)/32" else {
            return nil
        }
        return value
    }

    package static func relayPrefix(_ network: String) throws -> (UInt8, UInt8, UInt8) {
        guard network.hasSuffix("/24") else {
            throw MeshIntentError.refused("relay network must be a canonical private /24")
        }
        let host = String(network.dropLast(3))
        guard let octets = ipv4(host), octets[3] == 0, network == "\(host)/24" else {
            throw MeshIntentError.refused("relay network must be a canonical private /24")
        }
        let isPrivate = octets[0] == 10
            || (octets[0] == 172 && (16...31).contains(octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
        guard isPrivate, Array(octets.prefix(3)) != [10, 86, 0] else {
            throw MeshIntentError.refused("relay network must be private and must not overlap 10.86.0.0/24")
        }
        return (octets[0], octets[1], octets[2])
    }

    package static func canonicalRelayEndpoint(
        _ endpoint: String,
        relayPrefix: (UInt8, UInt8, UInt8)
    ) throws -> String {
        let host: String
        let portText: String
        let renderedHost: String
        if endpoint.hasPrefix("[") {
            guard let close = endpoint.firstIndex(of: "]"),
                  endpoint.index(after: close) < endpoint.endIndex,
                  endpoint[endpoint.index(after: close)] == ":"
            else {
                throw MeshIntentError.refused("relay endpoint must be a stable numeric host:port")
            }
            host = String(endpoint[endpoint.index(after: endpoint.startIndex)..<close])
            portText = String(endpoint[endpoint.index(close, offsetBy: 2)...])
            var address = in6_addr()
            guard !host.isEmpty, host.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else {
                throw MeshIntentError.refused("relay endpoint must be numeric IPv4 or bracketed IPv6")
            }
            let bytes = withUnsafeBytes(of: &address) { Array($0) }
            let isLoopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
            let isLinkLocal = bytes[0] == 0xFE && bytes[1] & 0xC0 == 0x80
            let isIPv4Mapped = bytes.prefix(10).allSatisfy { $0 == 0 }
                && bytes[10] == 0xFF && bytes[11] == 0xFF
            guard !bytes.allSatisfy({ $0 == 0 }), !isLoopback, !isLinkLocal,
                  !isIPv4Mapped, bytes.first != 0xFF
            else {
                throw MeshIntentError.refused("relay endpoint address is unsafe")
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)) != nil else {
                throw MeshIntentError.refused("relay endpoint IPv6 rendering failed")
            }
            let terminator = buffer.firstIndex(of: 0) ?? buffer.endIndex
            let canonical = String(
                decoding: buffer[..<terminator].map { UInt8(bitPattern: $0) },
                as: UTF8.self
            ).lowercased()
            guard host.lowercased() == canonical else {
                throw MeshIntentError.refused("relay endpoint IPv6 address is not canonical")
            }
            renderedHost = "[\(canonical)]"
        } else {
            guard let colon = endpoint.lastIndex(of: ":"),
                  !endpoint[..<colon].contains(":"), colon > endpoint.startIndex
            else {
                throw MeshIntentError.refused("relay endpoint must be numeric IPv4 or bracketed IPv6")
            }
            host = String(endpoint[..<colon])
            portText = String(endpoint[endpoint.index(after: colon)...])
            guard let octets = ipv4(host), host == octets.map(String.init).joined(separator: ".") else {
                throw MeshIntentError.refused("relay endpoint IPv4 address is not canonical")
            }
            guard octets != [0, 0, 0, 0], octets != [255, 255, 255, 255],
                  octets[0] != 127,
                  !(octets[0] == 169 && octets[1] == 254),
                  !(224...239).contains(octets[0]),
                  Array(octets.prefix(3)) != [10, 86, 0],
                  Array(octets.prefix(3)) != [relayPrefix.0, relayPrefix.1, relayPrefix.2]
            else {
                throw MeshIntentError.refused("relay endpoint address is unsafe or recursive through an overlay")
            }
            renderedHost = host
        }
        guard let port = Int(portText), (1_024...65_535).contains(port), String(port) == portText else {
            throw MeshIntentError.refused("relay endpoint port is outside 1024...65535")
        }
        return "\(renderedHost):\(port)"
    }

    private static func ipv4(_ host: String) -> [UInt8]? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [UInt8] = []
        for part in parts {
            guard let value = UInt8(part), String(value) == part else { return nil }
            octets.append(value)
        }
        return octets
    }

    package static func decodeKey(_ value: String, role: String) throws -> Data {
        guard let data = Data(base64Encoded: value), data.count == 32,
              data.base64EncodedString() == value
        else {
            throw MeshIntentError.refused("\(role) is not canonical 32-byte base64")
        }
        return data
    }

    private static func jsonString(_ value: String) throws -> String {
        String(decoding: try JSONEncoder().encode(value), as: UTF8.self)
    }
}

/// The root helper's complete, secret-bearing input. It exists in memory and
/// in one consumed mode-0600 staging file; its public digest deliberately
/// matches the Go helper's implementation without including the private key.
package struct MeshSpecification: Sendable, Equatable {
    package let intent: MeshIntent
    package let privateKey: String

    package init(intent: MeshIntent, privateKey: String) throws {
        try intent.validate(allowEmpty: false)
        let privateData = try MeshIntent.decodeKey(privateKey, role: "host private key")
        let expected = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateData)
            .publicKey.rawRepresentation
        let publicData = try MeshIntent.decodeKey(intent.publicKey, role: "host public key")
        guard expected == publicData else {
            throw MeshIntentError.refused("mesh host private and public keys do not agree")
        }
        self.intent = intent
        self.privateKey = privateKey
    }

    package var publicDigest: String { intent.publicDigest }

    package func encoded() throws -> Data {
        let peersJSON = try intent.peers.map { peer in
            """
                {
                  "publicKey": \(try jsonString(peer.publicKey)),
                  "allowedIP": \(try jsonString(peer.allowedIP)),
                  "keepalive": \(peer.keepalive)
                }
            """
        }.joined(separator: ",\n")
        guard let relay = intent.relay else {
            return Data("""
                {
                  "version": \(MeshIntent.version),
                  "generation": \(intent.generation),
                  "privateKey": \(try jsonString(privateKey)),
                  "publicKey": \(try jsonString(intent.publicKey)),
                  "address": \(try jsonString(MeshIntent.address)),
                  "port": \(MeshIntent.port),
                  "mtu": \(MeshIntent.mtu),
                  "peers": [
                \(peersJSON)
                  ]
                }

                """.utf8)
        }
        let routesJSON = try relay.routes.map(jsonString).joined(separator: ", ")
        return Data("""
            {
              "version": \(MeshIntent.relayVersion),
              "generation": \(intent.generation),
              "privateKey": \(try jsonString(privateKey)),
              "publicKey": \(try jsonString(intent.publicKey)),
              "address": \(try jsonString(MeshIntent.address)),
              "port": \(MeshIntent.port),
              "mtu": \(MeshIntent.mtu),
              "peers": [
            \(peersJSON)
              ],
              "relay": {
                "network": \(try jsonString(relay.network)),
                "address": \(try jsonString(relay.address)),
                "hubPublicKey": \(try jsonString(relay.hubPublicKey)),
                "endpoint": \(try jsonString(relay.endpoint)),
                "keepalive": \(relay.keepalive),
                "routes": [\(routesJSON)]
              }
            }

            """.utf8)
    }

    private func jsonString(_ value: String) throws -> String {
        String(decoding: try JSONEncoder().encode(value), as: UTF8.self)
    }
}

package enum MeshIntentStore {
    package static let lockFileName = "mesh-intent.lock"

    package static func intentURL(in stateDirectory: URL) -> URL {
        stateDirectory.appendingPathComponent(MeshIntent.fileName)
    }

    package static func load(in stateDirectory: URL) throws -> MeshIntent {
        try MeshIntent.decode(readSecureUserFile(intentURL(in: stateDirectory), exactMode: 0o600))
    }

    package static func loadOrImport(
        stateDirectory: URL,
        legacyConf: URL?,
        privateKey: String,
        publicKey: String
    ) throws -> MeshIntent {
        let url = intentURL(in: stateDirectory)
        if FileManager.default.fileExists(atPath: url.path) {
            let intent = try load(in: stateDirectory)
            guard intent.publicKey == publicKey else {
                throw MeshIntentError.refused("mesh intent host key does not match wg/server.pub")
            }
            return intent
        }
        let intent: MeshIntent
        if let legacyConf, FileManager.default.fileExists(atPath: legacyConf.path) {
            let data = try readSecureUserFile(legacyConf, exactMode: 0o600)
            guard let text = String(data: data, encoding: .utf8) else {
                throw MeshIntentError.refused("legacy WireGuard config is not UTF-8")
            }
            intent = try MeshIntent.importLegacy(text, privateKey: privateKey, publicKey: publicKey)
        } else {
            intent = try MeshIntent(generation: 1, publicKey: publicKey, peers: [])
        }
        try save(intent, in: stateDirectory)
        return intent
    }

    package static func save(_ intent: MeshIntent, in stateDirectory: URL) throws {
        try intent.validate(allowEmpty: true)
        // The canonical state root predates this feature and may be 0755; it
        // must be owned by this user and not writable by anyone else, but the
        // secret-bearing staging child below is the directory that must be
        // exactly 0700 for the root helper's handoff contract.
        try ensureUserDirectory(stateDirectory, mode: 0o700, exactMode: false)
        try writeUserFileAtomically(intent.encoded(), to: intentURL(in: stateDirectory), mode: 0o600)
    }

    package static func update(
        in stateDirectory: URL,
        _ mutation: (inout MeshIntent) throws -> Bool
    ) throws -> (intent: MeshIntent, changed: Bool) {
        try ensureUserDirectory(stateDirectory, mode: 0o700, exactMode: false)
        let lockURL = stateDirectory.appendingPathComponent(lockFileName)
        let fd = open(lockURL.path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw MeshIntentError.refused("could not open the mesh intent lock") }
        defer { close(fd) }
        var status = stat()
        guard fstat(fd, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == getuid(), status.st_nlink == 1,
              status.st_mode & 0o777 == 0o600,
              flock(fd, LOCK_EX) == 0
        else {
            throw MeshIntentError.refused("mesh intent lock has unsafe ownership or mode")
        }
        defer { _ = flock(fd, LOCK_UN) }
        var intent = try load(in: stateDirectory)
        let changed = try mutation(&intent)
        try intent.validate(allowEmpty: true)
        if changed {
            try save(intent, in: stateDirectory)
        }
        return (intent, changed)
    }

    package static func setRelay(
        in stateDirectory: URL,
        network: String,
        hubPublicKey: String,
        endpoint: String,
        activeRoutes: [MeshIPv4Prefix]? = nil
    ) throws -> (intent: MeshIntent, changed: Bool) {
        let routes = try activeRoutes ?? MeshRelayRouteInventory.current()
        return try update(in: stateDirectory) { intent in
            guard !intent.peers.isEmpty else {
                throw MeshIntentError.refused("relay intent requires at least one enrolled direct peer")
            }
            let candidate = try MeshIntent.Relay(
                network: network,
                hubPublicKey: hubPublicKey,
                endpoint: endpoint,
                directPeers: intent.peers
            )
            try MeshRelayRouteInventory.validate(
                relayNetwork: candidate.network,
                currentRelay: intent.relay,
                routes: routes
            )
            guard intent.relay != candidate else { return false }
            guard intent.generation < UInt64.max else {
                throw MeshIntentError.refused("mesh intent generation is exhausted")
            }
            intent.relay = candidate
            intent.generation += 1
            return true
        }
    }

    package static func removeRelay(
        in stateDirectory: URL
    ) throws -> (intent: MeshIntent, changed: Bool) {
        try update(in: stateDirectory) { intent in
            guard intent.relay != nil else { return false }
            guard intent.generation < UInt64.max else {
                throw MeshIntentError.refused("mesh intent generation is exhausted")
            }
            intent.relay = nil
            intent.generation += 1
            return true
        }
    }

    package static func specification(
        in stateDirectory: URL,
        devices: [DeviceRegistry.Device]
    ) throws -> MeshSpecification {
        let intent = try load(in: stateDirectory)
        let active = devices.filter(\.active)
        guard !active.isEmpty else {
            throw MeshIntentError.refused("the mesh has no active enrolled peers")
        }
        let expected = active.map {
            MeshIntent.Peer(
                publicKey: $0.wgPub.base64EncodedString(),
                allowedIP: "\($0.assignedIP)/32"
            )
        }.sorted {
            (MeshIntent.peerOrdinal($0.allowedIP) ?? Int.max)
                < (MeshIntent.peerOrdinal($1.allowedIP) ?? Int.max)
        }
        guard intent.peers == expected else {
            throw MeshIntentError.refused("mesh intent and the enrolled-device registry do not agree")
        }
        let privateKey = try readCanonicalKey(
            stateDirectory.appendingPathComponent("wg/server.key"),
            role: "host private key",
            exactMode: 0o600
        )
        let publicKey = try readCanonicalKey(
            stateDirectory.appendingPathComponent("wg/server.pub"),
            role: "host public key",
            exactMode: nil
        )
        guard publicKey == intent.publicKey else {
            throw MeshIntentError.refused("mesh intent host key does not match wg/server.pub")
        }
        return try MeshSpecification(intent: intent, privateKey: privateKey)
    }

    package static func stage(_ specification: MeshSpecification, in stateDirectory: URL) throws -> URL {
        let directory = stateDirectory.appendingPathComponent(MeshIntent.stagingDirectoryName, isDirectory: true)
        try ensureUserDirectory(directory, mode: 0o700, exactMode: true)
        let url = directory.appendingPathComponent("mesh-\(specification.intent.generation)-\(UUID().uuidString).json")
        try createExclusiveUserFile(specification.encoded(), at: url, mode: 0o600)
        return url
    }

    package static func readCanonicalKey(
        _ url: URL,
        role: String,
        exactMode: mode_t?
    ) throws -> String {
        let data = try readSecureUserFile(url, exactMode: exactMode)
        guard let text = String(data: data, encoding: .utf8) else {
            throw MeshIntentError.refused("\(role) is not UTF-8")
        }
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        _ = try MeshIntent.decodeKey(value, role: role)
        return value
    }

    private static func readSecureUserFile(_ url: URL, exactMode: mode_t?) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw MeshIntentError.refused("\(url.path) will not read securely") }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == getuid(), before.st_nlink == 1,
              before.st_size > 0, before.st_size <= 65_536,
              exactMode.map({ before.st_mode & 0o777 == $0 }) ?? (before.st_mode & 0o022 == 0)
        else {
            throw MeshIntentError.refused("\(url.path) has unsafe ownership, mode, link count, or size")
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while true {
            let count = read(fd, &buffer, buffer.count)
            guard count >= 0 else { throw MeshIntentError.refused("\(url.path) changed or failed while reading") }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
            guard data.count <= 65_536 else { throw MeshIntentError.refused("\(url.path) is oversized") }
        }
        var after = stat()
        guard fstat(fd, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              data.count == after.st_size
        else {
            throw MeshIntentError.refused("\(url.path) changed while reading")
        }
        return data
    }

    private static func ensureUserDirectory(_ url: URL, mode: mode_t, exactMode: Bool) throws {
        if mkdir(url.path, mode) != 0, errno != EEXIST {
            throw MeshIntentError.refused("could not create secure mesh state")
        }
        var status = stat()
        guard lstat(url.path, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == getuid(),
              exactMode ? status.st_mode & 0o777 == mode : status.st_mode & 0o022 == 0
        else {
            throw MeshIntentError.refused("mesh state directory has unsafe ownership or mode")
        }
    }

    private static func writeUserFileAtomically(_ data: Data, to url: URL, mode: mode_t) throws {
        if FileManager.default.fileExists(atPath: url.path) {
            var status = stat()
            guard lstat(url.path, &status) == 0,
                  status.st_mode & S_IFMT == S_IFREG,
                  status.st_uid == getuid(), status.st_nlink == 1
            else {
                throw MeshIntentError.refused("mesh intent target is unsafe")
            }
        }
        let temporary = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        try createExclusiveUserFile(data, at: temporary, mode: mode)
        guard rename(temporary.path, url.path) == 0 else {
            _ = unlink(temporary.path)
            throw MeshIntentError.refused("could not replace mesh intent")
        }
        let directory = open(url.deletingLastPathComponent().path, O_RDONLY | O_CLOEXEC)
        guard directory >= 0 else {
            throw MeshIntentError.refused("could not open mesh state for durable intent replacement")
        }
        defer { close(directory) }
        guard fsync(directory) == 0 else {
            throw MeshIntentError.refused("could not make the mesh intent replacement durable")
        }
    }

    private static func createExclusiveUserFile(_ data: Data, at url: URL, mode: mode_t) throws {
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode)
        guard fd >= 0 else { throw MeshIntentError.refused("could not create secure mesh staging file") }
        var succeeded = false
        defer {
            close(fd)
            if !succeeded { _ = unlink(url.path) }
        }
        guard fchmod(fd, mode) == 0 else { throw MeshIntentError.refused("could not secure mesh staging file") }
        let wrote = data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return data.isEmpty }
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard wrote, fsync(fd) == 0 else { throw MeshIntentError.refused("could not write secure mesh staging file") }
        succeeded = true
    }
}

enum StrictJSONValue {
    case object([String: StrictJSONValue])
    case array([StrictJSONValue])
    case string(String)
    case number(String)
    case bool(Bool)
    case null

    func object(exactly keys: Set<String>) throws -> [String: StrictJSONValue] {
        guard case .object(let value) = self else { throw MeshIntentError.refused("mesh JSON object expected") }
        guard Set(value.keys) == keys else { throw MeshIntentError.refused("mesh JSON has missing or unknown fields") }
        return value
    }
}

extension Dictionary where Key == String, Value == StrictJSONValue {
    func value(_ key: String) throws -> StrictJSONValue {
        guard let value = self[key] else {
            throw MeshIntentError.refused("mesh JSON field \(key) is missing")
        }
        return value
    }

    func string(_ key: String) throws -> String {
        guard case .string(let value) = self[key] else { throw MeshIntentError.refused("mesh JSON field \(key) must be a string") }
        return value
    }

    func integer(_ key: String) throws -> Int {
        guard case .number(let text) = self[key], let value = Int(text), String(value) == text else {
            throw MeshIntentError.refused("mesh JSON field \(key) must be an integer")
        }
        return value
    }

    func unsigned(_ key: String) throws -> UInt64 {
        guard case .number(let text) = self[key], let value = UInt64(text), String(value) == text else {
            throw MeshIntentError.refused("mesh JSON field \(key) must be a positive integer")
        }
        return value
    }

    func array(_ key: String) throws -> [StrictJSONValue] {
        guard case .array(let value) = self[key] else { throw MeshIntentError.refused("mesh JSON field \(key) must be an array") }
        return value
    }

    func boolean(_ key: String) throws -> Bool {
        guard case .bool(let value) = self[key] else { throw MeshIntentError.refused("mesh JSON field \(key) must be a boolean") }
        return value
    }
}

enum StrictJSON {
    static func parse(_ data: Data) throws -> StrictJSONValue {
        guard !data.isEmpty, data.count <= 65_536 else { throw MeshIntentError.refused("mesh JSON size rejected") }
        var parser = Parser(bytes: Array(data))
        return try parser.parse()
    }

    private struct Parser {
        let bytes: [UInt8]
        var index = 0

        mutating func parse() throws -> StrictJSONValue {
            skipWhitespace()
            let value = try parseValue()
            skipWhitespace()
            guard index == bytes.count else { throw MeshIntentError.refused("mesh JSON has trailing data") }
            return value
        }

        mutating func parseValue() throws -> StrictJSONValue {
            guard index < bytes.count else { throw MeshIntentError.refused("mesh JSON ended early") }
            switch bytes[index] {
            case 0x7B: return try parseObject()
            case 0x5B: return try parseArray()
            case 0x22: return .string(try parseString())
            case 0x74: try literal("true"); return .bool(true)
            case 0x66: try literal("false"); return .bool(false)
            case 0x6E: try literal("null"); return .null
            case 0x2D, 0x30...0x39: return .number(try parseNumber())
            default: throw MeshIntentError.refused("mesh JSON token rejected")
            }
        }

        mutating func parseObject() throws -> StrictJSONValue {
            index += 1
            skipWhitespace()
            var object: [String: StrictJSONValue] = [:]
            if take(0x7D) { return .object(object) }
            while true {
                guard index < bytes.count, bytes[index] == 0x22 else { throw MeshIntentError.refused("mesh JSON object key expected") }
                let key = try parseString()
                guard object[key] == nil else { throw MeshIntentError.refused("mesh JSON repeats a key") }
                skipWhitespace()
                guard take(0x3A) else { throw MeshIntentError.refused("mesh JSON object separator expected") }
                skipWhitespace()
                object[key] = try parseValue()
                skipWhitespace()
                if take(0x7D) { return .object(object) }
                guard take(0x2C) else { throw MeshIntentError.refused("mesh JSON object delimiter expected") }
                skipWhitespace()
            }
        }

        mutating func parseArray() throws -> StrictJSONValue {
            index += 1
            skipWhitespace()
            var array: [StrictJSONValue] = []
            if take(0x5D) { return .array(array) }
            while true {
                array.append(try parseValue())
                skipWhitespace()
                if take(0x5D) { return .array(array) }
                guard take(0x2C) else { throw MeshIntentError.refused("mesh JSON array delimiter expected") }
                skipWhitespace()
            }
        }

        mutating func parseString() throws -> String {
            guard take(0x22) else { throw MeshIntentError.refused("mesh JSON string expected") }
            var scalars = String.UnicodeScalarView()
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                if byte == 0x22 { return String(scalars) }
                if byte == 0x5C {
                    guard index < bytes.count else { throw MeshIntentError.refused("mesh JSON escape ended early") }
                    let escape = bytes[index]
                    index += 1
                    switch escape {
                    case 0x22: scalars.append("\"")
                    case 0x5C: scalars.append("\\")
                    case 0x2F: scalars.append("/")
                    case 0x62: scalars.append("\u{0008}")
                    case 0x66: scalars.append("\u{000C}")
                    case 0x6E: scalars.append("\n")
                    case 0x72: scalars.append("\r")
                    case 0x74: scalars.append("\t")
                    case 0x75:
                        let first = try parseHexScalar()
                        if (0xD800...0xDBFF).contains(first) {
                            guard take(0x5C), take(0x75) else { throw MeshIntentError.refused("mesh JSON surrogate pair is incomplete") }
                            let second = try parseHexScalar()
                            guard (0xDC00...0xDFFF).contains(second) else { throw MeshIntentError.refused("mesh JSON surrogate pair is invalid") }
                            let scalar = 0x10000 + ((first - 0xD800) << 10) + second - 0xDC00
                            guard let unicode = Unicode.Scalar(scalar) else { throw MeshIntentError.refused("mesh JSON scalar is invalid") }
                            scalars.append(unicode)
                        } else {
                            guard !(0xDC00...0xDFFF).contains(first), let unicode = Unicode.Scalar(first) else {
                                throw MeshIntentError.refused("mesh JSON scalar is invalid")
                            }
                            scalars.append(unicode)
                        }
                    default: throw MeshIntentError.refused("mesh JSON escape is invalid")
                    }
                    continue
                }
                guard byte >= 0x20 else { throw MeshIntentError.refused("mesh JSON contains a control character") }
                if byte < 0x80 {
                    scalars.append(Unicode.Scalar(byte))
                } else {
                    index -= 1
                    let start = index
                    let length: Int
                    switch byte {
                    case 0xC2...0xDF: length = 2
                    case 0xE0...0xEF: length = 3
                    case 0xF0...0xF4: length = 4
                    default: throw MeshIntentError.refused("mesh JSON UTF-8 is invalid")
                    }
                    guard start + length <= bytes.count,
                          let string = String(bytes: bytes[start..<(start + length)], encoding: .utf8),
                          string.unicodeScalars.count == 1
                    else { throw MeshIntentError.refused("mesh JSON UTF-8 is invalid") }
                    scalars.append(contentsOf: string.unicodeScalars)
                    index += length
                }
            }
            throw MeshIntentError.refused("mesh JSON string ended early")
        }

        mutating func parseHexScalar() throws -> UInt32 {
            guard index + 4 <= bytes.count else { throw MeshIntentError.refused("mesh JSON unicode escape ended early") }
            var value: UInt32 = 0
            for byte in bytes[index..<(index + 4)] {
                value <<= 4
                switch byte {
                case 0x30...0x39: value += UInt32(byte - 0x30)
                case 0x41...0x46: value += UInt32(byte - 0x41 + 10)
                case 0x61...0x66: value += UInt32(byte - 0x61 + 10)
                default: throw MeshIntentError.refused("mesh JSON unicode escape is invalid")
                }
            }
            index += 4
            return value
        }

        mutating func parseNumber() throws -> String {
            let start = index
            if take(0x2D), index == bytes.count { throw MeshIntentError.refused("mesh JSON number ended early") }
            if take(0x30) {
                if index < bytes.count, (0x30...0x39).contains(bytes[index]) {
                    throw MeshIntentError.refused("mesh JSON number has a leading zero")
                }
            } else {
                guard index < bytes.count, (0x31...0x39).contains(bytes[index]) else { throw MeshIntentError.refused("mesh JSON number is invalid") }
                while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
            }
            if take(0x2E) {
                guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else { throw MeshIntentError.refused("mesh JSON fraction is invalid") }
                while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
            }
            if index < bytes.count, bytes[index] == 0x65 || bytes[index] == 0x45 {
                index += 1
                if index < bytes.count, bytes[index] == 0x2B || bytes[index] == 0x2D { index += 1 }
                guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else { throw MeshIntentError.refused("mesh JSON exponent is invalid") }
                while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
            }
            return String(decoding: bytes[start..<index], as: UTF8.self)
        }

        mutating func literal(_ literal: StaticString) throws {
            let expected = Array(String(describing: literal).utf8)
            guard index + expected.count <= bytes.count,
                  Array(bytes[index..<(index + expected.count)]) == expected
            else { throw MeshIntentError.refused("mesh JSON literal is invalid") }
            index += expected.count
        }

        mutating func skipWhitespace() {
            while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
        }

        mutating func take(_ byte: UInt8) -> Bool {
            guard index < bytes.count, bytes[index] == byte else { return false }
            index += 1
            return true
        }
    }
}
