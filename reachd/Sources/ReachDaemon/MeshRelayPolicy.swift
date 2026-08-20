import Foundation

package struct MeshIPv4Prefix: Sendable, Hashable {
    package var network: UInt32
    package var length: Int

    package static func parse(_ text: String) -> MeshIPv4Prefix? {
        guard text != "default" else { return nil }
        let pieces = text.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let addressParts = pieces[0].split(separator: ".", omittingEmptySubsequences: false)
        guard (1...4).contains(addressParts.count) else { return nil }
        var octets = [UInt8](repeating: 0, count: 4)
        for (index, part) in addressParts.enumerated() {
            guard let value = UInt8(part), String(value) == part else { return nil }
            octets[index] = value
        }
        let length: Int
        if pieces.count == 2 {
            guard let parsed = Int(pieces[1]), (1...32).contains(parsed) else { return nil }
            length = parsed
        } else {
            // Darwin's routing table renders network destinations in their
            // abbreviated form (`192.168.8`, `169.254`, `127`). Those spell
            // /24, /16, and /8 respectively; treating only four-octet values
            // as routes would miss the ordinary LAN that this check exists
            // to protect.
            length = addressParts.count * 8
        }
        let raw = octets.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let mask = length == 32 ? UInt32.max : UInt32.max << UInt32(32 - length)
        return MeshIPv4Prefix(network: raw & mask, length: length)
    }

    package func overlaps(_ other: MeshIPv4Prefix) -> Bool {
        let shared = min(length, other.length)
        let mask = shared == 32 ? UInt32.max : UInt32.max << UInt32(32 - shared)
        return network & mask == other.network & mask
    }

    package func isContained(in other: MeshIPv4Prefix) -> Bool {
        length >= other.length && overlaps(other)
    }
}

package struct MeshIPv4RouteEntry: Sendable, Hashable {
    package var prefix: MeshIPv4Prefix
    package var interface: String
}

package enum MeshRelayRouteInventory {
    package static func current() throws -> [MeshIPv4Prefix] {
        try currentEntries().map(\.prefix)
    }

    package static func currentEntries() throws -> [MeshIPv4RouteEntry] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        process.arguments = ["-rn", "-f", "inet"]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        do { try process.run() } catch {
            throw MeshIntentError.refused("could not inspect the active IPv4 route table")
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw MeshIntentError.refused("could not inspect the active IPv4 route table")
        }
        return parseEntries(String(decoding: data, as: UTF8.self))
    }

    package static func parse(_ text: String) -> [MeshIPv4Prefix] {
        parseEntries(text).map(\.prefix)
    }

    package static func parseEntries(_ text: String) -> [MeshIPv4RouteEntry] {
        var routes: [MeshIPv4RouteEntry] = []
        var inInternet = false
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line == "Internet:" {
                inInternet = true
                continue
            }
            if line.hasSuffix(":") && line != "Internet:" {
                inInternet = false
            }
            guard inInternet, !line.isEmpty, !line.hasPrefix("Destination") else { continue }
            let fields = line.split(whereSeparator: \Character.isWhitespace)
            guard fields.count >= 4,
                  let route = MeshIPv4Prefix.parse(String(fields[0]))
            else { continue }
            routes.append(MeshIPv4RouteEntry(prefix: route, interface: String(fields[3])))
        }
        return routes
    }

    package static func validate(
        relayNetwork: String,
        currentRelay: MeshIntent.Relay?,
        routes: [MeshIPv4Prefix]
    ) throws {
        guard let candidate = MeshIPv4Prefix.parse(relayNetwork), candidate.length == 24 else {
            throw MeshIntentError.refused("relay network must be a canonical private /24")
        }
        let currentTexts = currentRelay.map { [$0.address] + $0.routes } ?? []
        let exemptions = Set(currentTexts.compactMap(MeshIPv4Prefix.parse))
        for route in routes where route.overlaps(candidate) {
            if currentRelay?.network == relayNetwork, exemptions.contains(route) {
                continue
            }
            throw MeshIntentError.refused("relay network overlaps an active IPv4 route")
        }
    }
}
