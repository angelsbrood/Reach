import Foundation
import Security

/// Authenticated relay calling cards, deliberately isolated from direct roads.
///
/// The two tiers have different authority. A v0 session may refresh direct
/// roads while saying nothing at all about relay state, and a v1 omission
/// preserves the last authenticated relay declaration. Keeping a separate
/// generic-password item makes those rules physical rather than conventional.
package enum ClusterRelayRoads {
    package static let service = "systems.reach.cluster-relay-roads"

    package struct Roads: Codable, Sendable, Equatable {
        package var endpoints: [ClusterRoads.Roads.Endpoint]

        package init(endpoints: [ClusterRoads.Roads.Endpoint]) throws {
            try Self.validate(endpoints)
            self.endpoints = endpoints
        }

        package init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let endpoints = try container.decode([ClusterRoads.Roads.Endpoint].self, forKey: .endpoints)
            try Self.validate(endpoints)
            self.endpoints = endpoints
        }

        private enum CodingKeys: String, CodingKey { case endpoints }

        private static func validate(_ endpoints: [ClusterRoads.Roads.Endpoint]) throws {
            guard !endpoints.isEmpty else { throw RelayRoadError.invalid }
            var seen: Set<ClusterRoads.Roads.Endpoint> = []
            for endpoint in endpoints {
                guard endpoint.port != 0,
                      canonicalPrivateIPv4(endpoint.host),
                      seen.insert(endpoint).inserted
                else { throw RelayRoadError.invalid }
            }
        }
    }

    package enum Declaration: Sendable, Equatable {
        case preserve
        case clear
        case replace([ClusterRoads.Roads.Endpoint])
    }

    package static func apply(_ declaration: Declaration, for label: String) throws {
        switch declaration {
        case .preserve:
            return
        case .clear:
            try forget(for: label)
        case .replace(let endpoints):
            try save(endpoints: endpoints, for: label)
        }
    }

    package static func save(
        endpoints: [ClusterRoads.Roads.Endpoint],
        for label: String
    ) throws {
        let data: Data
        do {
            data = try JSONEncoder().encode(Roads(endpoints: endpoints))
        } catch {
            throw IdentityError.roadsUnreadable(errSecDecode)
        }

        KeychainLock.acquire()
        defer { KeychainLock.release() }
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecValueData as String: data,
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecSuccess { return }
        guard status == errSecDuplicateItem else {
            throw IdentityError.keychainAddFailed(status)
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
        ]
        let updated = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        guard updated == errSecSuccess else {
            throw IdentityError.keychainAddFailed(updated)
        }
    }

    package static func load(for label: String) throws -> Roads? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        let status = KeychainLock.withLock {
            SecItemCopyMatching(query as CFDictionary, &item)
        }
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw IdentityError.roadsUnreadable(status)
        }
        do {
            return try JSONDecoder().decode(Roads.self, from: data)
        } catch {
            throw IdentityError.roadsUnreadable(errSecDecode)
        }
    }

    package static func forget(for label: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
        ]
        let status = KeychainLock.withLock { SecItemDelete(query as CFDictionary) }
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw IdentityError.keychainAddFailed(status)
        }
    }

    private enum RelayRoadError: Error { case invalid }

    private static func canonicalPrivateIPv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        var octets: [UInt8] = []
        for part in parts {
            guard let value = UInt8(part), String(value) == part else { return false }
            octets.append(value)
        }
        let rfc1918 = octets[0] == 10
            || (octets[0] == 172 && (16 ... 31).contains(octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
        return rfc1918 && (1 ... 254).contains(octets[3])
    }
}
