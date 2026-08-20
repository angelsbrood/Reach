import Foundation
import Security
import Testing

@testable import ReachIdentity

/// Serialized because every case here writes to the real keychain — there is
/// no seam to fake, and introducing one would test the seam instead of the
/// thing. Each case takes a fresh label so cases cannot see each other, and
/// forgets it on the way out whether it passed or not.
///
/// What this suite cannot reach: `swift test` on macOS exercises the *file*
/// keychain, and this store is iOS-facing. The data-protection path is proven
/// on hardware, not here.
@Suite(.serialized)
struct ClusterRoadsTests {
    private func freshLabel() -> String { "reach-test-roads-\(UUID().uuidString)" }

    @Test func legacyJSONLazilyBecomesEndpointSpecific() throws {
        let legacy = Data(#"{"addrs":["192.168.1.40","10.86.0.1"],"port":47337}"#.utf8)
        let decoded = try JSONDecoder().decode(ClusterRoads.Roads.self, from: legacy)
        #expect(decoded.endpoints == [
            .init(host: "192.168.1.40", port: 47337),
            .init(host: "10.86.0.1", port: 47337),
        ])
    }

    @Test func newJSONRetainsDifferentPorts() throws {
        let roads = ClusterRoads.Roads(endpoints: [
            .init(host: "192.168.1.40", port: 47337),
            .init(host: "198.51.100.8", port: 55001),
        ])
        let decoded = try JSONDecoder().decode(
            ClusterRoads.Roads.self,
            from: JSONEncoder().encode(roads)
        )
        #expect(decoded == roads)
    }

    @Test func roadsComeBackTheWayTheyWentIn() throws {
        let label = freshLabel()
        defer { try? ClusterRoads.forget(for: label) }

        try ClusterRoads.save(addrs: ["192.168.1.40", "10.86.0.1"], port: 47337, for: label)

        let loaded = try #require(try ClusterRoads.load(for: label))
        #expect(loaded.addrs == ["192.168.1.40", "10.86.0.1"])
        #expect(loaded.port == 47337)
    }

    @Test func aSecondSaveSupersedesTheFirst() throws {
        let label = freshLabel()
        defer { try? ClusterRoads.forget(for: label) }

        try ClusterRoads.save(addrs: ["192.168.1.40"], port: 47337, for: label)
        try ClusterRoads.save(addrs: ["10.86.0.1", "100.71.4.2"], port: 47400, for: label)

        let loaded = try #require(try ClusterRoads.load(for: label))
        #expect(loaded.addrs == ["10.86.0.1", "100.71.4.2"])
        #expect(loaded.port == 47400)
    }

    @Test func aLabelNothingWasStoredUnderReadsAsNothing() throws {
        #expect(try ClusterRoads.load(for: freshLabel()) == nil)
    }

    /// The distinction the refusal sentence depends on: an app that was never
    /// answered and an app whose roads will not read back are different
    /// situations, and only one of them is silence.
    @Test func storedBytesThatWillNotDecodeThrowRatherThanReadAsAbsent() throws {
        let label = freshLabel()
        defer { try? ClusterRoads.forget(for: label) }

        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: ClusterRoads.service,
            kSecAttrAccount as String: label,
            kSecValueData as String: Data("not json".utf8),
        ]
        #expect(SecItemAdd(add as CFDictionary, nil) == errSecSuccess)

        #expect(throws: IdentityError.self) {
            _ = try ClusterRoads.load(for: label)
        }
    }

    /// The daemon seeds its declared set with `127.0.0.1` because that list
    /// doubles as the server certificate's SAN set. On another device it names
    /// that device.
    @Test func loopbackNeverSurvivesTheStore() throws {
        let label = freshLabel()
        defer { try? ClusterRoads.forget(for: label) }

        try ClusterRoads.save(addrs: ["127.0.0.1", "192.168.1.40", "127.94.0.2"], port: 47337, for: label)

        let loaded = try #require(try ClusterRoads.load(for: label))
        #expect(loaded.addrs == ["192.168.1.40"])
    }

    @Test func endpointSpecificStoreFiltersLoopbackAndKeepsPorts() throws {
        let label = freshLabel()
        defer { try? ClusterRoads.forget(for: label) }

        try ClusterRoads.save(endpoints: [
            .init(host: "127.0.0.1", port: 47337),
            .init(host: "198.51.100.8", port: 55001),
            .init(host: "10.86.0.1", port: 51820),
        ], for: label)

        let loaded = try #require(try ClusterRoads.load(for: label))
        #expect(loaded.endpoints == [
            .init(host: "198.51.100.8", port: 55001),
            .init(host: "10.86.0.1", port: 51820),
        ])
    }

    /// A daemon that can currently see only itself has not learned that last
    /// week's roads are gone — so it must not be able to erase them.
    @Test func aSetThatIsAllLoopbackLeavesWhatWasThereAlone() throws {
        let label = freshLabel()
        defer { try? ClusterRoads.forget(for: label) }

        try ClusterRoads.save(addrs: ["192.168.1.40"], port: 47337, for: label)
        try ClusterRoads.save(addrs: ["127.0.0.1"], port: 47337, for: label)

        let loaded = try #require(try ClusterRoads.load(for: label))
        #expect(loaded.addrs == ["192.168.1.40"])
    }

    @Test func forgettingLeavesNothingBehind() throws {
        let label = freshLabel()
        try ClusterRoads.save(addrs: ["192.168.1.40"], port: 47337, for: label)
        try ClusterRoads.forget(for: label)
        #expect(try ClusterRoads.load(for: label) == nil)
    }

    @Test func forgettingWhatWasNeverKnownIsDone() throws {
        try ClusterRoads.forget(for: freshLabel())
    }
}

@Suite(.serialized)
struct ClusterRelayRoadsTests {
    private func freshLabel() -> String { "reach-test-relay-roads-\(UUID().uuidString)" }

    @Test func preserveReplaceAndClearAreDistinct() throws {
        let label = freshLabel()
        defer { try? ClusterRelayRoads.forget(for: label) }
        let first: [ClusterRoads.Roads.Endpoint] = [
            .init(host: "10.87.0.1", port: 47_337),
        ]
        let second: [ClusterRoads.Roads.Endpoint] = [
            .init(host: "192.168.77.1", port: 47_338),
        ]

        try ClusterRelayRoads.apply(.replace(first), for: label)
        try ClusterRelayRoads.apply(.preserve, for: label)
        #expect(try ClusterRelayRoads.load(for: label)?.endpoints == first)

        try ClusterRelayRoads.apply(.replace(second), for: label)
        #expect(try ClusterRelayRoads.load(for: label)?.endpoints == second)

        try ClusterRelayRoads.apply(.clear, for: label)
        #expect(try ClusterRelayRoads.load(for: label) == nil)
    }

    @Test func relayStoreRejectsUnsafeOrAmbiguousEndpoints() {
        let invalid: [[ClusterRoads.Roads.Endpoint]] = [
            [],
            [.init(host: "203.0.113.9", port: 47_337)],
            [.init(host: "010.87.0.1", port: 47_337)],
            [.init(host: "10.87.0.0", port: 47_337)],
            [.init(host: "10.87.0.255", port: 47_337)],
            [.init(host: "10.87.0.1", port: 0)],
            [
                .init(host: "10.87.0.1", port: 47_337),
                .init(host: "10.87.0.1", port: 47_337),
            ],
        ]
        for endpoints in invalid {
            #expect(throws: IdentityError.self) {
                try ClusterRelayRoads.save(endpoints: endpoints, for: freshLabel())
            }
        }
    }

    @Test func unreadableRelayStateDoesNotTouchDirectRoads() throws {
        let label = freshLabel()
        defer {
            try? ClusterRelayRoads.forget(for: label)
            try? ClusterRoads.forget(for: label)
        }
        try ClusterRoads.save(addrs: ["192.168.8.210"], port: 47_337, for: label)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: ClusterRelayRoads.service,
            kSecAttrAccount as String: label,
            kSecValueData as String: Data("not json".utf8),
        ]
        #expect(SecItemAdd(add as CFDictionary, nil) == errSecSuccess)

        #expect(throws: IdentityError.self) {
            _ = try ClusterRelayRoads.load(for: label)
        }
        #expect(try ClusterRoads.load(for: label)?.addrs == ["192.168.8.210"])
    }

    @Test func concurrentReplacementsAlwaysLeaveOneCompleteDeclaration() async throws {
        let label = freshLabel()
        defer { try? ClusterRelayRoads.forget(for: label) }
        let declarations = (1 ... 16).map {
            [ClusterRoads.Roads.Endpoint(host: "10.87.0.\($0)", port: UInt16(47_000 + $0))]
        }
        await withTaskGroup(of: Void.self) { group in
            for declaration in declarations {
                group.addTask {
                    try? ClusterRelayRoads.apply(.replace(declaration), for: label)
                }
            }
        }
        let stored = try #require(try ClusterRelayRoads.load(for: label)?.endpoints)
        #expect(declarations.contains(stored))
    }
}
