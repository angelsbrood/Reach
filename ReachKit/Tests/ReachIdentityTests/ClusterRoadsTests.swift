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
