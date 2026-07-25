import Foundation
import Testing
@testable import ReachDaemon

/// The config loader's whole job is telling three situations apart that used
/// to collapse into one: no config (a first run), a config that will not parse
/// (a typo), and a config that reads fine. The middle case used to return
/// defaults, which silently discarded the pinned mesh endpoint and the cluster
/// name — a failure that only shows up at the far end of a walk-out.
@Suite struct ConfigTests {
    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-config-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func absentConfigIsAFirstRunAndWritesNothing() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        #expect(!DaemonConfig.exists(in: directory))
        let config = try DaemonConfig.load(from: directory)
        #expect(config.clusterName == "Reach Cluster")
        #expect(config.meshEndpoint == nil)
        // Reading is not writing: a first run leaves the directory as it found it.
        #expect(!DaemonConfig.exists(in: directory))
    }

    @Test func malformedConfigThrowsAndNamesThePath() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("config.json")

        // The exact shape that bit at the studio: an endpoint written as a
        // bare token rather than a quoted JSON string.
        try #"""
        {
          "clusterName" : "Reach Cluster",
          "meshEndpoint" : 192.168.4.94:51820
        }
        """#.write(to: url, atomically: true, encoding: .utf8)

        #expect(DaemonConfig.exists(in: directory))
        do {
            _ = try DaemonConfig.load(from: directory)
            Issue.record("a config that will not parse must not load as defaults")
        } catch let error as ConfigError {
            #expect("\(error)".contains(url.path))
        }
    }

    @Test func aRejectedConfigIsLeftExactlyAsTheOperatorWroteIt() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("config.json")
        let original = Data(#"{ "meshEndpoint" : oops }"#.utf8)
        try original.write(to: url)

        #expect(throws: ConfigError.self) { try DaemonConfig.load(from: directory) }
        #expect(try Data(contentsOf: url) == original)
    }

    @Test func unreadableConfigIsDistinctFromAbsent() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        // A directory where the file should be: present, and unreadable as data.
        try FileManager.default.createDirectory(
            at: directory.appendingPathComponent("config.json"),
            withIntermediateDirectories: true
        )
        #expect(throws: ConfigError.self) { try DaemonConfig.load(from: directory) }
    }

    @Test func validConfigRoundTrips() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        var config = DaemonConfig()
        config.clusterName = "Studio"
        config.port = 1234
        config.enrollPort = 1235
        config.meshEndpoint = "203.0.113.7:51820"
        try config.save(to: directory)

        let loaded = try DaemonConfig.load(from: directory)
        #expect(loaded.clusterID == config.clusterID)
        #expect(loaded.clusterName == "Studio")
        #expect(loaded.port == 1234)
        #expect(loaded.enrollPort == 1235)
        #expect(loaded.meshEndpoint == "203.0.113.7:51820")
    }
}

/// Where the phone is told to send packets, and whether anyone can tell that
/// answer was a guess.
@Suite struct MeshEndpointTests {
    @Test func aPinnedEndpointWins() {
        var config = DaemonConfig()
        config.meshEndpoint = "203.0.113.7:51820"
        let resolved = MeshEndpoint.resolve(config: config, addresses: [[127, 0, 0, 1], [192, 168, 8, 104]])
        #expect(resolved.source == .pinned)
        #expect(resolved.endpoint == "203.0.113.7:51820")
    }

    @Test func derivationSkipsLoopbackAndTheMeshItself() {
        // The mesh address deliberately sits ahead of the LAN address: the old
        // code took whatever came second and would have handed a phone
        // 10.86.0.1 as the way to reach 10.86.0.1.
        let resolved = MeshEndpoint.resolve(
            config: DaemonConfig(),
            addresses: [[127, 0, 0, 1], [10, 86, 0, 1], [192, 168, 8, 104]]
        )
        #expect(resolved.source == .derived)
        #expect(resolved.endpoint == "192.168.8.104:51820")
    }

    @Test func nothingUsableIsSaidOutLoud() {
        let resolved = MeshEndpoint.resolve(config: DaemonConfig(), addresses: [[127, 0, 0, 1], [10, 86, 0, 1]])
        #expect(resolved.source == .unavailable)
    }

    @Test func aDerivedEndpointNeverReadsLikeAPinnedOne() {
        var pinnedConfig = DaemonConfig()
        pinnedConfig.meshEndpoint = "203.0.113.7:51820"
        let pinned = MeshEndpoint.resolve(config: pinnedConfig, addresses: [])
        let derived = MeshEndpoint.resolve(config: DaemonConfig(), addresses: [[192, 168, 8, 104]])

        #expect(pinned.summary.contains("(pinned)"))
        #expect(derived.summary.contains("DERIVED"))
        #expect(pinned.summary != derived.summary)
    }

    @Test func splitReadsHostAndPort() {
        #expect(MeshEndpoint.split("192.168.4.94:51820")?.host == "192.168.4.94")
        #expect(MeshEndpoint.split("192.168.4.94:51820")?.port == 51820)
        #expect(MeshEndpoint.split("192.168.4.94") == nil)
        #expect(MeshEndpoint.split("192.168.4.94:") == nil)
        #expect(MeshEndpoint.split(":51820") == nil)
        #expect(MeshEndpoint.split("192.168.4.94:99999") == nil)
    }

    @Test func classifyKnowsTheRangesThatDecideTheAwayLeg() {
        #expect(MeshEndpoint.classify("203.0.113.7") == .publicAddress)
        #expect(MeshEndpoint.classify("192.168.4.94") == .privateNetwork)
        #expect(MeshEndpoint.classify("10.0.0.5") == .privateNetwork)
        #expect(MeshEndpoint.classify("172.20.1.1") == .privateNetwork)
        #expect(MeshEndpoint.classify("172.32.1.1") == .publicAddress)
        // CGNAT, and where tailnets live — the range that ends a venue visit.
        #expect(MeshEndpoint.classify("100.66.143.31") == .sharedAddressSpace)
        // Inside 10/8, but the mesh reading has to win.
        #expect(MeshEndpoint.classify("10.86.0.1") == .mesh)
        #expect(MeshEndpoint.classify("127.0.0.1") == .loopback)
        #expect(MeshEndpoint.classify("169.254.1.1") == .linkLocal)
        #expect(MeshEndpoint.classify("reach.local") == nil)
        #expect(MeshEndpoint.classify("192.168.4") == nil)
        #expect(MeshEndpoint.classify("192.168.4.999") == nil)
    }
}
