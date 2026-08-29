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

    @Test func preV2FixtureReencodesByteExactlyAndKeepsMLXSelectionAndCopy() throws {
        let fixture = #"""
        {
          "clusterID" : "11111111-2222-3333-4444-555555555555",
          "clusterName" : "Studio",
          "enrollPort" : 1235,
          "meshEndpoint" : "203.0.113.7:51820",
          "modelID" : "legacy-model",
          "port" : 1234
        }
        """#
        let config = try JSONDecoder().decode(DaemonConfig.self, from: Data(fixture.utf8))
        #expect(config.exo == nil)
        #expect(config.providerKind == .mlx)
        #expect(config.modelID == "legacy-model")

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        #expect(try encoder.encode(config) == Data(fixture.utf8))

        let filling = try config.makeFilling()
        #expect(filling is MLXFilling)
        #expect(filling.modelID == "legacy-model")
        #expect(config.statusDescription(version: "test") == "reachd test — cluster \"Studio\", model legacy-model, port 1234")
        #expect(config.startupDescription(addresses: [[127, 0, 0, 1], [192, 168, 1, 4]]) == "[reachd] Studio serving legacy-model on :1234 (127.0.0.1, 192.168.1.4)")
        #expect(config.prewarmSuccessDescription == "[reachd] model prewarmed")
    }

    @Test func exactEXOFixtureRoundTripsSelectsEXOAndStartsNoRequest() throws {
        let fixture = #"""
        {
          "clusterID" : "11111111-2222-3333-4444-555555555555",
          "clusterName" : "Studio",
          "enrollPort" : 1235,
          "exo" : {
            "endpoint" : "http:\/\/127.0.0.1:52415"
          },
          "modelID" : "cluster-model",
          "port" : 1234
        }
        """#
        let config = try JSONDecoder().decode(DaemonConfig.self, from: Data(fixture.utf8))
        let expectedEXO = try EXOConfiguration(endpoint: "http://127.0.0.1:52415")
        #expect(config.exo == expectedEXO)
        #expect(config.providerKind == .exo(authority: "127.0.0.1:52415"))

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        #expect(try encoder.encode(config) == Data(fixture.utf8))

        let filling = try #require(try config.makeFilling() as? EXOFilling)
        #expect(filling.modelID == "cluster-model")
        #expect(filling.loaderStartCount == 0)
        #expect(config.statusDescription(version: "test") == "reachd test — cluster \"Studio\", model cluster-model via EXO at 127.0.0.1:52415, port 1234")
        #expect(config.startupDescription(addresses: [[127, 0, 0, 1]]) == "[reachd] Studio serving cluster-model via EXO at 127.0.0.1:52415 on :1234 (127.0.0.1)")
        #expect(config.prewarmSuccessDescription == "[reachd] EXO catalog check passed")
        #expect(filling.loaderStartCount == 0)
    }

    @Test func modelOverrideAppliesBeforeEitherProviderFactory() throws {
        var mlx = DaemonConfig()
        let ignoredOverride = mlx.applyModelOverride(nil)
        #expect(!ignoredOverride)
        let appliedMLXOverride = mlx.applyModelOverride("mlx-override")
        #expect(appliedMLXOverride)
        let mlxFilling = try mlx.makeFilling()
        #expect(mlxFilling is MLXFilling)
        #expect(mlxFilling.modelID == "mlx-override")

        var exo = DaemonConfig()
        exo.exo = try EXOConfiguration(endpoint: "http://[::1]:65535")
        let appliedEXOOverride = exo.applyModelOverride("exo-override")
        #expect(appliedEXOOverride)
        let exoFilling = try #require(try exo.makeFilling() as? EXOFilling)
        #expect(exoFilling.modelID == "exo-override")
        #expect(exoFilling.endpoint.authority == "[::1]:65535")
        #expect(exoFilling.loaderStartCount == 0)
    }

    @Test func missingEXOIsOmittedButExplicitNullAndMalformedEndpointsRefuse() throws {
        var config = DaemonConfig()
        config.clusterID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
        let encoded = try JSONEncoder().encode(config)
        let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(object["exo"] == nil)

        let base = #"""
        {
          "clusterID":"11111111-2222-3333-4444-555555555555",
          "clusterName":"Studio",
          "port":1234,
          "enrollPort":1235,
          "modelID":"model",
          "exo":REPLACEMENT
        }
        """#
        for replacement in [
            "null",
            #"{"endpoint":"http://localhost:52415"}"#,
            #"{"endpoint":"http://127.0.0.1:052415"}"#,
            #"{"endpoint":"http://127.0.0.1:52415/"}"#,
            #"{"endpoint":"https://127.0.0.1:52415"}"#,
            "{}",
        ] {
            let data = Data(base.replacingOccurrences(of: "REPLACEMENT", with: replacement).utf8)
            #expect(throws: DecodingError.self) {
                try JSONDecoder().decode(DaemonConfig.self, from: data)
            }
        }
    }

    @Test func loadSaveSelectionAndCopyNeverProbeEXO() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        var config = DaemonConfig()
        config.clusterName = "No Probe"
        config.modelID = "offline-model"
        config.exo = try EXOConfiguration(endpoint: "http://127.0.0.1:52415")
        try config.save(to: directory)
        let loaded = try DaemonConfig.load(from: directory)
        let filling = try #require(try loaded.makeFilling() as? EXOFilling)
        #expect(filling.loaderStartCount == 0)

        _ = loaded.providerKind
        _ = loaded.statusDescription(version: "test")
        _ = loaded.startupDescription(addresses: [])
        _ = loaded.prewarmSuccessDescription
        let encoder = JSONEncoder()
        _ = try encoder.encode(loaded)
        try loaded.save(to: directory)
        #expect(filling.loaderStartCount == 0)
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
        #expect(MeshEndpoint.classify("10.86.1.1") == .privateNetwork)
        #expect(MeshEndpoint.classify("127.0.0.1") == .loopback)
        #expect(MeshEndpoint.classify("169.254.1.1") == .linkLocal)
        #expect(MeshEndpoint.classify("reach.local") == nil)
        #expect(MeshEndpoint.classify("192.168.4") == nil)
        #expect(MeshEndpoint.classify("192.168.4.999") == nil)
    }
}

/// The endpoint a device is told to dial is read when it is granted, not when
/// the daemon started. Arriving at a venue means re-pinning `meshEndpoint`, and
/// a value cached at process start would send the next phone to the last
/// venue's address — which works perfectly on the LAN and fails only at the
/// far end of the walk-out.
@Suite struct MeshEndpointFreshnessTests {
    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-endpoint-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func host(reading directory: URL) throws -> WireGuardHost {
        try WireGuardHost(
            keysDirectory: directory.appendingPathComponent("wg", isDirectory: true),
            confPath: directory.appendingPathComponent("reach0.conf").path,
            endpoint: {
                MeshEndpoint.resolve(
                    config: try DaemonConfig.load(from: directory),
                    addresses: [[192, 168, 8, 104]]
                ).endpoint
            }
        )
    }

    @Test func theEndpointFollowsTheFileNotTheProcess() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        var config = DaemonConfig()
        config.meshEndpoint = "192.168.4.94:51820"
        try config.save(to: directory)

        let wgHost = try host(reading: directory)
        #expect(try wgHost.currentEndpoint() == "192.168.4.94:51820")

        // The venue changes. Nothing restarts.
        config.meshEndpoint = "203.0.113.7:51820"
        try config.save(to: directory)
        #expect(try wgHost.currentEndpoint() == "203.0.113.7:51820")
    }

    @Test func aBrokenConfigRefusesToNameAnEndpointAtAll() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let wgHost = try host(reading: directory)
        // Absent is a first run: derivation answers, and says it guessed.
        #expect(try wgHost.currentEndpoint() == "192.168.8.104:51820")

        try Data(#"{ "meshEndpoint" : 203.0.113.7:51820 }"#.utf8)
            .write(to: directory.appendingPathComponent("config.json"))
        #expect(throws: ConfigError.self) { try wgHost.currentEndpoint() }
    }
}
