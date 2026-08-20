import Crypto
import Darwin
import Foundation
import Testing
@testable import ReachDaemon

private final class MeshIntentTestLatch: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)

    func signal() {
        semaphore.signal()
    }

    func wait(seconds: Double) -> Bool {
        semaphore.wait(timeout: .now() + seconds) == .success
    }
}

@Suite(.serialized) struct MeshIntentTests {
    private func directory(_ name: String = "mesh-intent") throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        return url
    }

    private func publicKey(_ byte: UInt8) -> String {
        Data(repeating: byte, count: 32).base64EncodedString()
    }

    private func intent(generation: UInt64 = 7) throws -> MeshIntent {
        try MeshIntent(
            generation: generation,
            publicKey: publicKey(2),
            peers: [
                .init(publicKey: publicKey(3), allowedIP: "10.86.0.2/32", keepalive: 25),
                .init(publicKey: publicKey(4), allowedIP: "10.86.0.3/32"),
            ]
        )
    }

    @Test func deterministicRenderingRoundTripsAndMatchesTheGoDigest() throws {
        let one = try intent()
        let first = try one.encoded()
        #expect(try MeshIntent.decode(first) == one)
        #expect(try one.encoded() == first)

        let crossLanguage = try MeshIntent(
            generation: 7,
            publicKey: publicKey(2),
            peers: [.init(publicKey: publicKey(3), allowedIP: "10.86.0.2/32", keepalive: 25)]
        )
        #expect(crossLanguage.publicDigest == "692db30bc04abf695e0cac1254b43127eb35784ba922ee80fa757d67733d6cd7")
        #expect(!String(decoding: first, as: UTF8.self).contains("privateKey"))
    }

    @Test(arguments: [
        #"{"version":1,"version":1,"generation":1,"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","address":"10.86.0.1/24","port":51820,"mtu":1280,"peers":[]}"#,
        #"{"version":1,"generation":1,"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","address":"10.86.0.1/24","port":51820,"mtu":1280,"peers":[],"unknown":true}"#,
        #"{"version":1,"generation":1,"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","address":"10.86.0.1/24","port":51820,"mtu":1280,"peers":[]} trailing"#,
    ])
    func strictJSONRejectsDuplicateUnknownTrailingAndVersionDrift(json: String) {
        #expect(throws: (any Error).self) { try MeshIntent.decode(Data(json.utf8)) }
    }

    @Test func relayV2WithoutABlockReadsAsDirectOnlyAndCanonicalizesToV1() throws {
        let json = Data(#"{"version":2,"generation":1,"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","address":"10.86.0.1/24","port":51820,"mtu":1280,"peers":[]}"#.utf8)
        let decoded = try MeshIntent.decode(json)
        #expect(decoded.relay == nil)
        #expect(String(decoding: try decoded.encoded(), as: UTF8.self).contains(#""version": 1"#))
    }

    @Test func peerPolicyRejectsKeyRouteKeepaliveAndOrderingDrift() throws {
        #expect(throws: (any Error).self) {
            try MeshIntent(generation: 1, publicKey: "not-base64", peers: [])
        }
        #expect(throws: (any Error).self) {
            try MeshIntent(
                generation: 1,
                publicKey: publicKey(1),
                peers: [.init(publicKey: publicKey(2), allowedIP: "10.86.1.2/32")]
            )
        }
        #expect(throws: (any Error).self) {
            try MeshIntent(
                generation: 1,
                publicKey: publicKey(1),
                peers: [.init(publicKey: publicKey(2), allowedIP: "10.86.0.2/32", keepalive: 3_601)]
            )
        }
        #expect(throws: (any Error).self) {
            try MeshIntent(
                generation: 1,
                publicKey: publicKey(1),
                peers: [
                    .init(publicKey: publicKey(2), allowedIP: "10.86.0.3/32"),
                    .init(publicKey: publicKey(3), allowedIP: "10.86.0.2/32"),
                ]
            )
        }
        #expect(throws: (any Error).self) {
            try MeshIntent(
                generation: 1,
                publicKey: publicKey(1),
                peers: [
                    .init(publicKey: publicKey(2), allowedIP: "10.86.0.2/32"),
                    .init(publicKey: publicKey(2), allowedIP: "10.86.0.3/32"),
                ]
            )
        }
    }

    @Test func legacyImportIsStrictOneTimeAndLeavesTheRollbackBytesUntouched() throws {
        let state = try directory("legacy-import")
        defer { try? FileManager.default.removeItem(at: state) }
        let keys = state.appendingPathComponent("wg", isDirectory: true)
        try FileManager.default.createDirectory(at: keys, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: keys.path)
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let privateText = privateKey.rawRepresentation.base64EncodedString()
        let publicText = privateKey.publicKey.rawRepresentation.base64EncodedString()
        try privateText.write(to: keys.appendingPathComponent("server.key"), atomically: true, encoding: .utf8)
        try publicText.write(to: keys.appendingPathComponent("server.pub"), atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keys.appendingPathComponent("server.key").path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keys.appendingPathComponent("server.pub").path)

        let legacy = state.appendingPathComponent("reach0.conf")
        let original = Data("""
            [Interface]
            PrivateKey = \(privateText)
            Address = 10.86.0.1/24
            ListenPort = 51820

            [Peer]
            PublicKey = \(publicKey(8))
            AllowedIPs = 10.86.0.2/32

            """.utf8)
        try original.write(to: legacy)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: legacy.path)

        let imported = try MeshIntentStore.loadOrImport(
            stateDirectory: state,
            legacyConf: legacy,
            privateKey: privateText,
            publicKey: publicText
        )
        #expect(imported.generation == 1)
        #expect(imported.peers.map(\.allowedIP) == ["10.86.0.2/32"])
        #expect(try Data(contentsOf: legacy) == original)

        let changedLegacy = original + Data("PostUp = /bin/false\n".utf8)
        try changedLegacy.write(to: legacy)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: legacy.path)
        let loaded = try MeshIntentStore.loadOrImport(
            stateDirectory: state,
            legacyConf: legacy,
            privateKey: privateText,
            publicKey: publicText
        )
        #expect(loaded == imported, "an existing intent was re-imported from changed rollback evidence")
        #expect(try Data(contentsOf: legacy) == changedLegacy)
    }

    @Test(arguments: [
        "PostUp = /bin/true",
        "Table = off",
        "PrivateKey = duplicate",
        "[Unknown]",
    ])
    func legacyImportRefusesHooksUnknownsAndDuplicates(extra: String) throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let text = """
            [Interface]
            PrivateKey = \(privateKey.rawRepresentation.base64EncodedString())
            Address = 10.86.0.1/24
            ListenPort = 51820
            \(extra)
            """
        #expect(throws: (any Error).self) {
            try MeshIntent.importLegacy(
                text,
                privateKey: privateKey.rawRepresentation.base64EncodedString(),
                publicKey: privateKey.publicKey.rawRepresentation.base64EncodedString()
            )
        }
    }

    @Test func registryCrossCheckAndSecureStagingHoldThePrivateKeyBoundary() async throws {
        let state = try directory("mesh-stage")
        defer { try? FileManager.default.removeItem(at: state) }
        let host = try WireGuardHost(
            keysDirectory: state.appendingPathComponent("wg", isDirectory: true),
            confPath: state.appendingPathComponent("never-created.conf").path,
            endpoint: "192.0.2.1:51820"
        )
        let registry = DeviceRegistry(directory: state)
        let record = try await registry.reserve(
            name: "phone",
            devicePubX963: P256.Signing.PrivateKey().publicKey.x963Representation
        )
        let peer = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        try await host.addPeer(publicKey: peer, allowedIP: record.assignedIP)

        let reservedDevices = await registry.all
        #expect(throws: (any Error).self) {
            try MeshIntentStore.specification(in: state, devices: reservedDevices)
        }
        await registry.admit(record.id, wgPub: peer)
        let specification = try MeshIntentStore.specification(in: state, devices: await registry.all)
        let privateText = try MeshIntentStore.readCanonicalKey(
            state.appendingPathComponent("wg/server.key"),
            role: "host private key",
            exactMode: 0o600
        )
        #expect(!specification.publicDigest.contains(privateText))
        let staged = try MeshIntentStore.stage(specification, in: state)
        defer { try? FileManager.default.removeItem(at: staged) }
        let data = try Data(contentsOf: staged)
        let stagedObject = try StrictJSON.parse(data).object(exactly: [
            "version", "generation", "privateKey", "publicKey", "address", "port", "mtu", "peers",
        ])
        #expect(try stagedObject.string("privateKey") == privateText)
        var file = stat()
        var parent = stat()
        #expect(lstat(staged.path, &file) == 0)
        #expect(file.st_mode & 0o777 == 0o600)
        #expect(file.st_uid == getuid())
        #expect(file.st_nlink == 1)
        #expect(lstat(staged.deletingLastPathComponent().path, &parent) == 0)
        #expect(parent.st_mode & 0o777 == 0o700)
    }

    @Test func relayV2RenderingRoundTripsAndMatchesCrossLanguageDigestFixtures() throws {
        let direct = try intent()
        let relay = try MeshIntent.Relay(
            network: "10.87.0.0/24",
            hubPublicKey: publicKey(5),
            endpoint: "192.0.2.10:51821",
            directPeers: direct.peers
        )
        let value = try MeshIntent(
            generation: direct.generation,
            publicKey: direct.publicKey,
            peers: direct.peers,
            relay: relay
        )
        let data = try value.encoded()
        #expect(try MeshIntent.decode(data) == value)
        #expect(try value.encoded() == data)
        #expect(value.directDigest == "a8fba25b3a72a2a4e8ca6f54b7e1197fa012b98d58e206d2e248aa19f282fb85")
        #expect(value.relayDigest == "06bf5967403e04a3c31d38cc44d717d737cf1adab22dd738a2e0c22fdff72a1a")
        #expect(value.publicDigest == "dce04eda846843be63dba3b8d739a2160094af8d59b1bb641e37d33839778fdb")

        var removed = value
        removed.generation += 1
        removed.relay = nil
        try removed.validate(allowEmpty: false)
        #expect(removed.directDigest == value.directDigest)
        let removedObject = try StrictJSON.parse(removed.encoded()).object(exactly: [
            "version", "generation", "publicKey", "address", "port", "mtu", "peers",
        ])
        #expect(try removedObject.integer("version") == MeshIntent.version)
        #expect(!String(decoding: try removed.encoded(), as: UTF8.self).contains("relay"))
    }

    @Test(arguments: [
        ("198.51.100.0/24", "192.0.2.10:51821"),
        ("10.86.0.0/24", "192.0.2.10:51821"),
        ("10.87.0.0/24", "hub.example:51821"),
        ("10.87.0.0/24", "192.0.2.10:443"),
        ("10.87.0.0/24", "10.87.0.9:51821"),
        ("10.87.0.0/24", "127.0.0.1:51821"),
        ("10.87.0.0/24", "[::1]:51821"),
        ("10.87.0.0/24", "[fe80::1]:51821"),
    ])
    func relayPolicyRejectsUnsafeNetworksAndEndpoints(value: (String, String)) throws {
        let direct = try intent()
        #expect(throws: (any Error).self) {
            try MeshIntent.Relay(
                network: value.0,
                hubPublicKey: publicKey(5),
                endpoint: value.1,
                directPeers: direct.peers
            )
        }
    }

    @Test func relayStoreSetUpdateRemoveIsIdempotentAndReturnsToCanonicalV1() throws {
        let state = try directory("relay-store")
        defer { try? FileManager.default.removeItem(at: state) }
        let original = try intent(generation: 9)
        try MeshIntentStore.save(original, in: state)

        let added = try MeshIntentStore.setRelay(
            in: state,
            network: "10.87.0.0/24",
            hubPublicKey: publicKey(5),
            endpoint: "192.0.2.10:51821",
            activeRoutes: []
        )
        #expect(added.changed)
        #expect(added.intent.generation == 10)
        #expect(added.intent.relay?.routes == ["10.87.0.2/32", "10.87.0.3/32"])

        let same = try MeshIntentStore.setRelay(
            in: state,
            network: "10.87.0.0/24",
            hubPublicKey: publicKey(5),
            endpoint: "192.0.2.10:51821",
            activeRoutes: [
                MeshIPv4Prefix.parse("10.87.0.1/32")!,
                MeshIPv4Prefix.parse("10.87.0.2/32")!,
                MeshIPv4Prefix.parse("10.87.0.3/32")!,
            ]
        )
        #expect(!same.changed)
        #expect(same.intent.generation == 10)

        let changed = try MeshIntentStore.setRelay(
            in: state,
            network: "10.87.0.0/24",
            hubPublicKey: publicKey(5),
            endpoint: "192.0.2.11:51821",
            activeRoutes: [
                MeshIPv4Prefix.parse("10.87.0.1/32")!,
                MeshIPv4Prefix.parse("10.87.0.2/32")!,
                MeshIPv4Prefix.parse("10.87.0.3/32")!,
            ]
        )
        #expect(changed.changed)
        #expect(changed.intent.generation == 11)

        let removed = try MeshIntentStore.removeRelay(in: state)
        #expect(removed.changed)
        #expect(removed.intent.generation == 12)
        #expect(removed.intent.relay == nil)
        #expect(removed.intent.directDigest == original.directDigest)
        let repeated = try MeshIntentStore.removeRelay(in: state)
        #expect(!repeated.changed)
        #expect(repeated.intent.generation == 12)
        #expect(try MeshIntent.decode(repeated.intent.encoded()) == repeated.intent)
    }

    @Test func concurrentEnrollmentAndRelayIntentUpdatePreserveBothMutations() async throws {
        let state = try directory("relay-enrollment-race")
        defer { try? FileManager.default.removeItem(at: state) }
        let host = try WireGuardHost(
            keysDirectory: state.appendingPathComponent("wg", isDirectory: true),
            confPath: state.appendingPathComponent("never-created.conf").path,
            endpoint: "192.0.2.1:51820"
        )
        try await host.addPeer(
            publicKey: Data(repeating: 3, count: 32),
            allowedIP: "10.86.0.2"
        )

        let lockHeld = MeshIntentTestLatch()
        let enrollmentStarting = MeshIntentTestLatch()
        let relayUpdate = Task.detached {
            try MeshIntentStore.update(in: state) { intent in
                lockHeld.signal()
                guard enrollmentStarting.wait(seconds: 2) else {
                    throw MeshIntentError.refused("concurrent enrollment did not start")
                }
                // Keep the exclusive intent lock long enough for addPeer to
                // reach its own flock. Without the shared update primitive,
                // the later writer would save a stale read and lose relay.
                usleep(50_000)
                intent.relay = try MeshIntent.Relay(
                    network: "10.87.0.0/24",
                    hubPublicKey: Data(repeating: 5, count: 32).base64EncodedString(),
                    endpoint: "192.0.2.10:51821",
                    directPeers: intent.peers
                )
                intent.generation += 1
                return true
            }
        }
        let acquired = await Task.detached {
            lockHeld.wait(seconds: 2)
        }.value
        #expect(acquired)
        let enrollment = Task.detached {
            enrollmentStarting.signal()
            return try await host.addPeer(
                publicKey: Data(repeating: 4, count: 32),
                allowedIP: "10.86.0.3"
            )
        }

        let relayResult = try await relayUpdate.value
        #expect(relayResult.changed)
        #expect(try await enrollment.value)
        let final = try MeshIntentStore.load(in: state)
        #expect(final.generation == 4)
        #expect(final.peers.map(\.allowedIP) == ["10.86.0.2/32", "10.86.0.3/32"])
        #expect(final.relay?.routes == ["10.87.0.2/32", "10.87.0.3/32"])
    }

    @Test func relayRouteInventoryRejectsOverlapAndExemptsOnlyExactCurrentHelperRoutes() throws {
        let direct = try intent()
        let relay = try MeshIntent.Relay(
            network: "10.87.0.0/24",
            hubPublicKey: publicKey(5),
            endpoint: "192.0.2.10:51821",
            directPeers: direct.peers
        )
        try MeshRelayRouteInventory.validate(
            relayNetwork: relay.network,
            currentRelay: relay,
            routes: ([relay.address] + relay.routes).compactMap(MeshIPv4Prefix.parse)
        )
        #expect(throws: (any Error).self) {
            try MeshRelayRouteInventory.validate(
                relayNetwork: relay.network,
                currentRelay: relay,
                routes: [MeshIPv4Prefix.parse("10.87.0.99/32")!]
            )
        }
        #expect(throws: (any Error).self) {
            try MeshRelayRouteInventory.validate(
                relayNetwork: relay.network,
                currentRelay: nil,
                routes: [MeshIPv4Prefix.parse("10.87.0.0/24")!]
            )
        }
    }
}

@Suite struct MeshOwnerTests {
    private func key(_ byte: UInt8) -> String {
        Data(repeating: byte, count: 32).base64EncodedString()
    }

    private func intent(generation: UInt64 = 4) throws -> MeshIntent {
        try MeshIntent(
            generation: generation,
            publicKey: key(1),
            peers: [.init(publicKey: key(2), allowedIP: "10.86.0.2/32")]
        )
    }

    private func relayIntent(generation: UInt64 = 5) throws -> MeshIntent {
        let direct = try intent(generation: generation)
        return try MeshIntent(
            generation: generation,
            publicKey: direct.publicKey,
            peers: direct.peers,
            relay: MeshIntent.Relay(
                network: "10.87.0.0/24",
                hubPublicKey: key(3),
                endpoint: "192.0.2.10:51821",
                directPeers: direct.peers
            )
        )
    }

    private func v2Status(
        for intent: MeshIntent,
        pid: Int32 = 41,
        directReady: Bool = true,
        relayReady: Bool = true,
        error: String? = nil
    ) -> MeshOwner.Status {
        let relay = intent.relay
        return MeshOwner.Status(
            helperVersion: MeshOwner.helperVersion,
            pid: pid,
            generation: intent.generation,
            publicDigest: intent.publicDigest,
            interfaceName: directReady ? "utun7" : "",
            ready: directReady && relayReady,
            peerCount: intent.peers.count,
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            error: error,
            direct: .init(
                ready: directReady,
                digest: intent.directDigest,
                peerCount: intent.peers.count
            ),
            relay: .init(
                configured: relay != nil,
                ready: relayReady,
                digest: intent.relayDigest ?? "",
                address: relay?.address ?? "",
                routeCount: relay?.routes.count ?? 0,
                hubPeerCount: relay == nil ? 0 : 1
            )
        )
    }

    private func path(for intent: MeshIntent, includeRelay: Bool = true) -> MeshOwner.PathEvidence {
        var addresses: [LocalAddresses.IPv4Entry] = [
            .init(interface: "lo0", address: [127, 0, 0, 1]),
            .init(interface: "utun7", address: [10, 86, 0, 1]),
        ]
        var routes: [MeshIPv4RouteEntry] = [
            .init(prefix: MeshIPv4Prefix.parse("10.86.0.0/24")!, interface: "utun7"),
            .init(prefix: MeshIPv4Prefix.parse("10.86.0.1/32")!, interface: "utun7"),
        ]
        if includeRelay, let relay = intent.relay {
            let host = relay.address.dropLast(3).split(separator: ".").compactMap { UInt8($0) }
            addresses.append(.init(interface: "utun7", address: host))
            routes += relay.routes.map {
                .init(prefix: MeshIPv4Prefix.parse($0)!, interface: "utun7")
            }
        }
        return .init(addresses: addresses, routes: routes)
    }

    private func status(
        for intent: MeshIntent,
        pid: Int32 = 41,
        ready: Bool = true,
        error: String? = nil
    ) -> MeshOwner.Status {
        MeshOwner.Status(
            helperVersion: "1",
            pid: pid,
            generation: intent.generation,
            publicDigest: intent.publicDigest,
            interfaceName: ready ? "utun7" : "",
            ready: ready,
            peerCount: intent.peers.count,
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            error: error
        )
    }

    private func evidence(_ status: MeshOwner.Status?, pid: Int32? = 41) -> MeshOwner.Evidence {
        .init(helper: .valid, plist: .valid, statusFile: status == nil ? .absent : .valid, status: status, launchdPID: pid)
    }

    @Test func statusStrictlyDecodesAndRejectsUnknownOrUnboundedFields() throws {
        let value = try intent()
        let json = Data("""
            {
              "helperVersion":"1","pid":41,"generation":4,
              "publicDigest":"\(value.publicDigest)","interfaceName":"utun7",
              "ready":true,"peerCount":1,"updatedAt":"2023-11-14T22:13:20Z"
            }
            """.utf8)
        #expect(try MeshOwner.Status.decode(json).pid == 41)
        var unknown = Data(json.dropLast(2))
        unknown.append(Data(",\"unknown\":1}".utf8))
        #expect(throws: (any Error).self) { try MeshOwner.Status.decode(unknown) }
        let secretError = String(decoding: json, as: UTF8.self)
            .replacingOccurrences(of: "\"ready\":true", with: "\"ready\":false,\"error\":\"private key leaked\"")
        #expect(throws: (any Error).self) { try MeshOwner.Status.decode(Data(secretError.utf8)) }
        let badDigest = String(decoding: json, as: UTF8.self)
            .replacingOccurrences(of: value.publicDigest, with: "ABC")
        #expect(throws: (any Error).self) { try MeshOwner.Status.decode(Data(badDigest.utf8)) }
        let badInterface = String(decoding: json, as: UTF8.self)
            .replacingOccurrences(of: "utun7", with: "en0")
        #expect(throws: (any Error).self) { try MeshOwner.Status.decode(Data(badInterface.utf8)) }
        let contradictory = String(decoding: json, as: UTF8.self)
            .replacingOccurrences(of: "\"ready\":true", with: "\"ready\":false")
        #expect(throws: (any Error).self) { try MeshOwner.Status.decode(Data(contradictory.utf8)) }
    }

    @Test func statusStrictlySeparatesReadinessFromBoundedUpdateOutcomes() throws {
        let value = try intent()
        func encoded(ready: Bool, interfaceName: String, error: String?) -> Data {
            let errorField = error.map { ",\"error\":\"\($0)\"" } ?? ""
            return Data("""
                {
                  "helperVersion":"1","pid":41,"generation":4,
                  "publicDigest":"\(value.publicDigest)","interfaceName":"\(interfaceName)",
                  "ready":\(ready),"peerCount":1,"updatedAt":"2023-11-14T22:13:20Z"\(errorField)
                }
                """.utf8)
        }

        for error in ["configuration rejected", "update refused", "rollback restored"] {
            let decoded = try MeshOwner.Status.decode(encoded(ready: true, interfaceName: "utun7", error: error))
            #expect(decoded.ready)
            #expect(decoded.error == error)
        }
        for error in ["unconfigured", "interface unavailable", "stopped", "mesh owner unavailable"] {
            #expect(throws: (any Error).self) {
                try MeshOwner.Status.decode(encoded(ready: true, interfaceName: "utun7", error: error))
            }
        }
        #expect(throws: (any Error).self) {
            try MeshOwner.Status.decode(encoded(ready: false, interfaceName: "", error: "rollback restored"))
        }
        #expect(throws: (any Error).self) {
            try MeshOwner.Status.decode(encoded(ready: false, interfaceName: "utun7", error: "interface unavailable"))
        }
        let missingError = String(
            decoding: encoded(ready: false, interfaceName: "", error: "interface unavailable"),
            as: UTF8.self
        ).replacingOccurrences(of: ",\"error\":\"interface unavailable\"", with: "")
        #expect(throws: (any Error).self) {
            try MeshOwner.Status.decode(Data(missingError.utf8))
        }
        let partialRecovery = String(
            decoding: encoded(ready: false, interfaceName: "", error: "interface unavailable"),
            as: UTF8.self
        ).replacingOccurrences(of: value.publicDigest, with: "")
        #expect(throws: (any Error).self) {
            try MeshOwner.Status.decode(Data(partialRecovery.utf8))
        }
        #expect(try !MeshOwner.Status.decode(
            encoded(ready: false, interfaceName: "", error: "interface unavailable")
        ).ready)
    }

    @Test func v2StatusStrictlyDecodesIndependentDirectAndRelayComponents() throws {
        let desired = try relayIntent()
        let json = Data("""
            {
              "helperVersion":"2","pid":41,"generation":5,
              "publicDigest":"\(desired.publicDigest)","interfaceName":"utun7",
              "ready":true,"peerCount":1,
              "direct":{"ready":true,"digest":"\(desired.directDigest)","peerCount":1},
              "relay":{"configured":true,"ready":true,"digest":"\(desired.relayDigest!)","address":"10.87.0.1/32","routeCount":1,"hubPeerCount":1},
              "updatedAt":"2023-11-14T22:13:20Z"
            }
            """.utf8)
        let decoded = try MeshOwner.Status.decode(json)
        #expect(decoded.direct?.ready == true)
        #expect(decoded.relay?.configured == true)
        #expect(decoded.relay?.address == "10.87.0.1/32")

        let updating = String(decoding: json, as: UTF8.self)
            .replacingOccurrences(of: "\"ready\":true,\"peerCount\":1,", with: "\"ready\":false,\"peerCount\":1,")
            .replacingOccurrences(
                of: "\"configured\":true,\"ready\":true",
                with: "\"configured\":true,\"ready\":false"
            )
            .replacingOccurrences(
                of: "\"updatedAt\":\"2023-11-14T22:13:20Z\"",
                with: "\"updatedAt\":\"2023-11-14T22:13:20Z\",\"error\":\"updating\""
            )
        let partial = try MeshOwner.Status.decode(Data(updating.utf8))
        #expect(!partial.ready)
        #expect(partial.direct?.ready == true)
        #expect(partial.relay?.ready == false)
        #expect(partial.error == "updating")

        let falseReady = String(decoding: json, as: UTF8.self)
            .replacingOccurrences(
                of: "\"configured\":true,\"ready\":true",
                with: "\"configured\":true,\"ready\":false"
            )
        #expect(throws: (any Error).self) {
            try MeshOwner.Status.decode(Data(falseReady.utf8))
        }
    }

    @Test func v2DiagnosticsSeparateDirectReadinessFromRelayAuthorityAndActualPath() throws {
        let desired = try relayIntent()
        let healthy = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1], [10, 87, 0, 1]],
            evidence: evidence(v2Status(for: desired)),
            pathEvidence: .available(path(for: desired))
        )
        #expect(healthy.level == .pass)
        #expect(healthy.detail.contains("relay ready"))

        let updating = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(v2Status(for: desired, relayReady: false, error: "updating")),
            pathEvidence: .available(path(for: desired, includeRelay: false))
        )
        #expect(updating.level == .wait)
        #expect(updating.detail.contains("direct mesh remains ready"))

        let missingAlias = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(v2Status(for: desired)),
            pathEvidence: .available(path(for: desired, includeRelay: false))
        )
        #expect(missingAlias.level == .fail)
        #expect(missingAlias.detail.contains("relay route") || missingAlias.detail.contains("alias"))

        var missingDirectRoute = path(for: desired)
        missingDirectRoute.routes.removeAll {
            $0.prefix == MeshIPv4Prefix.parse("10.86.0.0/24")!
        }
        let directRouteMismatch = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1], [10, 87, 0, 1]],
            evidence: evidence(v2Status(for: desired)),
            pathEvidence: .available(missingDirectRoute)
        )
        #expect(directRouteMismatch.level == .fail)
        #expect(directRouteMismatch.detail.contains("direct mesh route"))

        let prior = try intent(generation: desired.generation - 1)
        let oldHelper = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: prior)),
            pathEvidence: .available(path(for: prior))
        )
        #expect(oldHelper.level == .wait)

        var removed = desired
        removed.generation += 1
        removed.relay = nil
        let removal = MeshOwner.verdict(
            intent: .success(removed),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(v2Status(for: removed)),
            pathEvidence: .available(path(for: removed))
        )
        #expect(removal.level == .pass)
        #expect(removal.detail.contains("relay verified absent"))

        let unavailable = MeshOwner.verdict(
            intent: .success(removed),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(v2Status(for: removed)),
            pathEvidence: .unavailable
        )
        #expect(unavailable.level == .fail)
        #expect(unavailable.detail.contains("mesh path could not be inspected"))
        #expect(!unavailable.detail.contains("relay verified absent"))

        let v1Fallback = MeshOwner.verdict(
            intent: .success(removed),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: removed)),
            pathEvidence: .unavailable
        )
        #expect(v1Fallback.level == .pass)

        var leakedPath = path(for: removed)
        leakedPath.addresses.append(.init(interface: "utun7", address: [10, 87, 0, 1]))
        let leaked = MeshOwner.verdict(
            intent: .success(removed),
            addresses: [[10, 86, 0, 1], [10, 87, 0, 1]],
            evidence: evidence(v2Status(for: removed)),
            pathEvidence: .available(leakedPath)
        )
        #expect(leaked.level == .fail)
    }

    @Test func relayRoadDeclarationRequiresExactV2AuthorityAndClearsOnlyFromDirectIntent() throws {
        let desired = try relayIntent()
        let healthy = RelayRoadDeclarationProvider.resolve(
            version: 1,
            port: 47_337,
            intent: desired,
            evidence: evidence(v2Status(for: desired)),
            addresses: [[10, 86, 0, 1], [10, 87, 0, 1]],
            pathEvidence: .available(path(for: desired))
        )
        #expect(healthy == .replace([.init(host: "10.87.0.1", port: 47_337)]))

        let unattested = RelayRoadDeclarationProvider.resolve(
            version: 1,
            port: 47_337,
            intent: desired,
            evidence: evidence(v2Status(for: desired)),
            addresses: [[10, 86, 0, 1]],
            pathEvidence: .available(path(for: desired, includeRelay: false))
        )
        #expect(unattested == .preserve)

        let v0 = RelayRoadDeclarationProvider.resolve(
            version: 0,
            port: 47_337,
            intent: desired,
            evidence: evidence(v2Status(for: desired)),
            addresses: [[10, 86, 0, 1], [10, 87, 0, 1]],
            pathEvidence: .available(path(for: desired))
        )
        #expect(v0 == .preserve)

        var removed = desired
        removed.generation += 1
        removed.relay = nil
        let clear = RelayRoadDeclarationProvider.resolve(
            version: 1,
            port: 47_337,
            intent: removed,
            evidence: evidence(nil, pid: nil),
            addresses: [],
            pathEvidence: .unavailable
        )
        #expect(clear == .clear)
    }

    @Test func directAddressSelectionQuarantinesEveryNonDirectAddressOnTheMeshInterface() {
        let entries: [LocalAddresses.IPv4Entry] = [
            .init(interface: "lo0", address: [127, 0, 0, 1]),
            .init(interface: "en0", address: [192, 168, 8, 210]),
            .init(interface: "utun7", address: [10, 86, 0, 1]),
            .init(interface: "utun7", address: [10, 87, 0, 1]),
            .init(interface: "utun7", address: [10, 88, 0, 1]),
            .init(interface: "utun9", address: [100, 66, 143, 31]),
        ]
        let selected = DirectAddressSelector.select(
            entries: entries,
            desiredRelayAddress: "10.87.0.1/32",
            appliedRelayAddress: "10.88.0.1/32"
        )
        #expect(selected == [
            [127, 0, 0, 1], [192, 168, 8, 210], [10, 86, 0, 1], [100, 66, 143, 31],
        ])
    }

    @Test func absentOwnerIsWaitingEvenWhenALegacyInterfaceIsUsable() throws {
        let result = MeshOwner.verdict(
            intent: .success(try intent()),
            addresses: [[10, 86, 0, 1]],
            evidence: .init(helper: .absent, plist: .absent, statusFile: .absent, status: nil, launchdPID: nil)
        )
        #expect(result.level == .wait)
        #expect(result.detail.contains("usable but unmanaged"))

        let leftover = MeshOwner.verdict(
            intent: .success(try intent()),
            addresses: [],
            evidence: .init(helper: .absent, plist: .absent, statusFile: .valid, status: status(for: try intent()), launchdPID: nil)
        )
        #expect(leftover.level == .fail)
    }

    @Test func matchingOwnerPassesAndEveryAuthorityMismatchRefusesOrWaits() throws {
        let desired = try intent()
        let healthy = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: desired))
        )
        #expect(healthy.level == .pass)

        let invalid = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: .init(helper: .invalid("user writable"), plist: .valid, statusFile: .valid, status: status(for: desired), launchdPID: 41)
        )
        #expect(invalid.level == .fail)

        let missingAddress = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [],
            evidence: evidence(status(for: desired))
        )
        #expect(missingAddress.level == .fail)

        let behind = try intent(generation: 5)
        let pending = MeshOwner.verdict(
            intent: .success(behind),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: desired))
        )
        #expect(pending.level == .wait)

        let rollback = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: behind))
        )
        #expect(rollback.level == .fail)

        let wrongPID = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: desired), pid: 99)
        )
        #expect(wrongPID.level == .fail)
    }

    @Test func boundedErrorsRemainVisibleAtEveryDiagnosticPrecedence() throws {
        let desired = try intent(generation: 5)
        let active = try intent(generation: 4)

        let exactRecovered = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: desired, error: "rollback restored"))
        )
        #expect(exactRecovered.level == .warn)
        #expect(exactRecovered.detail.contains("rollback restored"))

        let pending = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: active, error: "update refused"))
        )
        #expect(pending.level == .wait)
        #expect(pending.detail.contains("update refused"))
        #expect(pending.action?.contains("reachd mesh apply") == true)

        let unavailable = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: active, ready: false, error: "interface unavailable"))
        )
        #expect(unavailable.level == .fail)
        #expect(unavailable.detail.contains("interface unavailable"))

        let ahead = try intent(generation: 6)
        let helperAhead = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: ahead, error: "rollback restored"))
        )
        #expect(helperAhead.level == .fail)
        #expect(helperAhead.detail.contains("rollback restored"))

        let different = try MeshIntent(
            generation: desired.generation,
            publicKey: desired.publicKey,
            peers: [.init(publicKey: key(3), allowedIP: "10.86.0.2/32")]
        )
        let digestMismatch = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: different, error: "update refused"))
        )
        #expect(digestMismatch.level == .fail)
        #expect(digestMismatch.detail.contains("update refused"))

        let missingInterface = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [],
            evidence: evidence(status(for: desired, error: "configuration rejected"))
        )
        #expect(missingInterface.level == .fail)
        #expect(missingInterface.detail.contains("configuration rejected"))

        let wrongPeerCount = MeshOwner.Status(
            helperVersion: "1",
            pid: 41,
            generation: desired.generation,
            publicDigest: desired.publicDigest,
            interfaceName: "utun7",
            ready: true,
            peerCount: desired.peers.count + 1,
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            error: "rollback restored"
        )
        let peerMismatch = MeshOwner.verdict(
            intent: .success(desired),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(wrongPeerCount)
        )
        #expect(peerMismatch.level == .fail)
        #expect(peerMismatch.detail.contains("rollback restored"))

        let unconfigured = MeshOwner.Status(
            helperVersion: "1",
            pid: 41,
            generation: 0,
            publicDigest: "",
            interfaceName: "",
            ready: false,
            peerCount: 0,
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            error: "unconfigured"
        )
        #expect(MeshOwner.verdict(
            intent: .success(desired),
            addresses: [],
            evidence: evidence(unconfigured)
        ).level == .wait)
    }

    @Test func diagnosticAuthorityPrecedesInvalidIntentConvenience() throws {
        let desired = try intent()
        let invalidArtifact = MeshOwner.verdict(
            intent: .failure(MeshIntentError.refused("injected intent failure")),
            addresses: [[10, 86, 0, 1]],
            evidence: .init(
                helper: .invalid("user writable"),
                plist: .valid,
                statusFile: .valid,
                status: status(for: desired),
                launchdPID: 41
            )
        )
        #expect(invalidArtifact.level == .fail)
        #expect(invalidArtifact.detail.contains("invalid helper"))

        let invalidIntent = MeshOwner.verdict(
            intent: .failure(MeshIntentError.refused("injected intent failure")),
            addresses: [[10, 86, 0, 1]],
            evidence: evidence(status(for: desired))
        )
        #expect(invalidIntent.level == .fail)
        #expect(invalidIntent.detail.contains("mesh-intent.json"))

        let unconfigured = MeshOwner.Status(
            helperVersion: "1",
            pid: 41,
            generation: 0,
            publicDigest: "",
            interfaceName: "",
            ready: false,
            peerCount: 0,
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            error: "unconfigured"
        )
        #expect(MeshOwner.verdict(
            intent: .failure(MeshIntentError.refused("injected intent failure")),
            addresses: [],
            evidence: evidence(unconfigured)
        ).level == .wait)
    }

    @Test func applyNamesOnlySystemSudoAndTheInstalledRootOwnedHelper() {
        let input = URL(fileURLWithPath: "/Users/Reach Owner/Library/Application Support/Reach/mesh-stage/spec with spaces.json")
        let operation = MeshOwner.applyOperation(input: input)
        #expect(operation.executable == "/usr/bin/sudo")
        #expect(operation.arguments == [
            "--", "/Library/PrivilegedHelperTools/systems.reach.meshd",
            "apply", "--input", input.path,
        ])
        #expect(!operation.arguments.joined(separator: " ").contains("wg-quick"))
        #expect(!operation.arguments.joined(separator: " ").contains("/opt/homebrew"))
        let rendered = MeshOwner.renderOperation(executable: operation.executable, arguments: operation.arguments)
        #expect(rendered.contains(#""/Users/Reach Owner/Library/Application Support/Reach/mesh-stage/spec with spaces.json""#))
    }

    @Test func packagedLaunchPolicyIsStrictAndCarriesNoUserEnvironment() throws {
        let policy: [String: Any] = [
            "Label": MeshOwner.label,
            "ProgramArguments": [MeshOwner.helperPath, "serve"],
            "RunAtLoad": true,
            "KeepAlive": true,
            "ThrottleInterval": 10,
            "Umask": 0o77,
            "ProcessType": "Background",
            "StandardOutPath": MeshOwner.logPath,
            "StandardErrorPath": MeshOwner.logPath,
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: policy, format: .xml, options: 0)
        #expect(MeshOwner.validatePlist(data) == .valid)

        var changed = policy
        changed["EnvironmentVariables"] = ["PATH": "/Users/someone/bin"]
        let environment = try PropertyListSerialization.data(fromPropertyList: changed, format: .xml, options: 0)
        #expect(MeshOwner.validatePlist(environment) != .valid)

        changed = policy
        changed["ProgramArguments"] = ["/Users/someone/reach-meshd", "serve"]
        let executable = try PropertyListSerialization.data(fromPropertyList: changed, format: .xml, options: 0)
        #expect(MeshOwner.validatePlist(executable) != .valid)
    }
}
