import Crypto
import Darwin
import Foundation
import Testing
@testable import ReachDaemon

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
        #"{"version":2,"generation":1,"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","address":"10.86.0.1/24","port":51820,"mtu":1280,"peers":[]}"#,
    ])
    func strictJSONRejectsDuplicateUnknownTrailingAndVersionDrift(json: String) {
        #expect(throws: (any Error).self) { try MeshIntent.decode(Data(json.utf8)) }
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

    private func status(for intent: MeshIntent, pid: Int32 = 41, ready: Bool = true) -> MeshOwner.Status {
        MeshOwner.Status(
            helperVersion: MeshOwner.helperVersion,
            pid: pid,
            generation: intent.generation,
            publicDigest: intent.publicDigest,
            interfaceName: "utun7",
            ready: ready,
            peerCount: intent.peers.count,
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            error: nil
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
