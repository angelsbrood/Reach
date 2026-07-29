import Crypto
import Foundation
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Testing
import X509
@testable import ReachDaemon

/// The ceremony over loopback with a stub keeper: full sequence, token
/// single-use, proof-of-possession enforcement, and the issued chain
/// verifying against the root the QR pinned.
enum EnrollOutcome {
    case granted(EnrollGrant)
    case refused(ErrorFrame)
}

@Suite(.serialized) struct EnrollmentTests {
    private struct Fixture {
        let ca: ClusterCA
        let caHash: Data
        let tokens: TokenStore
        let listener: QUICListener
        let dialer: QUICDialer
        let stateDir: URL
        let confPath: String
        let cleanup: @Sendable () -> Void
    }

    private let fixedEndpoint: @Sendable () throws -> String = { "192.0.2.1:51820" }

    /// `endpoint` defaults to a fixed value; the venue tests hand it a
    /// resolver that reads the state directory's config, which is what the
    /// daemon does.
    private func makeFixture(
        port: UInt16,
        endpoint: (@Sendable (URL) -> @Sendable () throws -> String)? = nil
    ) throws -> Fixture {
        let stateDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-enroll-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)
        let confPath = stateDir.appendingPathComponent("reach0.conf").path

        let ca = try ClusterCA.create(commonName: "Ceremony CA")
        let caDER = try ca.certificateDER()
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-enroll-server-\(UUID())")
        // SecPKCS12Import adds to the login keychain as a side effect, so a
        // materialized identity has to be removed or it survives the run.
        let serverBox = IdentityBox(serverIdentity)
        let caCert = try IdentityStore.certificate(fromDER: caDER)

        let tokens = TokenStore(directory: stateDir)
        let wgHost = try WireGuardHost(
            keysDirectory: stateDir.appendingPathComponent("wg", isDirectory: true),
            confPath: confPath,
            endpoint: endpoint.map { $0(stateDir) } ?? fixedEndpoint
        )
        let service = EnrollmentService(
            ca: ca,
            tokens: tokens,
            devices: DeviceRegistry(directory: stateDir),
            wgHost: wgHost
        )

        let options = TLSBuilder.serverOptions(
            alpn: Wire.enrollALPN,
            identity: serverIdentity,
            clientTrustRoots: [],
            presentedChain: [caCert]
        )
        let listener = try QUICListener(port: port, parameters: .reachQUIC(options: options))
        let acceptTask = Task {
            for try await tunnel in listener.tunnels {
                for await stream in tunnel.inboundStreams {
                    Task { await service.serve(stream: stream) }
                }
            }
        }

        // The client trusts only the CA hash — exactly what the QR carries.
        let caHash = Data(SHA256.hash(data: caDER))
        let clientOptions = TLSBuilder.enrollClientOptions(alpn: Wire.enrollALPN, caHashPin: caHash)
        let dialer = QUICDialer(
            endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!),
            parameters: .reachQUIC(options: clientOptions)
        )
        return Fixture(
            ca: ca, caHash: caHash, tokens: tokens, listener: listener, dialer: dialer,
            stateDir: stateDir, confPath: confPath,
            cleanup: {
                acceptTask.cancel()
                listener.cancel()
                KeychainIdentity.remove(identity: serverBox.identity)
                try? FileManager.default.removeItem(at: stateDir)
            }
        )
    }

    private func enroll(
        _ fixture: Fixture,
        token: String,
        name: String,
        breakPoP: Bool = false,
        deviceKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
        completeCeremony: Bool = true
    ) async throws -> EnrollOutcome {
        let wgKey = Curve25519.KeyAgreement.PrivateKey()

        let stream = try await fixture.dialer.openStream(timeout: 45)
        defer { stream.cancel() }
        var frames = stream.frames.makeAsyncIterator()

        try await stream.send(EnrollBegin(token: token, deviceName: name))
        guard let challengeRaw = try await frames.next() else { throw TransportError.streamClosed }
        if challengeRaw.type == .errorFrame {
            return .refused(try challengeRaw.decode(ErrorFrame.self))
        }
        let challenge = try challengeRaw.decode(EnrollChallenge.self)

        let devicePub = deviceKey.publicKey.x963Representation
        let wgPub = wgKey.publicKey.rawRepresentation
        var message = challenge.nonce + devicePub + wgPub
        if breakPoP {
            message[0] ^= 0xFF
        }
        let signature = try deviceKey.signature(for: message)
        try await stream.send(EnrollCertRequest(
            devicePubDER: devicePub,
            wgPubKey: wgPub,
            popSig: signature.derRepresentation
        ))
        guard let grantRaw = try await frames.next() else { throw TransportError.streamClosed }
        if grantRaw.type == .errorFrame {
            return .refused(try grantRaw.decode(ErrorFrame.self))
        }
        let grant = try grantRaw.decode(EnrollGrant.self)
        // A phone that dies, is backgrounded, or refuses the tunnel between
        // the grant and the confirmation. The daemon must treat that as a
        // pairing that did not happen.
        guard completeCeremony else { return .granted(grant) }
        try await stream.send(EnrollComplete(ok: true))
        // The peer block is written after EnrollComplete lands, so a test
        // that reads reach0.conf has to wait for the daemon rather than for
        // its own send. The daemon closes its send side once it is done, so
        // draining to the end is the deterministic wait.
        while (try? await frames.next()) != nil {}
        return .granted(grant)
    }

    @Test func fullCeremonyIssuesVerifiableIdentityAndMesh() async throws {
        let fixture = try makeFixture(port: 47430)
        defer { fixture.cleanup() }

        let token = fixture.tokens.mint()
        let outcome = try await enroll(fixture, token: token, name: "cassies-iphone")
        guard case .granted(let grant) = outcome else {
            Issue.record("enrollment failed: \(outcome)")
            return
        }

        // The issued chain verifies against the pinned root.
        #expect(Data(SHA256.hash(data: grant.caCertDER)) == fixture.caHash)
        let leaf = try Certificate(derEncoded: Array(grant.deviceCertDER))
        let root = try Certificate(derEncoded: Array(grant.caCertDER))
        var verifier = try Verifier(rootCertificates: CertificateStore([root])) { RFC5280Policy() }
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore())
        guard case .validCertificate = result else {
            Issue.record("issued chain did not validate: \(result)")
            return
        }

        // Mesh provision: first device gets .2, and the host config gained
        // the peer for the operator's one visible sudo.
        #expect(grant.wg.assignedIP == "10.86.0.2/24")
        #expect(grant.wg.serverPublicKey.count == 32)
        #expect(grant.wg.endpoint == "192.0.2.1:51820")
        let conf = try String(contentsOfFile: fixture.confPath, encoding: .utf8)
        #expect(conf.contains("10.86.0.2/32"))
    }

    @Test func tokensAreSingleUseAndFakePoPCloses() async throws {
        let fixture = try makeFixture(port: 47431)
        defer { fixture.cleanup() }

        let token = fixture.tokens.mint()
        _ = try await enroll(fixture, token: token, name: "first")

        // Same token again: refused.
        let replay = try await enroll(fixture, token: token, name: "second")
        guard case .refused(let error) = replay else {
            Issue.record("token replay was accepted")
            return
        }
        #expect(error.code == "enroll-token")

        // Fresh token, broken proof of possession: refused.
        let fresh = fixture.tokens.mint()
        let forged = try await enroll(fixture, token: fresh, name: "forger", breakPoP: true)
        guard case .refused(let popError) = forged else {
            Issue.record("forged PoP was accepted")
            return
        }
        #expect(popError.code == "enroll-pop")
    }

    /// Re-pairing is the demo-day path: the same Secure Enclave key comes
    /// back with a fresh wg key, and must keep its identity — id, mesh
    /// address, and the admin grant — while the host config swaps the
    /// stale peer block for the new key.
    @Test func rePairKeepsIdentityAndReplacesPeer() async throws {
        let fixture = try makeFixture(port: 47432)
        defer { fixture.cleanup() }

        let deviceKey = P256.Signing.PrivateKey()
        let first = try await enroll(fixture, token: fixture.tokens.mint(), name: "keeper-phone", deviceKey: deviceKey)
        guard case .granted(let firstGrant) = first else {
            Issue.record("first enrollment failed")
            return
        }
        let firstPeer = firstGrant.wg.serverPublicKey   // (server key, constant)
        _ = firstPeer

        let devices = DeviceRegistry(directory: fixture.stateDir)
        let original = try #require(await devices.all.first)
        #expect(original.admin)

        let again = try await enroll(fixture, token: fixture.tokens.mint(), name: "keeper-phone-renamed", deviceKey: deviceKey)
        guard case .granted(let secondGrant) = again else {
            Issue.record("re-pair was refused")
            return
        }

        // Same device, same address, admin intact — and only one record.
        let after = DeviceRegistry(directory: fixture.stateDir)
        let records = await after.all
        #expect(records.count == 1)
        let record = try #require(records.first)
        #expect(record.id == original.id)
        #expect(record.assignedIP == original.assignedIP)
        #expect(record.admin)
        #expect(record.name == "keeper-phone-renamed")
        #expect(secondGrant.wg.assignedIP == firstGrant.wg.assignedIP)

        // The conf holds exactly one peer for the address — the new key.
        let conf = try String(contentsOfFile: fixture.confPath, encoding: .utf8)
        #expect(conf.components(separatedBy: "AllowedIPs = \(record.assignedIP)/32").count == 2)
        #expect(conf.contains(record.wgPub.base64EncodedString()))
        #expect(record.wgPub != original.wgPub)
    }

    /// Arriving at a venue is exactly this: re-pin `meshEndpoint`, re-pair the
    /// phone. If the grant carried a value cached when the daemon started, the
    /// second phone would be handed the first venue's address — and would work
    /// perfectly on the LAN right up until it walked out the door.
    @Test func aRePinReachesTheNextPhoneWithoutARestart() async throws {
        let fixture = try makeFixture(port: 47433) { stateDir in
            {
                MeshEndpoint.resolve(
                    config: try DaemonConfig.load(from: stateDir),
                    addresses: [[192, 168, 8, 104]]
                ).endpoint
            }
        }
        defer { fixture.cleanup() }

        var config = DaemonConfig()
        config.meshEndpoint = "192.168.4.94:51820"
        try config.save(to: fixture.stateDir)

        let home = try await enroll(fixture, token: fixture.tokens.mint(), name: "phone-at-home")
        guard case .granted(let homeGrant) = home else {
            Issue.record("first enrollment failed: \(home)")
            return
        }
        #expect(homeGrant.wg.endpoint == "192.168.4.94:51820")

        // The venue. The daemon keeps running.
        config.meshEndpoint = "203.0.113.7:51820"
        try config.save(to: fixture.stateDir)

        let away = try await enroll(fixture, token: fixture.tokens.mint(), name: "phone-at-venue")
        guard case .granted(let awayGrant) = away else {
            Issue.record("second enrollment failed: \(away)")
            return
        }
        #expect(awayGrant.wg.endpoint == "203.0.113.7:51820")
    }

    /// A config the daemon cannot read is a daemon that cannot say where its
    /// mesh is. Granting anyway would issue a certificate and append a peer
    /// for a device that can never arrive — so it refuses first, and leaves
    /// nothing behind to clean up.
    @Test func anUnreadableEndpointRefusesBeforeAnythingIsMinted() async throws {
        let fixture = try makeFixture(port: 47434) { stateDir in
            {
                MeshEndpoint.resolve(
                    config: try DaemonConfig.load(from: stateDir),
                    addresses: [[192, 168, 8, 104]]
                ).endpoint
            }
        }
        defer { fixture.cleanup() }

        try Data(#"{ "meshEndpoint" : 203.0.113.7:51820 }"#.utf8)
            .write(to: fixture.stateDir.appendingPathComponent("config.json"))

        let token = fixture.tokens.mint()
        let outcome = try await enroll(fixture, token: token, name: "phone-at-a-typo")
        guard case .refused(let error) = outcome else {
            Issue.record("a grant was issued against a config that will not parse")
            return
        }
        #expect(error.code == "enroll-endpoint")
        // The refusal names the file, so the fix is one line away rather than
        // a debugging session at a venue.
        #expect(error.message.contains("config.json"))

        // Nothing half-enrolled: no device record, and no peer block.
        let devices = await DeviceRegistry(directory: fixture.stateDir).all
        #expect(devices.isEmpty)
        let conf = (try? String(contentsOfFile: fixture.confPath, encoding: .utf8)) ?? ""
        #expect(!conf.contains("10.86.0.2/32"))

        // …but the QR IS spent, and that is deliberate rather than an
        // oversight: consuming it late enough to survive a refusal means
        // holding it open across the round trip, and a second device can
        // present it in that gap. Pinned here so nobody "fixes" the retry
        // by moving the consumption after the ceremony. The operator's remedy is a fresh `reachd pair`, which
        // is what the refusal now says on both ends.
        #expect(!fixture.tokens.consume(token))
    }

    /// …and the sentence above is only half of what one QR needs.
    ///
    /// `consume` is one synchronous step, which rules out a *suspension*
    /// landing between the check and the removal. It does not rule out two
    /// threads running that step at the same instant, and nothing upstream
    /// stops them: `EnrollmentService` is a non-isolated struct and
    /// `Daemon.startEnrollment` spawns a fresh `Task` per inbound stream,
    /// so two ceremonies execute in parallel on the global executor with
    /// nothing between them and one file. Both `load()` the same entry,
    /// both find it, both `save()` a copy without it — a lost update, which
    /// `.atomic` prevents from tearing the file but cannot prevent.
    ///
    /// The token is the *only* thing authenticating a device ceremony:
    /// proof-of-possession is over a key the caller generated moments
    /// earlier, so it proves the caller holds its own key and nothing about
    /// which device it is. A double-spend therefore hands an uninvited
    /// device a cluster-signed certificate and a mesh peer — and any
    /// chain-valid certificate may open sessions.
    @Test func oneQRAdmitsOneDeviceEvenWhenTwoRaceForIt() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-token-race-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let tokens = TokenStore(directory: dir)

        // Repeated because the window is a file read-modify-write: a single
        // trial that happens to serialize proves nothing either way, and a
        // rate reported from one sample is the error `0e839e4` records.
        var doubleSpends = 0
        for _ in 0..<24 {
            let token = tokens.mint()
            let admitted = await withTaskGroup(of: Bool.self) { group in
                for _ in 0..<8 { group.addTask { tokens.consume(token) } }
                return await group.reduce(into: 0) { $0 += $1 ? 1 : 0 }
            }
            if admitted > 1 { doubleSpends += 1 }
        }
        #expect(doubleSpends == 0, "one QR admitted two devices in \(doubleSpends) of 24 races")
    }

    /// A re-pair evicts the peer holding that /32 — two peers must never claim
    /// one address. So the eviction has to wait until the device has confirmed
    /// it holds the grant, or a pairing that fails at the last step leaves the
    /// phone with neither the new mesh nor the one it walked in with.
    @Test func aCeremonyAbandonedAfterTheGrantKeepsThePeerItAlreadyHad() async throws {
        let fixture = try makeFixture(port: 47436)
        defer { fixture.cleanup() }

        let deviceKey = P256.Signing.PrivateKey()
        _ = try await enroll(fixture, token: fixture.tokens.mint(), name: "phone", deviceKey: deviceKey)

        let afterFirst = try String(contentsOfFile: fixture.confPath, encoding: .utf8)
        #expect(afterFirst.contains("10.86.0.2/32"))

        // Same Secure Enclave key, so the daemon treats it as the same device
        // and the fresh wg key would replace the working block. Abandon after
        // the grant.
        _ = try await enroll(
            fixture,
            token: fixture.tokens.mint(),
            name: "phone",
            deviceKey: deviceKey,
            completeCeremony: false
        )
        try? await Task.sleep(for: .milliseconds(400))

        let afterAbandon = try String(contentsOfFile: fixture.confPath, encoding: .utf8)
        #expect(afterAbandon == afterFirst, "an abandoned re-pair rewrote the peer block the phone was using")
    }

    /// The same collapse `DaemonConfig.load` had, in the one other file the
    /// operator edits by hand: read failure and empty file are not the same
    /// answer, and treating them alike rewrites the conf without its
    /// [Interface] — destroying the host's own key line.
    @Test func anUnreadableWireGuardConfRefusesRatherThanRewritingIt() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-wg-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let confPath = dir.appendingPathComponent("reach0.conf").path
        let host = try WireGuardHost(
            keysDirectory: dir.appendingPathComponent("wg", isDirectory: true),
            confPath: confPath,
            endpoint: "192.0.2.1:51820"
        )
        let before = try String(contentsOfFile: confPath, encoding: .utf8)
        #expect(before.contains("[Interface]"))
        #expect(before.contains("PrivateKey"))

        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: confPath)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: confPath) }

        await #expect(throws: (any Error).self) {
            try await host.addPeer(publicKey: Data(repeating: 7, count: 32), allowedIP: "10.86.0.2")
        }

        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: confPath)
        let after = try String(contentsOfFile: confPath, encoding: .utf8)
        #expect(after == before, "a conf that could not be read was rewritten anyway")
    }

    @Test func aSpentTokenSaysWhatToDoAboutIt() async throws {
        let fixture = try makeFixture(port: 47435)
        defer { fixture.cleanup() }

        let token = fixture.tokens.mint()
        _ = try await enroll(fixture, token: token, name: "first")

        let replay = try await enroll(fixture, token: token, name: "second")
        guard case .refused(let error) = replay else {
            Issue.record("token replay was accepted")
            return
        }
        // "invalid or expired" pointed at the QR's age and left the operator
        // re-scanning the same dead code. The message names the remedy.
        #expect(error.code == "enroll-token")
        #expect(error.message.contains("reachd pair"))
    }
}
