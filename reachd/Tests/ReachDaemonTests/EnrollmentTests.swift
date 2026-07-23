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

    private func makeFixture(port: UInt16) throws -> Fixture {
        let stateDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-enroll-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)
        let confPath = stateDir.appendingPathComponent("reach0.conf").path

        let ca = try ClusterCA.create(commonName: "Ceremony CA")
        let caDER = try ca.certificateDER()
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-enroll-server-\(UUID())")
        let caCert = try IdentityStore.certificate(fromDER: caDER)

        let tokens = TokenStore(directory: stateDir)
        let wgHost = try WireGuardHost(
            keysDirectory: stateDir.appendingPathComponent("wg", isDirectory: true),
            confPath: confPath,
            endpoint: "192.0.2.1:51820"
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
                try? FileManager.default.removeItem(at: stateDir)
            }
        )
    }

    private func enroll(
        _ fixture: Fixture,
        token: String,
        name: String,
        breakPoP: Bool = false,
        deviceKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()
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
        try await stream.send(EnrollComplete(ok: true))
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
}
