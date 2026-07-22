import Foundation
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Testing
import X509
@testable import ReachDaemon

private func withTimeout<T: Sendable>(
    _ seconds: Double,
    _ operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(for: .seconds(seconds))
            throw TransportError.connectionFailed("test timeout after \(seconds)s")
        }
        let value = try await group.next()!
        group.cancelAll()
        return value
    }
}

@Suite struct ClusterCATests {
    @Test func issuedChainsVerifyAgainstTheRoot() async throws {
        let ca = try ClusterCA.create(commonName: "Reach Test CA")
        let server = try ca.issueServer(
            commonName: "localhost",
            dnsNames: ["localhost"],
            ipAddresses: [[127, 0, 0, 1]]
        )
        let client = try ca.issueClient(
            commonName: "test-device",
            uri: "reach://device/test"
        )

        var verifier = try Verifier(rootCertificates: CertificateStore([ca.certificate])) {
            RFC5280Policy()
        }
        for leaf in [server.certificate, client.certificate] {
            let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore())
            guard case .validCertificate = result else {
                Issue.record("chain did not validate: \(result)")
                return
            }
        }
    }

    @Test func caPersistsAndReloads() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-ca-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }

        let ca = try ClusterCA.create(commonName: "Reach Persist CA")
        try ca.save(to: dir)
        let loaded = try ClusterCA.load(from: dir)
        #expect(try loaded.certificateDER() == ca.certificateDER())
    }
}

@Suite(.serialized) struct LoopbackTransportTests {
    private struct Fixture {
        let ca: ClusterCA
        let caCert: SecCertificate
        let serverIdentity: SecIdentity
        let clientIdentity: SecIdentity
        let cleanup: @Sendable () -> Void
    }

    /// Builds a `SecIdentity` for an issued leaf. Prefers the production
    /// path (keychain assembly, as the ceremony uses on device); falls back
    /// to an openssl-built PKCS#12 when the test process lacks keychain
    /// access (errSecMissingEntitlement under the CI/harness sandbox —
    /// `SecPKCS12Import` works there and exercises the same TLS surface).
    private func makeIdentity(_ issued: ClusterCA.Issued, label: String) throws -> (SecIdentity, @Sendable () -> Void) {
        do {
            let identity = try KeychainIdentity.store(
                privateKeyX963: issued.privateKeyX963,
                certificateDER: try issued.certificateDER(),
                label: label
            )
            return (identity, { KeychainIdentity.remove(label: label) })
        } catch IdentityError.keychainAddFailed(let status) where status == errSecMissingEntitlement {
            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent("reach-id-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let keyURL = dir.appendingPathComponent("key.pem")
            let certURL = dir.appendingPathComponent("cert.pem")
            let p12URL = dir.appendingPathComponent("identity.p12")
            try issued.privateKey.pemRepresentation.write(to: keyURL, atomically: true, encoding: .utf8)
            try issued.certificate.serializeAsPEM().pemString.write(to: certURL, atomically: true, encoding: .utf8)

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
            process.arguments = [
                "pkcs12", "-export",
                "-inkey", keyURL.path, "-in", certURL.path,
                "-out", p12URL.path, "-passout", "pass:reach-test",
            ]
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                throw IdentityError.importFailed("openssl pkcs12 exited \(process.terminationStatus)")
            }
            let identity = try IdentityStore.identity(
                fromPKCS12: Data(contentsOf: p12URL),
                passphrase: "reach-test"
            )
            return (identity, { try? FileManager.default.removeItem(at: dir) })
        }
    }

    private func makeFixture() throws -> Fixture {
        let ca = try ClusterCA.create(commonName: "Reach Loopback CA")
        let server = try ca.issueServer(
            commonName: "localhost",
            dnsNames: ["localhost"],
            ipAddresses: [[127, 0, 0, 1]]
        )
        let client = try ca.issueClient(commonName: "loopback-client", uri: "reach://device/loopback")

        let (serverIdentity, serverCleanup) = try makeIdentity(server, label: "reach-test-server-\(UUID().uuidString)")
        let (clientIdentity, clientCleanup) = try makeIdentity(client, label: "reach-test-client-\(UUID().uuidString)")
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())
        return Fixture(
            ca: ca,
            caCert: caCert,
            serverIdentity: serverIdentity,
            clientIdentity: clientIdentity,
            cleanup: { serverCleanup(); clientCleanup() }
        )
    }

    @Test func mutualTLSRoundTripAndPeerIdentity() async throws {
        let fixture = try makeFixture()
        defer { fixture.cleanup() }

        let serverOptions = TLSBuilder.serverOptions(
            alpn: Wire.alpn,
            identity: fixture.serverIdentity,
            clientTrustRoots: [fixture.caCert]
        )
        let listener = try QUICListener(port: 47411, parameters: .reachQUIC(options: serverOptions))
        defer { listener.cancel() }

        let serverTask = Task {
            for try await tunnel in listener.tunnels {
                for await stream in tunnel.inboundStreams {
                    for try await raw in stream.frames {
                        let hello = try raw.decode(Hello.self)
                        #expect(hello.client == "loopback-test")
                        // The daemon's grant hook: the peer's leaf rides the
                        // stream's tunnel metadata.
                        #expect(stream.peerCertificateDER() != nil)
                        try await stream.send(HelloAck(cluster: "loopback", models: []))
                    }
                }
            }
        }
        defer { serverTask.cancel() }

        let clientOptions = TLSBuilder.clientOptions(
            alpn: Wire.alpn,
            identity: fixture.clientIdentity,
            serverTrustRoots: [fixture.caCert]
        )
        let ack: HelloAck = try await withTimeout(60) {
            let dialer = QUICDialer(
                endpoint: .hostPort(host: "127.0.0.1", port: 47411),
                parameters: .reachQUIC(options: clientOptions)
            )
            let stream = try await dialer.openStream(timeout: 45)
            try await stream.send(Hello(client: "loopback-test"))
            for try await raw in stream.frames {
                return try raw.decode(HelloAck.self)
            }
            throw TransportError.streamClosed
        }
        #expect(ack.cluster == "loopback")
        #expect(ack.version == Wire.version)
    }

    @Test func certlessClientNeverRoundTrips() async throws {
        let fixture = try makeFixture()
        defer { fixture.cleanup() }

        let serverOptions = TLSBuilder.serverOptions(
            alpn: Wire.alpn,
            identity: fixture.serverIdentity,
            clientTrustRoots: [fixture.caCert]
        )
        let listener = try QUICListener(port: 47412, parameters: .reachQUIC(options: serverOptions))
        defer { listener.cancel() }

        let serverTask = Task {
            for try await tunnel in listener.tunnels {
                for await stream in tunnel.inboundStreams {
                    for try await raw in stream.frames {
                        _ = try? raw.decode(Hello.self)
                        try await stream.send(HelloAck(cluster: "should-never-send", models: []))
                    }
                }
            }
        }
        defer { serverTask.cancel() }

        // No identity: TLS 1.3 may let the client believe it connected, so
        // the assertion probes the data plane (spike S1a).
        let clientOptions = TLSBuilder.clientOptions(
            alpn: Wire.alpn,
            identity: nil,
            serverTrustRoots: [fixture.caCert]
        )
        let outcome: String = await {
            do {
                return try await withTimeout(60) {
                    let dialer = QUICDialer(
                        endpoint: .hostPort(host: "127.0.0.1", port: 47412),
                        parameters: .reachQUIC(options: clientOptions)
                    )
                    let stream = try await dialer.openStream(timeout: 45)
                    try await stream.send(Hello(client: "illicit"))
                    for try await raw in stream.frames {
                        return "received \(raw.type)"
                    }
                    return "closed without frames"
                }
            } catch {
                return "refused: \(error)"
            }
        }()
        #expect(!outcome.hasPrefix("received"), "cert-less client obtained service: \(outcome)")
    }
}
