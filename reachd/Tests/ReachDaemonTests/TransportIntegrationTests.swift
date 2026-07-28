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

/// `SecIdentity` is a CF type with no Sendable conformance; deleting one is a
/// single Security call, and this carries it to a teardown closure.
struct IdentityBox: @unchecked Sendable {
    let identity: SecIdentity
    init(_ identity: SecIdentity) { self.identity = identity }
}

/// Identities materialized in the middle of a test, waiting to be removed.
///
/// `SecPKCS12Import` adds to the login keychain as a side effect, so every
/// identity a test makes outlives the run unless something deletes it — which
/// nothing did, for as long as this suite has existed. Fixtures own the ones
/// they create; this holds the ones created mid-test, and fixture teardown
/// drains it.
enum IdentityTrash {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var held: [IdentityBox] = []

    static func add(_ identity: SecIdentity) {
        lock.lock()
        defer { lock.unlock() }
        held.append(IdentityBox(identity))
    }

    static func drain() {
        lock.lock()
        let boxes = held
        held.removeAll()
        lock.unlock()
        for box in boxes { KeychainIdentity.remove(identity: box.identity) }
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

    /// Builds a `SecIdentity` for an issued leaf — through the production
    /// path, deliberately.
    ///
    /// This used to be a hand-written copy of `IdentityMaterializer`: the
    /// same keychain-then-openssl-PKCS#12 composition, spelled out again
    /// here. That is why `pkcs12ImportFailed(0)` — `errSecSuccess` with an
    /// empty item list, i.e. two materializations at once — outlived the fix
    /// for it. The lock added in 0e839e4 serializes the composition inside
    /// `IdentityMaterializer`, and this copy was not inside it, so the
    /// duplicate went on racing at roughly one full run in eight.
    ///
    /// A test that reimplements the thing it is testing around cannot inherit
    /// its fixes. Call the real one.
    private func makeIdentity(_ issued: ClusterCA.Issued, label: String) throws -> (SecIdentity, @Sendable () -> Void) {
        let identity = try IdentityMaterializer.materialize(issued, label: label)
        // Delete the identity itself, not a label the keychain did not keep.
        // `SecPKCS12Import` adds to the login keychain as a side effect, so
        // without this every run leaves its fixtures behind — which is why
        // this machine's keychain holds thousands of them.
        //
        // SecIdentity is a CF type without a Sendable conformance; deleting
        // is a single Security call and the box carries it to the teardown.
        let box = IdentityBox(identity)
        return (identity, { KeychainIdentity.remove(identity: box.identity) })
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
