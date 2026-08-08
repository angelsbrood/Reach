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

    /// The listener leaf survives a restart instead of being re-minted.
    ///
    /// The defect this pins is not visible from the daemon at all: fresh key
    /// and certificate material on every `reachd serve` is never a duplicate
    /// to `SecItemAdd`, so each start left one more of each in the login
    /// keychain, and nothing ever removed them. Measured at 13 certificates
    /// under the daemon's own common name, all from production starts.
    /// Reuse is what makes them duplicates, and duplicates are what
    /// `KeychainIdentity.store` already tolerates.
    @Test func theListenerLeafIsMintedOnceAndReused() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-serverleaf-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }

        let ca = try ClusterCA.create(commonName: "Reach Leaf CA")
        try ca.save(to: dir)

        let arguments = (commonName: "reachd", dnsNames: ["localhost"], ipAddresses: [[UInt8]]([[127, 0, 0, 1]]))
        let first = try ca.serverLeaf(in: dir, commonName: arguments.commonName, dnsNames: arguments.dnsNames, ipAddresses: arguments.ipAddresses)
        let second = try ca.serverLeaf(in: dir, commonName: arguments.commonName, dnsNames: arguments.dnsNames, ipAddresses: arguments.ipAddresses)

        // Byte-identical on both halves: a different key or a different
        // serial is a different keychain item, which is the whole defect.
        #expect(try first.certificateDER() == second.certificateDER())
        #expect(first.privateKey.rawRepresentation == second.privateKey.rawRepresentation)
        #expect(first.certificate.serialNumber == second.certificate.serialNumber)

        // The key is a secret and lands with the same guard as the CA's own.
        let keyMode = try FileManager.default.attributesOfItem(
            atPath: dir.appendingPathComponent("server-key.raw").path
        )[.posixPermissions] as? NSNumber
        #expect(keyMode?.int16Value == 0o600)
    }

    /// …but rotation is not lost, or a cluster would serve one leaf forever.
    @Test func aLeafInsideItsRenewalWindowIsReissued() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-serverleaf-renew-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }

        let ca = try ClusterCA.create(commonName: "Reach Renew CA")
        try ca.save(to: dir)

        let original = try ca.serverLeaf(in: dir, commonName: "reachd", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]], days: 30)
        // Stand 29½ days on: inside the one-day renewal window, so the next
        // start should mint rather than serve a leaf about to expire.
        let renewed = try ca.serverLeaf(
            in: dir,
            commonName: "reachd",
            dnsNames: ["localhost"],
            ipAddresses: [[127, 0, 0, 1]],
            days: 30,
            now: Date().addingTimeInterval(29.5 * 24 * 3600)
        )
        #expect(try original.certificateDER() != renewed.certificateDER())

        // And the replacement is what a later start will load.
        let afterwards = try ca.serverLeaf(in: dir, commonName: "reachd", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]], days: 30)
        #expect(try afterwards.certificateDER() == renewed.certificateDER())
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
/// identity a test makes outlives the run unless something deletes it. This
/// holds the ones a fixture creates after it exists, and fixture teardown
/// drains it.
///
/// **One bin per fixture, and that is the whole point.** This was a `static`
/// bin shared by the target, so `drain()` deleted every identity *any*
/// concurrent suite had deposited — and `.serialized` orders a suite against
/// itself only, so one suite's teardown could pull an identity out from under
/// another suite mid-handshake. Latent rather than observed, but two suites
/// had already declined to join it and written down why, which is a defect
/// being routed around rather than fixed. An instance cannot answer for
/// anyone else's identities, so the question stops being askable.
final class IdentityBin: @unchecked Sendable {
    private let lock = NSLock()
    private var held: [IdentityBox] = []

    func add(_ identity: SecIdentity) {
        lock.lock()
        defer { lock.unlock() }
        held.append(IdentityBox(identity))
    }

    func drain() {
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
        let listener = try QUICListener(port: TestPorts.port(47411), parameters: .reachQUIC(options: serverOptions))
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
        let (ack, stream): (HelloAck, ReachTransport.QUICStream) = try await withTimeout(60) {
            let dialer = QUICDialer(
                endpoint: .hostPort(host: "127.0.0.1", port: .init(rawValue: TestPorts.port(47411))!),
                parameters: .reachQUIC(options: clientOptions)
            )
            let stream = try await dialer.openStream(timeout: 45)
            try await stream.send(Hello(client: "loopback-test"))
            for try await raw in stream.frames {
                return (try raw.decode(HelloAck.self), stream)
            }
            throw TransportError.streamClosed
        }
        #expect(ack.cluster == "loopback")
        #expect(ack.version == Wire.version)

        // A read that is waiting when this side cancels its own stream. Folded
        // into this fixture on purpose — `makeFixture` materializes two
        // identities through `SecPKCS12Import`, and a fixture per assertion is
        // what starves the cooperative pool.
        //
        // Both halves of the enrollment ceremony do exactly this: they arm a
        // deadline task that calls `cancel()` on the stream they are parked on,
        // and the keeper's comment claims the cancel "lands as a clean nil
        // below." **Measured 2026-07-30 at 12 of 12: it does.** The race that
        // reading predicts is real on paper — `connection.cancel()` could
        // complete the parked receive with an error (`QUIC.swift:122` →
        // `finish(throwing:)`) before the state handler reaches `.cancelled`
        // (`QUIC.swift:50` → `finish()`), and `AsyncThrowingStream.finish` is
        // first-caller-wins — but on this transport the state handler wins
        // every time. Written down because the opposite was assumed first, and
        // the fix was very nearly justified by it.
        //
        // So the ending that bypasses a `guard`'s `else` is NOT a timeout. It
        // is a peer that resets: `.failed` → `finish(throwing:)`, which is the
        // `POSIXErrorCode 57` the July cut's own daemon log carries. That is
        // hardware evidence, not fixture evidence, and it is the whole reason
        // `FrameEnding.next` may not throw.
        //
        // What is asserted here is the invariant rather than the winner — the
        // winner is a race this machine happens to settle one way, and pinning
        // it would pin the settlement rather than the property. A cancelled
        // read TERMINATES. If it ever stopped finishing the continuation, the
        // keeper's ten-second deadline would never return and the phone would
        // sit on "Enrolling…" for as long as anyone waited, which no other test
        // in this tree would notice.
        let parked = Task { () -> FrameEnding in
            var iterator = stream.frames.makeAsyncIterator()
            return await FrameEnding.next(from: &iterator)
        }
        // The read has to be waiting before the cancel, or this measures the
        // wrong thing: a cancel that lands first finishes the stream and the
        // read never parks at all.
        try? await Task.sleep(for: .milliseconds(250))
        let cancelledAt = ContinuousClock.now
        stream.cancel()
        // Only so a regression fails instead of hanging the suite. The bound
        // being asserted is the elapsed time, not this.
        let watchdog = Task { try? await Task.sleep(for: .seconds(5)); parked.cancel() }
        defer { watchdog.cancel() }
        let ending = await parked.value
        #expect(
            ContinuousClock.now - cancelledAt < .seconds(5),
            "a cancelled read did not terminate — the keeper's deadline would wait forever"
        )
        // Not asserted, only named: `.frame` would mean the cancel did not end
        // the read at all, which the elapsed bound above cannot catch on its
        // own — a frame that was already buffered returns instantly.
        if case .frame = ending {
            Issue.record("a cancelled read returned a frame: the stream outlived its own cancel")
        }
    }

    @Test func certlessClientNeverRoundTrips() async throws {
        let fixture = try makeFixture()
        defer { fixture.cleanup() }

        let serverOptions = TLSBuilder.serverOptions(
            alpn: Wire.alpn,
            identity: fixture.serverIdentity,
            clientTrustRoots: [fixture.caCert]
        )
        let listener = try QUICListener(port: TestPorts.port(47412), parameters: .reachQUIC(options: serverOptions))
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
                        endpoint: .hostPort(host: "127.0.0.1", port: .init(rawValue: TestPorts.port(47412))!),
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

    @Test func dialectsNegotiateBeforeASessionExists() async throws {
        let fixture = try makeFixture()
        defer { fixture.cleanup() }

        var config = DaemonConfig()
        config.port = TestPorts.port(47458)
        config.clusterName = "versions-test"
        let registry = SessionRegistry()
        let daemon = Daemon(
            config: config,
            filling: ScriptedFilling(),
            identity: Daemon.ListenerIdentity(
                identity: fixture.serverIdentity,
                caCertificate: fixture.caCert
            ),
            registry: registry
        )
        try await daemon.start(advertise: false)
        defer { Task { await daemon.stop() } }

        let dialer = QUICDialer(
            endpoint: .hostPort(
                host: "127.0.0.1",
                port: .init(rawValue: TestPorts.port(47458))!
            ),
            parameters: .reachQUIC(options: TLSBuilder.clientOptions(
                alpn: Wire.alpn,
                identity: fixture.clientIdentity,
                serverTrustRoots: [fixture.caCert]
            ))
        )

        let incompatible = try await dialer.openStream(timeout: 45)
        defer { incompatible.cancel() }
        var refusedFrames = incompatible.frames.makeAsyncIterator()
        try await incompatible.send(Hello(versions: [1], client: "future-only"))
        let refused = try #require(try await refusedFrames.next())
        let error = try refused.decode(ErrorFrame.self)
        #expect(error.code == "wire-version")
        #expect(error.message.hasPrefix("your cluster speaks an older generation"))
        #expect(await registry.residentSessions == 0)

        let compatible = try await dialer.openStream(timeout: 45)
        defer { compatible.cancel() }
        var frames = compatible.frames.makeAsyncIterator()
        try await compatible.send(Hello(versions: [1, 0], client: "future-compatible"))
        let ack = try (try #require(try await frames.next())).decode(HelloAck.self)
        #expect(ack.version == 0)
        try await compatible.send(SessionOpen(modelID: "scripted"), for: ack.version)
        _ = try (try #require(try await frames.next())).decode(SessionOpened.self)
        #expect(await registry.residentSessions == 1)
    }
}
