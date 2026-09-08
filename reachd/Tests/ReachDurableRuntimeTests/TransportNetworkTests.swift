import Foundation
import XCTest
import Network
import ReachWire
import ReachTransport
import ReachIdentity
@testable import ReachDurableRuntime

final class TransportNetworkTests: XCTestCase, @unchecked Sendable {
    private func pair(_ fixture: TransportTLSFixtures, clientIdentity: TransportIdentity? = nil,
                      body: (BoundedQUICStream, BoundedQUICStream, BoundedQUICListener) async throws -> Void) async throws {
        let listener = try BoundedQUICListener(port: 54394, parameters: fixture.host.parameters())
        var client: BoundedQUICStream?, server: BoundedQUICStream?
        let incoming = Task { () throws -> BoundedQUICStream in
            for try await stream in listener.streams { return stream }
            throw BoundedTransportError.closed
        }
        do {
            try await listener.waitUntilReady()
            let c = try await BoundedQUICStream.open(endpoint: .hostPort(host: "127.0.0.1", port: 54394), parameters: (clientIdentity ?? fixture.client).parameters())
            client = c
            // QUIC stream creation is lazy; the first write makes the server's
            // stream available. These are bounded bytes, consumed after pinning.
            try await c.send(FrameCodec.encode(Hello(versions: [2], client: "fixture"), for: 2))
            let s = try await TransportConnection.deadline(.seconds(10)) {
                try await withTaskCancellationHandler { try await incoming.value } onCancel: { incoming.cancel() }
            }
            server = s; try await s.waitUntilReady()
            try await body(c, s, listener)
            await c.cancelAndWait(); await s.cancelAndWait(); await listener.cancelAndWait()
        } catch {
            await client?.cancelAndWait(); await server?.cancelAndWait(); await listener.cancelAndWait()
            incoming.cancel(); _ = await incoming.result; throw error
        }
        incoming.cancel(); _ = await incoming.result
    }
    func testPinnedTLSFragmentationOverflowTruncationAndContention() async throws {
        let fixture = try TransportTLSFixtures(); defer { try? fixture.close() }
        try await pair(fixture) { client, server, listener in
            XCTAssertEqual(try fixture.host.requirePeer(server), fixture.client.selection.pins.clientLeaf)
            XCTAssertEqual(try fixture.client.requirePeer(client), fixture.host.selection.pins.hostLeaf)
            _ = try await TransportConnection.read(server)
            let bytes = try FrameCodec.encode(Hello(versions: [2], client: String(repeating: "x", count: 180_000)), for: 2)
            let read = Task { try await TransportConnection.read(server) }
            for start in stride(from: 0, to: bytes.count, by: 997) { try await client.send(Data(bytes[start..<min(start + 997, bytes.count)])) }
            let frame = try await read.value
            XCTAssertEqual(try TransportConnection.bytes(frame), bytes)
            XCTAssertLessThanOrEqual(server.metrics.maximumReceive, 65536)
            XCTAssertGreaterThan(server.metrics.receiveCalls, 3)
            var extra: BoundedQUICStream?
            do {
                extra = try await BoundedQUICStream.open(endpoint: .hostPort(host: "127.0.0.1", port: 54394), parameters: fixture.client.parameters(), timeout: .seconds(2))
                try await extra!.send(FrameCodec.encode(Hello(versions: [2], client: "excess"), for: 2))
                _ = try await TransportConnection.read(extra!, timeout: .seconds(2))
                XCTFail("excess connection received a frame")
            } catch {}
            await extra?.cancelAndWait()
            XCTAssertGreaterThan(listener.rejectedConnectionsOrStreams, 0)
            // Cancellation must settle the old read before a later connection.
            let pending = Task { try await server.next() }
            await server.cancelAndWait()
            do { _ = try await pending.value; XCTFail("cancelled read succeeded") } catch {}
            do { try await server.send(Data([1])); XCTFail("closed send succeeded") }
            catch { XCTAssertEqual(error as? BoundedTransportError, .closed) }
        }
        try await pair(fixture) { client, server, _ in
            _ = try fixture.host.requirePeer(server); _ = try await TransportConnection.read(server)
            var count = UInt32((2 << 20) + 2).bigEndian
            let header = withUnsafeBytes(of: &count) { Data($0) } + Data([FrameType.hello.rawValue])
            try await client.send(header)
            do { _ = try await server.next(); XCTFail("oversize header accepted") }
            catch { XCTAssertEqual(error as? BoundedTransportError, .overflow) }
            // Previous valid Hello is the only allocated body.
            XCTAssertLessThan(server.metrics.maximumBody, 1024)
        }
        try await pair(fixture) { client, server, _ in
            _ = try fixture.host.requirePeer(server); _ = try await TransportConnection.read(server)
            try await client.send(Data([0,0,0,10,FrameType.hello.rawValue,123]))
            let pending = Task { try await TransportConnection.read(server, timeout: .seconds(2)) }
            await client.cancelAndWait()
            do { _ = try await pending.value; XCTFail("truncated body produced a frame") } catch {}
        }
        try await pair(fixture, clientIdentity: fixture.other) { _, server, _ in
            XCTAssertNotNil(server.peerCertificateDER()) // The same-CA TLS chain succeeded.
            XCTAssertThrowsError(try fixture.host.requirePeer(server)) // Exact leaf authority refuses before read.
            XCTAssertEqual(server.metrics.receiveCalls, 0)
        }
    }
}

extension TransportNetworkTests {
    func testNoCertificateAndUnrelatedCARefuseBeforeApplicationRead() async throws {
        let fixture = try TransportTLSFixtures(); defer { try? fixture.close() }
        let publicCAPath = try ArtifactFixtures.base().replacingOccurrences(of: "/fixtures", with: "/evidence/disposable-public-ca.json")
        struct PublicCA: Decodable { let caDER: Data }
        let unrelated = try IdentityStore.certificate(fromDER: JSONDecoder().decode(PublicCA.self, from: Data(contentsOf: URL(fileURLWithPath: publicCAPath))).caDER)
        for wrongCA in [false, true] {
            let listener = try BoundedQUICListener(port: 54394, parameters: fixture.host.parameters())
            try await listener.waitUntilReady()
            let identity = wrongCA ? try IdentityStore.identity(fromPKCS12: LocalFiles.read(fixture.root + "/accepted/client/identity.p12", maximum: 1 << 20), passphrase: TransportContract.archivePassphrase) : nil
            let options = TLSBuilder.clientOptions(alpn: Wire.alpn, identity: identity, serverTrustRoots: [wrongCA ? unrelated : fixture.ca])
            var connection: BoundedQUICStream?
            do {
                connection = try await BoundedQUICStream.open(endpoint: .hostPort(host: "127.0.0.1", port: 54394), parameters: .reachQUIC(options: options), timeout: .seconds(2))
                try await connection!.send(FrameCodec.encode(Hello(versions: [2], client: "refused"), for: 2))
                _ = try await TransportConnection.read(connection!, timeout: .seconds(2))
                XCTFail("unauthenticated connection produced application data")
            } catch {}
            await connection?.cancelAndWait(); await listener.cancelAndWait()
        }
    }
}
