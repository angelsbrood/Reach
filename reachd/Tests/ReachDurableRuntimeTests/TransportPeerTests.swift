import Foundation
import XCTest
import Network
import ReachWire
import ReachTransport
import RequestPreparationContract
@testable import ReachDurableRuntime

/// Controlled test peer for an explicitly supplied, owned normal-host fixture.
/// It imports only that pair's client TLS archive. It has no journal key, model
/// or provider and is never a production fault option.
final class TransportPeerTests: XCTestCase, @unchecked Sendable {
    private func selected() throws -> TransportIdentity {
        if let root=ProcessInfo.processInfo.environment["S95_PEER_ROOT"] {
            guard root.hasPrefix("/private/tmp/reach-s95."),root.contains("/roots/") else { throw TransportRuntimeError.invalid }
            let selection=try JSONDecoder().decode(TransportSelectionBinding.self,from:LocalFiles.read(root+"/client/selection.json",maximum:65536))
            try selection.validate(role:.client)
            guard selection.revision==IndependentContract.revision else { throw TransportRuntimeError.invalid }
            return try TransportIdentity(root:root,selection:selection,audit:TransportRoleAudit(.client))
        }
        guard let root = ProcessInfo.processInfo.environment["S94_PEER_ROOT"] else { throw XCTSkip("requires owned normal-host fixture") }
        guard root.hasPrefix("/private/tmp/reach-s94."), root.contains("/roots/") else { throw TransportRuntimeError.invalid }
        let selection = try JSONDecoder().decode(TransportSelection.self, from: LocalFiles.read(root + "/client/selection.json", maximum: 65536))
        try selection.binding.validate(role: .client)
        return try TransportIdentity(root: root, selection: selection.binding, audit: TransportRoleAudit(.client))
    }
    private func open(_ identity: TransportIdentity) async throws -> BoundedQUICStream {
        let stream = try await BoundedQUICStream.open(endpoint: .hostPort(host: "127.0.0.1", port: .init(rawValue: identity.selection.port)!), parameters: identity.parameters())
        do { _ = try identity.requirePeer(stream); return stream }
        catch { await stream.cancelAndWait(); throw error }
    }
    private func handshake(_ stream: BoundedQUICStream) async throws {
        try await TransportConnection.send(FrameCodec.encode(Hello(versions: [2], client: "controlled-peer"), for: 2), on: stream)
        let ack = try await TransportConnection.read(stream).decode(HelloAck.self)
        XCTAssertEqual(ack.version, 2); XCTAssertEqual(ack.models.map(\.id), [TransportContract.model])
        guard case .capabilities = try DurableMessage.decode(await TransportConnection.read(stream), version: 2) else { throw TransportRuntimeError.protocolRefused }
    }
    func testOldDialectAndPreHelloDurableFramesRefuse() async throws {
        let identity = try selected()
        let preHello = try DurableMessage.open(.init(.init(requestID: "premature", modelID: TransportContract.model, profile: identity.selection.profile, durable: true))).encode(version: 2)
        for bytes in [try FrameCodec.encode(Hello(versions: [1,0], client: "old")), preHello] {
            let stream = try await open(identity)
            do {
                try await TransportConnection.send(bytes, on: stream)
                _ = try await TransportConnection.read(stream)
                XCTFail("incompatible handshake received application data")
            } catch {}
            await stream.cancelAndWait()
        }
    }
    func testConfiguredProfileMismatchBeforeOriginalIssue() async throws {
        let identity=try selected(),stream=try await open(identity)
        do {
            try await handshake(stream)
            let other=identity.selection.profile == DurableWire.profile ? DurableWire.independentProfile : DurableWire.profile
            try await TransportConnection.send(DurableMessage.open(.init(.init(requestID:"wrong-profile",modelID:TransportContract.model,profile:other,durable:true))).encode(version:2),on:stream)
            guard case .refused = try DurableMessage.decode(await TransportConnection.read(stream),version:2) else { throw TransportRuntimeError.invalid }
            await stream.cancelAndWait()
        } catch { await stream.cancelAndWait();throw error }
    }
    func testUnsolicitedTerminalReceiptRefuses() async throws {
        let identity = try selected(), stream = try await open(identity)
        do {
            try await handshake(stream)
            let digest = String(repeating: "0", count: 64)
            let reference = DurableGenerationReference(session: .init(modelID: TransportContract.model, profile: identity.selection.profile, sessionID: UUID().uuidString.lowercased()), generationID: "generation", operationID: "operation")
            let witness = DurableWitness(context: digest, clientRoot: UUID().uuidString.lowercased(), revision: 1, high: 1, terminal: true, prefix: digest, registrations: 0, calls: digest)
            let receipt = try DurableMessage.receipt(.init(.init(requestID: "unsolicited-terminal", reference: reference, witness: witness))).encode(version: 2)
            try await TransportConnection.send(receipt, on: stream)
            do {
                let refusal = try await TransportConnection.read(stream).decode(ErrorFrame.self)
                XCTAssertEqual(refusal.code, "durable-unavailable")
            } catch {}
            await stream.cancelAndWait()
        } catch { await stream.cancelAndWait(); throw error }
    }
    func testWithholdReceiptAfterUnregisteredBegin() async throws {
        let identity = try selected(), stream = try await open(identity)
        do {
            try await handshake(stream)
            let request = try ArtifactFixtures.request("ordinary")
            try await TransportConnection.send(DurableMessage.open(.init(.init(requestID: "peer-open", modelID: TransportContract.model, profile: identity.selection.profile, durable: true))).encode(version: 2), on: stream)
            guard case .opened(let opened) = try DurableMessage.decode(await TransportConnection.read(stream), version: 2) else { throw TransportRuntimeError.protocolRefused }
            let id = request.id.uuidString.lowercased()
            let reference = DurableGenerationReference(session: opened.payload.session, generationID: "generation-" + id, operationID: "operation-" + id)
            try await TransportConnection.send(DurableMessage.begin(.init(.init(requestID: "peer-begin", reference: reference, ticket: opened.payload.ticket, request: request))).encode(version: 2), on: stream)
            guard case .accepted = try DurableMessage.decode(await TransportConnection.read(stream), version: 2) else { throw TransportRuntimeError.protocolRefused }
            guard case .batch = try DurableMessage.decode(await TransportConnection.read(stream), version: 2) else { throw TransportRuntimeError.protocolRefused }
            // No client journal is created, and transport receipt is not treated
            // as durable client receipt. A second batch must wait for a witness.
            do {
                _ = try await TransportConnection.read(stream, timeout: .milliseconds(400))
                XCTFail("host sent a second batch without a receipt")
            } catch { XCTAssertEqual(error as? BoundedTransportError, .timeout) }
            await stream.cancelAndWait()
        } catch { await stream.cancelAndWait(); throw error }
    }
}
