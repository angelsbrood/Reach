import Foundation
import XCTest
import ReachWire
import DurableRootKeys
import DurableStoreBootstrap
import WireAdapterContract
import RequestPreparationContract
@testable import ReachDurableRuntime

final class TransportContractTests: XCTestCase {
    func testClientAcquisitionGuardsFailBeforeForbiddenWork() throws {
        let client = TransportRoleAudit(.client)
        XCTAssertThrowsError(try client.load(.hostCatalog))
        XCTAssertThrowsError(try client.load(.hostTicket))
        XCTAssertThrowsError(try client.journal(.host))
        XCTAssertThrowsError(try client.model())
        XCTAssertTrue(client.snapshot.storageLoads.isEmpty)
        XCTAssertEqual(client.snapshot.hostJournalOpens, 0)
        XCTAssertEqual(client.snapshot.modelLoads, 0)
        try client.load(.clientMetadata); try client.journal(.client)
        XCTAssertEqual(client.snapshot.storageLoads, [RootKeyRole.clientMetadata.rawValue])
        let host = TransportRoleAudit(.host)
        XCTAssertThrowsError(try host.load(.clientMetadata))
        XCTAssertThrowsError(try host.journal(.client))
    }
    func testPinsDeriveCallerWithoutHelloClaims() throws {
        let pins = try TransportPins(.init(caDER: Data([1]), hostDER: Data([2]), clientDER: Data([3])))
        try pins.validate()
        XCTAssertEqual(pins.hostAuthorization.caller.principal, PreparationEncoding.hash(Data([1])))
        XCTAssertEqual(pins.hostAuthorization.caller.device, PreparationEncoding.hash(Data([3])))
        XCTAssertEqual(pins.clientAuthorization.caller.app, TransportContract.application)
        XCTAssertThrowsError(try TransportPins(.init(caDER: Data([1]), hostDER: Data([2]), clientDER: Data([2]))))
    }
    func testTransportQuotaAndNormalDialectRemainDistinct() throws {
        let policy = try TransportContract.bootstrapPolicy()
        XCTAssertEqual(policy.hostQuota, 1 << 30); XCTAssertEqual(policy.clientQuota, 1 << 30)
        XCTAssertEqual(Hello(client: "ordinary").versions, [1, 0])
        XCTAssertEqual(Hello(versions: [2], client: "explicit").versions, [2])
    }
    func testReservationSurvivesReopenAndRejectsReplacement() throws { try LocalDurableRuntime.withCPU {
        let root = try ArtifactFixtures.base() + "/admission-" + UUID().uuidString.lowercased()
        try LocalFiles.createDirectory(root); try LocalFiles.createDirectory(root + "/host")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let profile = try SelectedArtifactProfile(at: ArtifactFixtures.artifacts())
        let core = BootstrapCore(container: root + "/test.keychain-db", policy: try TransportContract.bootstrapPolicy())
        let pins = try TransportPins(.init(caDER: Data([1]), hostDER: Data([2]), clientDER: Data([3])))
        let hash = PreparationEncoding.hash(Data([4]))
        let selection = try TransportSelectionBinding(revision: TransportContract.revision, role: .host, bootstrap: core.binding(), profileDigest: profile.manifestDigest, archiveDigest: hash, executable: FrozenWorker(path: root + "/worker", sha256: hash), descriptor: profile.preparer.policy.descriptor, pins: pins, port: 54194)
        let key = try RootKeyMaterial(Data(repeating: 7, count: 32))
        let reference = DurableGenerationReference(session: .init(modelID: TransportContract.model, profile: DurableWire.profile, sessionID: UUID().uuidString.lowercased()), generationID: "generation", operationID: "operation")
        let requestBinding = try profile.preparer.policy.requestBinding(ArtifactFixtures.request("ordinary"), configuration: .init(dialect: 2, model: TransportContract.model, optIn: true, ready: true), route: "ordinary")
        XCTAssertFalse(PreparationEncoding.isDigest(requestBinding))
        let requestDigest = PreparationEncoding.hash(Data(requestBinding.utf8))
        let admission = try TransportHostAdmission(root: root, selection: selection, core: core, key: key)
        try admission.reserve(reference, requestDigest: requestDigest)
        let reopened = try TransportHostAdmission(root: root, selection: selection, core: core, key: key)
        XCTAssertEqual(reopened.reservation?.requestDigest, requestDigest)
        XCTAssertThrowsError(try reopened.reserve(reference, requestDigest: requestDigest))
        XCTAssertThrowsError(try TransportHostAdmission(root: root, selection: selection, core: core, key: RootKeyMaterial(Data(repeating: 8, count: 32))))
    } }
    func testEnvelopePreservesExactBytesAndRejectsOversizeControl() throws {
        let original = try FrameCodec.encode(Hello(versions: [2], client: "loopback"), for: 2)
        var parser = FrameReassembler(); let raw = try XCTUnwrap(parser.feed(original).first)
        XCTAssertEqual(try TransportConnection.bytes(raw), original)
        XCTAssertThrowsError(try TransportConnection.bytes(.init(type: .hello, body: Data(repeating: 0, count: (2 << 20) + 1))))
    }
}
