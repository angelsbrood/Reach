import AcceptanceControllerCore
import Darwin
import Foundation
import XCTest

final class PublicationTests: XCTestCase {
    private func payloads(packetName: String) throws -> [String: Data] {
        var vector = RunResourceVector(frozenActions: 0)
        try vector.assign(.publicationAttempts, value: 1)
        try vector.validateComplete(requireExact: true)
        let records: [ActionRecord] = []
        let action = try CanonicalJSON.encode(records)
        let ledger = try CanonicalJSON.encode(RunLedgerPayload(records: records, resourceVector: vector))
        let launch = Data("{\"rows\":[],\"version\":1}".utf8)
        let outcome = OutcomePayload(
            version: 1, outcome: .pass, packetBasename: packetName,
            actionTableDigest: SHA256.hex(action), runLedgerDigest: SHA256.hex(ledger),
            sliceLaunchSnapshotDigest: SHA256.hex(launch), earliestStopOrdinal: nil,
            publicResults: [:], claimBoundaryDigest: SHA256.hex(Data("synthetic".utf8))
        )
        return [
            "action-table.json": action,
            "launch-snapshot.json": launch,
            "outcome.json": try CanonicalJSON.encode(outcome),
            "run-ledger.json": ledger,
        ]
    }

    func testManifestRootAndIndependentVerification() throws {
        _ = TestLaunchCounts.shared
        let parent = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("reach-publication-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: parent, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let final = parent.appendingPathComponent("packet")
        let published = try PacketPublisher.publish(payloads: payloads(packetName: "packet"), finalURL: final)
        XCTAssertEqual(try PacketPublisher.verify(final).rootDigest, published.rootDigest)
    }

    func testMutationOmissionExtraAndModeRefuse() throws {
        _ = TestLaunchCounts.shared
        let parent = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("reach-mutation-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: parent, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let final = parent.appendingPathComponent("packet")
        _ = try PacketPublisher.publish(payloads: payloads(packetName: "packet"), finalURL: final)
        let extra = final.appendingPathComponent("extra")
        FileManager.default.createFile(atPath: extra.path, contents: Data())
        XCTAssertThrowsError(try PacketPublisher.verify(final))
        try FileManager.default.removeItem(at: extra)
        let outcome = final.appendingPathComponent("outcome.json")
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: outcome.path)
        XCTAssertThrowsError(try PacketPublisher.verify(final))
    }

    func testRenameExclRaceHasOneImmutableWinner() throws {
        _ = TestLaunchCounts.shared
        let parent = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("reach-race-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: parent, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: parent) }
        let final = parent.appendingPathComponent("packet")
        let body = try payloads(packetName: "packet")
        let lock = NSLock()
        var successes = 0
        var collisions = 0
        let group = DispatchGroup()
        let gate = DispatchSemaphore(value: 0)
        TestLaunchCounts.shared.chargePublisher(2)
        for _ in 0..<2 {
            group.enter()
            DispatchQueue.global().async {
                gate.wait()
                do { _ = try PacketPublisher.publish(payloads: body, finalURL: final); lock.withLock { successes += 1 } }
                catch { lock.withLock { collisions += 1 } }
                group.leave()
            }
        }
        gate.signal(); gate.signal(); group.wait()
        XCTAssertEqual(successes, 1)
        XCTAssertEqual(collisions, 1)
        XCTAssertNoThrow(try PacketPublisher.verify(final))
    }
}
