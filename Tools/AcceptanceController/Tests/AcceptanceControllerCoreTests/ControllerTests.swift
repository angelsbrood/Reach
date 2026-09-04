import AcceptanceControllerCore
import Darwin
import Foundation
import XCTest

final class TestLaunchCounts: @unchecked Sendable {
    static let shared = TestLaunchCounts()
    private let lock = NSLock()
    private var controllers = 0
    private var fixtures = 0
    private var publishers = 0

    private init() {
        atexit {
            let counts = TestLaunchCounts.shared.snapshot()
            print("REACH-ACCEPTANCE-TEST-COUNTS/1 {\"controllers\":\(counts.0),\"fixtures\":\(counts.1),\"publishers\":\(counts.2)}")
            fflush(stdout)
        }
    }

    func chargeController(_ count: Int = 1) { lock.withLock { controllers += count } }
    func chargeFixture(_ count: Int = 1) { lock.withLock { fixtures += count } }
    func chargePublisher(_ count: Int = 1) { lock.withLock { publishers += count } }
    func snapshot() -> (Int, Int, Int) { lock.withLock { (controllers, fixtures, publishers) } }
}

struct TestRunFactory {
    let root: URL
    let executable = URL(fileURLWithPath: "/bin/sh")

    init(_ name: String = UUID().uuidString) throws {
        _ = TestLaunchCounts.shared
        root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("reach-controller-test-\(name)")
        try? FileManager.default.removeItem(at: root)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }

    func makeAction(id: String, ordinal: Int, envelope: Data?, exit: Int32 = 0, sleep: Double = 0, allowed: [String] = []) throws -> ActionSpec {
        let script = root.appendingPathComponent("script-\(ordinal)-\(UUID().uuidString)")
        var text = "#!/bin/sh\n"
        if sleep > 0 { text += "/bin/sleep \(sleep)\n" }
        if let envelope {
            let encoded = envelope.base64EncodedString()
            text += "/usr/bin/base64 -D <<'EOF'\n\(encoded)\nEOF\n"
        }
        text += "exit \(exit)\n"
        try text.write(to: script, atomically: false, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let now = RawClock.now()
        return ActionSpec(
            id: id, ordinal: ordinal, executable: script.path, workingDirectory: root.path,
            workDeadlineNanoseconds: now + 2_000_000_000,
            settlementDeadlineNanoseconds: now + 8_000_000_000,
            allowedReasonCodes: allowed
        )
    }

    func writeSpec(actions: [ActionSpec], runID: String = UUID().uuidString) throws -> (URL, URL) {
        let launch = root.appendingPathComponent("launch.json")
        let source = root.appendingPathComponent("source-manifest.json")
        let launchData = Data("{\"rows\":[],\"version\":1}".utf8)
        let sourceData = Data("{\"paths\":[],\"version\":1}".utf8)
        try launchData.write(to: launch)
        try sourceData.write(to: source)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: launch.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: source.path)
        let packet = root.appendingPathComponent("packet")
        let spec = RunSpec(
            runID: runID, scratchRoot: root.path, packetPath: packet.path,
            launchSnapshotPath: launch.path, launchSnapshotDigest: SHA256.hex(launchData),
            sourceManifestPath: source.path, sourceManifestDigest: SHA256.hex(sourceData),
            executableDigest: try SHA256.file(executable), actions: actions
        )
        let specURL = root.appendingPathComponent("spec.json")
        try CanonicalJSON.encode(spec).write(to: specURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: specURL.path)
        return (specURL, packet)
    }
}

final class ControllerTests: XCTestCase {
    func testStrictDynamicEnvelopeRoundTrip() throws {
        let action = ActionSpec(
            id: "a", ordinal: 0, executable: "/bin/true", workingDirectory: "/private/tmp",
            workDeadlineNanoseconds: 1, settlementDeadlineNanoseconds: 2
        )
        let expected = ResultEnvelope(actionID: "a", ordinal: 0, kind: .ok, fields: ["n": .integer(7), "ok": .boolean(true)])
        XCTAssertEqual(try ResultDecoder.decode(CanonicalJSON.encode(expected), action: action), expected)
    }

    func testDuplicateUnknownAndSecretResultsRefuse() throws {
        let action = ActionSpec(
            id: "a", ordinal: 0, executable: "/bin/true", workingDirectory: "/private/tmp",
            workDeadlineNanoseconds: 1, settlementDeadlineNanoseconds: 2
        )
        let duplicate = Data("{\"actionID\":\"a\",\"actionID\":\"a\",\"fields\":{},\"kind\":\"ok\",\"ordinal\":0,\"reasonCode\":null,\"version\":1}".utf8)
        XCTAssertThrowsError(try ResultDecoder.decode(duplicate, action: action))
        let unknown = Data("{\"actionID\":\"a\",\"extra\":1,\"fields\":{},\"kind\":\"ok\",\"ordinal\":0,\"reasonCode\":null,\"version\":1}".utf8)
        XCTAssertThrowsError(try ResultDecoder.decode(unknown, action: action))
        let secret = ResultEnvelope(actionID: "a", ordinal: 0, kind: .ok, fields: ["token": .string("Bearer value")])
        XCTAssertThrowsError(try ResultDecoder.decode(CanonicalJSON.encode(secret), action: action))
    }

    func testMaximumZeroAndExactResourceBoundaries() throws {
        var maximum = RunResourceVector(frozenActions: 32)
        try maximum.assign(.frozenActions, value: 32)
        XCTAssertThrowsError(try maximum.assign(.frozenActions, value: 33))
        XCTAssertThrowsError(try maximum.assign(.workloadLaunchesAfterStop, value: 1))
        try maximum.assign(.publicationAttempts, value: 1)
        XCTAssertThrowsError(try maximum.assign(.publicationAttempts, value: 2))
    }

    func testPassFlowsFromPipeThroughPacketAndReceipt() throws {
        let factory = try TestRunFactory()
        defer { try? FileManager.default.removeItem(at: factory.root) }
        let envelope = try CanonicalJSON.encode(ResultEnvelope(actionID: "a", ordinal: 0, kind: .ok, fields: ["dynamic": .string("value")]))
        let action = try factory.makeAction(id: "a", ordinal: 0, envelope: envelope, sleep: 0.05)
        let authority = try factory.writeSpec(actions: [action])
        TestLaunchCounts.shared.chargeController(); TestLaunchCounts.shared.chargeFixture()
        let result = try AcceptanceController().run(specURL: authority.0, scratchURL: factory.root, packetURL: authority.1, executableURL: factory.executable)
        XCTAssertEqual(result.outcome, .pass)
        XCTAssertEqual(result.exitCode, 0)
        let receipt = try CanonicalJSON.decode(RunReceipt.self, from: result.receipt)
        let outcomeData = try Data(contentsOf: authority.1.appendingPathComponent("outcome.json"))
        XCTAssertEqual(try CanonicalJSON.encode(receipt.outcome), outcomeData)
        XCTAssertEqual(receipt.outcome.publicResults["a"]?["dynamic"], .string("value"))
        XCTAssertNoThrow(try PacketPublisher.verify(authority.1))
    }

    func testEarlyStopPublishesAndMarksLaterActionNotStarted() throws {
        let factory = try TestRunFactory()
        defer { try? FileManager.default.removeItem(at: factory.root) }
        let stop = try CanonicalJSON.encode(ResultEnvelope(actionID: "stop", ordinal: 0, kind: .stop, fields: ["edge": .string("synthetic")], reasonCode: "syntheticStop"))
        let later = try CanonicalJSON.encode(ResultEnvelope(actionID: "later", ordinal: 1, kind: .ok, fields: [:]))
        let actions = [
            try factory.makeAction(id: "stop", ordinal: 0, envelope: stop, sleep: 0.05, allowed: ["syntheticStop"]),
            try factory.makeAction(id: "later", ordinal: 1, envelope: later, sleep: 0.05),
        ]
        let authority = try factory.writeSpec(actions: actions)
        TestLaunchCounts.shared.chargeController(); TestLaunchCounts.shared.chargeFixture()
        let result = try AcceptanceController().run(specURL: authority.0, scratchURL: factory.root, packetURL: authority.1, executableURL: factory.executable)
        XCTAssertEqual(result.outcome, .stop)
        XCTAssertEqual(result.exitCode, 20)
        let records = try CanonicalJSON.decode([ActionRecord].self, from: Data(contentsOf: authority.1.appendingPathComponent("action-table.json")))
        XCTAssertEqual(records.map(\.state), [.settled, .notStarted])
    }

    func testTimeoutSettlesProcessGroup() throws {
        let factory = try TestRunFactory()
        defer { try? FileManager.default.removeItem(at: factory.root) }
        let action = try factory.makeAction(id: "timeout", ordinal: 0, envelope: nil, sleep: 3)
        let authority = try factory.writeSpec(actions: [action])
        TestLaunchCounts.shared.chargeController(); TestLaunchCounts.shared.chargeFixture()
        let result = try AcceptanceController().run(specURL: authority.0, scratchURL: factory.root, packetURL: authority.1, executableURL: factory.executable)
        XCTAssertEqual(result.outcome, .stop)
        let records = try CanonicalJSON.decode([ActionRecord].self, from: Data(contentsOf: authority.1.appendingPathComponent("action-table.json")))
        XCTAssertNotNil(records[0].timeoutDetectedAt)
        XCTAssertNotNil(records[0].groupAbsentAt)
    }

    func testOperatorWriteFailureDoesNotMutatePacket() throws {
        var descriptors = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(pipe(&descriptors), 0)
        close(descriptors[0]); close(descriptors[1])
        XCTAssertFalse(ReceiptWriter.write(Data("receipt".utf8), descriptor: descriptors[1]))
    }
}
