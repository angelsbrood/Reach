import AcceptanceControllerCore
import Darwin
import Foundation
import XCTest

struct TestRunFactory {
    let root: URL
    let executable = URL(fileURLWithPath: "/bin/sh")

    init(_ name: String = UUID().uuidString) throws {
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
        let result = try AcceptanceController().run(specURL: authority.0, scratchURL: factory.root, packetURL: authority.1, executableURL: factory.executable)
        XCTAssertEqual(result.outcome, .stop)
        XCTAssertEqual(result.exitCode, 20)
        let records = try CanonicalJSON.decode([ActionRecord].self, from: Data(contentsOf: authority.1.appendingPathComponent("action-table.json")))
        XCTAssertEqual(records.map(\.state), [.settled, .notStarted])
    }

    func testResultRefusalDoesNotPersistDecoderCanaries() throws {
        let enumCanary = "Bearer S64_TEST_CANARY_ENUM"
        let pathCanary = "Bearer S64_TEST_CANARY_CODING_PATH"
        let inputs = [
            Data("{\"actionID\":\"bad\",\"fields\":{},\"kind\":\"\(enumCanary)\",\"ordinal\":0,\"version\":1}".utf8),
            Data("{\"actionID\":\"bad\",\"fields\":{\"\(pathCanary)\":{\"type\":\"integer\",\"value\":\"bad\"}},\"kind\":\"ok\",\"ordinal\":0,\"version\":1}".utf8),
        ]
        for (index, input) in inputs.enumerated() {
            let factory = try TestRunFactory()
            defer { try? FileManager.default.removeItem(at: factory.root) }
            let actions = [
                try factory.makeAction(id: "bad", ordinal: 0, envelope: input),
                try factory.makeAction(id: "later", ordinal: 1, envelope: nil),
            ]
            XCTAssertThrowsError(try ResultDecoder.decode(input, action: actions[0])) { error in
                switch (index, error) {
                case (0, DecodingError.dataCorrupted(let context)):
                    XCTAssertTrue(context.debugDescription.contains(enumCanary))
                case (1, DecodingError.typeMismatch(_, let context)):
                    XCTAssertTrue(context.codingPath.contains { $0.stringValue == pathCanary })
                default:
                    XCTFail("Fixture did not reach its intended decoder error route")
                }
            }
            let authority = try factory.writeSpec(actions: actions)
            let result = try AcceptanceController().run(specURL: authority.0, scratchURL: factory.root,
                                                        packetURL: authority.1, executableURL: factory.executable)
            XCTAssertEqual(result.outcome, .stop)
            XCTAssertEqual(result.exitCode, 20)
            let records = try CanonicalJSON.decode([ActionRecord].self,
                from: Data(contentsOf: authority.1.appendingPathComponent("action-table.json")))
            XCTAssertEqual(records.map(\.state), [.settled, .notStarted])
            XCTAssertTrue(records[0].reason == "result-refusal", "Public refusal reason must be fixed")
            XCTAssertNil(records[0].result)
            XCTAssertEqual(records[1].reason, "caused-by-0")
            XCTAssertNil(records[1].processID)
            let receipt = try CanonicalJSON.decode(RunReceipt.self, from: result.receipt)
            XCTAssertEqual(receipt.outcome.earliestStopOrdinal, 0)
            XCTAssertTrue(receipt.outcome.publicResults.isEmpty)
            XCTAssertNoThrow(try PacketPublisher.verify(authority.1))
            var retainedText = [String(decoding: result.receipt, as: UTF8.self)]
            for directory in [factory.root.appendingPathComponent("journal"), authority.1] {
                let files = try XCTUnwrap(FileManager.default.enumerator(at: directory,
                    includingPropertiesForKeys: [.isRegularFileKey]))
                var textFiles = 0
                for case let file as URL in files {
                    if try file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
                        retainedText.append(try String(contentsOf: file, encoding: .utf8))
                        textFiles += 1
                    }
                }
                XCTAssertGreaterThan(textFiles, 0)
            }
            for text in retainedText {
                XCTAssertFalse(text.contains(enumCanary), "Enum canary persisted in runtime evidence")
                XCTAssertFalse(text.contains(pathCanary), "Coding-path canary persisted in runtime evidence")
            }
        }
    }

    func testTimeoutSettlesProcessGroup() throws {
        let factory = try TestRunFactory()
        defer { try? FileManager.default.removeItem(at: factory.root) }
        let action = try factory.makeAction(id: "timeout", ordinal: 0, envelope: nil, sleep: 3)
        let authority = try factory.writeSpec(actions: [action])
        let result = try AcceptanceController().run(specURL: authority.0, scratchURL: factory.root, packetURL: authority.1, executableURL: factory.executable)
        XCTAssertEqual(result.outcome, .stop)
        let records = try CanonicalJSON.decode([ActionRecord].self, from: Data(contentsOf: authority.1.appendingPathComponent("action-table.json")))
        XCTAssertNotNil(records[0].timeoutDetectedAt)
        XCTAssertNotNil(records[0].groupAbsentAt)
    }

    func testOperatorWriteFailureDoesNotMutatePacket() throws {
        var descriptors = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(pipe(&descriptors), 0)
        close(descriptors[0]); defer { close(descriptors[1]) }
        XCTAssertFalse(ReceiptWriter.write(Data("receipt".utf8), descriptor: descriptors[1]))
    }
}

extension ControllerTests {
    func testTimeoutEscalatesForTermIgnoringChild() throws {
        let now = RawClock.now()
        let result = try ProcessRunner.run(ActionSpec(
            id: "term-ignored", ordinal: 0, executable: "/bin/sh",
            arguments: ["-c", "trap '' TERM; while :; do :; done"],
            workingDirectory: "/private/tmp", workDeadlineNanoseconds: now + 100_000_000,
            settlementDeadlineNanoseconds: now + 6_100_000_000))
        XCTAssertEqual(result.termination, "timeout")
        XCTAssertNotNil(result.termSentAt)
        XCTAssertNotNil(result.killSentAt)
        XCTAssertEqual(result.signal, SIGKILL)
        XCTAssertTrue(result.cleanupComplete)
    }

    func testMalformedUTF8TrailingAndTypedValuesRefuse() throws {
        let action = ActionSpec(id: "a", ordinal: 0, executable: "/bin/true",
                                workingDirectory: "/private/tmp", workDeadlineNanoseconds: 1, settlementDeadlineNanoseconds: 2)
        let valid = try CanonicalJSON.encode(ResultEnvelope(actionID: "a", ordinal: 0, kind: .ok, fields: ["n": .integer(7)]))
        XCTAssertThrowsError(try ResultDecoder.decode(Data([0xff]), action: action))
        XCTAssertThrowsError(try ResultDecoder.decode(valid + Data("x".utf8), action: action))
        let mismatch = Data(String(decoding: valid, as: UTF8.self).replacingOccurrences(of: "\"value\":7", with: "\"value\":\"bad\"").utf8)
        XCTAssertThrowsError(try ResultDecoder.decode(mismatch, action: action))
    }

    func testOutputCrossingPublishesStopWithObservedCount() throws {
        let factory = try TestRunFactory()
        defer { try? FileManager.default.removeItem(at: factory.root) }
        let actions = [
            try factory.makeAction(id: "overflow", ordinal: 0, envelope: Data(repeating: 0x61, count: 1_300_000)),
            try factory.makeAction(id: "later", ordinal: 1, envelope: nil),
        ]
        let authority = try factory.writeSpec(actions: actions)
        let result = try AcceptanceController().run(specURL: authority.0, scratchURL: factory.root, packetURL: authority.1, executableURL: factory.executable)
        XCTAssertEqual(result.exitCode, 20)
        let records = try CanonicalJSON.decode([ActionRecord].self, from: Data(contentsOf: authority.1.appendingPathComponent("action-table.json")))
        XCTAssertEqual(records[0].reason, "output-limit")
        XCTAssertGreaterThan(records[0].stdoutBytes ?? 0, 1_048_576)
        XCTAssertEqual(records[1].state, .notStarted)
        XCTAssertNoThrow(try PacketPublisher.verify(authority.1))
    }

    func testSpawnFailureIsControllerFailureWithPacket() throws {
        let factory = try TestRunFactory()
        defer { try? FileManager.default.removeItem(at: factory.root) }
        let now = RawClock.now()
        let action = ActionSpec(id: "missing", ordinal: 0, executable: factory.root.appendingPathComponent("missing").path,
                                workingDirectory: factory.root.path, workDeadlineNanoseconds: now + 2_000_000_000,
                                settlementDeadlineNanoseconds: now + 8_000_000_000)
        let authority = try factory.writeSpec(actions: [action])
        let result = try AcceptanceController().run(specURL: authority.0, scratchURL: factory.root, packetURL: authority.1, executableURL: factory.executable)
        XCTAssertEqual(result.exitCode, 70)
        XCTAssertEqual(result.outcome, .controllerFailure)
        XCTAssertNoThrow(try PacketPublisher.verify(authority.1))
    }

    func testLauncherRecordsNormalParseSpawnSignalAndTimeoutFailures() throws {
        let factory = try TestRunFactory()
        defer { try? FileManager.default.removeItem(at: factory.root) }
        let candidates = [
            URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent(),
            Bundle(for: ControllerTests.self).bundleURL.deletingLastPathComponent(),
        ].map { $0.appendingPathComponent("reach-acceptance-launcher") }
        guard let launcher = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0.path) }) else {
            throw ControllerError.evidence("launcher-build-product-missing")
        }
        let broken = factory.root.appendingPathComponent("broken.swift")
        try Data("let broken = )\nprint(\"READY\")\n".utf8).write(to: broken)
        let cases: [(String, [String], Int32, Int)] = [
            ("normal", ["/bin/echo", "ready"], 0, 20),
            ("parse", ["/usr/bin/xcrun", "swift", broken.path], 1, 20),
            ("spawn", [factory.root.appendingPathComponent("absent").path], 127, 20),
            ("signal", ["/bin/sh", "-c", "kill -TERM $$"], 143, 20),
            ("timeout", ["/bin/sleep", "30"], 124, 1),
        ]
        for (name, command, expected, seconds) in cases {
            let record = factory.root.appendingPathComponent(name)
            let now = RawClock.now()
            let result = try ProcessRunner.run(ActionSpec(
                id: name, ordinal: 0, executable: launcher.path,
                arguments: ["--record", record.path, "--timeout-seconds", String(seconds), "--"] + command,
                workingDirectory: factory.root.path, workDeadlineNanoseconds: now + 40_000_000_000,
                settlementDeadlineNanoseconds: now + 46_000_000_000))
            XCTAssertEqual(result.exitCode, expected, name)
            XCTAssertTrue(result.cleanupComplete, name)
            let start = try JSONSerialization.jsonObject(with: Data(contentsOf: record.appendingPathComponent("start.json"))) as! [String: Any]
            let terminal = try JSONSerialization.jsonObject(with: Data(contentsOf: record.appendingPathComponent("terminal.json"))) as! [String: Any]
            let t0 = (start["rawT0"] as! NSNumber).uint64Value
            XCTAssertEqual((terminal["rawT0"] as! NSNumber).uint64Value, t0)
            XCTAssertGreaterThan((terminal["rawT1"] as! NSNumber).uint64Value, t0)
            XCTAssertEqual(terminal["cleanupComplete"] as? Bool, true, name)
            if name == "parse" {
                XCTAssertEqual(terminal["stdoutBytes"] as? Int, 0)
                XCTAssertGreaterThan(terminal["stderrBytes"] as? Int ?? 0, 0)
            }
            if name == "spawn" { XCTAssertEqual(terminal["spawnError"] as? Int, Int(ENOENT)) }
            if name == "signal" { XCTAssertEqual(terminal["signal"] as? Int, Int(SIGTERM)) }
            if name == "timeout" {
                XCTAssertEqual(terminal["termination"] as? String, "timeout")
                XCTAssertNotNil(terminal["termSentAt"])
            }
        }
    }
}
