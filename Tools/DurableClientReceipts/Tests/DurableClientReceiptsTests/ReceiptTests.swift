import XCTest
import Foundation
import Darwin
import ReachWire
import ClientReceiptFixtures
@testable import DurableClientReceipts

final class Fixture {
    let parent: URL, path: String
    let clock: FixtureClientClock, environment: ClientEnvironment, key: Data, a: ClientAuthority, auth: ClientAuthorization
    var client: DurableClientReceipts!
    var h: ClientHandle!
    var fault: ClientFaultHook = { _ in }
    init(quota: Int = ClientLimits.allocation, expires: UInt64 = 86_000_000_000_000) throws {
        guard let base = ProcessInfo.processInfo.environment["S83_FIXTURES"] else { throw ClientError.invalid("private fixture root") }
        parent = URL(fileURLWithPath: base).appendingPathComponent(UUID().uuidString.lowercased())
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        path = parent.appendingPathComponent("journal").path
        clock = try .init(id: "tests", time: 100); environment = try .init(clock: clock, quota: quota); key = clientRandomKey()
        a = try ReceiptFixtures.authority(expires: expires); auth = .init(caller: a.context.caller)
        client = try .init(path: path, create: true, environment: environment, metadataKey: key, clock: clock) { [weak self] point in try self?.fault(point) }
        h = try client.open(a, authorization: auth)
    }
    deinit { client?.close(); try? FileManager.default.removeItem(at: parent) }
    func reopen() throws {
        client.close(); client = try .init(path: path, create: false, environment: environment, metadataKey: key, clock: clock) { [weak self] point in try self?.fault(point) }
        h = try client.open(a, authorization: auth)
    }
    @discardableResult func accept(_ frame: ReplayEnvelope? = nil, cursor: UInt64 = 0) throws -> DurableReceipt {
        try client.accept(frame ?? ReceiptFixtures.frame(), requestedCursor: cursor, handle: h, authority: a, authorization: auth)
    }
    func receipt() throws -> DurableReceipt { try client.receipt(h, authority: a, authorization: auth) }
    func state(_ binding: ToolBinding? = nil) throws -> EffectKnowledge { try client.effect(binding ?? ReceiptFixtures.binding(), handle: h, authority: a, authorization: auth) }
    func begin(_ binding: ToolBinding? = nil) throws -> BeginEffectResult { try client.beginEffect(binding ?? ReceiptFixtures.binding(), handle: h, authority: a, authorization: auth) }
    @discardableResult func outcome(_ value: ClientOutcome? = nil) throws -> ClientOutcome {
        try client.recordOutcome(value ?? ReceiptFixtures.outcome(a), binding: ReceiptFixtures.binding(), handle: h, authority: a, authorization: auth)
    }
}
final class ReceiptTests: XCTestCase {
    func testAtomicReceiptLostReplyAndInteriorReplay() throws {
        let f = try Fixture(), frame = try ReceiptFixtures.frame()
        let r = try f.accept(frame)
        XCTAssertEqual(r.high, 4); XCTAssertEqual(r.registeredCalls, 2); XCTAssertTrue(r.terminal)
        XCTAssertTrue(try f.state() == .unbegun)
        try f.reopen(); XCTAssertTrue(try f.accept(frame) == r)
        let partial = ReplayEnvelope(firstSequence: 1, count: 4, providerCommit: frame.providerCommit, eventBytes: frame.eventBytes, skipPrefix: 2)
        XCTAssertTrue(try f.accept(partial, cursor: 2) == r)
        XCTAssertTrue(try f.client.inbox(f.h, authority: f.a, authorization: f.auth) == [frame.eventBytes])
        XCTAssertTrue(try f.accept(frame) == r)
    }
    func testFramingCursorCommitAndTerminalRefusals() throws {
        let f = try Fixture(), frame = try ReceiptFixtures.frame()
        XCTAssertThrowsError(try f.accept(.init(firstSequence: 1, count: 4, providerCommit: frame.providerCommit, eventBytes: frame.eventBytes, skipPrefix: 1), cursor: 1))
        XCTAssertEqual(try f.receipt().high, 0)
        _ = try f.accept(frame)
        let variants = [
            ReplayEnvelope(firstSequence: 1, count: 3, providerCommit: frame.providerCommit, eventBytes: frame.eventBytes),
            .init(firstSequence: 1, count: 4, providerCommit: String(repeating: "c", count: 64), eventBytes: frame.eventBytes),
            .init(firstSequence: 2, count: 4, providerCommit: frame.providerCommit, eventBytes: frame.eventBytes),
            .init(firstSequence: 6, count: 4, providerCommit: frame.providerCommit, eventBytes: frame.eventBytes),
            .init(firstSequence: 1, count: 4, providerCommit: frame.providerCommit, eventBytes: frame.eventBytes+Data([32])),
            .init(firstSequence: UInt64.max, count: 4, providerCommit: frame.providerCommit, eventBytes: frame.eventBytes),
        ]
        for v in variants { XCTAssertThrowsError(try f.accept(v)) }
        XCTAssertThrowsError(try f.accept(frame, cursor: 5)); XCTAssertThrowsError(try f.accept(frame, cursor: 4))
        XCTAssertThrowsError(try f.accept(ReceiptFixtures.frame(first: 5, calls: 0, terminal: false, commit: String(repeating: "d", count: 64))))
        XCTAssertEqual(try f.receipt().high, 4)
    }
    func testSequentialAppendAndCallCommitAliases() throws {
        let f = try Fixture()
        let first = try ReceiptFixtures.frame(calls: 1, terminal: false)
        _ = try f.accept(first)
        XCTAssertThrowsError(try f.accept(ReceiptFixtures.frame(first: 2, calls: 0, terminal: false)))
        XCTAssertThrowsError(try f.accept(ReceiptFixtures.frame(first: 2, calls: 1, terminal: false, commit: String(repeating: "c", count: 64))))
        XCTAssertEqual(try f.receipt().high, 1)
        let tail = try ReceiptFixtures.envelope([.usage(inputTokens: 1, outputTokens: 1), .finished(.complete)], first: 2, commit: String(repeating: "c", count: 64))
        XCTAssertEqual(try f.accept(tail, cursor: 1).high, 3)
        XCTAssertEqual(try f.accept(first).high, 3)
    }
    func testProjectionAndCanonicalConstraints() throws {
        let invalid: [[WireEvent]] = [
            [.responseReplace(entryID: nil, text: "x", segmentID: nil, tokenCount: 1)],
            [.reasoningAppend(entryID: nil, text: "x", segmentID: nil, tokenCount: 1)],
            [.responseAppend(entryID: nil, text: "x", segmentID: nil, tokenCount: 2)],
            [.usage(inputTokens: 1, outputTokens: 1)], [.finished(.complete)],
            [.usage(inputTokens: -1, outputTokens: 2), .finished(.complete)],
            [.finished(.cancelled), .finished(.cancelled)], [.finished(.error(""))],
            [.toolCallAppendArguments(entryID: nil, id: "", name: "fake", content: "{}", tokenCount: 1)]
        ]
        let f = try Fixture()
        for events in invalid {
            let bytes = try crEncode(events)
            XCTAssertThrowsError(try f.accept(.init(firstSequence: 1, count: events.count, providerCommit: String(repeating: "b", count: 64), eventBytes: bytes)))
        }
        XCTAssertEqual(try f.receipt().high, 0)
        let frame = try ReceiptFixtures.envelope([.responseAppend(entryID: nil, text: "https://synthetic/é", segmentID: nil, tokenCount: 1), .finished(.cancelled)])
        XCTAssertTrue(try f.accept(frame).terminal)
    }
    func testContextExactBytesAndOriginalExpiry() throws {
        let f = try Fixture()
        let changed = try ReceiptFixtures.authority(request: "changed")
        XCTAssertThrowsError(try f.client.open(changed, authorization: f.auth))
        let later = try ReceiptFixtures.authority(expires: f.a.context.expires+1)
        XCTAssertThrowsError(try f.client.open(later, authorization: f.auth))
        let laterGeneration = try ReceiptFixtures.authority(generation: "generation-2", expires: f.a.context.expires+1)
        XCTAssertThrowsError(try f.client.open(laterGeneration, authorization: f.auth))
        let unicodeA = try ReceiptFixtures.authority(namespace: "unicode", generation: "é")
        let unicodeB = try ReceiptFixtures.authority(namespace: "unicode", generation: "e\u{301}")
        let a = try f.client.open(unicodeA, authorization: f.auth), b = try f.client.open(unicodeB, authorization: f.auth)
        XCTAssertTrue(a.record != b.record)
        f.clock.time = f.a.context.expires; try f.client.maintenance()
        XCTAssertThrowsError(try f.client.open(f.a, authorization: f.auth))
        XCTAssertFalse(try f.client.readManifest().records.contains { $0.live?.identity == f.a.identity })
    }
    func testBatchCapacityIsAtomicAndGlobalCallCount() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.accept(ReceiptFixtures.frame(calls: 33)))
        XCTAssertEqual(try f.receipt().high, 0)
        for n in 0..<8 {
            let a = try ReceiptFixtures.authority(generation: "capacity-\(n)")
            let h = try f.client.open(a, authorization: f.auth)
            let r = try f.client.accept(ReceiptFixtures.frame(calls: 32), requestedCursor: 0, handle: h, authority: a, authorization: f.auth)
            XCTAssertEqual(r.registeredCalls, 32)
        }
        XCTAssertThrowsError(try f.accept(ReceiptFixtures.frame(calls: 1)))
        XCTAssertEqual(try f.receipt().high, 0)
    }
    func testActualReplayBytesAndPredecodeEnvelopeBounds() throws {
        let f = try Fixture()
        let text = String(repeating: "x", count: 6<<20)
        func batch(_ n: UInt64) throws -> ReplayEnvelope {
            try ReceiptFixtures.envelope([.responseAppend(entryID: nil, text: text, segmentID: nil, tokenCount: 1)],
                first: n, commit: String(repeating: String(n), count: 64))
        }
        _ = try f.accept(batch(1)); _ = try f.accept(batch(2), cursor: 1)
        let bytes = try f.client.fs.usage().bytes
        XCTAssertGreaterThan(bytes, 12<<20)
        XCTAssertThrowsError(try f.accept(batch(3), cursor: 2))
        XCTAssertEqual(try f.receipt().high, 2)
        let oversized = ReplayEnvelope(firstSequence: 3, count: 1, providerCommit: String(repeating: "3", count: 64),
            eventBytes: Data(repeating: 0, count: ClientLimits.batch+1))
        XCTAssertThrowsError(try f.accept(oversized, cursor: 2))
        let count = ReplayEnvelope(firstSequence: 3, count: 4097, providerCommit: String(repeating: "3", count: 64), eventBytes: Data())
        XCTAssertThrowsError(try f.accept(count, cursor: 2))
        XCTAssertEqual(try f.client.fs.usage().bytes, bytes)
    }
}
