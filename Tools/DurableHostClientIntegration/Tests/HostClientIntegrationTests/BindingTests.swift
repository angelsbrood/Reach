import XCTest
import Foundation
import HostClientContract
import HostClientFixtures
import LifecycleFixtures
import ReachWire
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts

final class BindingTests: XCTestCase {
    func testOriginalContextAndStableNamespaceAcrossGenerations() throws {
        let f = try JoinedFixture()
        let bytes = f.authority.bytes, original = f.authority.context
        XCTAssertTrue(try f.host.exportClientContext(ticket: f.ticket, authorization: f.auth, attachment: f.attachment) == bytes)
        XCTAssertTrue(original.host == f.hostIdentity.incarnation && original.store == original.host)
        let id = try f.host.catalog.load().records[0].identity!
        XCTAssertTrue(original.namespace == id.namespace && original.generation == id.generation)
        XCTAssertEqual(original.expires, id.ticketExpiry)
        _ = try f.host.cancel(ticket: f.ticket, authorization: f.auth, attachment: f.attachment)
        try f.newGeneration(route: "guided", generation: "g-2")
        XCTAssertTrue(original.namespace == f.authority.context.namespace && original.store == f.authority.context.store)
        XCTAssertEqual(original.issued, f.authority.context.issued); XCTAssertEqual(original.expires, f.authority.context.expires)
        XCTAssertTrue(original.upstreamDigest != f.authority.context.upstreamDigest)
        XCTAssertEqual(try f.client.readManifest().records.count, 2)
    }
    func testExactCallerAndContextBytes() throws {
        let f = try JoinedFixture(lifetime: 10_000_000_000)
        f.auth.caller = .init(principal: "changed", device: "device", app: "app")
        XCTAssertThrowsError(try f.host.exportClientContext(ticket: f.ticket, authorization: f.auth, attachment: f.attachment))
        f.auth.caller = caller().caller
        var object = try JSONSerialization.jsonObject(with: f.authority.bytes) as! [String: Any]
        for field in ["upstreamDigest", "revision", "request", "host", "store"] {
            var changed = object; changed[field] = field == "upstreamDigest" ? String(repeating: "0", count: 64) : "different"
            let data = try JSONSerialization.data(withJSONObject: changed, options: [.sortedKeys, .withoutEscapingSlashes])
            let a = try ClientAuthority(JSONDecoder().decode(ClientContext.self, from: data))
            XCTAssertThrowsError(try f.client.open(a, authorization: f.clientAuth))
        }
        object["expires"] = f.authority.context.expires+1
        let later = try ClientAuthority(JSONDecoder().decode(ClientContext.self, from: JSONSerialization.data(withJSONObject: object)))
        XCTAssertThrowsError(try f.client.open(later, authorization: f.clientAuth))
        let c = ClientCaller(principal: "é", device: "device", app: "app")
        let originalAuth = LifecycleAuthorization(caller: .init(principal: c.principal, device: c.device, app: c.app), allowed: true)
        let ticket = try f.host.issueTicket(authorization: originalAuth)
        let a = try XCTUnwrap(f.host.begin(ticket: ticket, authorization: originalAuth, generation: "unicode", provider: cpuBinding("unicode")).attachment)
        originalAuth.caller = .init(principal: "e\u{301}", device: c.device, app: c.app)
        XCTAssertThrowsError(try f.host.exportClientContext(ticket: ticket, authorization: originalAuth, attachment: a))
    }
    func testDigestFramingAndExactUnicode() throws {
        var a = HandoffDigest("test", context: Data()), b = HandoffDigest("test", context: Data())
        a.append(Data("ab".utf8)); a.append(Data("c".utf8)); b.append(Data("a".utf8)); b.append(Data("bc".utf8))
        XCTAssertNotEqual(a.finish(), b.finish())
        var c = HandoffPrefix(context: Data()), d = HandoffPrefix(context: Data())
        try c.register(id: Data("id".utf8), name: Data("fake".utf8), arguments: Data("é".utf8))
        try d.register(id: Data("id".utf8), name: Data("fake".utf8), arguments: Data("e\u{301}".utf8))
        XCTAssertNotEqual(c.digests().1, d.digests().1)
    }
    func testControlAndReplayLimitsBeforeBodyAllocation() throws {
        for (kind, limit) in [(UInt8(0), HandoffContract.control), (1, HandoffContract.replayMessage)] {
            let pipe = Pipe(); var count = UInt32(limit+1).bigEndian
            try pipe.fileHandleForWriting.write(contentsOf: Data([kind])+withUnsafeBytes(of: &count) { Data($0) })
            XCTAssertThrowsError(try HandoffPipe.read(from: pipe.fileHandleForReading))
            try pipe.fileHandleForWriting.close(); try pipe.fileHandleForReading.close()
        }
        var m = HandoffMessage("control"); m.context = Data(repeating: 1, count: HandoffContract.control)
        XCTAssertThrowsError(try HandoffContract.encode(m))
        let b = HandoffBatch(first: 1, count: 1, commit: String(repeating: "a", count: 64), bytes: Data(repeating: 1, count: HandoffContract.batch+1))
        XCTAssertThrowsError(try b.last())
        XCTAssertThrowsError(try HandoffBatch(first: UInt64.max, count: 2, commit: b.commit, bytes: Data()).last())
    }
    func testEstablishedHistoryCannotBeRecreatedOrSubstituted() throws {
        let f = try JoinedFixture(), original = try f.witness()
        f.client.close(); try FileManager.default.removeItem(atPath: f.clientPath)
        XCTAssertThrowsError(try f.reopenClient())
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.clientPath))
        var changed = original; changed.clientRoot = UUID().uuidString.lowercased()
        XCTAssertThrowsError(try f.accept(changed))
        XCTAssertTrue(try f.host.catalog.load().records[0].work != nil)
    }
    func testActualReplayRejectsUnknownAdvancedAndSkippedHistory() throws {
        let f = try JoinedFixture(route: "required")
        var cursor: UInt64 = 0
        _ = try complete(f.host, ticket: f.ticket, auth: f.auth, attachment: f.attachment, setup: f.setup, cursor: &cursor)
        let frames = try f.host.replayForClient(ticket: f.ticket, authorization: f.auth, attachment: f.attachment, after: 0)
        let tail = try XCTUnwrap(frames.last); XCTAssertGreaterThan(tail.count, 1)
        let empty = try f.witness(), allocated = try JoinedFixture.allocation(f.clientPath)
        var skipped = tail; skipped.skip = 1
        XCTAssertThrowsError(try f.client.acceptHostBatch(skipped, requestedCursor: tail.first, handle: f.handle,
            authority: f.authority, authorization: f.clientAuth))
        var advanced = try XCTUnwrap(frames.first); advanced.first += 1
        XCTAssertThrowsError(try f.client.acceptHostBatch(advanced, requestedCursor: 0, handle: f.handle,
            authority: f.authority, authorization: f.clientAuth))
        XCTAssertEqual(try f.witness(), empty); XCTAssertEqual(try JoinedFixture.allocation(f.clientPath), allocated)
        for frame in frames {
            _ = try f.client.acceptHostBatch(frame, requestedCursor: f.witness().high, handle: f.handle,
                authority: f.authority, authorization: f.clientAuth)
        }
        let full = try f.witness()
        XCTAssertEqual(try f.client.acceptHostBatch(skipped, requestedCursor: tail.first, handle: f.handle,
            authority: f.authority, authorization: f.clientAuth), full)
        XCTAssertEqual(try f.accept(full).disposition, try full.disposition())
    }
}
