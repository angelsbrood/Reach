import Foundation
import XCTest
import ReachWire
import RecoveryContract

final class ReceiptOutcomeTests:XCTestCase {
    func testWholeWitnessMustMatchAndReceiptIsNotEffectPermission() throws {
        let f=try AdapterPair();try f.setup()
        let bytes=try f.client.receipt(requestID:"receipt");var r=FrameReassembler();let original:ReachWire.DurableReceipt=try r.feed(bytes)[0].decode()
        var changed=original;changed.payload.witness.prefix=String(repeating:"a",count:64)
        _=try f.refused(DurableMessage.receipt(changed).encode(version:2))
        _=try f.exchange(bytes)
        XCTAssertThrowsError(try f.client.beginLocalEffect());XCTAssertEqual(f.native.calls,0)
    }
    func testUnsolicitedKnowledgeCannotCreateLocalIntentOrHostOutcome() throws {
        let f=try AdapterPair();try f.setup();let accepted=try XCTUnwrap(f.accepted).payload
        let report=DurableMessage.knowledge(.init(.init(reference:accepted.reference,contextDigest:accepted.contextDigest,
            callID:Data("substitute".utf8),name:Data("fake".utf8),arguments:Data("{}".utf8),state:.unknown,outcome:nil)))
        let bytes=try report.encode(version:2)
        XCTAssertThrowsError(try f.toHost(bytes));XCTAssertThrowsError(try f.toClient(bytes))
        XCTAssertThrowsError(try f.client.localKnowledge());XCTAssertThrowsError(try f.client.beginLocalEffect())
        XCTAssertEqual(f.host.peerReports,0);XCTAssertEqual(f.client.peerReports,0);XCTAssertEqual(f.native.calls,0)
    }
}
