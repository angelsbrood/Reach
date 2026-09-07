import Foundation
import XCTest
import ReachWire
import RecoveryContract

final class RecoveryTests:XCTestCase {
    func testFreshClientRechecksAuthorizationBeforePublishingDiskRecovery() throws {
        let f=try AdapterPair();try f.setup();try f.reopenClient();try f.toClient(f.host.capabilities())
        f.client.publicationHook={f.clientAuth.allowed=false}
        XCTAssertThrowsError(try f.client.recover(requestID:"revoked-after-IO"))
        XCTAssertEqual(f.client.negotiation.phase,.declared);XCTAssertEqual(f.client.recoveryEntries,0)
        XCTAssertEqual(f.host.recoveries,0);XCTAssertEqual(f.native.calls,0)
        f.clientAuth.allowed=true;f.client.publicationHook={}
        _=try f.exchange(f.client.recover(requestID:"current-caller"))
        XCTAssertEqual(f.client.negotiation.phase,.accepted)
    }
    func testFreshSelectedDiskOriginalTicketAndPendingOverwriteRefusal() throws {
        let f=try AdapterPair();try f.setup();let ticket=try XCTUnwrap(f.opened).payload.ticket,context=try XCTUnwrap(f.accepted).payload.context
        try f.reopenClient();try f.toClient(f.host.capabilities())
        let bytes=try f.client.recover(requestID:"recover")
        var r=FrameReassembler();let p:DurableGenerateRecover=try r.feed(bytes)[0].decode()
        XCTAssertEqual(p.payload.ticket,ticket);XCTAssertEqual(p.payload.context,context)
        XCTAssertEqual(f.client.negotiation.phase,.recovering)
        XCTAssertThrowsError(try f.toClient(f.host.capabilities()))
        _=try f.exchange(bytes);XCTAssertEqual(f.client.negotiation.phase,.accepted)
        XCTAssertEqual(f.host.issues,1);XCTAssertEqual(f.host.begins,1);XCTAssertEqual(f.host.recoveries,1)
        XCTAssertEqual(f.native.calls,0)
    }
    func testRecoveryContextDigestWitnessAndMissingStateRefuse() throws {
        let f=try AdapterPair();try f.setup();try f.reopenClient();try f.toClient(f.host.capabilities())
        let bytes=try f.client.recover(requestID:"recover");var rr=FrameReassembler();let original:DurableGenerateRecover=try rr.feed(bytes)[0].decode()
        let edits:[(inout DurableGenerateRecoverPayload)->Void]=[
            {$0.context.append(32)},{$0.contextDigest=String(repeating:"a",count:64);$0.witness.context=$0.contextDigest},
            {$0.clientRoot="00000000-0000-0000-0000-000000000001";$0.witness.clientRoot=$0.clientRoot},
            {$0.witness.prefix=String(repeating:"b",count:64)},{$0.reference.generationID="missing"}
        ]
        for edit in edits {var changed=original;edit(&changed.payload);_=try f.refused(DurableMessage.recover(changed).encode(version:2))}
        XCTAssertEqual(f.host.recoveries,0);XCTAssertEqual(f.native.calls,0)
        f.clientOwner.close();try FileManager.default.removeItem(atPath:f.root+"/client")
        XCTAssertThrowsError(try f.reopenClient())
    }
}
