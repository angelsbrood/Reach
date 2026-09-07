import XCTest
import Foundation
import Darwin
import RecoveryContract
@testable import DurableClientReceipts

final class RegistrationTests:XCTestCase {
    func testImmutableExactTicketAndRetrySurviveSnapshotUpdates() throws {
        let f=try DiscoveryFixture(), (a,ticket)=try f.create(); try f.register(a,ticket)
        let role=f.sidecar+"/"+RecoveryFileSystem.role(try f.select(a).record), original=try Data(contentsOf:URL(fileURLWithPath:role))
        try f.register(a,ticket); XCTAssertTrue(try Data(contentsOf:URL(fileURLWithPath:role))==original)
        _=try f.seed(a,known:true); XCTAssertTrue(try f.ticket(a)==ticket)
        var changed=ticket; changed[changed.count-1]^=1
        XCTAssertThrowsError(try f.register(a,changed)); XCTAssertTrue(try Data(contentsOf:URL(fileURLWithPath:role))==original)
        try f.reopen(); XCTAssertTrue(try f.ticket(a)==ticket)
    }
    func testUnselectedFaultsStayIncompleteWithoutPromotion() throws {
        for point in [RecoveryFault.beforeEnvelopeWrite,.beforeEnvelopeSync,.beforeSelection] {
            let f=try DiscoveryFixture(), (a,ticket)=try f.create()
            XCTAssertThrowsError(try f.register(a,ticket,hook:{ if $0==point { throw RecoveryError.io("injected",EIO) } }))
            XCTAssertThrowsError(try f.ticket(a)); XCTAssertEqual(try f.owner.discover(binding:f.binding,authorization:f.auth()).count,1)
            XCTAssertFalse(FileManager.default.fileExists(atPath:f.sidecar+"/"+RecoveryFileSystem.role(try f.select(a).record)))
        }
    }
    func testSelectedLostReplyAndDirectorySyncUncertaintyReadBackExactly() throws {
        for point in [RecoveryFault.afterSelection,.beforeDirectorySync,.beforePublication] {
            let f=try DiscoveryFixture(), (a,ticket)=try f.create()
            XCTAssertThrowsError(try f.register(a,ticket,hook:{ if $0==point { throw RecoveryError.io("injected",EIO) } }))
            try f.reopen(); XCTAssertTrue(try f.ticket(a)==ticket); try f.register(a,ticket)
        }
    }
    func testChangedTicketRelationshipAndAuthorizationBeforeSelectionRefuse() throws {
        let f=try DiscoveryFixture(), (a,_)=try f.create("a"), (_,wrong)=try f.create("b")
        XCTAssertThrowsError(try f.register(a,wrong))
        let g=try DiscoveryFixture(), (b,ticket)=try g.create(), auth=g.auth(), selected=try g.select(b)
        XCTAssertThrowsError(try g.owner.registerRecoveryTicket(ticket,selection:selected,in:g.parent,binding:g.binding,authorization:auth,hook:{
            if $0 == .beforeSelection { auth.caller=DiscoveryFixture.caller("bob") }
        }))
        XCTAssertFalse(FileManager.default.fileExists(atPath:g.sidecar+"/"+RecoveryFileSystem.role(selected.record)))
    }
    func testMissingDirectoryAndEnvelopeNeverCreateHistory() throws {
        let f=try DiscoveryFixture(enroll:false), (a,ticket)=try f.create()
        XCTAssertThrowsError(try f.ticket(a)); XCTAssertFalse(FileManager.default.fileExists(atPath:f.sidecar))
        XCTAssertThrowsError(try f.register(a,ticket)); XCTAssertFalse(FileManager.default.fileExists(atPath:f.sidecar))
        try f.owner.enrollRecovery(in:f.parent,binding:f.binding); XCTAssertThrowsError(try f.ticket(a))
        XCTAssertThrowsError(try f.owner.enrollRecovery(in:f.parent,binding:f.binding))
    }
}
