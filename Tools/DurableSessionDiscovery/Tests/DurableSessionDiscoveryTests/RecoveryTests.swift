import XCTest
import Foundation
import Darwin
import RecoveryContract
@testable import DurableClientReceipts

final class RecoveryTests:XCTestCase {
    func testRecoveredJoinExactBytesAndFreshWitness() throws {
        let f=try DiscoveryFixture(), (a,ticket)=try f.create(); try f.register(a,ticket); try f.reopen()
        let recovered=try f.owner.recoverHostJoin(f.select(a),in:f.parent,binding:f.binding,authorization:f.auth())
        XCTAssertTrue(recovered.client.authority.bytes==a.bytes && recovered.ticket==ticket)
        XCTAssertEqual(recovered.witness.high,0); XCTAssertEqual(recovered.witness.clientRoot,f.binding.clientRoot)
    }
    func testEnvelopeReadAuthChangeAndDeadlineRefusePublication() throws {
        for changeCaller in [true,false] {
            let f=try DiscoveryFixture(), (a,ticket)=try f.create(); try f.register(a,ticket)
            let selected=try f.select(a), auth=f.auth()
            XCTAssertThrowsError(try f.owner.recoverHostJoin(selected,in:f.parent,binding:f.binding,authorization:auth,hook:{ p in
                if p == .afterEnvelope { if changeCaller { auth.caller=DiscoveryFixture.caller("bob") } else { f.clock.time=a.context.expires } }
            }))
        }
    }
    func testCorruptAndRecordSubstitutedEnvelopesDoNotBlockClientKnowledge() throws {
        let f=try DiscoveryFixture(), (a,t)=try f.create("a"), (b,u)=try f.create("b")
        try f.register(a,t); try f.register(b,u)
        let ap=f.sidecar+"/"+RecoveryFileSystem.role(try f.select(a).record), bp=f.sidecar+"/"+RecoveryFileSystem.role(try f.select(b).record)
        try Data(contentsOf:URL(fileURLWithPath:ap)).write(to:URL(fileURLWithPath:bp))
        XCTAssertThrowsError(try f.ticket(b)); XCTAssertTrue(try f.owner.resolve(f.select(b),binding:f.binding,authorization:f.auth()).authority.bytes==b.bytes)
        try Data("bad ticket ciphertext".utf8).write(to:URL(fileURLWithPath:ap)); XCTAssertThrowsError(try f.ticket(a))
        XCTAssertEqual(try f.owner.discover(binding:f.binding,authorization:f.auth()).count,2)
    }
    func testFixedSiblingNoFollowBoundsAndShortLock() throws {
        let f=try DiscoveryFixture(), (a,ticket)=try f.create()
        let locked=try f.owner.recoveryDirectory(f.parent,binding:f.binding,fresh:false)
        XCTAssertThrowsError(try f.register(a,ticket)); locked.close(); try f.register(a,ticket)
        let path=f.sidecar+"/"+RecoveryFileSystem.role(try f.select(a).record)
        try FileManager.default.removeItem(atPath:path)
        XCTAssertEqual(symlink("/dev/null",path),0); XCTAssertThrowsError(try f.ticket(a))
        XCTAssertEqual(unlink(path),0); try Data(count:RecoveryLimits.envelope+1).write(to:URL(fileURLWithPath:path)); XCTAssertEqual(chmod(path,0o600),0)
        XCTAssertThrowsError(try f.ticket(a))
        XCTAssertThrowsError(try f.owner.recoveryDirectory(f.parent+"/bootstrap",binding:f.binding,fresh:false))
    }
    func testBoundedEnvelopeRoleCount() throws {
        let f=try DiscoveryFixture()
        for _ in 0...RecoveryLimits.records {
            let path=f.sidecar+"/"+RecoveryFileSystem.role(UUID().uuidString.lowercased())
            XCTAssertEqual(creat(path,0o600).withClosedDescriptor(),0)
        }
        XCTAssertThrowsError(try f.owner.recoveryDirectory(f.parent,binding:f.binding,fresh:false))
    }
}
private extension Int32 {
    func withClosedDescriptor() -> Int32 { self<0 ? -1 : Darwin.close(self) }
}
