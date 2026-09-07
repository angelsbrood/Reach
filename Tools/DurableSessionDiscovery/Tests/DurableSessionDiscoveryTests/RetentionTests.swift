import XCTest
import Foundation
import Darwin
import CryptoKit
import RecoveryContract
@testable import DurableClientReceipts

final class RetentionTests:XCTestCase {
    func testKnownAndUnknownRemainIndependentOfMissingTicketStorage() throws {
        let f=try DiscoveryFixture(), (a,t)=try f.create("known"), (b,u)=try f.create("unknown")
        try f.register(a,t); try f.register(b,u); let at=try f.seed(a,known:true), bt=try f.seed(b,known:false)
        try FileManager.default.removeItem(atPath:f.sidecar); try f.reopen()
        for (authority,tool,known) in [(a,at,true),(b,bt,false)] {
            let client=try f.owner.resolve(f.select(authority),binding:f.binding,authorization:f.auth())
            switch try f.owner.beginEffect(tool,handle:client.handle,authority:client.authority,authorization:f.auth()) {
            case .fresh: XCTFail("Recovery reissued invocation permission")
            case .unknown: XCTAssertFalse(known)
            case .known(let value): XCTAssertTrue(known && value.result==Data("fixture-known".utf8))
            }
            XCTAssertThrowsError(try f.ticket(authority))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.sidecar))
    }
    func testOriginalKeyPruningPrecedesInterruptedOrphanCleanup() throws {
        let f=try DiscoveryFixture(), (a,ticket)=try f.create(); try f.register(a,ticket)
        let record=try XCTUnwrap(f.owner.readManifest().records.first), path=f.sidecar+"/"+RecoveryFileSystem.role(record.id)
        let envelope=try Data(contentsOf:URL(fileURLWithPath:path)); f.clock.time=a.context.expires
        XCTAssertThrowsError(try f.owner.maintainRecovery(in:f.parent,binding:f.binding,hook:{ if $0 == .beforeOrphanDelete { throw RecoveryError.io("injected",EIO) } }))
        XCTAssertTrue(try f.owner.readManifest().records.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath:path)); XCTAssertTrue(try f.owner.discover(binding:f.binding,authorization:f.auth()).isEmpty)
        // Ownership survives without selected live identity or key; the metadata key is not the content key.
        XCTAssertNoThrow(try RecoveryEncryption.inspect(envelope,binding:f.binding,root:f.owner.rootKey))
        var wrong=record.live!; wrong.key=f.metadata
        XCTAssertThrowsError(try RecoveryEncryption.open(envelope,live:wrong,record:record.id,binding:f.binding,root:f.owner.rootKey))
        try f.owner.maintainRecovery(in:f.parent,binding:f.binding)
        XCTAssertFalse(FileManager.default.fileExists(atPath:path))
    }
    func testKeyPruningSurvivesCorruptTicketAndCleanupRefusesUnownedBytes() throws {
        let f=try DiscoveryFixture(), (a,ticket)=try f.create(); try f.register(a,ticket)
        let path=f.sidecar+"/"+RecoveryFileSystem.role(try f.select(a).record)
        try Data("unauthenticated orphan".utf8).write(to:URL(fileURLWithPath:path)); f.clock.time=a.context.expires
        XCTAssertThrowsError(try f.owner.maintainRecovery(in:f.parent,binding:f.binding))
        XCTAssertTrue(try f.owner.readManifest().records.isEmpty); XCTAssertTrue(FileManager.default.fileExists(atPath:path))
    }
    func testLiveTicketSurvivesClientKnowledgeUpdatesUntilOriginalExpiry() throws {
        let f=try DiscoveryFixture(), (a,ticket)=try f.create(); try f.register(a,ticket); _=try f.seed(a,known:true)
        f.clock.time=a.context.expires-1; try f.owner.maintainRecovery(in:f.parent,binding:f.binding); XCTAssertTrue(try f.ticket(a)==ticket)
        f.clock.time=a.context.expires; try f.owner.maintainRecovery(in:f.parent,binding:f.binding)
        XCTAssertTrue(try f.owner.discover(binding:f.binding,authorization:f.auth()).isEmpty)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath:f.sidecar),["lock"])
    }
}
