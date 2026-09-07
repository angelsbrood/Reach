import XCTest
import Foundation
import Darwin
import DurableRootKeys
@testable import DurableStoreBootstrap

final class RecoveryTests: XCTestCase {
    func testPartialCreationRefusesWithoutRepairOrProviderLookup() throws {
        for fault in [BootstrapFault.afterIntent,.afterFirstKey,.afterStores,.beforeReadyRename] {
            let f = try BootstrapTestFixture()
            XCTAssertThrowsError(try f.create { if $0 == fault { throw BootstrapError.io("injected",EIO) } })
            let creates = f.provider.creates, factories = f.factories
            XCTAssertThrowsError(try f.acquire()); XCTAssertThrowsError(try f.create())
            XCTAssertEqual(f.provider.creates,creates); XCTAssertEqual(f.factories,factories)
            XCTAssertFalse(FileManager.default.fileExists(atPath:f.root+"/ready.json"))
        }
    }
    func testSelectedReadyReplyLossReopensOriginalIdentity() throws {
        let f = try BootstrapTestFixture()
        XCTAssertThrowsError(try f.create { if $0 == .afterReady { throw BootstrapError.io("lost reply",EIO) } })
        let intent = try RootKeyCodec.decode(BootstrapIntent.self,f.bytes("intent.json"),limit:BootstrapLimits.record)
        let selected = try f.acquire().descriptor
        XCTAssertEqual(selected.core.identifier,intent.core.identifier)
        XCTAssertEqual(selected.core.hostID,intent.core.hostID); XCTAssertEqual(selected.core.clientID,intent.core.clientID)
        XCTAssertEqual(f.provider.creates,3)
    }
    func testWriteAndSyncFaultsRemainDistinctFromProcessDeaths() throws {
        for point in [BootstrapFault.beforeIntentWrite,.beforeFileSync,.afterReadyRename,.beforeReadySync] {
            let f = try BootstrapTestFixture()
            XCTAssertThrowsError(try f.create { if $0 == point { throw BootstrapError.io("injected sync",EIO) } })
            let selected = FileManager.default.fileExists(atPath:f.root+"/ready.json"), creates = f.provider.creates
            if selected { XCTAssertNoThrow(try f.acquire()) } else { XCTAssertThrowsError(try f.acquire()) }
            XCTAssertEqual(f.provider.creates,creates)
        }
    }
    func testMissingJournalIsRoleSpecificAndNeverRecreated() throws {
        let f = try BootstrapTestFixture(); _ = try f.create()
        try FileManager.default.removeItem(atPath:f.root+"/host")
        XCTAssertThrowsError(try f.acquire(.host)); XCTAssertNoThrow(try f.acquire(.client))
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.root+"/host"))
        try FileManager.default.removeItem(atPath:f.root+"/client")
        XCTAssertThrowsError(try f.acquire(.client)); XCTAssertFalse(FileManager.default.fileExists(atPath:f.root+"/client"))
    }
    func testRecordBoundsNoFollowAndExclusiveLock() throws {
        let f = try BootstrapTestFixture(); _ = try f.create()
        let held = try BootstrapFileSystem(path:f.root,fresh:false)
        XCTAssertThrowsError(try f.acquire()); held.close()
        try FileManager.default.removeItem(atPath:f.root+"/ready.json")
        XCTAssertEqual(symlink("intent.json",f.root+"/ready.json"),0)
        XCTAssertThrowsError(try f.acquire())
        try FileManager.default.removeItem(atPath:f.root+"/ready.json")
        try Data(repeating:0,count:BootstrapLimits.record+1).write(to:URL(fileURLWithPath:f.root+"/ready.json"))
        XCTAssertEqual(chmod(f.root+"/ready.json",0o600),0)
        XCTAssertThrowsError(try f.acquire())
    }
}
