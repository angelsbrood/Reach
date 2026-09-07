import XCTest
import Foundation
import Darwin
import ClientReceiptFixtures
@testable import DurableClientReceipts

final class RecoveryTests: XCTestCase {
    func testOwnerLockAndStaleEpochAfterClose() throws {
        let f = try Fixture(), old = f.h!
        XCTAssertThrowsError(try DurableClientReceipts(path: f.path, create: false, environment: f.environment, metadataKey: f.key, clock: f.clock)) { e in
            XCTAssertTrue(e as? ClientError == .busy)
        }
        try f.reopen(); XCTAssertGreaterThan(f.h.ownerEpoch, old.ownerEpoch)
        XCTAssertThrowsError(try f.client.receipt(old, authority: f.a, authorization: f.auth))
        f.client.close(); XCTAssertThrowsError(try f.receipt())
    }
    func testRenameAndSyncUncertaintyReconcilesCurrent() throws {
        for point in [ClientFault.afterSnapshot, .beforeManifestRename, .afterManifestRename, .beforeDirectorySync] {
            let f = try Fixture()
            f.fault = { if $0 == point { throw ClientError.io("injected", EIO) } }
            XCTAssertThrowsError(try f.accept()); XCTAssertTrue(f.client.uncertain)
            f.fault = { _ in }
            let committed = point == .afterManifestRename || point == .beforeDirectorySync
            XCTAssertEqual(try f.receipt().high, committed ? 4 : 0)
            XCTAssertFalse(f.client.uncertain)
            XCTAssertFalse(try f.client.fs.names().contains("prepared"))
            XCTAssertEqual(try f.client.fs.names().filter { $0.hasPrefix("s-") }.count, 1)
            _ = try f.accept(); XCTAssertTrue(try f.state() == .unbegun)
        }
    }
    func testIntentUncertaintyDoesNotManufactureFreshPermission() throws {
        for point in [ClientFault.beforeManifestRename, .afterManifestRename, .beforeDirectorySync, .afterIntent] {
            let f = try Fixture(); _ = try f.accept()
            f.fault = { if $0 == point { throw ClientError.io("injected", EIO) } }
            XCTAssertThrowsError(try f.begin()); f.fault = { _ in }; try f.reopen()
            switch try f.begin() {
            case .fresh: XCTAssertTrue(point == .beforeManifestRename)
            case .unknown: XCTAssertTrue(point != .beforeManifestRename)
            case .known: XCTFail("invented outcome")
            }
        }
    }
    func testExpiredIdentityPrunedBeforeFailedDeletionAndRetry() throws {
        for point in [ClientFault.afterRetirement, .duringDeletion, .afterDeletion] {
            let f = try Fixture(expires: 1000); _ = try f.accept(); _ = try f.begin()
            f.clock.time = 1000; f.fault = { if $0 == point { throw ClientError.io("injected", EIO) } }
            XCTAssertThrowsError(try f.client.maintenance())
            let m = try f.client.readManifest()
            XCTAssertEqual(m.records.count, 1); XCTAssertTrue(m.records[0].live == nil)
            XCTAssertTrue(m.records[0].cleanup != nil)
            XCTAssertThrowsError(try f.client.open(f.a, authorization: f.auth))
            f.fault = { _ in }; f.client.close()
            f.client = try .init(path: f.path, create: false, environment: f.environment, metadataKey: f.key, clock: f.clock)
            try f.client.maintenance(); XCTAssertTrue(try f.client.readManifest().records.isEmpty)
            XCTAssertEqual(Set(try f.client.fs.names()), Set(["lock", "current"]))
            XCTAssertThrowsError(try f.client.open(f.a, authorization: f.auth))
        }
    }
    func testClockRollbackOverflowAndSystemSmoke() throws {
        let f = try Fixture(); f.clock.time = 200; _ = try f.accept()
        f.clock.time = 199; XCTAssertThrowsError(try f.receipt())
        f.client.close()
        XCTAssertThrowsError(try DurableClientReceipts(path: f.path, create: false, environment: f.environment, metadataKey: f.key, clock: f.clock))
        XCTAssertThrowsError(try ReceiptFixtures.authority(issued: UInt64.max-1, expires: UInt64.max))
        XCTAssertThrowsError(try crAdd(UInt64.max, 1))
        let clock = SystemClientClock(), a = try clock.now(), b = try clock.now()
        XCTAssertGreaterThan(a, 0); XCTAssertGreaterThanOrEqual(b, a)
        XCTAssertTrue(crUUID(try ClientEnvironment.bootIdentity()))
    }
    func testExpiredMissingOrCorruptContentCannotRetainIdentityAndKey() throws {
        for corrupt in [false, true] {
            let f = try Fixture(expires: 1000); _ = try f.accept()
            let name = try f.client.readManifest().records[0].live!.snapshot.name
            f.client.close()
            let url = URL(fileURLWithPath: f.path).appendingPathComponent(name)
            if corrupt { try Data(repeating: 0, count: 200).write(to: url) }
            else { try FileManager.default.removeItem(at: url) }
            f.clock.time = 1000
            f.client = try .init(path: f.path, create: false, environment: f.environment, metadataKey: f.key, clock: f.clock)
            if corrupt { XCTAssertThrowsError(try f.client.maintenance()) }
            else { try f.client.maintenance() }
            let m = try f.client.readManifest()
            XCTAssertTrue(m.records.allSatisfy { $0.live == nil })
            XCTAssertEqual(m.records.count, corrupt ? 1 : 0)
            XCTAssertThrowsError(try f.client.open(f.a, authorization: f.auth))
            if corrupt { XCTAssertTrue(FileManager.default.fileExists(atPath: url.path)) }
        }
    }
    func testMissingCorruptWrongKeyAndUnsafeRolesFailClosed() throws {
        for variant in ["missing-current", "corrupt-current", "key", "symlink", "hardlink", "unknown", "missing-content", "corrupt-content", "mode"] {
            let f = try Fixture(); _ = try f.accept(); let current = URL(fileURLWithPath: f.path).appendingPathComponent("current")
            let content = URL(fileURLWithPath: f.path).appendingPathComponent(try f.client.readManifest().records[0].live!.snapshot.name)
            f.client.close()
            var key = f.key
            switch variant {
            case "missing-current": try FileManager.default.removeItem(at: current)
            case "corrupt-current": try Data(repeating: 0, count: 200).write(to: current)
            case "key": key = clientRandomKey()
            case "symlink":
                try FileManager.default.removeItem(at: current)
                XCTAssertEqual(symlink(content.path, current.path), 0)
            case "hardlink": XCTAssertEqual(link(current.path, f.path+"/prepared"), 0)
            case "unknown": try Data([1]).write(to: URL(fileURLWithPath: f.path+"/unrelated"))
            case "missing-content": try FileManager.default.removeItem(at: content)
            case "corrupt-content": try Data(repeating: 1, count: 200).write(to: content)
            default: XCTAssertEqual(chmod(current.path, 0o644), 0)
            }
            XCTAssertThrowsError(try DurableClientReceipts(path: f.path, create: false, environment: f.environment, metadataKey: key, clock: f.clock))
            XCTAssertThrowsError(try DurableClientReceipts(path: f.path, create: true, environment: f.environment, metadataKey: key, clock: f.clock))
            if variant == "unknown" { XCTAssertTrue(FileManager.default.fileExists(atPath: f.path+"/unrelated")) }
        }
    }
    func testEncryptedContentAndAuthenticatedOrphanRefusal() throws {
        let f = try Fixture(); _ = try f.accept()
        for role in try f.client.fs.names() where role != "lock" {
            let bytes = try f.client.fs.read(role)
            XCTAssertNil(bytes.range(of: f.a.bytes))
            XCTAssertNil(bytes.range(of: Data("verified-fake-result".utf8)))
        }
        let name = "s-"+UUID().uuidString.lowercased()+".bin"
        try f.client.fs.writeNew(name, Data(repeating: 0, count: 200))
        XCTAssertThrowsError(try f.receipt()); XCTAssertTrue(try f.client.fs.exists(name))
    }
    func testGenerationRecordCeilingAndDuplicateOpen() throws {
        let f = try Fixture()
        for n in 1..<64 {
            let a = try ReceiptFixtures.authority(generation: "record-\(n)")
            _ = try f.client.open(a, authorization: f.auth)
        }
        _ = try f.client.open(f.a, authorization: f.auth)
        XCTAssertEqual(try f.client.readManifest().records.count, 64)
        let a = try ReceiptFixtures.authority(generation: "overflow")
        XCTAssertThrowsError(try f.client.open(a, authorization: f.auth))
    }
}
