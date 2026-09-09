import Foundation
import Darwin
import XCTest
@testable import DurableRootKeys
import DurableStoreBootstrap
@testable import ReachDurableRuntime

final class RoleUnlockTests: XCTestCase {
    private func descriptor(_ fixture: LifecycleFixture, bytes: Data, mode: mode_t = 0o600,
                            access: Int32 = O_RDONLY) throws -> Int32 {
        let path = fixture.base+"/input-"+UUID().uuidString.lowercased()
        try LocalFiles.writeNew(bytes,to:path)
        XCTAssertEqual(chmod(path,mode),0)
        let fd = open(path,access|O_CLOEXEC)
        guard fd > STDERR_FILENO else { throw RootKeyError.invalid }
        return fd
    }
    func testNewPolicyBindingAndLegacyEncodingsStayExact() throws {
        let old = try LifecycleFixture(), fresh = try LifecycleFixture(unlock:true)
        let oldBytes = try RootKeyCodec.encode(old.core,limit:64<<10)
        let oldFields = try XCTUnwrap(JSONSerialization.jsonObject(with:oldBytes) as? [String:Any])
        XCTAssertEqual(old.core.version,2); XCTAssertNil(oldFields["unlockPolicy"])
        XCTAssertEqual(try old.core.binding(),RootKeyCodec.hash(Data("S96/role-bootstrap/v2\0".utf8)+oldBytes))
        XCTAssertEqual(fresh.core.version,3); XCTAssertEqual(fresh.core.unlockPolicy,UnlockCredential.policy)
        XCTAssertEqual(try fresh.core.binding(),RootKeyCodec.hash(Data("S97/role-bootstrap/v3\0".utf8)+(try RootKeyCodec.encode(fresh.core,limit:64<<10))))
        let receipt = try RoleOwnershipReceipt(ready:fresh.ready)
        XCTAssertEqual(receipt.ready.core,fresh.core)
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with:RootKeyCodec.encode(fresh.core,limit:64<<10)) as? [String:Any])
        fields["version"] = 2; fields.removeValue(forKey:"unlockPolicy")
        let bytes = try JSONSerialization.data(withJSONObject:fields,options:[.sortedKeys,.withoutEscapingSlashes])
        let downgraded = try RootKeyCodec.decode(RoleBootstrapCore.self,bytes,limit:64<<10)
        try downgraded.validate(role:.client,root:fresh.root)
        let reference = fresh.core.keys[0]
        let original = try XCTUnwrap(fresh.provider.values[reference.identifier])
        XCTAssertThrowsError(try original.1.confirm(fresh.ready.confirmations[0],reference:reference,binding:downgraded.binding()))
        fields["version"] = 3; fields["unlockPolicy"] = "unselected-policy"
        let invalid = try RootKeyCodec.decode(RoleBootstrapCore.self,JSONSerialization.data(withJSONObject:fields,options:[.sortedKeys,.withoutEscapingSlashes]),limit:64<<10)
        XCTAssertThrowsError(try invalid.validate(role:.client,root:fresh.root))
    }
    func testDescriptorBoundsCloseAndNoOnwardInheritance() throws {
        let f = try LifecycleFixture()
        for count in [32,64,128] {
            let fd = try descriptor(f,bytes:Data(repeating:65,count:count))
            XCTAssertEqual(fcntl(fd,F_SETFD,0),0)
            XCTAssertEqual(lseek(fd,7,SEEK_SET),7)
            let credential = try UnlockCredential(consumingDescriptor:fd)
            XCTAssertNotEqual(fcntl(fd,F_GETFD)&FD_CLOEXEC,0)
            let matches = try credential.consume { bytes in
                XCTAssertEqual(fcntl(fd,F_GETFD),-1)
                return bytes.count == count && bytes.allSatisfy { $0 == 65 }
            }
            XCTAssertTrue(matches)
            XCTAssertThrowsError(try credential.consume { _ in true })
        }
    }
    func testMalformedDescriptorInputIsConsumedWithoutExposingBytes() throws {
        let f = try LifecycleFixture()
        let samples = [Data(),Data(repeating:65,count:31),Data(repeating:65,count:129),
                       Data(repeating:65,count:32)+Data([10]),Data(repeating:255,count:64),
                       Data(repeating:0,count:64)]
        for bytes in samples {
            let fd = try descriptor(f,bytes:bytes)
            XCTAssertThrowsError(try UnlockCredential(consumingDescriptor:fd).consume { _ in true })
            XCTAssertEqual(fcntl(fd,F_GETFD),-1)
        }
    }
    func testClosedStandardWrongAccessNonprivateAndNonregularRefuse() throws {
        let f = try LifecycleFixture(), standard = fcntl(STDERR_FILENO,F_GETFD)
        XCTAssertThrowsError(try UnlockCredential(consumingDescriptor:STDERR_FILENO))
        XCTAssertEqual(fcntl(STDERR_FILENO,F_GETFD),standard)
        XCTAssertThrowsError(try UnlockCredential(consumingDescriptor:Int32.max))
        let variants: [(mode_t,Int32)] = [(0o644,O_RDONLY),(0o600,O_RDWR),(0o600,O_WRONLY)]
        for (mode,access) in variants {
            let fd = try descriptor(f,bytes:Data(repeating:65,count:64),mode:mode,access:access)
            XCTAssertThrowsError(try UnlockCredential(consumingDescriptor:fd))
            XCTAssertEqual(fcntl(fd,F_GETFD),-1)
        }
        var pair = [Int32](repeating:-1,count:2)
        XCTAssertEqual(pipe(&pair),0); defer { _ = Darwin.close(pair[1]) }
        XCTAssertThrowsError(try UnlockCredential(consumingDescriptor:pair[0]))
        XCTAssertEqual(fcntl(pair[0],F_GETFD),-1)
    }
    func testLockedWrongCredentialStaysLockedWithoutConfirmation() throws {
        var confirmations = 0, relocks = 0
        XCTAssertThrowsError(try OwnedUnlockTransaction.run(initiallyUnlocked:false,unlock:{ throw RootKeyError.unavailable },isUnlocked:{ false },confirm:{ confirmations += 1 },relock:{ relocks += 1 })) {
            XCTAssertEqual($0 as? OwnedContainerUnlockError,.refused)
        }
        XCTAssertEqual(confirmations,0); XCTAssertEqual(relocks,0)
    }
    func testPostUnlockConfirmationAndSelectionRefusalRelock() throws {
        for failingCheck in [0,1] {
            var unlocked = false, checks = 0, relocks = 0
            XCTAssertThrowsError(try OwnedUnlockTransaction.run(initiallyUnlocked:false,unlock:{ unlocked = true },isUnlocked:{ unlocked },confirm:{
                for index in [0,1] { checks += 1; if index == failingCheck { throw RootKeyError.invalid } }
            },relock:{ relocks += 1; unlocked = false })) {
                XCTAssertEqual($0 as? OwnedContainerUnlockError,.verificationRefusedLocked)
            }
            XCTAssertFalse(unlocked); XCTAssertEqual(relocks,1); XCTAssertEqual(checks,failingCheck+1)
        }
    }
    func testRelockFailureCannotBecomeSuccess() throws {
        for throwsOnRelock in [false,true] {
            var unlocked = false, attempted = 0
            XCTAssertThrowsError(try OwnedUnlockTransaction.run(initiallyUnlocked:false,unlock:{ unlocked = true },isUnlocked:{ unlocked },confirm:{ throw RootKeyError.invalid },relock:{
                attempted += 1
                if throwsOnRelock { throw RootKeyError.unavailable }
                // Simulates an OS operation that did not establish locked state.
            })) { XCTAssertEqual($0 as? OwnedContainerUnlockError,.relockUnconfirmed) }
            XCTAssertTrue(unlocked); XCTAssertEqual(attempted,1)
        }
    }
    func testAlreadyUnlockedOnlyProvesOriginalKeyAvailability() throws {
        var unlockCalls = 0, confirms = 0, relocks = 0
        let changed = try OwnedUnlockTransaction.run(initiallyUnlocked:true,unlock:{ unlockCalls += 1 },isUnlocked:{ true },confirm:{ confirms += 1 },relock:{ relocks += 1 })
        XCTAssertFalse(changed); XCTAssertEqual(unlockCalls,0); XCTAssertEqual(confirms,1); XCTAssertEqual(relocks,0)
        XCTAssertThrowsError(try OwnedUnlockTransaction.run(initiallyUnlocked:true,unlock:{ unlockCalls += 1 },isUnlocked:{ true },confirm:{ throw RootKeyError.invalid },relock:{ relocks += 1 }))
        XCTAssertEqual(unlockCalls,0); XCTAssertEqual(relocks,0)
    }
    func testVersionThreeStillRequiresLeaseAndRetiringCannotAcquire() throws {
        let f = try LifecycleFixture(unlock:true)
        XCTAssertThrowsError(try RoleBootstrapStore.acquire(at:f.root,role:.client,validate:{ _ in },provider:{ _ in f.provider }))
        XCTAssertEqual(f.provider.loads,0)
        let lease = try RoleLifecycleLease.acquire(ready:f.ready)
        XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:f.ready))
        _ = try RoleBootstrapStore.acquire(at:f.root,role:.client,validate:{ XCTAssertEqual($0,f.core) },provider:{ _ in f.provider },lifecycle:lease)
        XCTAssertEqual(f.provider.creates,1); lease.close()
        _ = try f.mutate(f.receipt+".state.json") { $0["phase"] = "retiring" }
        XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:f.ready))
        let (receipt,selected) = try RoleLifecycleLease.selectRetirement(receipt:f.receipt,expectedDigest:XCTUnwrap(f.digest))
        defer { selected.close() }
        XCTAssertEqual(try selected.phase(receipt:receipt),.retiring)
        XCTAssertEqual(f.provider.creates,1); XCTAssertEqual(f.provider.loads,1)
    }
}
