import Foundation
import Darwin
import XCTest
@testable import DurableRootKeys
@testable import DurableStoreBootstrap
@testable import ReachDurableRuntime

private enum AfterBootInterruption: Error { case pendingWrite, authorityRefused }

/// Injected prior-boot public fixtures qualify admission, not an actual reboot.
private final class AfterBootFixture {
    var originalKeyConfirmations = 0
    let original: LifecycleFixture, core: RoleBootstrapCore, receipt: RoleOwnershipReceipt, digest: String
    let current: OwnedAfterBootRoot
    var path: String { original.receipt }
    var root: String { original.root }
    init() throws {
        original = try LifecycleFixture(unlock:true)
        var fields = try Self.object(RootKeyCodec.encode(original.core,limit:64<<10))
        fields["boot"] = UUID().uuidString.lowercased()
        var lifecycle = fields["lifecycle"] as! [String:Any], identity = lifecycle["identity"] as! [String:Any]
        identity["device"] = original.core.lifecycle!.identity.device ^ 1
        lifecycle["identity"] = identity; fields["lifecycle"] = lifecycle
        core = try RootKeyCodec.decode(RoleBootstrapCore.self,Self.bytes(fields),limit:64<<10)
        let binding = try core.binding(), provider = original.provider
        let confirmations = try core.keys.map { reference in
            try XCTUnwrap(provider.values[reference.identifier]).1.confirmation(reference,binding:binding).base64EncodedString()
        }
        let ready: [String:Any] = ["state":"ready","core":fields,"confirmations":confirmations]
        var receiptFields = try Self.object(Data(contentsOf:URL(fileURLWithPath:original.receipt)))
        var container = receiptFields["container"] as! [String:Any]
        container["identity"] = identity; container["boot"] = core.boot
        container["binding"] = binding; container["confirmations"] = confirmations
        receiptFields["ready"] = ready; receiptFields["container"] = container
        receipt = try RootKeyCodec.decode(RoleOwnershipReceipt.self,Self.bytes(receiptFields),limit:64<<10)
        digest = try receipt.digestForAfterBootRetirement()
        try Self.bytes(receiptFields).write(to:URL(fileURLWithPath:original.receipt))
        try Self.bytes(ready).write(to:URL(fileURLWithPath:original.root+"/bootstrap/ready.json"))
        try Self.bytes(["state":"creating","core":fields]).write(to:URL(fileURLWithPath:original.root+"/bootstrap/intent.json"))
        try Self.bytes(["version":1,"phase":"ready","core":binding,"receipt":digest]).write(to:URL(fileURLWithPath:original.receipt+".state.json"))
        current = try XCTUnwrap(OwnedAfterBootRoot.open(core.lifecycle!.identity))
    }
    static func bytes(_ value: [String:Any]) throws -> Data { try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys,.withoutEscapingSlashes]) }
    static func object(_ bytes: Data) throws -> [String:Any] { try XCTUnwrap(JSONSerialization.jsonObject(with:bytes) as? [String:Any]) }
    func select() throws -> RoleLifecycleLease { try RoleLifecycleLease.selectAfterBootRetirement(receipt:path,expectedDigest:digest).1 }
    func confirmOriginalKeys() throws {
        for (reference,confirmation) in zip(core.keys,receipt.container.confirmations) {
            let key = try XCTUnwrap(original.provider.values[reference.identifier]).1
            try key.confirm(confirmation,reference:reference,binding:core.binding())
        }
        originalKeyConfirmations += 1
    }
    func interruptRetiringWrite() throws -> Data {
        let lease = try select(); defer { lease.close() }
        try lease.lockAfterBootJournal(current,required:true)
        XCTAssertThrowsError(try lease.beginAfterBootRetirement(receipt:receipt,current:current,
            confirmAuthority:confirmOriginalKeys,afterPendingWrite:{ throw AfterBootInterruption.pendingWrite })) {
            guard case AfterBootInterruption.pendingWrite = $0 else { return XCTFail("Wrong interruption: \($0)") }
        }
        XCTAssertEqual(try lease.phase(receipt:receipt),.ready)
        XCTAssertThrowsError(try lease.confirmAfterBootRetry(receipt:receipt,current:current))
        return try Data(contentsOf:URL(fileURLWithPath:path+".next"))
    }
    func setRetiring() throws {
        _ = try original.mutate(path+".state.json") { $0["phase"] = "retiring" }
    }
    func observe() throws {
        let bytes = try RootKeyCodec.encode(RoleLifecycleCleanupObservation(receipt:receipt,current:current),limit:64<<10)
        let target = path+".cleanup.json"
        if FileManager.default.fileExists(atPath:target) { try bytes.write(to:URL(fileURLWithPath:target)) }
        else { try LocalFiles.writeNew(bytes,to:target) }
    }
}

final class AfterBootRetirementTests: XCTestCase {
    func testCleanupAdmissionDoesNotChangeOriginalDomainsOrRuntimeDefaults() throws {
        let f = try AfterBootFixture(), before = try Data(contentsOf:URL(fileURLWithPath:f.path))
        XCTAssertThrowsError(try f.core.validateDescription(role:.client,root:f.root))
        XCTAssertThrowsError(try f.receipt.validate())
        XCTAssertThrowsError(try f.receipt.digest())
        XCTAssertThrowsError(try RoleBootstrapStore.inspect(at:f.root,role:.client))
        XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:f.receipt.ready))
        XCTAssertThrowsError(try RoleLifecycleLease.selectRetirement(receipt:f.path,expectedDigest:f.digest))
        XCTAssertNoThrow(try f.core.validateForAfterBootRetirement())
        XCTAssertEqual(try RoleBootstrapStore.inspectForAfterBootRetirement(at:f.root,role:.client).core,f.core)
        let lease = try f.select(); defer { lease.close() }
        XCTAssertThrowsError(try lease.confirmReady(f.receipt.ready))
        XCTAssertThrowsError(try lease.lockJournal())
        XCTAssertEqual(try lease.phase(receipt:f.receipt),.ready)
        XCTAssertEqual(try f.core.binding(),RootKeyCodec.hash(Data("S97/role-bootstrap/v3\0".utf8)+(try RootKeyCodec.encode(f.core,limit:64<<10))))
        XCTAssertEqual(f.digest,RootKeyCodec.hash(Data("S96/role-ownership-receipt/v1\0".utf8)+before))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.path)),before)
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.path+".cleanup.json"))
        XCTAssertEqual(f.original.provider.loads,0)
    }
    func testSameBootAndLegacyVersionsHaveNoCleanupAdmission() throws {
        let same = try LifecycleFixture(unlock:true)
        XCTAssertNoThrow(try same.core.validateDescription(role:.client,root:same.root))
        XCTAssertThrowsError(try same.core.validateForAfterBootRetirement())
        XCTAssertThrowsError(try RoleLifecycleLease.selectAfterBootRetirement(receipt:same.receipt,expectedDigest:XCTUnwrap(same.digest)))
        let f = try AfterBootFixture()
        for version in [1,2] {
            var fields = try AfterBootFixture.object(RootKeyCodec.encode(f.core,limit:64<<10))
            fields["version"] = version; fields.removeValue(forKey:"unlockPolicy")
            if version == 1 { fields.removeValue(forKey:"lifecycle") }
            let core = try RootKeyCodec.decode(RoleBootstrapCore.self,AfterBootFixture.bytes(fields),limit:64<<10)
            XCTAssertThrowsError(try core.validateForAfterBootRetirement())
        }
    }
    func testWrongReceiptPolicyAndExecutableRefuseBeforeKeys() throws {
        let f = try AfterBootFixture()
        XCTAssertThrowsError(try RoleLifecycleLease.selectAfterBootRetirement(receipt:f.path,expectedDigest:String(repeating:"0",count:64)))
        let saved = try f.original.mutate(f.path) { fields in
            var ready = fields["ready"] as! [String:Any], core = ready["core"] as! [String:Any]
            core["unlockPolicy"] = "unselected"; ready["core"] = core; fields["ready"] = ready
        }
        XCTAssertThrowsError(try f.select()); try saved.write(to:URL(fileURLWithPath:f.path))
        let worker = URL(fileURLWithPath:f.original.worker.path), executable = try Data(contentsOf:worker)
        try Data("changed-executable".utf8).write(to:worker)
        XCTAssertThrowsError(try f.select()); try executable.write(to:worker)
        XCTAssertEqual(f.original.provider.loads,0)
    }
    func testCurrentPinAllowsDeviceDriftButRejectsNameReplacementAndSymlink() throws {
        let f = try AfterBootFixture()
        XCTAssertNotEqual(f.current.device,f.core.lifecycle!.identity.device)
        XCTAssertThrowsError(try f.core.lifecycle!.identity.present())
        XCTAssertNoThrow(try f.current.check())
        let moved = f.original.base+"/moved"
        XCTAssertEqual(rename(f.root,moved),0)
        defer { _ = rename(moved,f.root) }
        try LocalFiles.createDirectory(f.root)
        XCTAssertThrowsError(try f.current.check())
        XCTAssertThrowsError(try OwnedAfterBootRoot.open(f.core.lifecycle!.identity))
        XCTAssertEqual(rmdir(f.root),0); XCTAssertEqual(symlink(moved,f.root),0)
        XCTAssertThrowsError(try f.current.check())
        XCTAssertThrowsError(try OwnedAfterBootRoot.open(f.core.lifecycle!.identity))
        XCTAssertEqual(unlink(f.root),0)
    }
    func testPinnedTraversalRejectsHardLinksSymlinksAndOtherDevices() throws {
        let f = try AfterBootFixture(), file = f.root+"/keys/public", outside = f.original.base+"/outside"
        try LocalFiles.writeNew(Data([1]),to:file)
        XCTAssertNoThrow(try f.current.inspect(file))
        XCTAssertEqual(link(file,outside),0)
        XCTAssertThrowsError(try f.current.inspect(file)); XCTAssertEqual(unlink(outside),0)
        XCTAssertEqual(symlink(file,outside),0)
        let inside = f.root+"/keys/link"
        XCTAssertEqual(symlink(outside,inside),0)
        XCTAssertThrowsError(try f.current.inspect(inside)); XCTAssertEqual(unlink(inside),0)
        var value = try f.current.inspect(file)
        XCTAssertNoThrow(try OwnedAfterBootRoot.requireMember(value,on:f.current.device,leaf:true))
        value.st_dev ^= 1
        XCTAssertThrowsError(try OwnedAfterBootRoot.requireMember(value,on:f.current.device,leaf:true))
        XCTAssertThrowsError(try f.current.inspect(f.root+"/keys/../keys/public"))
    }
    func testLifetimeAndJournalExclusionAreRetained() throws {
        let f = try AfterBootFixture(), lease = try f.select(); defer { lease.close() }
        XCTAssertThrowsError(try f.select()) { XCTAssertEqual($0 as? BootstrapError,.busy) }
        let path = f.root+"/bootstrap/client/lock", fd = open(path,O_RDWR|O_NOFOLLOW|O_CLOEXEC)
        XCTAssertGreaterThan(fd,2); defer { _ = Darwin.close(fd) }
        XCTAssertEqual(flock(fd,LOCK_EX|LOCK_NB),0)
        XCTAssertThrowsError(try lease.lockAfterBootJournal(f.current,required:true)) { XCTAssertEqual($0 as? BootstrapError,.busy) }
        XCTAssertEqual(flock(fd,LOCK_UN),0)
        XCTAssertNoThrow(try lease.lockAfterBootJournal(f.current,required:true))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)).count,0)
    }
    func testObservationAloneAndMissingContainerReadyNeverAuthorizeRemoval() throws {
        let f = try AfterBootFixture(), lease = try f.select(); defer { lease.close() }
        try f.observe()
        XCTAssertThrowsError(try lease.confirmAfterBootRetry(receipt:f.receipt,current:f.current))
        XCTAssertEqual(try lease.phase(receipt:f.receipt),.ready)
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.root))
    }
    func testMissingContainerRetryIsBoundToObservedBootAndExactTuple() throws {
        let f = try AfterBootFixture(), lease = try f.select(); defer { lease.close() }
        try f.setRetiring(); try f.observe()
        XCTAssertNoThrow(try lease.confirmAfterBootRetry(receipt:f.receipt,current:f.current))
        let path = f.path+".cleanup.json"
        for (key,value) in [("boot",UUID().uuidString.lowercased() as Any),("device",f.current.device ^ 1),
                            ("inode",f.current.inode+1),("root",f.root+"-other"),("receipt",String(repeating:"0",count:64)),
                            ("core",String(repeating:"0",count:64)),("selection",String(repeating:"0",count:64)),("version",2)] {
            let original = try f.original.mutate(path) { $0[key] = value }
            XCTAssertThrowsError(try lease.confirmAfterBootRetry(receipt:f.receipt,current:f.current))
            try original.write(to:URL(fileURLWithPath:path))
        }
        try Data("malformed".utf8).write(to:URL(fileURLWithPath:path))
        XCTAssertThrowsError(try lease.confirmAfterBootRetry(receipt:f.receipt,current:f.current))
        XCTAssertEqual(unlink(path),0)
        XCTAssertThrowsError(try lease.confirmAfterBootRetry(receipt:f.receipt,current:f.current))
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.root))
    }
    func testContentFreePinnedRemovalAndRetiredStateKeepOriginalReceipt() throws {
        let f = try AfterBootFixture(), lease = try f.select(); defer { lease.close() }
        try f.setRetiring(); try f.observe(); try lease.lockAfterBootJournal(f.current,required:true)
        let before = try Data(contentsOf:URL(fileURLWithPath:f.path))
        try LocalFiles.writeNew(Data("not a generation manifest".utf8),to:f.root+"/bootstrap/client/current")
        try lease.confirmAfterBootRetry(receipt:f.receipt,current:f.current)
        try IndependentRoleLifecycle.removeSelectedRoot(f.core,current:f.current)
        try lease.finishAfterBootRetirement(receipt:f.receipt,current:f.current)
        XCTAssertTrue(try f.current.absent()); XCTAssertNil(try OwnedAfterBootRoot.open(f.core.lifecycle!.identity))
        XCTAssertEqual(try lease.phase(receipt:f.receipt),.retired)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.path)),before)
        let state = try AfterBootFixture.object(Data(contentsOf:URL(fileURLWithPath:f.path+".state.json")))
        XCTAssertEqual(Set(state.keys),["version","phase","core","receipt"]); XCTAssertEqual(state["version"] as? Int,1)
    }
    func testPendingRetiringWriteRecoversThroughFreshAuthenticatedTransition() throws {
        let f = try AfterBootFixture(), receipt = try Data(contentsOf:URL(fileURLWithPath:f.path))
        let pending = try f.interruptRetiringWrite(), path = f.path+".next"
        let expected = try RootKeyCodec.encode(RoleLifecycleState(phase:.retiring,core:f.core.binding(),receipt:f.digest),limit:64<<10)
        XCTAssertEqual(pending,expected); XCTAssertEqual(f.originalKeyConfirmations,1)
        var written = stat(); XCTAssertEqual(lstat(path,&written),0)
        let fresh = try f.select(); defer { fresh.close() }
        try fresh.lockAfterBootJournal(f.current,required:true)
        try fresh.beginAfterBootRetirement(receipt:f.receipt,current:f.current,confirmAuthority:f.confirmOriginalKeys,afterPendingWrite:{
            var recovered = stat(); XCTAssertEqual(lstat(path,&recovered),0)
            XCTAssertEqual(recovered.st_ino,written.st_ino)
            XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),pending)
        })
        XCTAssertEqual(f.originalKeyConfirmations,2)
        XCTAssertEqual(try fresh.phase(receipt:f.receipt),.retiring)
        XCTAssertFalse(FileManager.default.fileExists(atPath:path))
        XCTAssertNoThrow(try fresh.confirmAfterBootRetry(receipt:f.receipt,current:f.current))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.path+".state.json")),pending)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.path)),receipt)
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.root))
    }
    func testPendingRetiringWriteCannotReplaceFreshAuthorityOrJournalExclusion() throws {
        let f = try AfterBootFixture(), pending = try f.interruptRetiringWrite()
        let fresh = try f.select(); defer { fresh.close() }
        XCTAssertThrowsError(try fresh.beginAfterBootRetirement(receipt:f.receipt,current:f.current,confirmAuthority:f.confirmOriginalKeys))
        XCTAssertEqual(f.originalKeyConfirmations,1)
        try fresh.lockAfterBootJournal(f.current,required:true)
        XCTAssertThrowsError(try fresh.beginAfterBootRetirement(receipt:f.receipt,current:f.current,
            confirmAuthority:{ throw AfterBootInterruption.authorityRefused })) {
            guard case AfterBootInterruption.authorityRefused = $0 else { return XCTFail("Wrong refusal: \($0)") }
        }
        XCTAssertEqual(f.originalKeyConfirmations,1)
        XCTAssertEqual(try fresh.phase(receipt:f.receipt),.ready)
        XCTAssertThrowsError(try fresh.confirmAfterBootRetry(receipt:f.receipt,current:f.current))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.path+".next")),pending)
        XCTAssertTrue(FileManager.default.fileExists(atPath:f.root))
    }
    func testPendingRetiringWriteRejectsWrongBindingPhaseAndMalformedBytes() throws {
        for (field,value) in [("core",String(repeating:"0",count:64) as Any),
                              ("receipt",String(repeating:"0",count:64)),("phase","retired"),("version",2),("malformed",true)] {
            let f = try AfterBootFixture(), pending = try f.interruptRetiringWrite(), path = f.path+".next"
            var fields = try AfterBootFixture.object(pending); fields[field] = value
            let wrong = field == "malformed" ? Data("invalid".utf8) : try AfterBootFixture.bytes(fields)
            try wrong.write(to:URL(fileURLWithPath:path))
            let fresh = try f.select(); defer { fresh.close() }
            try fresh.lockAfterBootJournal(f.current,required:true)
            XCTAssertThrowsError(try fresh.beginAfterBootRetirement(receipt:f.receipt,current:f.current,confirmAuthority:f.confirmOriginalKeys))
            XCTAssertEqual(f.originalKeyConfirmations,2)
            XCTAssertEqual(try fresh.phase(receipt:f.receipt),.ready)
            XCTAssertThrowsError(try fresh.confirmAfterBootRetry(receipt:f.receipt,current:f.current))
            XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),wrong)
        }
    }
    func testPendingRetiringWriteRejectsUnsafeFilesWithoutReplacement() throws {
        for kind in ["symlink","hardlink","nonprivate","directory","fifo"] {
            let f = try AfterBootFixture(), pending = try f.interruptRetiringWrite(), path = f.path+".next"
            let outside = f.original.base+"/pending-outside"
            switch kind {
            case "symlink":
                XCTAssertEqual(rename(path,outside),0); XCTAssertEqual(symlink(outside,path),0)
            case "hardlink": XCTAssertEqual(link(path,outside),0)
            case "nonprivate": XCTAssertEqual(chmod(path,0o644),0)
            case "directory": XCTAssertEqual(unlink(path),0); XCTAssertEqual(mkdir(path,0o700),0)
            default: XCTAssertEqual(unlink(path),0); XCTAssertEqual(mkfifo(path,0o600),0)
            }
            var before = stat(); XCTAssertEqual(lstat(path,&before),0)
            let fresh = try f.select(); defer { fresh.close() }
            try fresh.lockAfterBootJournal(f.current,required:true)
            XCTAssertThrowsError(try fresh.beginAfterBootRetirement(receipt:f.receipt,current:f.current,confirmAuthority:f.confirmOriginalKeys))
            XCTAssertEqual(try fresh.phase(receipt:f.receipt),.ready)
            XCTAssertThrowsError(try fresh.confirmAfterBootRetry(receipt:f.receipt,current:f.current))
            var after = stat(); XCTAssertEqual(lstat(path,&after),0)
            XCTAssertEqual(after.st_ino,before.st_ino); XCTAssertEqual(after.st_mode,before.st_mode)
            if kind == "symlink" || kind == "hardlink" { XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:outside)),pending) }
        }
    }
    func testWrongSecretAndPostUnlockFailureRelockWithoutPhaseRollback() throws {
        var unlocked = false, phase = "ready", calls = 0
        XCTAssertThrowsError(try OwnedRetirementTransaction.run(initiallyUnlocked:false,unlock:{ throw RootKeyError.unavailable },isUnlocked:{ unlocked },containerPresent:{ true },relock:{ calls += 1 },operation:{ calls += 1 }))
        XCTAssertEqual(calls,0); XCTAssertFalse(unlocked)
        XCTAssertThrowsError(try OwnedRetirementTransaction.run(initiallyUnlocked:false,unlock:{ unlocked = true },isUnlocked:{ unlocked },containerPresent:{ true },relock:{ calls += 1; unlocked = false },operation:{ phase = "retiring"; throw RootKeyError.invalid })) {
            XCTAssertEqual($0 as? OwnedAfterBootRetirementError,.refusedLocked)
        }
        XCTAssertFalse(unlocked); XCTAssertEqual(calls,1); XCTAssertEqual(phase,"retiring")
    }
    func testOriginalKeyConfirmationFailureCannotAuthorizeRetirement() throws {
        let f = try AfterBootFixture(), reference = f.core.keys[0]
        let key = try XCTUnwrap(f.original.provider.values[reference.identifier]).1
        var unlocked = false, authorized = false, relocks = 0
        XCTAssertThrowsError(try OwnedRetirementTransaction.run(initiallyUnlocked:false,unlock:{ unlocked = true },isUnlocked:{ unlocked },containerPresent:{ true },relock:{ relocks += 1; unlocked = false },operation:{
            try key.confirm(Data(repeating:0,count:32),reference:reference,binding:f.core.binding())
            authorized = true
        })) { XCTAssertEqual($0 as? OwnedAfterBootRetirementError,.refusedLocked) }
        XCTAssertFalse(authorized); XCTAssertFalse(unlocked); XCTAssertEqual(relocks,1)
    }
    func testFailedAndNoEffectRelockCannotBecomeSuccess() throws {
        for failure in [false,true] {
            var unlocked = false, relocks = 0
            XCTAssertThrowsError(try OwnedRetirementTransaction.run(initiallyUnlocked:false,unlock:{ unlocked = true },isUnlocked:{ unlocked },containerPresent:{ true },relock:{ relocks += 1; if failure { throw RootKeyError.unavailable } },operation:{ throw RootKeyError.invalid })) {
                XCTAssertEqual($0 as? OwnedAfterBootRetirementError,.relockUnconfirmed)
            }
            XCTAssertTrue(unlocked); XCTAssertEqual(relocks,1)
        }
    }
    func testAlreadyUnlockedAndDeletedContainersAreNeverRelocked() throws {
        var unlocks = 0, relocks = 0
        let available = try OwnedRetirementTransaction.run(initiallyUnlocked:true,unlock:{ unlocks += 1 },isUnlocked:{ true },containerPresent:{ true },relock:{ relocks += 1 },operation:{ true })
        XCTAssertTrue(available)
        XCTAssertThrowsError(try OwnedRetirementTransaction.run(initiallyUnlocked:true,unlock:{ unlocks += 1 },isUnlocked:{ true },containerPresent:{ true },relock:{ relocks += 1 },operation:{ throw RootKeyError.invalid }))
        XCTAssertThrowsError(try OwnedRetirementTransaction.run(initiallyUnlocked:false,unlock:{ unlocks += 1 },isUnlocked:{ true },containerPresent:{ false },relock:{ relocks += 1 },operation:{ throw RootKeyError.invalid }))
        XCTAssertEqual(unlocks,1); XCTAssertEqual(relocks,0)
    }
}
