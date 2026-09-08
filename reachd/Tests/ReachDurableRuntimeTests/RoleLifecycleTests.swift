import Foundation
import Darwin
import XCTest
import DurableRootKeys
import DurableStoreBootstrap
@testable import ReachDurableRuntime

private final class LifecycleMemoryKeys: RootKeyProvider {
    var values: [String:(String,RootKeyMaterial)] = [:], creates = 0, loads = 0
    func create(_ reference: RootKeyReference, binding: String) throws -> RootKeyMaterial {
        guard values[reference.identifier] == nil else { throw RootKeyError.duplicate }
        let key = try RootKeyMaterial(RootKeyCodec.random())
        values[reference.identifier] = (binding,key); creates += 1; return key
    }
    func load(_ reference: RootKeyReference, binding: String) throws -> RootKeyMaterial {
        loads += 1
        guard let value = values[reference.identifier],value.0 == binding else { throw RootKeyError.unavailable }
        return value.1
    }
}
private final class LifecycleFixture {
    let base: String, root: String, receipt: String, worker: FrozenWorker
    let core: RoleBootstrapCore, provider = LifecycleMemoryKeys(), ready: RoleBootstrapReady
    let digest: String?
    init(publish: Bool = true, role: BootstrapRole = .client) throws {
        base = try ArtifactFixtures.base() + "/life-" + UUID().uuidString.lowercased()
        root = base + "/root"; receipt = base + "/control/owner.json"
        for path in [base,root,root+"/keys",base+"/control"] { try LocalFiles.createDirectory(path) }
        let path = base + "/control/worker", bytes = Data("fixed-lifecycle-fixture".utf8)
        try LocalFiles.writeNew(bytes,to:path); XCTAssertEqual(chmod(path,0o700),0)
        worker = .init(path:path,sha256:RootKeyCodec.hash(bytes))
        let lifecycle = try RoleLifecycleIdentity(root:root,receipt:receipt,executable:worker)
        core = try .init(role:role,localID:UUID().uuidString.lowercased(),root:root,agreement:String(repeating:"a",count:64),selection:String(repeating:"b",count:64),origin:1,epoch:UUID().uuidString.lowercased(),boot:RootKeyCodec.boot(),quota:1<<30,lifecycle:lifecycle)
        let lease = try RoleLifecycleLease.create(core:core); defer { lease.close() }
        let store = provider, rootPath = root
        ready = try RoleBootstrapStore.create(core:core,provider:{ store },initializeStore:{ _ in
            try LocalFiles.createDirectory(rootPath+"/bootstrap/"+role.rawValue)
            try LocalFiles.writeNew(Data(),to:rootPath+"/bootstrap/"+role.rawValue+"/lock")
        },lifecycle:lease)
        digest = try publish ? lease.publish(ready) : nil
    }
    deinit { try? FileManager.default.removeItem(atPath:base) }
    func mutate(_ path: String, _ body: (inout [String:Any]) -> Void) throws -> Data {
        let original = try Data(contentsOf:URL(fileURLWithPath:path))
        var value = try XCTUnwrap(JSONSerialization.jsonObject(with:original) as? [String:Any])
        body(&value)
        try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys,.withoutEscapingSlashes]).write(to:URL(fileURLWithPath:path))
        return original
    }
}

final class RoleLifecycleTests: XCTestCase {
    func testVersionOneEncodingAndBindingStayExact() throws {
        let f = try LifecycleFixture()
        let old = RoleBootstrapCore(role:.client,localID:f.core.localID,root:f.root,agreement:f.core.agreement,selection:f.core.selection,origin:f.core.origin,epoch:f.core.epoch,boot:f.core.boot,quota:f.core.quota)
        let bytes = try RootKeyCodec.encode(old,limit:64<<10)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with:bytes) as? [String:Any])
        XCTAssertEqual(Set(object.keys),["version","role","identifier","localID","root","container","agreement","selection","boot","epoch","origin","quota","keys"])
        XCTAssertEqual(old.version,1); XCTAssertNil(old.lifecycle)
        XCTAssertEqual(try old.binding(),RootKeyCodec.hash(Data("S95/role-bootstrap/v1\0".utf8)+bytes))
        XCTAssertEqual(try f.core.binding(),RootKeyCodec.hash(Data("S96/role-bootstrap/v2\0".utf8)+(try RootKeyCodec.encode(f.core,limit:64<<10))))
    }
    func testLeaseRequiredBeforeKeysAndFreshAcquisitionPreservesOriginalCore() throws {
        let f = try LifecycleFixture()
        XCTAssertThrowsError(try RoleBootstrapStore.acquire(at:f.root,role:.client,validate:{ _ in },provider:{ _ in f.provider }))
        XCTAssertEqual(f.provider.loads,0)
        let first = try RoleLifecycleLease.acquire(ready:f.ready)
        XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:f.ready)) { XCTAssertEqual($0 as? BootstrapError,.busy) }
        let acquired = try RoleBootstrapStore.acquire(at:f.root,role:.client,validate:{ XCTAssertEqual($0,f.core) },provider:{ _ in f.provider },lifecycle:first)
        XCTAssertEqual(acquired.ready.core,f.core); XCTAssertEqual(f.provider.creates,1)
        first.close()
        let second = try RoleLifecycleLease.acquire(ready:f.ready); defer { second.close() }
        _ = try RoleBootstrapStore.acquire(at:f.root,role:.client,validate:{ _ in },provider:{ _ in f.provider },lifecycle:second)
        XCTAssertEqual(f.provider.creates,1); XCTAssertEqual(f.provider.loads,2)
    }
    func testIncompletePublicationCannotBeAcquired() throws {
        let f = try LifecycleFixture(publish:false)
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.receipt))
        XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:f.ready))
        XCTAssertThrowsError(try RoleBootstrapStore.acquire(at:f.root,role:.client,validate:{ _ in },provider:{ _ in f.provider }))
        XCTAssertEqual(f.provider.loads,0)
    }
    func testWrongDigestReceiptAndRoleRefuseWithoutKeyAccess() throws {
        let f = try LifecycleFixture(), digest = try XCTUnwrap(f.digest)
        XCTAssertThrowsError(try RoleLifecycleLease.selectRetirement(receipt:f.receipt,expectedDigest:String(repeating:"0",count:64)))
        let original = try f.mutate(f.receipt) { value in
            var ready = value["ready"] as! [String:Any], core = ready["core"] as! [String:Any]
            core["role"] = "host"; ready["core"] = core; value["ready"] = ready
        }
        XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:f.ready))
        XCTAssertThrowsError(try RoleLifecycleLease.selectRetirement(receipt:f.receipt,expectedDigest:digest))
        XCTAssertEqual(f.provider.loads,0)
        try original.write(to:URL(fileURLWithPath:f.receipt))
        let (receipt,lease) = try RoleLifecycleLease.selectRetirement(receipt:f.receipt,expectedDigest:digest); defer { lease.close() }
        XCTAssertEqual(receipt.ready.core,f.core)
    }
    func testWrongBootstrapAndContainerRefuseWithoutKeyAccess() throws {
        let f = try LifecycleFixture(), digest = try XCTUnwrap(f.digest)
        for (field, replacement) in [("identifier",UUID().uuidString.lowercased()),("container",f.root+"/keys/unselected.keychain-db")] {
            let original = try f.mutate(f.receipt) { value in
                var ready = value["ready"] as! [String:Any], core = ready["core"] as! [String:Any]
                core[field] = replacement; ready["core"] = core; value["ready"] = ready
            }
            XCTAssertThrowsError(try RoleLifecycleLease.selectRetirement(receipt:f.receipt,expectedDigest:digest))
            XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:f.ready))
            XCTAssertEqual(f.provider.loads,0)
            try original.write(to:URL(fileURLWithPath:f.receipt))
        }
        let lease = try RoleLifecycleLease.acquire(ready:f.ready); lease.close()
        XCTAssertEqual(f.provider.creates,1); XCTAssertEqual(f.provider.loads,0)
    }
    func testReplacementAndSymlinkRootFailIdentityBeforeAcquisition() throws {
        let f = try LifecycleFixture(), moved = f.base+"/original"
        XCTAssertEqual(rename(f.root,moved),0)
        defer { _ = rename(moved,f.root) }
        try LocalFiles.createDirectory(f.root)
        XCTAssertThrowsError(try f.core.lifecycle!.identity.present())
        XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:f.ready))
        XCTAssertEqual(rmdir(f.root),0)
        XCTAssertEqual(symlink(moved,f.root),0)
        XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:f.ready))
        XCTAssertEqual(unlink(f.root),0); XCTAssertEqual(f.provider.loads,0)
    }
    func testJournalExclusionDoesNotReadItsContents() throws {
        let f = try LifecycleFixture(), lease = try RoleLifecycleLease.acquire(ready:f.ready)
        defer { lease.close() }
        let fd = open(f.root+"/bootstrap/client/lock",O_RDWR|O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd,0); defer { _ = Darwin.close(fd) }
        XCTAssertEqual(flock(fd,LOCK_EX|LOCK_NB),0)
        XCTAssertThrowsError(try lease.lockJournal()) { XCTAssertEqual($0 as? BootstrapError,.busy) }
        XCTAssertEqual(flock(fd,LOCK_UN),0)
        try LocalFiles.writeNew(Data("not a decryptable snapshot".utf8),to:f.root+"/bootstrap/client/opaque")
        try lease.lockJournal(); XCTAssertEqual(f.provider.loads,0)
    }
    func testRetiringStateExcludesAcquisitionAndSurvivesPartialRootRemoval() throws {
        let f = try LifecycleFixture(), digest = try XCTUnwrap(f.digest)
        // This unit fixture models persisted authorized progress; the real
        // key-confirmation/deletion boundary is qualified separately via CLI.
        _ = try f.mutate(f.receipt+".state.json") { $0["phase"] = "retiring" }
        XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:f.ready))
        try FileManager.default.removeItem(atPath:f.root+"/keys")
        let (receipt,lease) = try RoleLifecycleLease.selectRetirement(receipt:f.receipt,expectedDigest:digest)
        XCTAssertEqual(try lease.phase(receipt:receipt),.retiring)
        XCTAssertTrue(try receipt.container.identity.present()); lease.close()
        try FileManager.default.removeItem(atPath:f.root)
        let (again,fresh) = try RoleLifecycleLease.selectRetirement(receipt:f.receipt,expectedDigest:digest)
        defer { fresh.close() }
        XCTAssertFalse(try again.container.identity.present())
        try fresh.finishRetirement(receipt:again)
        XCTAssertEqual(try fresh.phase(receipt:again),.retired)
        XCTAssertEqual(f.provider.loads,0)
    }
}
