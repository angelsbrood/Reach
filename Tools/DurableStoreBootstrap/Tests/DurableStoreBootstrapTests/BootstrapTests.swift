import XCTest
import Foundation
import DurableRootKeys
@testable import DurableStoreBootstrap

final class MemoryRootKeys: RootKeyProvider {
    var records: [String:(RootKeyReference,String,Data)] = [:], creates = 0, loads = 0
    func id(_ r: RootKeyReference) -> String { r.service+"/"+r.account }
    func create(_ reference: RootKeyReference,binding:String) throws -> RootKeyMaterial {
        creates += 1; guard records[id(reference)] == nil else { throw RootKeyError.duplicate }
        let bytes = try RootKeyCodec.random(); records[id(reference)] = (reference,binding,bytes); return try .init(bytes)
    }
    func load(_ reference: RootKeyReference,binding:String) throws -> RootKeyMaterial {
        loads += 1
        guard let r = records[id(reference)], r.0 == reference, r.1 == binding else { throw RootKeyError.unavailable }; return try .init(r.2)
    }
}
final class BootstrapTestFixture {
    let root: String, container: String, policy: BootstrapPolicy, provider = MemoryRootKeys()
    var factories = 0, initializations = 0
    init(policy: BootstrapPolicy? = nil) throws {
        let base = try XCTUnwrap(ProcessInfo.processInfo.environment["S85_FIXTURES"])
        root = base+"/test-"+UUID().uuidString.lowercased(); container = base+"/mock.keychain-db"; self.policy = try policy ?? .current()
    }
    deinit { try? FileManager.default.removeItem(atPath:root) }
    func factory(_ core: BootstrapCore) throws -> any RootKeyProvider { factories += 1; return provider }
    func create(hook: BootstrapHook = { _ in }) throws -> BootstrapReady {
        guard let result = try DurableStoreBootstrap.create(optIn:true,at:root,container:container,policy:policy,provider:factory,
            initializeStores:{ _,_ in
                self.initializations += 1
                for role in ["host","client"] { try FileManager.default.createDirectory(atPath:self.root+"/"+role,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]) }
            },hook:hook) else { throw BootstrapError.disabled }; return result
    }
    func acquire(_ role: BootstrapRole = .host, expected: BootstrapPolicy? = nil) throws -> BootstrapAcquisition {
        guard let result = try DurableStoreBootstrap.acquire(optIn:true,at:root,role:role,policy:expected ?? policy,provider:factory) else { throw BootstrapError.disabled }; return result
    }
    func bytes(_ name: String) throws -> Data { try Data(contentsOf:URL(fileURLWithPath:root+"/"+name)) }
    func write<T: Encodable>(_ name: String,_ value:T) throws {
        try RootKeyCodec.encode(value,limit:BootstrapLimits.record).write(to:URL(fileURLWithPath:root+"/"+name))
    }
}
final class BootstrapTests: XCTestCase {
    func testDefaultOffDoesNotTouchProviderOrStores() throws {
        let f = try BootstrapTestFixture()
        XCTAssertNil(try DurableStoreBootstrap.create(optIn:false,at:f.root,container:f.container,policy:f.policy,
            provider:f.factory,initializeStores:{ _,_ in XCTFail("off store initialization") }))
        XCTAssertNil(try DurableStoreBootstrap.acquire(optIn:false,at:f.root,role:.host,policy:f.policy,provider:f.factory))
        XCTAssertEqual(f.factories,0); XCTAssertEqual(f.provider.creates,0); XCTAssertEqual(f.provider.loads,0)
        XCTAssertFalse(FileManager.default.fileExists(atPath:f.root))
    }
    func testFreshOptInAndIndependentLoadOnlyRoleAcquisition() throws {
        let f = try BootstrapTestFixture(), selected = try f.create()
        XCTAssertEqual(f.provider.creates,3); XCTAssertEqual(f.initializations,1)
        let host = try f.acquire(), client = try f.acquire(.client)
        XCTAssertEqual(host.descriptor.core.hostID,selected.core.hostID)
        XCTAssertEqual(client.descriptor.core.clientID,selected.core.clientID)
        XCTAssertEqual(f.provider.loads,3); XCTAssertEqual(f.provider.creates,3)
        XCTAssertThrowsError(try client.keys.key(.hostTicket)); XCTAssertThrowsError(try host.keys.key(.clientMetadata))
        XCTAssertThrowsError(try f.create()); XCTAssertEqual(f.provider.creates,3)
        let fs = try BootstrapFileSystem(path:f.root,fresh:false); fs.close() // Neither acquisition retains the pair lock.
    }
    func testExistingEmptyRootCannotBecomeFreshHistory() throws {
        let f = try BootstrapTestFixture()
        try FileManager.default.createDirectory(atPath:f.root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        XCTAssertThrowsError(try f.create()); XCTAssertEqual(f.factories,0)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath:f.root).isEmpty)
    }
    func testDescriptorRefusalsPrecedeProviderFactory() throws {
        let f = try BootstrapTestFixture(), selected = try f.create()
        let factories = f.factories, intent = try f.bytes("intent.json"), ready = try f.bytes("ready.json")
        for field in ["boot","quota","policy","revision","root","role","location"] {
            var changed = selected
            switch field {
            case "boot": changed.core.policy.boot = UUID().uuidString.lowercased()
            case "quota": changed.core.policy.clientQuota += 1
            case "policy": changed.core.policy.hostClock = "fixture-ns-v1:changed"
            case "revision": changed.core.revision = "different"
            case "root": changed.core.clientID = UUID().uuidString.lowercased()
            case "role": changed.core.keys[0].role = .clientMetadata
            default: changed.core.hostLocation = "../host"
            }
            try f.write("ready.json",changed)
            XCTAssertThrowsError(try f.acquire()); XCTAssertEqual(f.factories,factories)
            try ready.write(to:URL(fileURLWithPath:f.root+"/ready.json"))
        }
        XCTAssertEqual(try f.bytes("intent.json"),intent)
        var wrongExpected = f.policy; wrongExpected.hostQuota += 1
        XCTAssertThrowsError(try f.acquire(expected:wrongExpected)); XCTAssertEqual(f.factories,factories)
    }
}
