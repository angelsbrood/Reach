import Foundation
import XCTest
import DurableRootKeys
import DurableStoreBootstrap
@testable import ReachDurableRuntime

private final class IndependentMemoryKeys: RootKeyProvider {
    var values: [String:(String,RootKeyMaterial)]=[:], created:[RootKeyRole]=[], loaded:[RootKeyRole]=[]
    func create(_ r:RootKeyReference,binding:String) throws -> RootKeyMaterial {
        guard values[r.identifier]==nil else { throw RootKeyError.duplicate }
        let key=try RootKeyMaterial(RootKeyCodec.random());values[r.identifier]=(binding,key);created.append(r.role);return key
    }
    func load(_ r:RootKeyReference,binding:String) throws -> RootKeyMaterial {
        guard let (bound,key)=values[r.identifier],bound==binding else { throw RootKeyError.unavailable };loaded.append(r.role);return key
    }
}
final class IndependentBootstrapTests:XCTestCase {
    func testRoleOnlyTransactionsAndLoadOnlyAcquisition() throws {
        for role in [BootstrapRole.host,.client] {
            let root=try ArtifactFixtures.base()+"/bootstrap-"+UUID().uuidString.lowercased()
            try LocalFiles.createDirectory(root);try LocalFiles.createDirectory(root+"/keys")
            defer { try? FileManager.default.removeItem(atPath:root) }
            let core=try RoleBootstrapCore(role:role,localID:UUID().uuidString.lowercased(),root:root,agreement:String(repeating:"a",count:64),selection:String(repeating:"b",count:64),origin:1,epoch:UUID().uuidString.lowercased(),boot:RootKeyCodec.boot(),quota:1<<30)
            let provider=IndependentMemoryKeys()
            _=try RoleBootstrapStore.create(core:core,provider:{provider},initializeStore:{ _ in try LocalFiles.createDirectory(root+"/bootstrap/"+role.rawValue) })
            let acquired=try RoleBootstrapStore.acquire(at:root,role:role,validate:{XCTAssertEqual($0,core)},provider:{_ in provider})
            XCTAssertEqual(acquired.journal,root+"/bootstrap/"+role.rawValue)
            XCTAssertEqual(provider.created,role == .host ? [.hostCatalog,.hostTicket] : [.clientMetadata]);XCTAssertEqual(provider.loaded,provider.created)
            XCTAssertFalse(FileManager.default.fileExists(atPath:root+"/bootstrap/"+(role == .host ? "client" : "host")))
            var queried=false
            XCTAssertThrowsError(try RoleBootstrapStore.acquire(at:root,role:role == .host ? .client : .host,validate:{_ in},provider:{_ in queried=true;return provider}))
            XCTAssertFalse(queried)
            XCTAssertThrowsError(try RoleBootstrapStore.create(core:core,provider:{provider},initializeStore:{_ in}))
            let path=root+"/bootstrap/ready.json",original=try Data(contentsOf:URL(fileURLWithPath:path))
            var object=try XCTUnwrap(JSONSerialization.jsonObject(with:original) as? [String:Any])
            object["confirmations"]=core.keys.map{_ in Data(repeating:0,count:32).base64EncodedString()}
            try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys,.withoutEscapingSlashes]).write(to:URL(fileURLWithPath:path))
            XCTAssertThrowsError(try RoleBootstrapStore.acquire(at:root,role:role,validate:{_ in},provider:{_ in provider}))

        }
    }
    func testPartialCreationNeverSelectsReady() throws {
        for point in [BootstrapFault.afterIntent,.afterFirstKey,.afterStores,.beforeReadyRename] {
            let root=try ArtifactFixtures.base()+"/partial-"+UUID().uuidString.lowercased()
            try LocalFiles.createDirectory(root);try LocalFiles.createDirectory(root+"/keys")
            defer { try? FileManager.default.removeItem(atPath:root) }
            let core=try RoleBootstrapCore(role:.client,localID:UUID().uuidString.lowercased(),root:root,agreement:String(repeating:"a",count:64),selection:String(repeating:"b",count:64),origin:1,epoch:UUID().uuidString.lowercased(),boot:RootKeyCodec.boot(),quota:1<<30)
            let provider=IndependentMemoryKeys()
            XCTAssertThrowsError(try RoleBootstrapStore.create(core:core,provider:{provider},initializeStore:{_ in try LocalFiles.createDirectory(root+"/bootstrap/client")},hook:{if $0==point {throw BootstrapError.invalid}}))
            XCTAssertFalse(FileManager.default.fileExists(atPath:root+"/bootstrap/ready.json"))
            XCTAssertThrowsError(try RoleBootstrapStore.acquire(at:root,role:.client,validate:{_ in},provider:{_ in provider}))
        }
    }
}
