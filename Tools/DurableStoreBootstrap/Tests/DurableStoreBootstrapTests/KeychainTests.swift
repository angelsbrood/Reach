import XCTest
import Foundation
import DurableRootKeys
import DurableStoreBootstrap

// Contract/fault supplements. Real OS behavior is executed by the scoped worker cell.
final class KeychainTests: XCTestCase {
    func testRoleAndMaterialConfirmationsAreIndependent() throws {
        let f = try BootstrapTestFixture(), ready = try f.create(), binding = try ready.core.binding()
        let a = ready.core.keys[0], b = ready.core.keys[1]
        let key = try f.provider.load(a,binding:binding)
        XCTAssertThrowsError(try key.confirm(ready.confirmations[1],reference:b,binding:binding))
        XCTAssertThrowsError(try key.confirm(ready.confirmations[0],reference:a,binding:String(repeating:"0",count:64)))
        XCTAssertThrowsError(try f.provider.create(a,binding:binding))
    }
    func testCorrectlyLabelledTicketKeyReplacementRefuses() throws {
        let f = try BootstrapTestFixture(), ready = try f.create(), reference = ready.core.keys[1]
        let id = f.provider.id(reference), original = try XCTUnwrap(f.provider.records[id])
        f.provider.records[id] = (original.0,original.1,try RootKeyCodec.random())
        let before = f.provider.creates
        XCTAssertThrowsError(try f.acquire(.host)); XCTAssertEqual(f.provider.creates,before)
        XCTAssertNoThrow(try f.acquire(.client))
    }
    func testMissingHostKeyDoesNotBlockClientAcquisition() throws {
        let f = try BootstrapTestFixture(), ready = try f.create()
        f.provider.records.removeValue(forKey:f.provider.id(ready.core.keys[0]))
        XCTAssertThrowsError(try f.acquire(.host))
        XCTAssertEqual(try f.acquire(.client).descriptor.core.clientID,ready.core.clientID)
        XCTAssertEqual(f.provider.creates,3)
    }
}
