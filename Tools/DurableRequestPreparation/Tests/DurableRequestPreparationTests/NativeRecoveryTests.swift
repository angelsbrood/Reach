import Foundation
import XCTest
import ReachWire
import RequestPreparationFixtures
import RequestPreparationContract

final class NativeRecoveryTests:XCTestCase {
    func testNativePrefillConsumesActualPreparedTokens() throws { try withNative {
        for route in ["ordinary","required"] {
            let f=try pair();defer { try? f.remove() };try f.start(PreparationFixtures.request(route))
            let prepared=f.native.preparer.lastTokens
            for _ in 0..<10 { try f.step();if f.native.model.calls>0 { break } }
            XCTAssertGreaterThan(f.native.model.calls,0);XCTAssertEqual(f.native.model.prepares,0)
            let actual=Array(f.native.model.inputs.flatMap{$0}.prefix(prepared.count))
            XCTAssertEqual(actual,prepared);XCTAssertNotEqual(prepared,[1,2,3,4,5]);XCTAssertNotNil(f.native.model.llama)
        }
    } }
    func testExplicitZeroGeneratesNoNativeForwardWork() throws { try withNative {
        let f=try pair();defer { try? f.remove() };var request=try PreparationFixtures.request("ordinary",maximum:0);request.options.sampling = .greedy
        try f.start(request)
        for _ in 0..<10 { if f.terminal { break };try f.step() }
        XCTAssertTrue(f.terminal);XCTAssertEqual(f.native.model.calls,0);XCTAssertEqual(f.native.preparer.preparations,1)
    } }
    func testCompatibleDiskRecoveryDoesNotRenderOrPrepareAgain() throws { try withNative {
        let original=try pair(),root=original.root;try original.start(PreparationFixtures.request("ordinary"));try original.step()
        let binding=try original.stored(),accepted=original.accepted;original.close()
        let fresh=try PreparationPair(root:root,fresh:false);defer { try? fresh.remove() };try fresh.recover();try fresh.step()
        XCTAssertEqual(fresh.accepted?.context,accepted?.context)
        XCTAssertEqual(try PreparationEncoding.encode(fresh.stored()),try PreparationEncoding.encode(binding))
        XCTAssertEqual(fresh.native.preparer.preparations,0);XCTAssertEqual(fresh.native.tokenizer.renders,0);XCTAssertEqual(fresh.native.model.prepares,0)
        XCTAssertEqual(fresh.native.tokenizer.encodes,0)
        XCTAssertEqual(fresh.host.issues,0);XCTAssertEqual(fresh.host.begins,0);XCTAssertGreaterThan(fresh.native.model.calls,0)
    } }
}
