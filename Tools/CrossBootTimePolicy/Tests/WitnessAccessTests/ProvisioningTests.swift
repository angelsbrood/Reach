import XCTest
import Foundation
import Darwin
import ClockPolicy
@testable import WitnessAccess

let second:UInt64=1_000_000_000
func uuid()->String {UUID().uuidString.lowercased()}
final class FixtureClock:PolicyClock {
    var boot=uuid(),incarnation=uuid(),now:UInt64=100*second,broken=false
    func sample() throws -> Sample {
        if broken {throw Refusal.clock}
        return Sample(boot:boot,incarnation:incarnation,nanoseconds:now)
    }
}
func refuses<E:Error & Equatable>(_ expected:E,file:StaticString=#filePath,line:UInt=#line,_ body:()throws->Void) {
    XCTAssertThrowsError(try body(),file:file,line:line) {XCTAssertEqual($0 as? E,expected,file:file,line:line)}
}
func selection(_ subject:String=uuid(),host:UInt64=100*second,client:UInt64=200*second)->PairSelection {
    PairSelection(subject:subject,hostCap:host,clientCap:client)
}
func descriptor(_ witness:Witness,_ selections:[PairSelection]) throws -> Descriptor {
    let pairs=try Provisioning.issue(selections,pin:witness.identity) {try witness.register(subject:$0,role:$1,cap:$2)}
    return try Descriptor(endpoint:"/private/tmp/qualification-only/s",uid:getuid(),identity:witness.identity,pairs:pairs)
}
func directory() throws -> String {
    let path="/private/tmp/r106-test-"+uuid();try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);return path
}

final class ProvisioningTests:XCTestCase {
    func testDuplicateSelectionsIssueExactlyOneOriginalPerRole() throws {
        let wc=FixtureClock(),w=try Witness(clock:wc),selected=selection();var calls=0
        let pairs=try Provisioning.issue([selected,selected],pin:w.identity) {calls+=1;return try w.register(subject:$0,role:$1,cap:$2)}
        XCTAssertEqual(calls,2);XCTAssertEqual(pairs.count,1)
        wc.now+=500*second
        XCTAssertEqual(try w.register(subject:selected.subject,role:.host,cap:selected.hostCap),pairs[0].host)
        XCTAssertEqual(try w.register(subject:selected.subject,role:.client,cap:selected.clientCap),pairs[0].client)
    }
    func testCompleteValidationBeforeFirstRoleAndPartialFailurePublishesNoPairs() throws {
        let w=try Witness(clock:FixtureClock()),p=selection();var calls=0
        for input in [[],[p,selection(p.subject,host:1)], [p,selection(host:0)], [p,selection(client:Profile.qualification.maximumDuration+1)], (0..<9).map {_ in selection()}] {
            XCTAssertThrowsError(try Provisioning.issue(input,pin:w.identity) {calls+=1;return try w.register(subject:$0,role:$1,cap:$2)})
            XCTAssertEqual(calls,0)
        }
        var published:[Originals]?
        refuses(AccessError.io) {
            published=try Provisioning.issue([p],pin:w.identity) {
                calls+=1;if $1 == .client {throw AccessError.io}
                return try w.register(subject:$0,role:$1,cap:$2)
            }
        }
        XCTAssertEqual(calls,2);XCTAssertNil(published)
    }
    func testEightPairsFillSixteenSlotsAndExpiryDoesNotReclaim() throws {
        let wc=FixtureClock(),w=try Witness(clock:wc),input=(0..<8).map {_ in selection(host:second,client:second)}
        let d=try descriptor(w,input);XCTAssertEqual(d.pairs.count,8)
        wc.now+=10*second
        refuses(Refusal.capacity) {_=try w.register(subject:uuid(),role:.host,cap:second)}
        let p=input[0],original=try d.select(subject:p.subject)
        XCTAssertEqual(try w.register(subject:p.subject,role:.host,cap:p.hostCap),original.host)
        refuses(Refusal.conflict) {_=try w.register(subject:p.subject,role:.host,cap:2*second)}
    }
    func testDescriptorDigestCanonicalFormBoundsAndCompletePin() throws {
        let w=try Witness(clock:FixtureClock()),p=selection(),d=try descriptor(w,[p]),bytes=try Wire.encode(d)
        XCTAssertEqual(try Descriptor.checked(bytes,expectedSHA256:Wire.digest(bytes)),d)
        refuses(AccessError.selection) {_=try Descriptor.checked(bytes,expectedSHA256:String(repeating:"0",count:64))}
        let malformed=Data("{not even JSON".utf8)
        refuses(AccessError.selection) {_=try Descriptor.checked(malformed,expectedSHA256:String(repeating:"0",count:64))}
        let large=Data(repeating:32,count:65537)
        refuses(Refusal.malformed) {_=try Descriptor.checked(large,expectedSHA256:Wire.digest(large))}
        let extra=Data(([UInt8(32)]+bytes))
        refuses(Refusal.malformed) {_=try Descriptor.checked(extra,expectedSHA256:Wire.digest(extra))}
        refuses(AccessError.selection) {_=try d.select(subject:uuid())}
        let replacement=try Witness(clock:FixtureClock())
        refuses(AccessError.selection) {_=try Descriptor(endpoint:d.endpoint,uid:d.uid,identity:replacement.identity,pairs:d.pairs)}
        var object=try XCTUnwrap(JSONSerialization.jsonObject(with:bytes) as? [String:Any])
        object["uid"]=Int(getuid())+1
        let wrong=try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys,.withoutEscapingSlashes])
        refuses(AccessError.selection) {_=try Descriptor.checked(wrong,expectedSHA256:Wire.digest(wrong))}
    }
    func testPublicFilesRejectWrongModesSymlinksOversizeAndReplacement() throws {
        let root=try directory();defer {try? FileManager.default.removeItem(atPath:root)}
        let path=root+"/selection",bytes=Data([1,2,3]);try PublicFile.writeNew(bytes,to:path)
        XCTAssertEqual(try PublicFile.read(path),bytes)
        refuses(AccessError.occupied) {try PublicFile.writeNew(Data([4]),to:path)}
        XCTAssertEqual(try PublicFile.read(path),bytes)
        try FileManager.default.createSymbolicLink(atPath:root+"/link",withDestinationPath:path)
        refuses(AccessError.path) {_=try PublicFile.read(root+"/link")}
        XCTAssertEqual(mkfifo(root+"/fifo",0o600),0)
        refuses(AccessError.permissions) {_=try PublicFile.read(root+"/fifo")}
        XCTAssertEqual(chmod(path,0o644),0)
        refuses(AccessError.permissions) {_=try PublicFile.read(path)}
        XCTAssertEqual(chmod(path,0o600),0)
        try Data(repeating:0,count:65537).write(to:URL(fileURLWithPath:path))
        refuses(AccessError.permissions) {_=try PublicFile.read(path)}
    }
    func testEndpointSyntaxModesAliasesOccupiedRootAndWrongPeerSelection() throws {
        for path in ["relative/s","/s","/private/tmp/a/../s","/private//tmp/s","/private/tmp/s\0x","/private/tmp/"+String(repeating:"x",count:100)] {
            refuses(AccessError.path) {_=try UnixEndpoint(path:path,uid:getuid())}
        }
        refuses(AccessError.path) {_=try UnixEndpoint(path:"/private/tmp/a/s",uid:getuid()+1)}
        let root=try directory();defer {try? FileManager.default.removeItem(atPath:root)}
        let endpoint=try UnixEndpoint(path:root+"/s",uid:getuid());try endpoint.validateRoot(empty:true)
        XCTAssertEqual(chmod(root,0o755),0)
        refuses(AccessError.permissions) {try endpoint.validateRoot()}
        XCTAssertEqual(chmod(root,0o700),0)
        let sentinel=root+"/sentinel";try Data([42]).write(to:URL(fileURLWithPath:sentinel))
        refuses(AccessError.occupied) {_=try endpoint.listen()}
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:sentinel)),Data([42]))
        try FileManager.default.createSymbolicLink(atPath:endpoint.path,withDestinationPath:sentinel)
        refuses(AccessError.permissions) {try endpoint.validateSocket()}
        let alias=root+"-alias";try FileManager.default.createSymbolicLink(atPath:alias,withDestinationPath:root)
        defer {try? FileManager.default.removeItem(atPath:alias)}
        refuses(AccessError.permissions) {try UnixEndpoint(path:alias+"/s",uid:getuid()).validateRoot()}
    }
}
