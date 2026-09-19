import XCTest
import Foundation
import Darwin
import CryptoKit
import DurableStoreBootstrap
@testable import ClockPolicy
import WitnessAccess
import RecoveryAuthorityContract
import ResumableMLXProvider
@testable import ReachDurableRuntime

private struct WitnessDescriptorFixture:Encodable {
    let version=1,profile=Profile.qualification,endpoint="/private/tmp/reach-native-unit/s",uid=getuid()
    let identity:Identity,pairs:[Originals]
}
private final class WitnessStepClock:PolicyClock {
    var value:Sample,reads=0,jumpAt:Int?
    init(_ value:Sample) {self.value=value}
    func sample() throws -> Sample {
        reads+=1
        if reads==jumpAt {value = .init(boot:value.boot,incarnation:value.incarnation,nanoseconds:value.nanoseconds+5_000_000_000)}
        return value
    }
}
final class NativeWitnessTests:XCTestCase {
    private func selection(_ f:NativeRecoveryFixture,pairs:[Originals]?=nil) throws -> (NativeWitnessSelection,String,String) {
        let bytes=try Wire.encode(WitnessDescriptorFixture(identity:(pairs?.first ?? f.scope.provision.originals).pin,pairs:pairs ?? [f.scope.provision.originals]))
        let path=f.base+"/descriptor-"+UUID().uuidString.lowercased();try PublicFile.writeNew(bytes,to:path)
        return (try NativeWitnessSelection(path:path,expectedSHA256:Wire.digest(bytes)),path,Wire.digest(bytes))
    }
    func testCompleteSelectionDigestSubjectAndFrozenBytes() throws {
        let f=try NativeRecoveryFixture(),(s,path,digest)=try selection(f),subject=try f.scope.provision.originals.records().host.subject
        XCTAssertNil(try NativeWitnessSelection.load(path:nil,expectedSHA256:nil))
        XCTAssertThrowsError(try NativeWitnessSelection.load(path:path,expectedSHA256:nil))
        XCTAssertThrowsError(try NativeWitnessSelection.load(path:nil,expectedSHA256:digest))
        XCTAssertThrowsError(try NativeWitnessSelection.load(path:path,expectedSHA256:String(repeating:"0",count:64)))
        XCTAssertThrowsError(try s.originals(subject:UUID().uuidString.lowercased()))
        let exact=try s.originals(subject:subject)
        XCTAssertEqual(exact,try AuthorityCodec.encode(f.scope.provision.originals))
        try Data("replacement".utf8).write(to:URL(fileURLWithPath:path))
        XCTAssertEqual(try s.originals(subject:subject),exact)
    }
    func testSamePinAndSubjectStillRequireExactSignedRegistrations() throws {
        let f=try NativeRecoveryFixture(),key=Curve25519.Signing.PrivateKey(),subject=UUID().uuidString.lowercased()
        let pin=Identity(publicKey:key.publicKey.rawRepresentation,boot:UUID().uuidString.lowercased(),incarnation:UUID().uuidString.lowercased(),epoch:UUID().uuidString.lowercased())
        func pair(_ hostCap:UInt64) throws -> Originals {
            func registration(_ role:Role,_ cap:UInt64) throws -> Data {
                try Wire.encode(Signed(Registration(domain:"reach-original-clock-registration-v1",profile:.qualification,witness:pin,subject:subject,role:role,anchor:100_000_000_000,cap:cap,deadline:100_000_000_000+cap),key:key))
            }
            return try Originals(pin:pin,host:registration(.host,hostCap),client:registration(.client,150_000_000_000))
        }
        let original=try pair(90_000_000_000),replacement=try pair(91_000_000_000),(s,_,_)=try selection(f,pairs:[replacement])
        XCTAssertEqual(original.pin,replacement.pin)
        XCTAssertEqual(try original.records().host.subject,try replacement.records().host.subject)
        XCTAssertThrowsError(try s.validate(originals:original,binding:f.provider,fixture:nil)) {XCTAssertEqual($0 as? AuthorityError,.scope)}
        try s.validate(originals:replacement,binding:f.provider,fixture:nil)
    }
    func testSamePinOtherOriginalPairRefusesBeforeTransport() throws {
        let f=try NativeRecoveryFixture(),subject=UUID().uuidString.lowercased()
        let other=try Originals(pin:f.witness.identity,host:f.witness.register(subject:subject,role:.host,cap:90_000_000_000),client:f.witness.register(subject:subject,role:.client,cap:150_000_000_000))
        let (s,_,_)=try selection(f,pairs:[other]),a=try f.owner.begin(.reopen);var transports=0
        XCTAssertThrowsError(try s.exchange(a,clock:f.receiverClock,transport:{_,_,_ in transports+=1;return Data()},report:{_ in}))
        XCTAssertEqual(transports,0);XCTAssertThrowsError(try a.check());XCTAssertThrowsError(try f.owner.begin(.advance))
    }
    func testToolProvisionRefusesBeforeModelAndRequestRead() throws {
        for route in ["required","allowed","combined"] {
            let f=try NativeRecoveryFixture(request:ArtifactFixtures.request(route,maximum:16)),(s,_,_)=try selection(f)
            let prepared=f.base+"/prepared",output=f.base+"/not-created"
            try LocalFiles.writeNew(AuthorityCodec.encode(f.scope.provision.execution!),to:prepared)
            XCTAssertThrowsError(try NativeRecoveryRoots.provision(originals:AuthorityCodec.encode(f.scope.provision.originals),publicModel:"/missing-public-model",request:"/missing-request",model:"/missing-model",prepared:prepared,output:output,witness:s)) {XCTAssertEqual($0 as? AuthorityError,.scope)}
            XCTAssertEqual(f.counter.models,0);XCTAssertFalse(FileManager.default.fileExists(atPath:output))
        }
    }
    func testFixtureRefusesAtEveryEntryBeforeCredentialsOrPaths() throws {
        let f=try NativeRecoveryFixture(),(s,_,_)=try selection(f);var loads=0
        let fixture=AllowedRecoveryQualificationFactory(load:{_ in loads+=1;throw AuthorityError.state})
        let calls:[()throws->Void]=[
            {try NativeRecoveryRoots.provision(originals:Data(),publicModel:"/missing",request:"/missing",model:"/missing",prepared:"/missing",output:"/missing",fixture:fixture,witness:s)},
            {try NativeRecoveryRuntime.admit(hostReceipt:"/missing",hostDigest:"",clientReceipt:"/missing",clientDigest:"",secretDescriptor:-1,request:"/missing",export:"/missing",fixture:fixture,witness:s)},
            {try NativeRecoveryRuntime.accept(hostReceipt:"/missing",hostDigest:"",clientReceipt:"/missing",clientDigest:"",secretDescriptor:-1,export:"/missing",originalIssuer:Data(),successfulExportDigest:"",fixture:fixture,witness:s)},
            {try NativeRecoveryRuntime.run(hostReceipt:"/missing",hostDigest:"",clientReceipt:"/missing",clientDigest:"",hostSecret:-1,clientSecret:-1,original:false,stopAfterCalls:0,leaveHostAhead:false,report:"/missing",fault:"none",fixture:fixture,witness:s)}]
        for call in calls {XCTAssertThrowsError(try call()) {XCTAssertEqual($0 as? AuthorityError,.scope)}}
        XCTAssertEqual(loads,0)
    }
    func testMetadataRouteRefusalPrecedesCredentialsAtExecutableEntries() throws {
        let f=try NativeRecoveryFixture(request:ArtifactFixtures.request("required",maximum:16)),(s,_,_)=try selection(f)
        let h=try LifecycleFixture(role:.host,unlock:true,authority:f.scope.provision),c=try LifecycleFixture(unlock:true,authority:f.scope.provision)
        let hd=try XCTUnwrap(h.digest),cd=try XCTUnwrap(c.digest)
        let checks:[()throws->Void]=[
            {try NativeRecoveryRuntime.admit(hostReceipt:h.receipt,hostDigest:hd,clientReceipt:c.receipt,clientDigest:cd,secretDescriptor:-1,request:"/missing",export:"/missing",witness:s)},
            {try NativeRecoveryRuntime.accept(hostReceipt:h.receipt,hostDigest:hd,clientReceipt:c.receipt,clientDigest:cd,secretDescriptor:-1,export:"/missing",originalIssuer:Data(),successfulExportDigest:"",witness:s)},
            {try NativeRecoveryRuntime.run(hostReceipt:h.receipt,hostDigest:hd,clientReceipt:c.receipt,clientDigest:cd,hostSecret:-1,clientSecret:-1,original:false,stopAfterCalls:0,leaveHostAhead:false,report:"/missing",fault:"none",witness:s)}]
        for check in checks {XCTAssertThrowsError(try check()) {XCTAssertEqual($0 as? AuthorityError,.scope)}}
        XCTAssertEqual(h.provider.loads,0);XCTAssertEqual(c.provider.loads,0)
        // No selection leaves the old pipe entry path in control of metadata.
        try NativeRecoveryRoots.validateWitness(nil,hostReceipt:"/missing",hostDigest:"",clientReceipt:"/missing",clientDigest:"",fixture:nil)
    }
    func testOrdinaryAndCanonicalSchemaSelectionsUseAuthenticatedOriginalMetadata() throws {
        for route in ["ordinary","guided"] {
            let f=try NativeRecoveryFixture(request:ArtifactFixtures.request(route,maximum:route == "guided" ? 32 : 16)),(s,_,_)=try selection(f)
            XCTAssertEqual(try AuthorityCodec.encode(s.validate(f.scope.provision,fixture:nil)),try AuthorityCodec.encode(f.provider))
            let h=try LifecycleFixture(role:.host,unlock:true,authority:f.scope.provision),c=try LifecycleFixture(unlock:true,authority:f.scope.provision)
            let hd=try XCTUnwrap(h.digest),cd=try XCTUnwrap(c.digest)
            try NativeRecoveryRoots.validateWitness(s,hostReceipt:h.receipt,hostDigest:hd,clientReceipt:c.receipt,clientDigest:cd,fixture:nil)
            if route == "guided" {
                try NativeRecoveryRoots.validateWitness(s,hostReceipt:h.receipt,hostDigest:hd,clientReceipt:c.receipt,clientDigest:cd,fixture:nil,stopWithPendingGuided:true)
            }
            XCTAssertThrowsError(try NativeRecoveryRoots.validateWitness(s,hostReceipt:h.receipt,hostDigest:String(repeating:"0",count:64),clientReceipt:c.receipt,clientDigest:cd,fixture:nil,stopWithPendingGuided:true))
            XCTAssertEqual(h.provider.loads,0);XCTAssertEqual(c.provider.loads,0);XCTAssertEqual(f.counter.models,0)
        }
    }
    func testGuidedTagDoesNotAdmitOtherKindsOrNoncanonicalSchema() throws {
        let f=try NativeRecoveryFixture(request:ArtifactFixtures.request("guided",maximum:32)),(s,_,_)=try selection(f)
        let encoded=String(decoding:try ArtifactFixtures.encode(f.provider),as:UTF8.self)
        XCTAssertTrue(encoded.contains("\"kind\":\"json-schema\""))
        for kind in ["structural-tag","literal-fixture","unknown-kind"] {
            let bytes=Data(encoded.replacingOccurrences(of:"\"kind\":\"json-schema\"",with:"\"kind\":\""+kind+"\"").utf8)
            let binding=try JSONDecoder().decode(ProviderBinding.self,from:bytes)
            XCTAssertThrowsError(try s.validate(originals:f.scope.provision.originals,binding:binding,fixture:nil))
        }
        guard case .guided(let original)=f.provider.lane else {return XCTFail("schema fixture")}
        var lane=original;lane.specification.source=" "+lane.specification.source
        var binding=f.provider;binding.lane = .guided(lane)
        XCTAssertThrowsError(try s.validate(originals:f.scope.provision.originals,binding:binding,fixture:nil))
        XCTAssertEqual(f.counter.models,0)
    }
    func testPendingGuidedOnOrdinaryRefusesBeforeLeasesAndCredentialConsumption() throws {
        let f=try NativeRecoveryFixture(),(s,_,_)=try selection(f)
        let h=try LifecycleFixture(role:.host,unlock:true,authority:f.scope.provision),c=try LifecycleFixture(unlock:true,authority:f.scope.provision)
        let (_,hostLease)=try RoleLifecycleLease.selectNativeRecovery(receipt:h.receipt,expectedDigest:XCTUnwrap(h.digest))
        let (_,clientLease)=try RoleLifecycleLease.selectNativeRecovery(receipt:c.receipt,expectedDigest:XCTUnwrap(c.digest))
        defer {hostLease.close();clientLease.close()}
        let secret=f.base+"/unconsumed-secret",report=f.base+"/not-created"
        try LocalFiles.writeNew(Data(repeating:65,count:64),to:secret)
        let fd=open(secret,O_RDONLY|O_NOFOLLOW);XCTAssertGreaterThanOrEqual(fd,0);defer {close(fd)}
        XCTAssertThrowsError(try NativeRecoveryRuntime.run(hostReceipt:h.receipt,hostDigest:XCTUnwrap(h.digest),clientReceipt:c.receipt,clientDigest:XCTUnwrap(c.digest),hostSecret:fd,clientSecret:fd,original:false,stopAfterCalls:0,leaveHostAhead:true,report:report,fault:"none",stopWithPendingGuided:true,witness:s)) {XCTAssertEqual($0 as? AuthorityError,.scope)}
        XCTAssertEqual(lseek(fd,0,SEEK_CUR),0);XCTAssertFalse(FileManager.default.fileExists(atPath:report))
        XCTAssertEqual(h.provider.loads,0);XCTAssertEqual(c.provider.loads,0);XCTAssertEqual(f.counter.models,0)
    }
    func testUnsupportedSocketOptionsRefuseBeforeReceiptAndCredentialAccess() throws {
        for route in ["ordinary","guided"] {
            let f=try NativeRecoveryFixture(request:ArtifactFixtures.request(route,maximum:16)),(s,_,_)=try selection(f)
            for options in [("generating","none",false,"none"),("none","guided",false,"none"),("none","none",true,"none"),("none","none",false,"after-next-pass-native")] {
                XCTAssertThrowsError(try NativeRecoveryRuntime.run(hostReceipt:"/missing",hostDigest:"",clientReceipt:"/missing",clientDigest:"",hostSecret:-1,clientSecret:-1,original:false,stopAfterCalls:0,leaveHostAhead:false,report:"/missing",fault:options.3,stopWithPendingGuided:route == "guided",requiredBoundary:options.0,duplicateExact:options.2,allowedBoundary:options.1,witness:s)) {XCTAssertEqual($0 as? AuthorityError,.scope)}
            }
            XCTAssertEqual(f.counter.models,0)
        }
    }
    func testGuidedReceiptsStillRequireTheExactPairAndMatchingProvisions() throws {
        let f=try NativeRecoveryFixture(request:ArtifactFixtures.request("guided",maximum:32)),g=try NativeRecoveryFixture(request:ArtifactFixtures.request("guided",maximum:32))
        let (s,_,_)=try selection(f),(other,_,_)=try selection(g)
        let h=try LifecycleFixture(role:.host,unlock:true,authority:f.scope.provision),c=try LifecycleFixture(unlock:true,authority:f.scope.provision),wrong=try LifecycleFixture(unlock:true,authority:g.scope.provision)
        XCTAssertThrowsError(try NativeRecoveryRoots.validateWitness(other,hostReceipt:h.receipt,hostDigest:XCTUnwrap(h.digest),clientReceipt:c.receipt,clientDigest:XCTUnwrap(c.digest),fixture:nil,stopWithPendingGuided:true))
        XCTAssertThrowsError(try NativeRecoveryRoots.validateWitness(s,hostReceipt:h.receipt,hostDigest:XCTUnwrap(h.digest),clientReceipt:wrong.receipt,clientDigest:XCTUnwrap(wrong.digest),fixture:nil,stopWithPendingGuided:true)) {XCTAssertEqual($0 as? AuthorityError,.scope)}
        XCTAssertEqual(h.provider.loads+c.provider.loads+wrong.provider.loads,0)
    }
    func testOriginalR0AndSameOwnerCapacityAcrossRenewals() throws {
        for route in ["ordinary","guided"] {
        let f=try NativeRecoveryFixture(request:ArtifactFixtures.request(route,maximum:16)),(s,_,_)=try selection(f)
        var nonces=Set<String>(),reports=0
        for _ in 0..<64 {
            let a=try f.owner.begin(.advance),sent=a.clockAction.sent
            f.receiverClock.advance(1)
            try s.exchange(a,clock:f.receiverClock,transport:{request,_,deadline in
                XCTAssertEqual(request,a.request);XCTAssertEqual(deadline.start,sent)
                XCTAssertTrue(nonces.insert(try XCTUnwrap((JSONSerialization.jsonObject(with:request) as? [String:Any])?["nonce"] as? String)).inserted)
                return try f.witness.respond(to:request)
            },report:{r in reports+=1;XCTAssertTrue(r.accepted);XCTAssertEqual(r.sent,sent)})
            let e=try a.check();XCTAssertEqual(e.r0,sent);try a.finish();XCTAssertThrowsError(try a.check())
        }
        XCTAssertEqual(reports,64);XCTAssertEqual(f.owner.actionCount,64);XCTAssertThrowsError(try f.owner.begin(.delivery))
        }
    }
    func testOriginalR0IncludesDelayBeforeConnect() throws {
        let f=try NativeRecoveryFixture(),(s,_,_)=try selection(f),a=try f.owner.begin(.reopen);var calls=0
        f.receiverClock.advance(5_000_000_000)
        XCTAssertThrowsError(try s.exchange(a,clock:f.receiverClock,transport:{_,_,_ in calls+=1;return Data()},report:{_ in}))
        XCTAssertEqual(calls,0);XCTAssertThrowsError(try a.check())
    }
    func testVerificationTimeIsInsideTransportBudgetAndLatches() throws {
        let f=try NativeRecoveryFixture(),(s,_,_)=try selection(f),clock=WitnessStepClock(f.receiverClock.value)
        let owner=try GenerationAuthorityOwner(scope:f.scope,clock:clock),a=try owner.begin(.reopen)
        XCTAssertThrowsError(try s.exchange(a,clock:clock,transport:{request,_,_ in
            clock.jumpAt=clock.reads+2 // post-I/O check then Verifier r1, after signature validation
            return try f.witness.respond(to:request)
        },report:{r in XCTAssertFalse(r.accepted)}))
        XCTAssertThrowsError(try a.check());XCTAssertThrowsError(try owner.begin(.advance))
    }
    func testAmbiguousMalformedWrongPinAndClockFailuresLatchExistingOwner() throws {
        for failure in 0..<4 {
            let f=try NativeRecoveryFixture(),(s,_,_)=try selection(f),a=try f.owner.begin(.reopen)
            XCTAssertThrowsError(try s.exchange(a,clock:f.receiverClock,transport:{request,_,_ in
                switch failure {
                case 0:throw AccessError.io
                case 1:return Data("invalid".utf8)
                case 2:let g=try NativeRecoveryFixture(),b=try g.owner.begin(.reopen);return try g.witness.respond(to:b.request)
                default:let response=try f.witness.respond(to:request);f.receiverClock.value = .init(boot:UUID().uuidString.lowercased(),incarnation:f.receiverClock.value.incarnation,nanoseconds:f.receiverClock.value.nanoseconds);return response
                }
            },report:{r in XCTAssertFalse(r.accepted)}))
            XCTAssertThrowsError(try a.check());XCTAssertThrowsError(try a.finish());XCTAssertThrowsError(try f.owner.begin(.advance))
        }
    }
    func testSocketControlsCannotAffirmWitnessAndCompletedActionKeepsAgeLimit() throws {
        let f=try NativeRecoveryFixture(),(s,_,_)=try selection(f),a=try f.owner.begin(.advance)
        try s.exchange(a,clock:f.receiverClock,transport:{request,_,_ in try f.witness.respond(to:request)},report:{_ in})
        XCTAssertThrowsError(try NativeWitnessAccess.continueAction("observe",action:a,selection:s)) {XCTAssertEqual($0 as? AuthorityError,.state)}
        XCTAssertThrowsError(try NativeWitnessAccess.continueAction("certificate",action:a,selection:s))
        try NativeWitnessAccess.continueAction("continue",action:a,selection:s)
        f.receiverClock.advance(10_000_000_001)
        XCTAssertThrowsError(try NativeWitnessAccess.continueAction("continue",action:a,selection:s))
    }
}
