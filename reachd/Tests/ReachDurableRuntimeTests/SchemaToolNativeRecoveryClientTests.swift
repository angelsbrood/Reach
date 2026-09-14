import XCTest
import Foundation
import CryptoKit
import ReachWire
import ResumableMLXProvider
import RecoveryAuthorityContract
import HostClientContract
@testable import ReachDurableRuntime
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts

final class SchemaToolNativeRecoveryClientTests:XCTestCase {
    private func callEvents(_ f:NativeRecoveryFixture) throws -> [WireEvent] {
        guard case .allowed(let b)=f.provider.lane else {throw AuthorityError.state}
        return [.toolCallAppendArguments(entryID:b.entryID,id:"selected-proposal",name:b.tools[0].name,content:"{\"n\":7}",tokenCount:1),
            .usage(inputTokens:b.originalTokens.count+350,outputTokens:83),.finished(.complete)]
    }
    private func frame(_ events:[WireEvent],first:UInt64=1) throws -> ReplayEnvelope {
        .init(firstSequence:first,count:events.count,providerCommit:String(repeating:first==1 ? "e" : "f",count:64),eventBytes:try ClientEvents.encode(events))
    }
    func testCombinedCallAfterResponseRefusesBeforeWritesAndAfterReopen() throws {
        let f=try NativeRecoveryFixture(request:SchemaToolNativeTestRun.request());_=try f.provision()
        var a=try f.action(.reopen),c=try f.openClient(a)
        try c.accept(frame([.responseAppend(entryID:nil,text:"{",segmentID:nil,tokenCount:1)]),action:a)
        let before=try f.hashes()
        XCTAssertThrowsError(try c.accept(frame(callEvents(f),first:2),action:a));XCTAssertEqual(try f.hashes(),before)
        c.close();try a.finish();a=try f.action(.reopen);c=try f.openClient(a);defer {c.close();try? a.finish()}
        let reopened=try f.hashes()
        XCTAssertThrowsError(try c.accept(frame(callEvents(f),first:2),action:a));XCTAssertEqual(try f.hashes(),reopened)
        XCTAssertEqual(try c.witness(action:a).registrations,0)
    }
    func testSchemaSuccessUsageAndPartialErrorShapesAreClosed() throws {
        for failure in [false,true] {
            let f=try NativeRecoveryFixture(request:SchemaToolNativeTestRun.request());_=try f.provision()
            let a=try f.action(.reopen),c=try f.openClient(a);defer {c.close();try? a.finish()}
            guard case .allowed(let b)=f.provider.lane else {return XCTFail("allowed")}
            let response=WireEvent.responseAppend(entryID:nil,text:"{",segmentID:nil,tokenCount:1)
            let usage=WireEvent.usage(inputTokens:2*b.originalTokens.count,outputTokens:80)
            let malformed:[[WireEvent]]=[
                [.usage(inputTokens:b.originalTokens.count,outputTokens:64),.finished(.complete)],
                [.usage(inputTokens:2*b.originalTokens.count,outputTokens:128),.finished(.complete)],
                [response,.finished(.cancelled)],[response,.finished(.complete)],
                [response,usage,.finished(.error("incomplete"))],
                [response,.finished(.error("incomplete")),response],
                [.finished(.error("incomplete")),.finished(.error("extra"))]]
            let before=try f.hashes()
            for events in malformed {XCTAssertThrowsError(try c.accept(frame(events),action:a));XCTAssertEqual(try f.hashes(),before)}
            if failure {try c.accept(frame([response,.finished(.error("incomplete"))]),action:a)}
            else {try c.accept(frame([response]),action:a);try c.accept(frame([usage,.finished(.complete)],first:2),action:a)}
            let receipt=try c.witness(action:a);XCTAssertTrue(receipt.terminal);XCTAssertEqual(receipt.registrations,0)
        }
    }
    func testOriginalResponseSchemaProjectionRejectsMalformedProvenance() throws {
        let f=try NativeRecoveryFixture(request:SchemaToolNativeTestRun.request()),a=try f.provision()
        let context=try JSONDecoder().decode(ClientContext.self,from:a.context)
        let original=try AuthorityCodec.encode(f.provider)
        let good=try NativeRecoveryPrefix(context:a.context,provider:original,providerDigest:AuthorityCodec.hash(original),request:context.request,operation:context.operation,route:context.route)
        XCTAssertNotNil(good.allowed?.responseSchema)
        for value:Any in [NSNull(),42," {\"type\":\"string\"}"] {
            var root=try JSONSerialization.jsonObject(with:original) as! [String:Any]
            var lane=root["lane"] as! [String:Any],selected=lane["allowed"] as! [String:Any],b=selected["_0"] as! [String:Any]
            b["responseSchema"]=value;selected["_0"]=b;lane["allowed"]=selected;root["lane"]=lane
            let bytes=try JSONSerialization.data(withJSONObject:root,options:[.sortedKeys,.withoutEscapingSlashes])
            XCTAssertThrowsError(try NativeRecoveryPrefix(context:a.context,provider:bytes,providerDigest:AuthorityCodec.hash(bytes),request:context.request,operation:context.operation,route:context.route))
        }
    }
    func testPersistedNativeCountIntentOutcomeAndSchemaProvenanceRefuse() throws {
        for variant in ["count","intent","outcome","schema"] {
            let f=try NativeRecoveryFixture(request:SchemaToolNativeTestRun.request());_=try f.provision()
            var a=try f.action(.reopen);let c=try f.openClient(a);try c.accept(frame(callEvents(f)),action:a);c.close();try a.finish()
            a=try f.action(.reopen)
            let fs=try ClientFileSystem(path:f.client+"/bootstrap/client",create:false),key=SymmetricKey(data:f.clientKey)
            var m=try DurableClientReceipts.readNativeManifest(fs,environment:f.clientEnvironment,key:key,action:a)
            var live=m.records[0].live!
            let (bytes,originalFrame)=try ClientCrypto.open(fs.read(live.snapshot.name),role:"snapshot",environment:f.clientEnvironment,key:SymmetricKey(data:live.key),rootKey:key)
            var s=try JSONDecoder().decode(ClientSnapshot.self,from:bytes)
            if variant=="count" { live.calls=0 }
            else if variant=="schema" {
                // Noncanonical schema bytes refuse even with a matching supplied
                // digest. The signed original still binds the immutable provider.
                guard case .allowed(var b)=f.provider.lane else { throw AuthorityError.state }
                b.tools[0].schemaJSON=" "+b.tools[0].schemaJSON
                var p=f.provider;p.lane = .allowed(b)
                let provider=try AuthorityCodec.encode(p),context=try AuthorityCodec.decode(ClientContext.self,s.context)
                XCTAssertThrowsError(try NativeRecoveryPrefix(context:s.context,provider:provider,providerDigest:AuthorityCodec.hash(provider),request:context.request,operation:context.operation,route:context.route))
                // Persist another original context request under the same signed
                // acceptance. ClientAuthority shape alone would permit this.
                var changed=try JSONSerialization.jsonObject(with:s.context) as! [String:Any];changed["request"]="replacement-request"
                s.context=try JSONSerialization.data(withJSONObject:changed,options:[.sortedKeys,.withoutEscapingSlashes])
            } else {
                s.calls[0].intent=true
                if variant=="outcome" {
                    let binding=try s.calls[0].binding(),result=Data("unexecuted-test-record".utf8)
                    let context=try ClientAuthority(JSONDecoder().decode(ClientContext.self,from:s.context),retention:live.retention)
                    let outcome=try ClientOutcome.make(kind:.success,result:result,binding:binding,authority:context)
                    s.calls[0].outcome=try ArtifactFixtures.encode(outcome)
                }
                try s.calls[0].validate(context:s.context) // Generic effect storage would accept it.
            }
            let encrypted=try ClientCrypto.seal(ArtifactFixtures.encode(s),role:"snapshot",record:originalFrame.record,generation:originalFrame.generation,revision:originalFrame.revision,environment:f.clientEnvironment,key:SymmetricKey(data:live.key),rootKey:key)
            try encrypted.write(to:URL(fileURLWithPath:f.client+"/bootstrap/client/"+live.snapshot.name))
            live.snapshot.digest=crHash(encrypted);live.snapshot.length=encrypted.count;live.futureBytes=try s.maximumFutureBytes();m.records[0].live=live
            try DurableClientReceipts.selectNativeManifest(m,fs:fs,environment:f.clientEnvironment,key:key,check:{})
            fs.close();try a.finish();a=try f.action(.reopen)
            XCTAssertThrowsError(try f.openClient(a));try a.finish()
        }
    }
    func testForgedReceiptCountDigestTerminalAndRetainedReopenRefuse() throws { try LocalDurableRuntime.withCPU {
        let run=try SchemaToolNativeTestRun(maximum:32);try run.advance(to:"finalEmitted")
        let f=run.fixture,receipt=try run.client.witness(action:run.action)
        XCTAssertEqual(receipt.registrations,0)
        var bad:[HandoffWitness]=[]
        for index in 0..<5 {
            var w=receipt
            switch index {case 0:w.registrations=1;case 1:w.registrations=2;case 2:w.calls=String(repeating:"f",count:64);case 3:w.terminal=false;default:w.prefix=String(repeating:"f",count:64)}
            bad.append(w)
        }
        let before=try f.hashes()
        for w in bad {XCTAssertThrowsError(try run.host.acceptReceipt(w,action:run.action));XCTAssertEqual(try f.hashes(),before)}
        run.generation.close();run.host.close();run.client.close();try run.action.finish()
        for w in bad {
            let fs=try LifecycleFileSystem(path:f.host+"/bootstrap/host",create:false)
            var d=try LifecycleCatalog.read(fs,identity:f.hostIdentity,keys:f.hostKeys);d.nativeReceipt=w
            try DurableSessionLifecycle.selectNativeCatalog(d,files:fs,identity:f.hostIdentity,keys:f.hostKeys,check:{})
            fs.close();run.action=try f.action(.reopen,owner:run.owner)
            XCTAssertThrowsError(try f.openHost(run.action));try run.action.finish()
        }
    } }
}
