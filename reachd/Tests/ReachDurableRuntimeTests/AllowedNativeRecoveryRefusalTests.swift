import XCTest
import Foundation
import CryptoKit
import MLX
import ReachWire
import ResumableMLXProvider
import RecoveryAuthorityContract
import HostClientContract
@testable import ReachDurableRuntime
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts

final class AllowedNativeRecoveryRefusalTests:XCTestCase {
    private func callEvents(_ f:NativeRecoveryFixture) throws -> [WireEvent] {
        guard case .allowed(let b)=f.provider.lane else { throw AuthorityError.state }
        return [.toolCallAppendArguments(entryID:b.entryID,id:"selected-proposal",name:b.tools[0].name,content:"{\"n\":7}",tokenCount:1),
            .usage(inputTokens:b.originalTokens.count+350,outputTokens:83),.finished(.complete)]
    }
    private func frame(_ events:[WireEvent],first:UInt64=1,skip:Int=0) throws -> ReplayEnvelope {
        .init(firstSequence:first,count:events.count,providerCommit:String(repeating:first==1 ? "e" : "f",count:64),eventBytes:try ClientEvents.encode(events),skipPrefix:skip)
    }
    func testProseThenWholeCallRejectsMalformedAndConflictingFramesBeforeWrites() throws {
        let f=try NativeRecoveryFixture(request:AllowedNativeTestProfile.request());_=try f.provision()
        let a=try f.action(.reopen),c=try f.openClient(a);defer { c.close();try? a.finish() }
        try c.accept(frame([.responseAppend(entryID:nil,text:"P",segmentID:nil,tokenCount:1)]),action:a)
        let good=try callEvents(f),before=try f.hashes()
        guard case .toolCallAppendArguments(let entry,let id,let name,let arguments,_)=good[0] else { return XCTFail("call") }
        let malformed:[[WireEvent]]=[
            [good[0]],Array(good.prefix(2)),[good[0],good[0],good[1],good[2]],
            [.responseAppend(entryID:nil,text:"mixed",segmentID:nil,tokenCount:1)]+good,
            [.toolCallAppendArguments(entryID:"wrong",id:id,name:name,content:arguments,tokenCount:1),good[1],good[2]],
            [.toolCallAppendArguments(entryID:entry,id:"",name:name,content:arguments,tokenCount:1),good[1],good[2]],
            [.toolCallAppendArguments(entryID:entry,id:id,name:"unoffered",content:arguments,tokenCount:1),good[1],good[2]],
            [.toolCallAppendArguments(entryID:entry,id:id,name:name,content:arguments,tokenCount:2),good[1],good[2]],
            [good[0],.usage(inputTokens:1,outputTokens:83),good[2]],
            [good[0],.usage(inputTokens:789,outputTokens:128),good[2]],
            [good[0],good[1],.finished(.cancelled)],
            [.toolCallAppendArguments(entryID:entry,id:id,name:name,content:"{\"n\":",tokenCount:1),good[1],good[2]]]
        for events in malformed { XCTAssertThrowsError(try c.accept(frame(events,first:2),action:a));XCTAssertEqual(try f.hashes(),before) }
        XCTAssertThrowsError(try c.accept(frame(good,first:2,skip:1),action:a));XCTAssertEqual(try f.hashes(),before)
        let exact=try frame(good,first:2);try c.accept(exact,action:a)
        let receipt=try c.witness(action:a),after=try f.hashes();XCTAssertEqual(receipt.registrations,1)
        try c.accept(exact,action:a);XCTAssertEqual(try c.witness(action:a),receipt);XCTAssertEqual(try f.hashes(),after)
        let conflicting=[WireEvent.toolCallAppendArguments(entryID:entry,id:"other-proposal",name:name,content:arguments,tokenCount:1),good[1],good[2]]
        XCTAssertThrowsError(try c.accept(frame(conflicting,first:2),action:a));XCTAssertThrowsError(try c.accept(frame(good,first:5),action:a))
        XCTAssertEqual(try f.hashes(),after)
    }
    func testForeignOwnerWrongOperationAndStaleNextPassRefuse() throws { try LocalDurableRuntime.withCPU {
        for point in [StoreFaultPoint.afterNativeBeforeCommit,.afterCommitBeforeAck] {
            let run=try AllowedNativeTestRun(profile:AllowedNativeTestProfile());try run.advance(to:"routeReady")
            let beforeCalls=run.profile.calls,receipt=try run.client.witness(action:run.action),selected=try run.host.store.snapshot().candidate!.commit
            try run.action.finish()
            let foreignOwner=try GenerationAuthorityOwner(scope:run.fixture.scope,clock:run.fixture.receiverClock)
            let foreign=try run.fixture.action(.advance,owner:foreignOwner);try foreign.bindAuthenticated(run.original)
            XCTAssertThrowsError(try run.generation.allowedProgress(action:foreign));XCTAssertThrowsError(try run.generation.advance(action:foreign));try foreign.finish()
            let wrong=try run.fixture.action(.delivery,owner:run.owner);XCTAssertThrowsError(try run.generation.advance(action:wrong));try wrong.finish()
            XCTAssertEqual(run.profile.calls,beforeCalls)
            run.action=try run.fixture.action(.advance,owner:run.owner)
            run.host.store.fault={p in if p==point {run.fixture.receiverClock.advance(10_000_000_001)}}
            XCTAssertThrowsError(try run.generation.advance(action:run.action));XCTAssertEqual(run.profile.calls-beforeCalls,2)
            XCTAssertThrowsError(try run.client.witness(action:run.action));try run.action.finish()
            run.action=try run.fixture.action(.reopen,owner:run.owner);try run.host.store.authorize(run.action)
            XCTAssertEqual(try run.host.store.reconcile().candidate!.commit==selected,point == .afterNativeBeforeCommit)
            XCTAssertEqual(try run.client.witness(action:run.action),receipt);XCTAssertEqual(receipt.registrations,0)
            run.host.store.fault={_ in} // Release the test-only closure's owner cycle.
        }
    } }
    func testForgedReceiptCountDigestTerminalAndRetainedReopenRefuse() throws { try LocalDurableRuntime.withCPU {
        let run=try AllowedNativeTestRun(profile:AllowedNativeTestProfile());try run.advance(to:"finalEmitted")
        let f=run.fixture,receipt=try run.client.witness(action:run.action)
        XCTAssertEqual(receipt.registrations,1)
        var bad:[HandoffWitness]=[]
        for index in 0..<5 {
            var w=receipt
            switch index {case 0:w.registrations=0;case 1:w.registrations=2;case 2:w.calls=String(repeating:"f",count:64);case 3:w.terminal=false;default:w.prefix=String(repeating:"f",count:64)}
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
    func testOriginalProviderAndNormalFixtureSelectionRemainClosed() throws { try LocalDurableRuntime.withCPU {
        let p=try AllowedNativeTestProfile(),f=try NativeRecoveryFixture(prepared:p.binding()),before=try f.hashes(),a=try f.action(.admitHost)
        defer {try? a.finish()}
        var replacement=f.provider;replacement.operationID="replacement"
        XCTAssertThrowsError(try DurableSessionLifecycle.admitNativeRecovery(at:f.host+"/bootstrap/host",identity:f.hostIdentity,keys:f.hostKeys,scope:f.scope,caller:f.caller,provider:replacement,action:a))
        XCTAssertEqual(try f.hashes(),before)
        let model=IndependentPublicModel(descriptor:p.native.preparer.policy.descriptor,artifactDigest:p.native.manifestDigest)
        let provision=try AuthorityProvision(originals:f.scope.provision.originals,hostID:f.scope.host.localID,clientID:f.scope.client.localID,
            publicModelDigest:AuthorityCodec.digest(model),requestInputDigest:String(repeating:"b",count:64),execution:f.scope.provision.execution!)
        let config=NativeConfiguration(version:2,profile:AuthorityCodec.nativeProfile,provision:provision,model:model,artifactPath:f.base)
        XCTAssertThrowsError(try config.validate());XCTAssertNoThrow(try config.validate(selection:.allowedFixture))
        XCTAssertEqual(config.profile,AuthorityCodec.nativeProfile)
    } }
    func testPersistedNativeCountIntentOutcomeAndSchemaProvenanceRefuse() throws {
        for variant in ["count","intent","outcome","schema"] {
            let f=try NativeRecoveryFixture(request:AllowedNativeTestProfile.request());_=try f.provision()
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
    func testLegacyEffectAPIsRefuseAllowedNativeAuthority() throws {
        let f=try NativeRecoveryFixture(request:AllowedNativeTestProfile.request()),admission=try f.provision()
        let context=try ClientAuthority(JSONDecoder().decode(ClientContext.self,from:admission.context))
        let clock=SystemClientClock(),environment=try ClientEnvironment(clock:clock)
        let legacy=try DurableClientReceipts(path:f.base+"/legacy",create:true,environment:environment,metadataKey:clientRandomKey(),clock:clock)
        defer { legacy.close() }
        let auth=ClientAuthorization(caller:context.context.caller),handle=ClientHandle(record:UUID().uuidString.lowercased(),ownerEpoch:legacy.ownerEpoch)
        let binding=try ToolBinding(id:Data("call".utf8),name:Data("a".utf8),arguments:Data("{\"n\":7}".utf8))
        let outcome=try ClientOutcome.make(kind:.success,result:Data(),binding:binding,authority:context),before=try f.hashes()
        XCTAssertThrowsError(try legacy.effect(binding,handle:handle,authority:context,authorization:auth))
        XCTAssertThrowsError(try legacy.beginEffect(binding,handle:handle,authority:context,authorization:auth))
        XCTAssertThrowsError(try legacy.recordOutcome(outcome,binding:binding,handle:handle,authority:context,authorization:auth))
        XCTAssertEqual(try f.hashes(),before)
    }
}
