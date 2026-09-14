import XCTest
import Foundation
import CryptoKit
import MLX
import MLXLMCommon
import ClockPolicy
import ReachWire
import WireAdapterContract
import RecoveryAuthorityContract
import HostClientContract
import ResumableMLXProvider
@testable import ReachDurableRuntime
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts

final class RequiredNativeRecoveryTests:XCTestCase {
    static func request(maximum:Int=48) throws -> WireGenerationRequest {
        var object=try JSONSerialization.jsonObject(with:ArtifactFixtures.encode(ArtifactFixtures.request("required",maximum:maximum))) as! [String:Any]
        object["id"]="00000000-0000-0000-0000-000000000103"
        var tools=object["tools"] as! [[String:Any]],tool=tools[0]
        tool["name"]="a"
        var parameters=tool["parameters"] as! [String:Any];parameters["title"]="A"
        tool["parameters"]=parameters;tools[0]=tool;object["tools"]=tools
        return try JSONDecoder().decode(WireGenerationRequest.self,from:JSONSerialization.data(withJSONObject:object,options:[.sortedKeys,.withoutEscapingSlashes]))
    }
    private func binding(_ p:SelectedArtifactProfile,_ request:WireGenerationRequest?=nil) throws -> ProviderBinding {
        let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
        return try p.preparer.prepare(request ?? Self.request(),reference:.init(session:.init(modelID:config.model,profile:config.profile,sessionID:"fixture"),generationID:"fixture",operationID:"s103-original-common-operation"),configuration:config)
    }
    private func callEvents(_ f:NativeRecoveryFixture) throws -> [WireEvent] {
        guard case .required(let b,let tokens)=f.provider.lane else { throw AuthorityError.state }
        return [.toolCallAppendArguments(entryID:b.entryID,id:b.callID,name:b.tools[0].name,content:"{\"n\":7}",tokenCount:1),.usage(inputTokens:tokens.count,outputTokens:35),.finished(.complete)]
    }
    private func frame(_ events:[WireEvent],first:UInt64=1,skip:Int=0) throws -> ReplayEnvelope {
        .init(firstSequence:first,count:events.count,providerCommit:String(repeating:"e",count:64),eventBytes:try ClientEvents.encode(events),skipPrefix:skip)
    }
    func testClosedRequiredBoundsOriginalSchemaAndStoredBinding() throws { try LocalDurableRuntime.withCPU {
        let p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true),good=try binding(p)
        guard case .required(let original,let tokens)=good.lane else { return XCTFail("required") }
        XCTAssertEqual(tokens.count,439);XCTAssertEqual(original.tools.count,1)
        func check(_ b:ProviderBinding,_ accepted:Bool) throws {
            let request=LifecycleRequest(version:3,authority:String(repeating:"a",count:64),namespace:UUID().uuidString.lowercased(),generation:"required",caller:.init(principal:"fixture",device:"fixture",app:"fixture"),provider:b)
            if accepted { try NativeRecoveryRuntime.validateFixture(b);try request.validate() }
            else { XCTAssertThrowsError(try NativeRecoveryRuntime.validateFixture(b));XCTAssertThrowsError(try request.validate()) }
        }
        try check(good,true)
        for maximum in [0,1,48,49] {
            var lane=original;lane.options.model.maximumTokens=maximum;var b=good;b.lane = .required(lane,tokens:tokens)
            try check(b,maximum==1 || maximum==48)
        }
        for count in [1,256,257,512,513] {
            let input=[Int](repeating:1,count:count);var lane=original;let i=lane.identity
            lane.identity = .init(model:i.model,configuration:i.configuration,weights:i.weights,input:try ResumableTokenIdentity.inputDigest(input),backend:i.backend,dependency:i.dependency)
            var b=good;b.lane = .required(lane,tokens:input);try check(b,count<=512)
        }
        for kind in 0..<5 {
            var lane=original
            switch kind {
            case 0:lane.options.model.prefillStepSize=64
            case 1:lane.tools.append(.init(name:"b",schemaJSON:lane.tools[0].schemaJSON))
            case 2:lane.tools[0].schemaJSON=lane.tools[0].schemaJSON.replacingOccurrences(of:"\"maximum\":7",with:"\"maximum\":8")
            case 3:lane.requestIdentity="replacement-request"
            default:lane.specification.source=" "+lane.specification.source
            }
            var b=good;b.lane = .required(lane,tokens:tokens);try check(b,false)
        }
        for route in ["allowed","combined"] { try check(binding(p,ArtifactFixtures.request(route,maximum:16)),false) }
        let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
        for kind in 0..<4 {
            var lane=original
            switch kind { case 0:lane.entryID="replacement-entry";case 1:lane.callID="replacement-call";case 2:lane.codecIdentity="replacement-codec";default:lane.options.completionReserve += 1 }
            var b=good;b.lane = .required(lane,tokens:tokens);try check(b,true)
            XCTAssertThrowsError(try p.runtime(b,configuration:config))
        }
        XCTAssertTrue(p.observations.isEmpty)
    } }
    func testRequiredOriginalAdmissionRejectsReplacementBeforeWrites() throws {
        let f=try NativeRecoveryFixture(request:Self.request()),before=try f.hashes(),a=try f.action(.admitHost)
        defer { try? a.finish() }
        for index in 0..<3 {
            var b=f.provider
            if index==0 { b.operationID="replacement" }
            else if index==1 { b.requestID="replacement" }
            else if case .required(var lane,let tokens)=b.lane { lane.callID="replacement";b.lane = .required(lane,tokens:tokens) }
            XCTAssertThrowsError(try DurableSessionLifecycle.admitNativeRecovery(at:f.host+"/bootstrap/host",identity:f.hostIdentity,keys:f.hostKeys,scope:f.scope,caller:f.caller,provider:b,action:a))
            XCTAssertEqual(try f.hashes(),before)
        }
    }
    func testRequiredProgressRequiresExactAcknowledgedSelection() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(request:Self.request())
        let live=try ResumableMLXProvider.prepare(binding:f.provider,runtime:f.runtime(),owner:"a",credit:ResumableMLXProvider.reservationBytes)
        defer { live.close() }
        let first=try XCTUnwrap(live.pendingCandidate())
        XCTAssertThrowsError(try live.committedRequiredProgress(first))
        try live.acceptCommit(first.commit,owner:"a")
        let start=try live.committedRequiredProgress(first);XCTAssertEqual(start.phase,"generating");XCTAssertEqual(start.guided.consumedTokens,0)
        let next=try XCTUnwrap(live.advance(owner:"a",current:first.commit,credit:ResumableMLXProvider.reservationBytes))
        XCTAssertThrowsError(try live.committedRequiredProgress(first));XCTAssertThrowsError(try live.committedRequiredProgress(next))
        try live.acceptCommit(next.commit,owner:"a")
        XCTAssertThrowsError(try live.committedRequiredProgress(first));XCTAssertEqual(try live.committedRequiredProgress(next).guided.consumedTokens,1)
        live.close();XCTAssertThrowsError(try live.committedRequiredProgress(next))
    } }
    func testRealRequiredGeneratingReadyAndTerminalReopen() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(request:Self.request()),admission=try f.provision()
        var owner=f.owner,a=try f.action(.reopen);var h=try f.openHost(a),c=try f.openClient(a)
        var p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true)
        let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
        try a.finish();a=try f.action(.prepare)
        var g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:{try p.runtime(f.provider,configuration:config)})
        try f.deliver(h,c,g,a);XCTAssertEqual(p.observations.reduce(0){$0+$1.calls},2)
        try a.finish();a=try f.action(.advance);try g.advance(action:a);try h.synchronize(action:a);try f.deliver(h,c,g,a)
        let cut=try g.requiredProgress(action:a),original=try AuthorityCodec.encode(admission)
        XCTAssertEqual(cut.phase,"generating");XCTAssertGreaterThan(cut.guided.pendingTokens,0);XCTAssertGreaterThan(cut.guided.consumedTokens,0)
        XCTAssertFalse(cut.whole.isEmpty);XCTAssertTrue(cut.guided.modelOffsets.allSatisfy{$0>0})
        XCTAssertEqual(try c.witness(action:a).high,0);XCTAssertEqual(try h.store.snapshot().high,0)
        let oldCalls=p.observations.reduce(0){$0+$1.calls};try a.finish()
        owner=try GenerationAuthorityOwner(scope:f.scope,clock:f.receiverClock)
        let foreign=try f.action(.advance,owner:owner);try foreign.bindAuthenticated(admission)
        XCTAssertThrowsError(try g.requiredProgress(action:foreign));XCTAssertThrowsError(try g.advance(action:foreign))
        XCTAssertEqual(p.observations.reduce(0){$0+$1.calls},oldCalls);try foreign.finish()
        let wrong=try f.action(.delivery);XCTAssertThrowsError(try g.advance(action:wrong));try wrong.finish()
        g.close();h.close();c.close()
        a=try f.action(.reopen,owner:owner);h=try f.openHost(a);c=try f.openClient(a)
        p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true)
        g=try GuardedNativeGeneration.restore(store:h.store,action:a,runtime:{try p.runtime(f.provider,configuration:config)})
        XCTAssertEqual(try g.requiredProgress(action:a),cut);XCTAssertEqual(p.observations.reduce(0){$0+$1.calls},0)
        XCTAssertEqual(try AuthorityCodec.encode(h.admission),original);try f.deliver(h,c,g,a)
        var progress=cut
        for step in 1...48 where progress.phase == "generating" {
            try a.finish();a=try f.action(.advance,owner:owner);try g.advance(action:a);try h.synchronize(action:a);try f.deliver(h,c,g,a)
            progress=try g.requiredProgress(action:a)
            if step<=cut.guided.pendingTokens {
                XCTAssertEqual(progress.guided.sampledTokens,cut.guided.sampledTokens);XCTAssertEqual(progress.guided.accepts,cut.guided.accepts)
                XCTAssertEqual(progress.guided.forcedTokens,cut.guided.forcedTokens+step);XCTAssertEqual(progress.guided.pendingTokens,cut.guided.pendingTokens-step)
            }
        }
        XCTAssertEqual(progress.phase,"ready");XCTAssertEqual(progress.guided.interceptedEndings,1);XCTAssertEqual(progress.guided.consumedTokens,36)
        XCTAssertEqual(try c.witness(action:a).high,0);XCTAssertEqual(try h.store.snapshot().high,0)
        let ready=progress;g.close();h.close();c.close();try a.finish()
        owner=try GenerationAuthorityOwner(scope:f.scope,clock:f.receiverClock)
        a=try f.action(.reopen,owner:owner);h=try f.openHost(a);c=try f.openClient(a)
        p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true)
        g=try GuardedNativeGeneration.restore(store:h.store,action:a,runtime:{try p.runtime(f.provider,configuration:config)})
        XCTAssertEqual(try g.requiredProgress(action:a),ready)
        try a.finish();a=try f.action(.advance,owner:owner);try g.advance(action:a);try h.synchronize(action:a)
        XCTAssertEqual(p.observations.reduce(0){$0+$1.calls},0);XCTAssertEqual(try g.requiredProgress(action:a).phase,"emitted")
        XCTAssertEqual(try h.store.snapshot().high,3);XCTAssertEqual(try c.witness(action:a).high,0)
        let emitted=try XCTUnwrap(h.store.replay(after:0).first)
        XCTAssertEqual(emitted.eventBytes,try ClientEvents.encode(callEvents(f)))
        g.close();h.close();c.close();try a.finish()
        owner=try GenerationAuthorityOwner(scope:f.scope,clock:f.receiverClock)
        a=try f.action(.reopen,owner:owner);h=try f.openHost(a);c=try f.openClient(a)
        var factories=0
        g=try GuardedNativeGeneration.restore(store:h.store,action:a,runtime:{factories += 1;throw AuthorityError.state})
        try f.deliver(h,c,g,a)
        let inbox=try c.inbox(action:a),receipt=try c.witness(action:a)
        XCTAssertEqual(receipt.high,3);XCTAssertTrue(receipt.terminal);XCTAssertEqual(receipt.registrations,1);XCTAssertEqual(factories,0)
        g.close();h.close();c.close();try a.finish()
        owner=try GenerationAuthorityOwner(scope:f.scope,clock:f.receiverClock)
        a=try f.action(.reopen,owner:owner);h=try f.openHost(a);c=try f.openClient(a)
        defer { h.close();c.close();try? a.finish() }
        try c.accept(.init(firstSequence:emitted.firstSequence,count:emitted.count,providerCommit:emitted.providerCommit,eventBytes:emitted.eventBytes),action:a)
        XCTAssertEqual(try c.witness(action:a),receipt);XCTAssertEqual(try ArtifactFixtures.encode(c.inbox(action:a)),try ArtifactFixtures.encode(inbox))
        try h.acceptReceipt(receipt,action:a)
    } }
    func testRealRequiredBudgetExhaustionNeverRegistersOrPublishesSuccessUsage() throws { try LocalDurableRuntime.withCPU {
        for maximum in [1,35] {
            let f=try NativeRecoveryFixture(request:Self.request(maximum:maximum));_=try f.provision()
            let p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true)
            let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
            var a=try f.action(.reopen);let h=try f.openHost(a),c=try f.openClient(a)
            try a.finish();a=try f.action(.prepare)
            let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:{try p.runtime(f.provider,configuration:config)})
            try f.deliver(h,c,g,a)
            for _ in 0..<maximum where try !h.store.snapshot().terminal {
                try a.finish();a=try f.action(.advance);try g.advance(action:a);try h.synchronize(action:a);try f.deliver(h,c,g,a)
            }
            let progress=try g.requiredProgress(action:a),inbox=try c.inbox(action:a),receipt=try c.witness(action:a)
            XCTAssertEqual(progress.phase,"emitted");XCTAssertNil(progress.call);XCTAssertEqual(progress.guided.terminalReason,"incomplete")
            XCTAssertEqual(progress.guided.consumedTokens,maximum);XCTAssertEqual(progress.guided.interceptedEndings,0)
            XCTAssertEqual(receipt.registrations,0);XCTAssertTrue(receipt.terminal)
            let events=try inbox.flatMap{try ClientEvents.decode($0.bytes)};XCTAssertEqual(events.count,1)
            guard case .finished(.error)?=events.first else { return XCTFail("Required exhaustion must emit only failure") }
            if maximum==35 {
                let envelope=try JSONSerialization.jsonObject(with:progress.whole) as! [String:Any]
                XCTAssertEqual(envelope["name"] as? String,"a");XCTAssertEqual(envelope["arguments"] as? [String:Int],["n":7])
            } else { XCTAssertThrowsError(try JSONSerialization.jsonObject(with:progress.whole)) }
            let calls=p.observations.reduce(0){$0+$1.calls};XCTAssertGreaterThan(calls,0)
            g.close();h.close();c.close();try a.finish()
            a=try f.action(.reopen);let host=try f.openHost(a),client=try f.openClient(a)
            var factories=0
            let replay=try GuardedNativeGeneration.restore(store:host.store,action:a,runtime:{factories += 1;throw AuthorityError.state})
            try f.deliver(host,client,replay,a);XCTAssertEqual(try client.witness(action:a),receipt);XCTAssertEqual(factories,0)
            struct Result:Encodable { let maximum:Int,progress:ProviderRequiredProgress,eventBytes:Data,nativeCalls:Int,terminalReplayFactories:Int }
            try LocalFiles.writeNew(ArtifactFixtures.encode(Result(maximum:maximum,progress:progress,eventBytes:try ClientEvents.encode(events),nativeCalls:calls,terminalReplayFactories:factories)),to:ArtifactFixtures.base()+"/required-exhaustion-"+String(maximum)+"-"+UUID().uuidString.lowercased()+".json")
            replay.close();host.close();client.close();try a.finish()
        }
    } }
    func testRequiredInboxRejectsWrongPartialMixedAndConflictingCalls() throws {
        let f=try NativeRecoveryFixture(request:Self.request());_=try f.provision()
        let a=try f.action(.reopen),c=try f.openClient(a);defer { c.close();try? a.finish() }
        let good=try callEvents(f),before=try f.hashes()
        guard case .toolCallAppendArguments(let entry,let id,let name,let arguments,_)=good[0] else { return XCTFail("call") }
        let malformed:[[WireEvent]]=[
            [good[0]],Array(good.prefix(2)),[good[0],good[0],good[1],good[2]],
            [.responseAppend(entryID:"x",text:"mixed",segmentID:nil,tokenCount:0)]+good,
            [.toolCallAppendArguments(entryID:"wrong",id:id,name:name,content:arguments,tokenCount:1),good[1],good[2]],
            [.toolCallAppendArguments(entryID:entry,id:"wrong",name:name,content:arguments,tokenCount:1),good[1],good[2]],
            [.toolCallAppendArguments(entryID:entry,id:id,name:"wrong",content:arguments,tokenCount:1),good[1],good[2]],
            [.toolCallAppendArguments(entryID:entry,id:id,name:name,content:arguments,tokenCount:2),good[1],good[2]],
            [good[0],.usage(inputTokens:1,outputTokens:35),good[2]],
            [good[0],.usage(inputTokens:439,outputTokens:48),good[2]],
            [good[0],good[1],.finished(.cancelled)],
            [.toolCallAppendArguments(entryID:entry,id:id,name:name,content:"{\"n\":",tokenCount:1),good[1],good[2]]]
        for events in malformed { XCTAssertThrowsError(try c.accept(frame(events),action:a));XCTAssertEqual(try f.hashes(),before) }
        XCTAssertThrowsError(try c.accept(frame(good,skip:1),action:a));XCTAssertEqual(try f.hashes(),before)
        let exact=try frame(good);try c.accept(exact,action:a)
        let receipt=try c.witness(action:a),after=try f.hashes();XCTAssertEqual(receipt.registrations,1)
        try c.accept(exact,action:a);XCTAssertEqual(try c.witness(action:a),receipt);XCTAssertEqual(try f.hashes(),after)
        let changed=[WireEvent.toolCallAppendArguments(entryID:entry,id:id,name:name,content:"{\"n\":8}",tokenCount:1),good[1],good[2]]
        XCTAssertThrowsError(try c.accept(frame(changed),action:a));XCTAssertThrowsError(try c.accept(frame(good,first:4),action:a))
        XCTAssertEqual(try f.hashes(),after);XCTAssertEqual(try c.witness(action:a),receipt)
    }
    private func terminal(_ f:NativeRecoveryFixture) throws -> HandoffWitness {
        _=try f.provision();var a=try f.action(.reopen);let h=try f.openHost(a),c=try f.openClient(a)
        try a.finish();a=try f.action(.prepare);let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:f.runtime)
        defer { g.close();h.close();c.close();try? a.finish() };try f.deliver(h,c,g,a)
        for _ in 0..<49 where try !h.store.snapshot().terminal {
            try a.finish();a=try f.action(.advance);try g.advance(action:a);try h.synchronize(action:a);try f.deliver(h,c,g,a)
        }
        let receipt=try c.witness(action:a);XCTAssertTrue(receipt.terminal);XCTAssertEqual(receipt.registrations,1);return receipt
    }
    func testForgedReceiptCountDigestTerminalAndRetainedReopenRefuse() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(request:Self.request()),receipt=try terminal(f)
        let a=try f.action(.reopen),h=try f.openHost(a)
        var bad:[HandoffWitness]=[]
        for index in 0..<5 {
            var w=receipt
            switch index { case 0:w.registrations=0;case 1:w.registrations=2;case 2:w.calls=String(repeating:"f",count:64);case 3:w.terminal=false;default:w.prefix=String(repeating:"f",count:64) }
            bad.append(w)
        }
        let before=try f.hashes()
        for w in bad { XCTAssertThrowsError(try h.acceptReceipt(w,action:a));XCTAssertEqual(try f.hashes(),before) }
        h.close();try a.finish()
        for w in bad {
            let fs=try LifecycleFileSystem(path:f.host+"/bootstrap/host",create:false)
            var d=try LifecycleCatalog.read(fs,identity:f.hostIdentity,keys:f.hostKeys);d.nativeReceipt=w
            try DurableSessionLifecycle.selectNativeCatalog(d,files:fs,identity:f.hostIdentity,keys:f.hostKeys,check:{})
            fs.close()
            let action=try f.action(.reopen);XCTAssertThrowsError(try f.openHost(action));try action.finish()
        }
    } }
    func testPersistedNativeCountIntentOutcomeAndSchemaProvenanceRefuse() throws {
        for variant in ["count","intent","outcome","schema"] {
            let f=try NativeRecoveryFixture(request:Self.request());_=try f.provision()
            var a=try f.action(.reopen);let c=try f.openClient(a);try c.accept(frame(callEvents(f)),action:a);c.close();try a.finish()
            a=try f.action(.reopen)
            let fs=try ClientFileSystem(path:f.client+"/bootstrap/client",create:false),key=SymmetricKey(data:f.clientKey)
            var m=try DurableClientReceipts.readNativeManifest(fs,environment:f.clientEnvironment,key:key,action:a)
            var live=m.records[0].live!
            let (bytes,originalFrame)=try ClientCrypto.open(fs.read(live.snapshot.name),role:"snapshot",environment:f.clientEnvironment,key:SymmetricKey(data:live.key),rootKey:key)
            var s=try JSONDecoder().decode(ClientSnapshot.self,from:bytes)
            if variant=="count" { live.calls=0 }
            else if variant=="schema" {
                // The sole schema must reconstruct the original structural
                // specification even when the supplied digest matches its bytes.
                guard case .required(var b,let tokens)=f.provider.lane else { throw AuthorityError.state }
                b.tools[0].schemaJSON=b.tools[0].schemaJSON.replacingOccurrences(of:"\"maximum\":7",with:"\"maximum\":8")
                var p=f.provider;p.lane = .required(b,tokens:tokens)
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
    func testRequiredNativeAndCommitGapsPreserveSelectedStateAndNoCall() throws { try LocalDurableRuntime.withCPU {
        for point in [StoreFaultPoint.afterNativeBeforeCommit,.afterCommitBeforeAck] {
            let f=try NativeRecoveryFixture(request:Self.request());_=try f.provision()
            var a=try f.action(.reopen);let h=try f.openHost(a),c=try f.openClient(a)
            defer { h.close();c.close() };try a.finish();a=try f.action(.prepare)
            let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:f.runtime);defer { g.close() };try f.deliver(h,c,g,a)
            let selected=try h.store.snapshot().candidate!.commit,receipt=try c.witness(action:a)
            try a.finish();a=try f.action(.advance)
            h.store.fault={p in if p==point { f.receiverClock.advance(10_000_000_001) }}
            XCTAssertThrowsError(try g.advance(action:a));XCTAssertThrowsError(try c.witness(action:a))
            try a.finish();let fresh=try f.action(.reopen);try h.store.authorize(fresh)
            XCTAssertEqual(try h.store.reconcile().candidate!.commit==selected,point == .afterNativeBeforeCommit)
            XCTAssertEqual(try c.witness(action:fresh),receipt);XCTAssertEqual(receipt.registrations,0);try fresh.finish()
        }
    } }
    func testLegacyEffectAPIsRefuseRequiredNativeAuthority() throws {
        let f=try NativeRecoveryFixture(request:Self.request()),admission=try f.provision()
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
