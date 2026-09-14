import XCTest
import Foundation
import MLX
import MLXLMCommon
import ClockPolicy
import RecoveryAuthorityContract
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts
import ReachWire
import WireAdapterContract
import RequestPreparationContract
import ResumableMLXProvider
@testable import ReachDurableRuntime
@testable import DurableHostStore

final class SchemaNativeRecoveryTests: XCTestCase {
    static func request(maximum: Int=32) throws -> WireGenerationRequest {
        let schema=try WireGenerationSchema(jsonValue:.object([
            "title":.string("ForcedFixture"),"type":.string("object"),
            "properties":.object(["value":.object(["type":.string("string"),"enum":.array([.string("中")])])]),
            "required":.array([.string("value")]),"x-order":.array([.string("value")]),"additionalProperties":.bool(false)]))
        return .init(id:UUID(uuidString:"00000000-0000-0000-0000-000000000102")!,
            portableTranscript:.init(entries:[.prompt(.init(id:"prompt",segments:[.text(.init(id:"text",content:"Hi."))]))]),
            portableSchema:schema,options:.init(temperature:0,maximumResponseTokens:maximum,sampling:.greedy),context:.init(includeSchemaInPrompt:false))
    }
    static func binding(_ p: SelectedArtifactProfile, _ request: WireGenerationRequest?=nil) throws -> ProviderBinding {
        let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
        return try p.preparer.prepare(request ?? Self.request(),reference:.init(session:.init(modelID:config.model,profile:config.profile,sessionID:"00000000-0000-0000-0000-000000000001"),generationID:"fixture-generation",operationID:"s102-original-common-operation"),configuration:config)
    }
    func testActualGuidedFixtureFeasibilityBeforeOriginals() throws { try LocalDurableRuntime.withCPU {
        let path=try ArtifactFixtures.artifacts(); try ArtifactFixtures.writeRequests()
        let requestPath=try ArtifactFixtures.base()+"/requests/native-guided.json", bytes=try ArtifactFixtures.encode(Self.request())
        if FileManager.default.fileExists(atPath:requestPath) { XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:requestPath)),bytes) }
        else { try LocalFiles.writeNew(bytes,to:requestPath) }
        let p=try SelectedArtifactProfile(at:path,nativeRecovery:true), b=try Self.binding(p)
        try NativeRecoveryRuntime.validateFixture(b)
        let second=try SelectedArtifactProfile(at:path,nativeRecovery:true)
        XCTAssertEqual(try ArtifactFixtures.encode(b),try ArtifactFixtures.encode(Self.binding(second)))
        let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
        let live=try ResumableMLXProvider.prepare(binding:b,runtime:p.runtime(b,configuration:config),owner:"feasibility",credit:ResumableMLXProvider.reservationBytes)
        defer { live.close() }
        var candidate=try XCTUnwrap(live.pendingCandidate()), cut:ProviderCandidate?, history:[ProviderGuidedProgress]=[]
        XCTAssertThrowsError(try live.committedGuidedProgress(candidate,tokenizer:p.tokenizer))
        try live.acceptCommit(candidate.commit,owner:"feasibility")
        history.append(try live.committedGuidedProgress(candidate,tokenizer:p.tokenizer))
        for _ in 0..<32 where !live.isTerminal {
            candidate=try XCTUnwrap(live.advance(owner:"feasibility",current:candidate.commit,credit:ResumableMLXProvider.reservationBytes))
            try live.acceptCommit(candidate.commit,owner:"feasibility")
            let v=try live.committedGuidedProgress(candidate,tokenizer:p.tokenizer); history.append(v)
            if cut == nil, v.consumedTokens>1, v.pendingTokens>0, !v.cumulativeEmittedBytes.isEmpty, v.modelOffsets.allSatisfy({$0>0}) { cut=candidate }
        }
        let end=try XCTUnwrap(history.last)
        XCTAssertEqual(end.terminalReason,"complete"); XCTAssertEqual(end.interceptedEndings,1)
        XCTAssertLessThanOrEqual(end.consumedTokens,32); XCTAssertEqual(end.pendingTokens,0)
        let text=try JSONSerialization.jsonObject(with:end.cumulativeEmittedBytes) as? [String:String]
        XCTAssertEqual(text,["value":"中"])
        struct Feasibility: Encodable { let beforeOriginals=true; let provider:ProviderBinding; let progress:[ProviderGuidedProgress]; let nativeCalls:Int, nativePeak:Int }
        let report=try ArtifactFixtures.encode(Feasibility(provider:b,progress:history,nativeCalls:p.observations.reduce(0){$0+$1.calls},nativePeak:Memory.peakMemory))
        let reportPath=try ArtifactFixtures.base()+"/feasibility-"+UUID().uuidString.lowercased()+".json"
        try LocalFiles.writeNew(report,to:reportPath)
        let selected=try XCTUnwrap(cut,"A successful ending alone does not prove a pending forced-token cut")
        let expected=try XCTUnwrap(history.first(where:{$0.commit==selected.commit.identity}))
        live.close()
        let restored=try ResumableMLXProvider.restore(committed:selected,expected:b,runtime:second.runtime(b,configuration:config),owner:"resumed-feasibility")
        defer { restored.close() }
        XCTAssertEqual(second.observations.reduce(0){$0+$1.calls},0)
        XCTAssertEqual(try restored.committedGuidedProgress(selected,tokenizer:second.tokenizer),expected)
        var current=selected
        for step in 1...expected.pendingTokens {
            current=try XCTUnwrap(restored.advance(owner:"resumed-feasibility",current:current.commit,credit:ResumableMLXProvider.reservationBytes))
            try restored.acceptCommit(current.commit,owner:"resumed-feasibility")
            let after=try restored.committedGuidedProgress(current,tokenizer:second.tokenizer)
            XCTAssertEqual(after.sampledTokens,expected.sampledTokens)
            XCTAssertEqual(after.forcedTokens,expected.forcedTokens+step)
            XCTAssertEqual(after.accepts,expected.accepts)
            XCTAssertEqual(after.pendingTokens,expected.pendingTokens-step)
        }
        XCTAssertLessThanOrEqual(Memory.peakMemory,128<<20)
    } }

    func testGuidedBudgetExhaustionPublishesIncompleteAndReplaysTerminal() throws { try LocalDurableRuntime.withCPU {
        // Budget 18 reaches valid JSON but stops before accepted EOS. Neither it
        // nor the partial-JSON budget may project a successful schema ending.
        for maximum in [2,18] {
            let f=try NativeRecoveryFixture(request:Self.request(maximum:maximum)); _=try f.provision()
            let p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true)
            let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
            var a=try f.action(.reopen); let h=try f.openHost(a), c=try f.openClient(a)
            try a.finish(); a=try f.action(.prepare)
            let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:{ try p.runtime(f.provider,configuration:config) })
            try f.deliver(h,c,g,a)
            XCTAssertFalse(try h.store.snapshot().terminal)
            for _ in 0..<maximum where try !h.store.snapshot().terminal {
                try a.finish(); a=try f.action(.advance); try g.advance(action:a); try f.deliver(h,c,g,a)
            }
            let progress=try g.guidedProgress(action:a,tokenizer:p.tokenizer)
            XCTAssertTrue(try h.store.snapshot().terminal)
            XCTAssertEqual(progress.consumedTokens,maximum); XCTAssertEqual(progress.terminalReason,"incomplete")
            XCTAssertEqual(progress.interceptedEndings,0)
            if maximum==18 {
                XCTAssertEqual(try JSONSerialization.jsonObject(with:progress.cumulativeEmittedBytes) as? [String:String],["value":"中"])
            } else { XCTAssertThrowsError(try JSONSerialization.jsonObject(with:progress.cumulativeEmittedBytes)) }
            let inbox=try c.inbox(action:a), receipt=try c.witness(action:a)
            let events=try inbox.flatMap { try ClientEvents.decode($0.bytes) }
            let endings=events.compactMap { event -> WireFinishReason? in if case .finished(let reason)=event { return reason }; return nil }
            XCTAssertEqual(endings.count,1)
            guard case .error(let message)?=endings.first else { return XCTFail("Budget exhaustion must not publish schema success") }
            XCTAssertEqual(message,"Guided response did not reach accepted EOS within its generation budget.")
            XCTAssertFalse(events.contains { if case .usage=$0 { return true }; return false })
            XCTAssertTrue(receipt.terminal); XCTAssertEqual(receipt.registrations,0)
            let calls=p.observations.reduce(0){$0+$1.calls}, models=p.observations.count
            XCTAssertGreaterThan(calls,0); XCTAssertEqual(f.counter.calls,0)
            let selected=try XCTUnwrap(h.store.snapshot().candidate).commit
            g.close(); h.close(); c.close(); try a.finish()
            a=try f.action(.reopen); let host=try f.openHost(a), client=try f.openClient(a)
            defer { host.close(); client.close() }
            var factories=0
            let replay=try GuardedNativeGeneration.restore(store:host.store,action:a,runtime:{ factories += 1; throw AuthorityError.state })
            defer { replay.close() }
            try f.deliver(host,client,replay,a)
            XCTAssertEqual(try host.store.snapshot().candidate!.commit,selected)
            XCTAssertEqual(try client.witness(action:a),receipt)
            XCTAssertEqual(try ArtifactFixtures.encode(client.inbox(action:a)),try ArtifactFixtures.encode(inbox))
            XCTAssertEqual(factories,0); XCTAssertEqual(p.observations.count,models)
            XCTAssertEqual(p.observations.reduce(0){$0+$1.calls},calls)
            struct Exhaustion: Encodable {
                let maximum:Int, provider:ProviderBinding, progress:ProviderGuidedProgress, eventBytes:Data
                let clientHigh:UInt64, clientTerminal:Bool, terminalReplayFactories:Int, nativeCalls:Int, nativePeak:Int
            }
            let report=Exhaustion(maximum:maximum,provider:f.provider,progress:progress,eventBytes:try ClientEvents.encode(events),
                clientHigh:receipt.high,clientTerminal:receipt.terminal,terminalReplayFactories:factories,nativeCalls:calls,nativePeak:Memory.peakMemory)
            try LocalFiles.writeNew(ArtifactFixtures.encode(report),to:ArtifactFixtures.base()+"/budget-exhaustion-"+String(maximum)+"-"+UUID().uuidString.lowercased()+".json")
            XCTAssertLessThanOrEqual(Memory.peakMemory,128<<20); try a.finish()
        }
    } }

    func testClosedSchemaKindsBoundsAndPersistedRequestGuard() throws { try LocalDurableRuntime.withCPU {
        let p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true), good=try Self.binding(p)
        func check(_ b: ProviderBinding, accepted: Bool) throws {
            let request=LifecycleRequest(version:3,authority:String(repeating:"a",count:64),namespace:UUID().uuidString.lowercased(),generation:"schema",caller:.init(principal:"fixture",device:"fixture",app:"fixture"),provider:b)
            if accepted { try NativeRecoveryRuntime.validateFixture(b); try request.validate() }
            else { XCTAssertThrowsError(try NativeRecoveryRuntime.validateFixture(b)); XCTAssertThrowsError(try request.validate()) }
        }
        try check(good,accepted:true)
        guard case .guided(let original)=good.lane else { return XCTFail("guided fixture") }
        for maximum in [0,1,32,33] {
            var lane=original; lane.options.model.maximumTokens=maximum
            var b=good; b.lane = .guided(lane); try check(b,accepted:maximum==1 || maximum==32)
        }
        var lane=original; lane.options.model.prefillStepSize=64; var bad=good; bad.lane = .guided(lane); try check(bad,accepted:false)
        for count in [1,256,257] {
            var lane=original; lane.tokens=[Int](repeating:1,count:count)
            let i=lane.model.identity
            lane.model.identity = .init(model:i.model,configuration:i.configuration,weights:i.weights,input:try ResumableTokenIdentity.inputDigest(lane.tokens),backend:i.backend,dependency:i.dependency)
            var b=good; b.lane = .guided(lane); try check(b,accepted:count<=256)
        }
        let raw=String(decoding:try ArtifactFixtures.encode(good),as:UTF8.self)
        XCTAssertTrue(raw.contains("\"kind\":\"json-schema\""))
        for kind in ["structural-tag","literal-fixture","unknown-kind"] {
            let value=raw.replacingOccurrences(of:"\"kind\":\"json-schema\"",with:"\"kind\":\""+kind+"\"")
            try check(JSONDecoder().decode(ProviderBinding.self,from:Data(value.utf8)),accepted:false)
        }
        lane=original; lane.specification.source=" "+lane.specification.source; bad=good; bad.lane = .guided(lane); try check(bad,accepted:false)
        for route in ["allowed","combined"] {
            try check(Self.binding(p,ArtifactFixtures.request(route,maximum:16)),accepted:false)
        }
        XCTAssertTrue(p.observations.isEmpty)
    } }
    func testCompleteStoredArtifactComparisonStillPrecedesFactory() throws { try LocalDurableRuntime.withCPU {
        let p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true), good=try Self.binding(p)
        let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
        guard case .guided(let original)=good.lane else { return XCTFail("guided fixture") }
        for index in 0..<4 {
            var lane=original
            switch index {
            case 0: lane.options.completionReserve += 1
            case 1: lane.specification.fastForward=false
            case 2: lane.model.codecIdentity="replacement-codec"
            default: lane.entryID="replacement-entry"
            }
            var b=good; b.lane = .guided(lane)
            try NativeRecoveryRuntime.validateFixture(b)
            XCTAssertThrowsError(try p.runtime(b,configuration:config))
        }
        XCTAssertTrue(p.observations.isEmpty)
        let legacy=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts())
        let ordinary=try Self.binding(legacy,ArtifactFixtures.request("ordinary",maximum:16))
        guard case .ordinary(let b)=ordinary.lane else { return XCTFail("ordinary") }
        XCTAssertEqual(b.options.prefillStepSize,64)
        XCTAssertThrowsError(try NativeRecoveryRuntime.validateFixture(ordinary))
    } }
    func testGuidedRestoreKeepsOwnerOperationsAndForcedSuffix() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(request:Self.request()); let admission=try f.provision()
        var a=try f.action(.reopen); let h=try f.openHost(a), c=try f.openClient(a)
        try a.finish(); a=try f.action(.prepare)
        let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:f.runtime)
        try f.deliver(h,c,g,a)
        var cut=try g.guidedProgress(action:a,tokenizer:ArtifactTokenizer())
        for _ in 0..<32 where cut.pendingTokens==0 {
            try a.finish(); a=try f.action(.advance); try g.advance(action:a); try h.synchronize(action:a)
            cut=try g.guidedProgress(action:a,tokenizer:ArtifactTokenizer())
            if cut.pendingTokens==0 { try f.deliver(h,c,g,a) }
        }
        XCTAssertGreaterThan(cut.pendingTokens,0); XCTAssertGreaterThan(cut.consumedTokens,0)
        XCTAssertGreaterThan(try h.store.snapshot().high,try c.witness(action:a).high)
        let calls=f.counter.calls, selected=try h.store.snapshot().candidate!.commit
        try a.finish()
        let foreign=try GenerationAuthorityOwner(scope:f.scope,clock:f.receiverClock), b=try f.action(.advance,owner:foreign)
        try b.bindAuthenticated(admission); let before=try f.hashes()
        XCTAssertThrowsError(try g.guidedProgress(action:b,tokenizer:ArtifactTokenizer()))
        XCTAssertThrowsError(try g.advance(action:b)); XCTAssertThrowsError(try h.synchronize(action:b)); XCTAssertThrowsError(try c.inbox(action:b))
        XCTAssertEqual(try f.hashes(),before); XCTAssertEqual(f.counter.calls,calls); try b.finish()
        let wrong=try f.action(.delivery); try h.store.authorize(wrong)
        XCTAssertThrowsError(try g.advance(action:wrong)); XCTAssertEqual(f.counter.calls,calls); try wrong.finish()
        g.close(); h.close(); c.close()
        let reopened=try f.action(.reopen,owner:foreign), host=try f.openHost(reopened), client=try f.openClient(reopened)
        defer { host.close(); client.close() }
        XCTAssertEqual(try host.store.snapshot().candidate!.commit,selected)
        try f.deliver(host,client,nil,reopened)
        let live=try GuardedNativeGeneration.restore(store:host.store,action:reopened,runtime:f.runtime)
        defer { live.close() }
        XCTAssertEqual(f.counter.calls,calls)
        XCTAssertEqual(try live.guidedProgress(action:reopened,tokenizer:ArtifactTokenizer()),cut)
        try f.deliver(host,client,live,reopened); try reopened.finish()
        for step in 1...cut.pendingTokens {
            let action=try f.action(.advance,owner:foreign); try live.advance(action:action)
            let v=try live.guidedProgress(action:action,tokenizer:ArtifactTokenizer())
            XCTAssertEqual(v.sampledTokens,cut.sampledTokens); XCTAssertEqual(v.forcedTokens,cut.forcedTokens+step)
            XCTAssertEqual(v.accepts,cut.accepts); try f.deliver(host,client,live,action); try action.finish()
        }
    } }
    func testGuidedNativeAndCommitGapsRefuseStalePublication() throws { try LocalDurableRuntime.withCPU {
        for point in [StoreFaultPoint.afterNativeBeforeCommit,.afterCommitBeforeAck] {
            let f=try NativeRecoveryFixture(request:Self.request()); _=try f.provision()
            var a=try f.action(.reopen); let h=try f.openHost(a), c=try f.openClient(a)
            defer { h.close(); c.close() }
            try a.finish(); a=try f.action(.prepare); let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:f.runtime)
            defer { g.close() }; try f.deliver(h,c,g,a)
            let selected=try h.store.snapshot().candidate!.commit, receipt=try c.witness(action:a)
            try a.finish(); a=try f.action(.advance)
            h.store.fault={ p in if p==point { f.receiverClock.advance(10_000_000_001) } }
            XCTAssertThrowsError(try g.advance(action:a)); XCTAssertThrowsError(try c.witness(action:a))
            try a.finish(); let fresh=try f.action(.reopen); try h.store.authorize(fresh)
            let reconciled=try h.store.reconcile(); XCTAssertEqual(reconciled.candidate!.commit==selected,point == .afterNativeBeforeCommit)
            XCTAssertEqual(try c.witness(action:fresh),receipt); try fresh.finish()
        }
    } }
    func testGuidedOriginalHostAndClientExpiryRemainIndependent() throws { try LocalDurableRuntime.withCPU {
        for caps in [(UInt64(30),UInt64(90)),(90,30)] {
            let f=try NativeRecoveryFixture(hostCap:caps.0,clientCap:caps.1,request:Self.request()); _=try f.provision()
            var a=try f.action(.reopen); let h=try f.openHost(a), c=try f.openClient(a)
            defer { h.close(); c.close() }
            try a.finish(); a=try f.action(.prepare); let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:f.runtime)
            defer { g.close() }; try f.deliver(h,c,g,a); let calls=f.counter.calls
            try a.finish(); f.witnessClock.advance(29_000_000_000); let expired=try f.action(.advance)
            XCTAssertThrowsError(try g.advance(action:expired)); XCTAssertThrowsError(try c.witness(action:expired)); XCTAssertEqual(f.counter.calls,calls)
            try expired.finish()
        }
    } }
    func testGuidedInboxStillRefusesEffectsAndUnknownRoutes() throws {
        let f=try NativeRecoveryFixture(request:Self.request()); let admission=try f.provision()
        let a=try f.action(.reopen), c=try f.openClient(a); defer { c.close(); try? a.finish() }
        let before=try f.hashes()
        let bytes=try ClientEvents.encode([.toolCallAppendArguments(entryID:nil,id:"effect",name:"write",content:"{}",tokenCount:1)])
        XCTAssertThrowsError(try c.accept(.init(firstSequence:1,count:1,providerCommit:String(repeating:"e",count:64),eventBytes:bytes),action:a))
        XCTAssertEqual(try f.hashes(),before); XCTAssertEqual(try c.witness(action:a).registrations,0)
        let raw=String(decoding:admission.context,as:UTF8.self)
        for route in ["allowed","combined","unknown"] {
            let bytes=Data(raw.replacingOccurrences(of:"\"route\":\"guided\"",with:"\"route\":\""+route+"\"").utf8)
            XCTAssertThrowsError(try ClientAuthority(JSONDecoder().decode(ClientContext.self,from:bytes)))
        }
    }
}
