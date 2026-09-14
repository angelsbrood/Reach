import XCTest
import Foundation
import MLX
import MLXLMCommon
import AllowedToolCoordinator
import ReachWire
import WireAdapterContract
import RequestPreparationContract
import ResumableMLXProvider
import RecoveryAuthorityContract
import HostClientContract
@testable import ReachDurableRuntime
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts

final class SchemaToolNativeRecoveryTests:XCTestCase {
    func testCombinedBindingIdentityCanonicalSchemaAndSharedBounds() throws { try LocalDurableRuntime.withCPU {
        let p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true),r=try SchemaToolNativeTestRun.request()
        let good=try SchemaNativeRecoveryTests.binding(p,r),nilSchema=try SchemaNativeRecoveryTests.binding(p,AllowedNativeTestProfile.request())
        guard case .allowed(let b)=good.lane,case .allowed(let plain)=nilSchema.lane else {return XCTFail("allowed")}
        try NativeRecoveryBinding.validate(good)
        XCTAssertEqual(b.originalTokens,plain.originalTokens);XCTAssertNotEqual(good.requestID,nilSchema.requestID)
        XCTAssertNotEqual(b.namespace,plain.namespace);XCTAssertNotNil(b.responseSchema)
        let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
        for variant in 0..<6 {
            var v=b
            switch variant {
            case 0:v.responseSchema=" "+v.responseSchema!
            case 1:v.responseSchema=nil
            case 2:v.responseSchema=plain.tools[0].schemaJSON
            case 3:v.namespace=String(repeating:"f",count:32)
            case 4:v.entryID="replacement"
            default:v.guidedOptions.model.maximumTokens=63
            }
            var bad=good;bad.lane = .allowed(v)
            XCTAssertThrowsError(try p.runtime(bad,configuration:config))
        }
        let array=WireJSONValue.array((0..<4100).map { .string(String($0)) })
        let source=String(decoding:try AuthorityCodec.encode(WireJSONValue.object(["type":.string("string"),"enum":array])),as:UTF8.self)
        XCTAssertNoThrow(try RequestBounds.validateStoredTools(names:["a"],schemas:[source]))
        XCTAssertThrowsError(try RequestBounds.validateStoredTools(names:["a"],schemas:[source],responseSchema:source))
        XCTAssertTrue(p.observations.isEmpty)
    } }
    func testSchemaPassUsesExactOriginalTokensAndRejectsRepairBeforeFactory() throws { try LocalDurableRuntime.withCPU {
        let p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true),b=try SchemaNativeRecoveryTests.binding(p,SchemaToolNativeTestRun.request())
        guard case .allowed(let allowed)=b.lane,case .allowed(let runtime)=try p.runtime(b,configuration:.init(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)) else {return XCTFail("allowed")}
        let pass=try AllowedToolReplayInput.prepare(binding:allowed,kind:.schema,tokenizer:p.tokenizer)
        XCTAssertEqual(pass.tokens,allowed.originalTokens);XCTAssertTrue(pass.messages.isEmpty);XCTAssertNil(pass.proposalID)
        try validateAllowedRecoveryPass(pass,binding:allowed,tokenizer:p.tokenizer)
        for variant in 0..<6 {
            var wrong=pass
            switch variant {
            case 0:wrong.index=1
            case 1:wrong.proposalID="call"
            case 2:wrong.messages=Data("repair".utf8)
            case 3:wrong.tokens[0]=(wrong.tokens[0]+1)%258;wrong.inputDigest=try ResumableTokenIdentity.inputDigest(wrong.tokens)
            case 4:wrong.tokens=[Int](repeating:1,count:513);wrong.inputDigest=try ResumableTokenIdentity.inputDigest(wrong.tokens)
            default:wrong.inputDigest=String(repeating:"a",count:64)
            }
            XCTAssertThrowsError(try runtime.model(wrong));XCTAssertTrue(p.observations.isEmpty)
        }
        XCTAssertEqual(p.tokenizer.repairEncodes,0)
    } }
    func testActualLlamaPrivateProbeSchemaPendingRestoreReadyAndAggregateUsage() throws { try LocalDurableRuntime.withCPU {
        let run=try SchemaToolNativeTestRun(actual:true)
        try run.advanceUnit(until:{$0.probe.rawTokens>0})
        XCTAssertEqual(try run.progress.phase,"probe");XCTAssertGreaterThan(try run.progress.probe.rawTokens,0)
        XCTAssertEqual(try run.progress.proseDelivered,0);XCTAssertEqual(try run.client.witness(action:run.action).high,0)
        try run.reopen();try run.advance(to:"routeReady")
        let route=try run.progress;XCTAssertEqual(route.route,"schema");XCTAssertTrue(route.proposals.isEmpty)
        try run.advanceUnit()
        for _ in 0..<20 {
            let p=try run.progress
            if (p.guided?.pendingTokens ?? 0)>0,try run.client.witness(action:run.action).high>0 {break}
            try run.advanceUnit()
        }
        // Leave one additional schema fragment host-ahead of an already visible prefix.
        try run.advanceUnit(until:{_ in true},deliver:false)
        let cut=try run.progress,g=try XCTUnwrap(cut.guided)
        XCTAssertEqual(cut.phase,"guided");XCTAssertGreaterThan(g.consumedTokens,0);XCTAssertGreaterThan(g.pendingTokens,0)
        XCTAssertGreaterThan(try run.client.witness(action:run.action).high,0)
        XCTAssertGreaterThan(try run.host.store.snapshot().high,try run.client.witness(action:run.action).high)
        XCTAssertEqual(cut.inputTokens,cut.probe.promptTokens);XCTAssertTrue(cut.completed.isEmpty)
        try run.reopen()
        for step in 1...g.pendingTokens {
            try run.advanceUnit(until:{_ in true})
            let now=try XCTUnwrap(run.progress.guided)
            XCTAssertEqual(now.sampledTokens,g.sampledTokens);XCTAssertEqual(now.forcedTokens,g.forcedTokens+step)
            XCTAssertEqual(now.pendingTokens,g.pendingTokens-step);XCTAssertEqual(now.accepts,g.accepts)
        }
        try run.advance(to:"finalReady");let ready=try run.progress
        XCTAssertEqual(ready.completed.count,1);XCTAssertEqual(ready.completed[0].kind,"schema")
        XCTAssertEqual(ready.inputTokens,2*ready.probe.promptTokens)
        XCTAssertEqual(ready.outputTokens,ready.probe.generationTokens+ready.guided!.sampledTokens+ready.guided!.forcedTokens)
        XCTAssertEqual(try JSONSerialization.jsonObject(with:ready.whole) as? [String:String],["value":"中"])
        try run.reopen();try run.advanceUnit();XCTAssertEqual(run.calls,0)
        try run.terminalReplayAndDuplicate();XCTAssertLessThanOrEqual(Memory.peakMemory,128<<20)
    } }
    func testCombinedToolPrecedenceLeavesUnsupportedFallbackUncompiled() throws { try LocalDurableRuntime.withCPU {
        let run=try AllowedNativeTestRun(profile:AllowedNativeTestProfile(),request:SchemaToolNativeTestRun.request(lazy:true))
        try run.advanceUnit(until:{$0.probe.rawTokens>0});XCTAssertEqual(try run.progress.proseDelivered,0)
        XCTAssertEqual(try run.client.witness(action:run.action).high,0);try run.reopen()
        try run.advance(to:"routeReady");XCTAssertEqual(try run.progress.route,"calls")
        try run.advance(to:"finalReady");let ready=try run.progress
        XCTAssertEqual(ready.completed.count,1);XCTAssertEqual(ready.completed[0].kind,"tool")
        XCTAssertEqual(ready.completedCalls.count,1);XCTAssertEqual(ready.schemaReturnedBytes,0)
        XCTAssertEqual(try run.client.witness(action:run.action).high,0)
        XCTAssertEqual(ready.inputTokens,ready.probe.promptTokens+ready.current!.tokens.count)
        try run.reopen();try run.advanceUnit(deliver:false);XCTAssertEqual(run.profile.calls,0)
        try run.terminalReplayAndDuplicate(expectedCalls:1)
    } }
    func testSelectedUnsupportedSchemaThrowsAfterFactoryWithoutNativePreparation() throws { try LocalDurableRuntime.withCPU {
        let run=try SchemaToolNativeTestRun(maximum:2,lazy:true);try run.advance(to:"routeReady")
        let selected=try run.host.store.snapshot().candidate!,calls=run.calls,models=run.fixture.counter.models
        let receipt=try run.client.witness(action:run.action)
        XCTAssertThrowsError(try run.advanceUnit())
        XCTAssertEqual(run.calls,calls);XCTAssertEqual(run.fixture.counter.models,models+1)
        XCTAssertEqual(try run.host.store.snapshot().candidate!.commit,selected.commit)
        XCTAssertFalse(try run.host.store.snapshot().terminal);XCTAssertEqual(try run.client.witness(action:run.action),receipt)
    } }
    func testIncompleteSchemaRetainsLastFragmentAndErrorWithoutUsageOrCall() throws { try LocalDurableRuntime.withCPU {
        for maximum in [2,18] {
            let run=try SchemaToolNativeTestRun(maximum:maximum);try run.advance(to:"finalEmitted")
            let p=try run.progress
            XCTAssertEqual(p.outcome,"incompleteGuidance");XCTAssertEqual(p.guided?.interceptedEndings,0)
            XCTAssertEqual(p.guided?.consumedTokens,maximum);XCTAssertTrue(p.completed.isEmpty);XCTAssertTrue(p.completedCalls.isEmpty)
            XCTAssertEqual(p.inputTokens,p.probe.promptTokens);XCTAssertEqual(p.outputTokens,p.probe.generationTokens)
            let inbox=try run.client.inbox(action:run.action),last=try JSONDecoder().decode([WireEvent].self,from:XCTUnwrap(inbox.last).bytes)
            XCTAssertGreaterThan(last.count,1)
            guard case .responseAppend=last[0],case .finished(.error)?=last.last else {return XCTFail("partial schema plus error")}
            let events=try inbox.flatMap{try JSONDecoder().decode([WireEvent].self,from:$0.bytes)}
            XCTAssertFalse(events.contains {if case .usage=$0 {return true};if case .toolCallAppendArguments=$0 {return true};return false})
            if maximum==18 {XCTAssertEqual(try JSONSerialization.jsonObject(with:p.whole) as? [String:String],["value":"中"])}
            try run.terminalReplayAndDuplicate()
        }
    } }
    func testPendingStaleAndForgedSchemaProgressRefuse() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(request:SchemaToolNativeTestRun.request(maximum:2)),owner="progress"
        let live=try ResumableMLXProvider.prepare(binding:f.provider,runtime:f.runtime(),owner:owner,credit:ResumableMLXProvider.reservationBytes);defer {live.close()}
        var selected=try XCTUnwrap(live.pendingCandidate());XCTAssertThrowsError(try live.committedAllowedProgress(selected))
        try live.acceptCommit(selected.commit,owner:owner)
        repeat {
            let old=selected
            selected=try XCTUnwrap(live.advance(owner:owner,current:selected.commit,credit:ResumableMLXProvider.reservationBytes))
            XCTAssertThrowsError(try live.committedAllowedProgress(selected));XCTAssertThrowsError(try live.committedAllowedProgress(old))
            try live.acceptCommit(selected.commit,owner:owner)
        } while try live.committedAllowedProgress(selected).phase != "guided"
        let p=try live.committedAllowedProgress(selected)
        for variant in 0..<6 {
            var value=try JSONSerialization.jsonObject(with:AuthorityCodec.encode(p)) as! [String:Any]
            var pass=value["current"] as! [String:Any]
            switch variant {
            case 0:value["proseDelivered"]=1
            case 1:value["inputTokens"]=2*p.inputTokens
            case 2:pass["proposalID"]="unexpected"
            case 3:pass["messagesDigest"]=String(repeating:"a",count:64)
            case 4:pass["tokens"]=[1]
            default:value["proposals"]=[["id":"one","name":"a","arguments":"{}"],["id":"two","name":"a","arguments":"{}"]]
            }
            value["current"]=pass
            let wrong=try JSONDecoder().decode(ProviderAllowedProgress.self,from:JSONSerialization.data(withJSONObject:value))
            XCTAssertThrowsError(try NativeRecoveryAllowed.validate(wrong,binding:f.provider))
        }
        live.close();XCTAssertThrowsError(try live.committedAllowedProgress(selected))
    } }
    func testProbeAndSchemaCancellationPreserveOnlyCommittedPrefix() throws { try LocalDurableRuntime.withCPU {
        for phase in ["probe","guided"] {
            let f=try NativeRecoveryFixture(request:SchemaToolNativeTestRun.request(maximum:18));_=try f.provision()
            let a=try f.action(.reopen),client=try f.openClient(a);defer {client.close();try? a.finish()}
            let owner="cancel",live=try ResumableMLXProvider.prepare(binding:f.provider,runtime:f.runtime(),owner:owner,credit:ResumableMLXProvider.reservationBytes)
            defer {live.close()}
            var selected=try XCTUnwrap(live.pendingCandidate()),high:UInt64=0
            try live.acceptCommit(selected.commit,owner:owner)
            func receive() throws {
                let events=try JSONDecoder().decode([WireEvent].self,from:selected.eventBytes)
                if !events.isEmpty {try client.accept(.init(firstSequence:high+1,count:events.count,providerCommit:selected.commit.identity,eventBytes:selected.eventBytes),action:a);high+=UInt64(events.count)}
            }
            for _ in 0..<40 {
                let p=try live.committedAllowedProgress(selected)
                if p.phase==phase && (phase=="probe" ? p.probe.rawTokens>0 : p.schemaReturnedBytes>0) {break}
                selected=try XCTUnwrap(live.advance(owner:owner,current:selected.commit,credit:ResumableMLXProvider.reservationBytes))
                try live.acceptCommit(selected.commit,owner:owner);try receive()
            }
            XCTAssertEqual(try live.committedAllowedProgress(selected).phase,phase)
            let before=try client.inbox(action:a),calls=f.counter.calls
            selected=try XCTUnwrap(live.cancel(owner:owner,current:selected.commit,credit:ResumableMLXProvider.reservationBytes));try live.acceptCommit(selected.commit,owner:owner);try receive()
            let p=try live.committedAllowedProgress(selected);try NativeRecoveryAllowed.validate(p,binding:f.provider)
            XCTAssertEqual(p.outcome,"cancelled");XCTAssertTrue(p.completed.isEmpty);XCTAssertEqual(p.proseDelivered,0)
            XCTAssertEqual(f.counter.calls,calls);XCTAssertEqual(try JSONDecoder().decode([WireEvent].self,from:selected.eventBytes),[.finished(.cancelled)])
            XCTAssertEqual(try client.witness(action:a).registrations,0)
            XCTAssertEqual(try AuthorityCodec.encode(Array(client.inbox(action:a).prefix(before.count))),try AuthorityCodec.encode(before))
        }
    } }
}
