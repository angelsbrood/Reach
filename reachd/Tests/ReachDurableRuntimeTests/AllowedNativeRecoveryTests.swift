import XCTest
import Foundation
import MLX
import MLXLMCommon
import AllowedToolCoordinator
import ReachWire
import WireAdapterContract
import ResumableMLXProvider
import RecoveryAuthorityContract
import HostClientContract
@testable import ReachDurableRuntime
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts

final class AllowedNativeRecoveryTests:XCTestCase {
    func testClosedAllowedBoundsAndOriginalSelection() throws { try LocalDurableRuntime.withCPU {
        let p=try AllowedNativeTestProfile(),good=try p.binding()
        guard case .allowed(let original)=good.lane else { return XCTFail("allowed") }
        try NativeRecoveryBinding.validate(good)
        for maximum in [0,1,64,65] {
            var b=original;b.probeOptions.maximumTokens=maximum;b.guidedOptions.model.maximumTokens=maximum
            var candidate=good;candidate.lane = .allowed(b)
            if maximum==1 || maximum==64 { try NativeRecoveryBinding.validate(candidate) }
            else { XCTAssertThrowsError(try NativeRecoveryBinding.validate(candidate)) }
        }
        for count in [1,256,512,513] {
            var b=original;b.originalTokens=[Int](repeating:1,count:count)
            for probe in [true,false] {
                var model=probe ? b.probeModel : b.guidedModel
                let i=model.identity;model.identity = .init(model:i.model,configuration:i.configuration,weights:i.weights,input:try ResumableTokenIdentity.inputDigest(b.originalTokens),backend:i.backend,dependency:i.dependency)
                if probe { b.probeModel=model } else { b.guidedModel=model }
            }
            var candidate=good;candidate.lane = .allowed(b)
            if count<=512 { try NativeRecoveryBinding.validate(candidate) }
            else { XCTAssertThrowsError(try NativeRecoveryBinding.validate(candidate)) }
        }
        for variant in 0..<6 {
            var b=original
            switch variant {
            case 0:b.tools.append(.init(name:"extra",schemaJSON:b.tools[0].schemaJSON))
            case 1:b.responseSchema="{}"
            case 2:b.probeOptions.prefillStepSize=64
            case 3:b.guidedOptions.model.prefillStepSize=64
            case 4:b.guidedOptions.model.maximumTokens=63
            default:b.requestIdentity="replacement"
            }
            var candidate=good;candidate.lane = .allowed(b)
            XCTAssertThrowsError(try NativeRecoveryBinding.validate(candidate))
        }
        for variant in 0..<4 {
            var b=original
            switch variant { case 0:b.entryID="replacement";case 1:b.namespace=String(repeating:"f",count:32);case 2:b.probeModel.codecIdentity="replacement";default:b.guidedOptions.completionReserve=1 }
            var candidate=good;candidate.lane = .allowed(b)
            XCTAssertThrowsError(try p.runtime(candidate));XCTAssertEqual(p.calls,0)
        }
    } }
    func testProbeGuidedReadyAndModelFreeTerminalRestores() throws { try LocalDurableRuntime.withCPU {
        let run=try AllowedNativeTestRun(profile:AllowedNativeTestProfile())
        try run.advanceUnit(until:{$0.proseDelivered>0});XCTAssertEqual(try run.progress.phase,"probe")
        XCTAssertGreaterThan(try run.client.witness(action:run.action).high,0);try run.reopen()
        try run.advance(to:"routeReady");XCTAssertEqual(try run.progress.proposals.count,1)
        try run.advanceUnit();XCTAssertEqual(try run.progress.phase,"guided")
        try run.advanceUnit(until:{($0.guided?.pendingTokens ?? 0)>0})
        let cut=try run.progress;XCTAssertGreaterThan(cut.guided?.pendingTokens ?? 0,0);XCTAssertFalse(cut.whole.isEmpty)
        try run.reopen()
        let pending=cut.guided!.pendingTokens
        for step in 1...pending {
            try run.action.finish();run.action=try run.fixture.action(.advance,owner:run.owner)
            try run.generation.advance(action:run.action);try run.host.synchronize(action:run.action)
            try run.fixture.deliver(run.host,run.client,run.generation,run.action)
            let now=try run.progress
            XCTAssertEqual(now.guided?.sampledTokens,cut.guided?.sampledTokens)
            XCTAssertEqual(now.guided?.forcedTokens,cut.guided!.forcedTokens+step)
            XCTAssertEqual(now.guided?.pendingTokens,pending-step)
        }
        try run.advance(to:"finalReady");let ready=try run.progress
        XCTAssertEqual(ready.completedCalls.count,1);XCTAssertEqual(ready.guided?.interceptedEndings,1)
        XCTAssertEqual(try run.client.witness(action:run.action).registrations,0)
        let high=try run.client.witness(action:run.action).high
        try run.reopen();try run.advanceUnit(deliver:false)
        XCTAssertEqual(run.profile.calls,0);XCTAssertEqual(try run.host.store.snapshot().high,high+3)
        XCTAssertEqual(try run.client.witness(action:run.action).high,high)
        try run.terminalReplayAndDuplicate(expectedCalls:1)
        XCTAssertLessThanOrEqual(run.owner.actionCount,64)
    } }
    func testNoCallProseCompletionReopenAndDuplicate() throws { try LocalDurableRuntime.withCPU {
        let run=try AllowedNativeTestRun(profile:AllowedNativeTestProfile(probe:"Plain prose."))
        try run.advanceUnit();try run.reopen();try run.advance(to:"finalReady")
        XCTAssertEqual(try run.progress.route,"prose");XCTAssertTrue(try run.progress.proposals.isEmpty)
        try run.reopen();try run.advanceUnit(deliver:false)
        XCTAssertEqual(run.profile.calls,0);try run.terminalReplayAndDuplicate(expectedCalls:0)
    } }
    func testGuidedExhaustionSharedBudgetAndCompleteEnvelopeWithoutEOS() throws { try LocalDurableRuntime.withCPU {
        for length in [31,40] {
            let run=try AllowedNativeTestRun(profile:AllowedNativeTestProfile(length:length))
            try run.advance(to:"finalEmitted")
            let progress=try run.progress
            XCTAssertEqual(progress.outcome,"incompleteGuidance");XCTAssertEqual(progress.guided?.consumedTokens,64)
            XCTAssertEqual(progress.guided?.interceptedEndings,0);XCTAssertEqual(progress.completedCalls.count,0)
            let events=try run.client.inbox(action:run.action).flatMap{try JSONDecoder().decode([WireEvent].self,from:$0.bytes)}
            XCTAssertTrue(events.contains{if case .responseAppend = $0 {true} else {false}})
            XCTAssertFalse(events.contains{if case .toolCallAppendArguments = $0 {true} else if case .usage = $0 {true} else {false}})
            if length==31 {
                XCTAssertEqual(progress.whole.count,64)
                XCTAssertNoThrow(try JSONSerialization.jsonObject(with:progress.whole))
            }
            try run.terminalReplayAndDuplicate(expectedCalls:0)
        }
    } }
    func testUnknownProposalFailsBeforeGuidedPreparation() throws { try LocalDurableRuntime.withCPU {
        // The selected JSON parser filters unoffered names. Exercise the
        // coordinator's existing all-name guard using its accepted XML parser,
        // with the same native state model; this is not a new durable format.
        let p=try AllowedNativeTestProfile(probe:"P<tool_call><function=b></function></tool_call>"),binding=try p.binding()
        guard case .allowed(var b)=binding.lane,case .allowed(let runtime)=try p.runtime(binding) else { return XCTFail("allowed") }
        b.format = .xmlFunction
        let live=try AllowedToolCoordinator.prepare(binding:b,runtime:runtime);defer {live.close()}
        for _ in 0..<64 { if live.phase != .probe {break};_=try live.advance() }
        XCTAssertEqual(live.phase,.routeReady)
        let progress=try live.validatedProgress(live.capture());XCTAssertEqual(progress.outcome,"unknownTool")
        XCTAssertEqual(progress.proposals.count,1);let calls=p.calls
        let end=try XCTUnwrap(live.advance())
        XCTAssertEqual(end.events,[.finished(.error(AllowedToolCoordinator.unknownMessage))])
        XCTAssertEqual(p.calls,calls);XCTAssertEqual(p.native.observations.count,1)
        XCTAssertEqual(live.phase,.finalEmitted)
    } }
    func testProbeAndGuidedCancellationPreserveProseAndRegisterNoCall() throws { try LocalDurableRuntime.withCPU {
        for phase in ["probe","guided"] {
            let p=try AllowedNativeTestProfile(),binding=try p.binding(),f=try NativeRecoveryFixture(prepared:binding)
            _=try f.provision();let a=try f.action(.reopen),client=try f.openClient(a)
            defer {client.close();try? a.finish()}
            let live=try ResumableMLXProvider.prepare(binding:binding,runtime:p.runtime(binding),owner:"cancel",credit:ResumableMLXProvider.reservationBytes)
            defer {live.close()}
            var selected=try XCTUnwrap(live.pendingCandidate());try live.acceptCommit(selected.commit,owner:"cancel")
            var high:UInt64=0
            func receive(_ c:ProviderCandidate) throws {
                let events=try JSONDecoder().decode([WireEvent].self,from:c.eventBytes)
                if !events.isEmpty {
                    try client.accept(.init(firstSequence:high+1,count:events.count,providerCommit:c.commit.identity,eventBytes:c.eventBytes),action:a)
                    high+=UInt64(events.count)
                }
            }
            for _ in 0..<100 {
                let progress=try live.committedAllowedProgress(selected)
                if progress.phase==phase && progress.proseDelivered>0 {break}
                selected=try XCTUnwrap(live.advance(owner:"cancel",current:selected.commit,credit:ResumableMLXProvider.reservationBytes))
                try live.acceptCommit(selected.commit,owner:"cancel");try receive(selected)
            }
            XCTAssertEqual(try live.committedAllowedProgress(selected).phase,phase)
            let before=p.calls,beforeInbox=try client.inbox(action:a)
            selected=try XCTUnwrap(live.cancel(owner:"cancel",current:selected.commit,credit:ResumableMLXProvider.reservationBytes))
            try live.acceptCommit(selected.commit,owner:"cancel");try receive(selected)
            let progress=try live.committedAllowedProgress(selected)
            try NativeRecoveryAllowed.validate(progress,binding:binding)
            XCTAssertEqual(progress.outcome,"cancelled");XCTAssertEqual(progress.phase,"finalEmitted")
            XCTAssertEqual(p.calls,before);XCTAssertEqual(try JSONDecoder().decode([WireEvent].self,from:selected.eventBytes),[.finished(.cancelled)])
            let receipt=try client.witness(action:a);XCTAssertTrue(receipt.terminal);XCTAssertEqual(receipt.registrations,0)
            XCTAssertEqual(try AuthorityCodec.encode(Array(client.inbox(action:a).prefix(beforeInbox.count))),try AuthorityCodec.encode(beforeInbox))
        }
    } }
    func testOversizedRepairRefusesBeforeModelFactory() throws { try LocalDurableRuntime.withCPU {
        let p=try AllowedNativeTestProfile(),binding=try p.binding()
        guard case .allowed(let b)=binding.lane,case .allowed(let runtime)=try p.runtime(binding) else { return XCTFail("allowed runtime") }
        let call=ToolCall(function:.init(name:"a",arguments:["large":.string(String(repeating:"x",count:300))]),id:"proposal")
        let pass=try AllowedToolReplayInput.prepare(binding:b,kind:.tool,proposal:call,tokenizer:p.native.tokenizer)
        XCTAssertGreaterThan(pass.tokens.count,512)
        XCTAssertThrowsError(try runtime.model(pass));XCTAssertTrue(p.native.observations.isEmpty);XCTAssertEqual(p.calls,0)
    } }
    func testPendingOldAndClosedProgressRefuse() throws { try LocalDurableRuntime.withCPU {
        let p=try AllowedNativeTestProfile(),b=try p.binding(),owner="selected"
        let live=try ResumableMLXProvider.prepare(binding:b,runtime:p.runtime(b),owner:owner,credit:ResumableMLXProvider.reservationBytes)
        let first=try XCTUnwrap(live.pendingCandidate())
        XCTAssertThrowsError(try live.committedAllowedProgress(first));try live.acceptCommit(first.commit,owner:owner)
        _=try live.committedAllowedProgress(first)
        let next=try XCTUnwrap(live.advance(owner:owner,current:first.commit,credit:ResumableMLXProvider.reservationBytes))
        XCTAssertThrowsError(try live.committedAllowedProgress(first));XCTAssertThrowsError(try live.committedAllowedProgress(next))
        try live.acceptCommit(next.commit,owner:owner);XCTAssertThrowsError(try live.committedAllowedProgress(first))
        _=try live.committedAllowedProgress(next);live.close();XCTAssertThrowsError(try live.committedAllowedProgress(next))
    } }
    func testMultipleProposalAndWrongAggregateRefuseBeforePreparationOrPublication() throws { try LocalDurableRuntime.withCPU {
        let run=try AllowedNativeTestRun(profile:AllowedNativeTestProfile());try run.advance(to:"routeReady")
        let progress=try run.progress,before=run.profile.calls
        var object=try JSONSerialization.jsonObject(with:AuthorityCodec.encode(progress)) as! [String:Any]
        var proposals=object["proposals"] as! [[String:Any]],extra=proposals[0];extra["id"]="second-original-proposal";proposals.append(extra);object["proposals"]=proposals
        let multiple=try JSONDecoder().decode(ProviderAllowedProgress.self,from:JSONSerialization.data(withJSONObject:object))
        XCTAssertThrowsError(try NativeRecoveryAllowed.validate(multiple,binding:run.fixture.provider));XCTAssertEqual(run.profile.calls,before)
        try run.advance(to:"finalReady")
        object=try JSONSerialization.jsonObject(with:AuthorityCodec.encode(run.progress)) as! [String:Any]
        object["inputTokens"]=1
        let wrong=try JSONDecoder().decode(ProviderAllowedProgress.self,from:JSONSerialization.data(withJSONObject:object))
        XCTAssertThrowsError(try NativeRecoveryAllowed.validate(wrong,binding:run.fixture.provider))
        XCTAssertEqual(try run.client.witness(action:run.action).registrations,0)
    } }
}
