import Foundation
import XCTest
import ReachWire
import RequestPreparationContract
import DurableRequestPreparation
import RequestPreparationFixtures
import AllowedPreparationFixtures
import AllowedToolCoordinator
import MLXLMCommon
import ResumableMLXProvider
import WireAdapterContract
import DurableHostWireAdapter
import DurableClientReceipts

final class AllowedRecoveryTests:XCTestCase {
    func testDeferredNegotiatedBeginRefusesBeforeEnrollment() throws { try cpu {
        let fixture=try AllowedNativeFixture(family:"state"),pair=try fixture.pair();defer { try? pair.remove() }
        try pair.toClient(pair.host.capabilities());_=try pair.exchange(pair.client.open(requestID:"open"));let phase=pair.client.negotiation.phase
        for native:Data? in [nil,Data(#"{"type":"object"}"#.utf8)] {
            deferredRefusal { _=try pair.client.begin(requestID:"begin",generation:"generation",operation:"operation",request:deferred(native)) }
            XCTAssertEqual(pair.client.negotiation.phase,phase)
        }
        XCTAssertEqual(pair.host.begins,0);XCTAssertNil(pair.host.status);XCTAssertTrue(fixture.models.isEmpty)
        XCTAssertEqual(fixture.native.preparer.preparations,0);XCTAssertEqual(fixture.native.tokenizer.encodes,0)
        XCTAssertTrue(try pair.clientOwner.discover(binding:WireFixture.binding(pair.core),authorization:pair.clientAuth).isEmpty)
        for directory in ["requests","children"] { XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath:pair.root+"/host/"+directory).isEmpty) }
    } }
    func testBeginSubstitutionAndDuplicateOperationPreserveOriginalBinding() throws { try cpu {
        for variant in ["text","name","schema","options"] {
            let f=try AllowedNativeFixture(family:"state"),p=try f.pair();defer { try? p.remove() }
            try p.toClient(p.host.capabilities());_=try p.exchange(p.client.open(requestID:"open"))
            let original=try p.client.begin(requestID:"begin",generation:"generation",operation:"operation",request:AllowedPreparationFixtures.request())
            var decoder=FrameReassembler();var frame:DurableGenerateBegin=try decoder.feed(original)[0].decode()
            if variant=="text" { frame.payload.request=try AllowedPreparationFixtures.request(text:"Changed prompt") }
            if variant=="name" { frame.payload.request.tools[0].name="renamed" }
            if variant=="schema" { frame.payload.request.tools=try AllowedPreparationFixtures.request("eight").tools }
            if variant=="options" { frame.payload.request.options.maximumResponseTokens=255 }
            let reply=try XCTUnwrap(p.toHost(DurableMessage.begin(frame).encode(version:2)).first);XCTAssertThrowsError(try p.toClient(reply))
            XCTAssertTrue(try p.clientOwner.discover(binding:WireFixture.binding(p.core),authorization:p.clientAuth).isEmpty);XCTAssertEqual(f.calls,0)
        }
        let f=try AllowedNativeFixture(family:"state"),p=try f.pair();defer { try? p.remove() };try p.start(AllowedPreparationFixtures.request())
        let bound=try p.stored(),bytes=try XCTUnwrap(p.beginBytes),reply=try p.toHost(bytes);var decoder=FrameReassembler()
        let again:DurableGenerationAccepted=try decoder.feed(XCTUnwrap(reply.first))[0].decode()
        XCTAssertEqual(again.payload.context,p.accepted?.context);XCTAssertEqual(again.payload.reference,p.accepted?.reference);XCTAssertEqual(again.payload.requestID,"begin-1")
        var d=FrameReassembler();var changed:DurableGenerateBegin=try d.feed(bytes)[0].decode();changed.payload.request.options.maximumResponseTokens=255
        let refused=try p.toHost(DurableMessage.begin(changed).encode(version:2));var r=FrameReassembler()
        let no:DurableRefused=try r.feed(XCTUnwrap(refused.first))[0].decode();XCTAssertEqual(no.payload.correlation.operation,.begin)
        XCTAssertEqual(try PreparationEncoding.encode(bound),try PreparationEncoding.encode(p.stored()));XCTAssertEqual(f.calls,0)
    } }
    func testSelectedStructuralIdentityAndRecoveryValidationPrecedeRuntime() throws { try cpu {
        let fixture=try AllowedNativeFixture(family:"state"),p=try fixture.pair(),root=p.root
        let d=fixture.native.preparer.policy.descriptor,llama=try AllowedNativeFixture(family:"llama").native.preparer.policy.descriptor
        XCTAssertNotEqual(d.model,llama.model);XCTAssertNotEqual(d.weights,llama.weights);XCTAssertNotEqual(d.configuration,llama.configuration)
        let changed:RequestPreparationContract.ModelDescriptor=try edited(d){$0["configuration"]="changed-script-policy"}
        XCTAssertThrowsError(try RequestPreparation(descriptor:changed,actualDescriptor:d,native:fixture.native.preparer.native,tokenizer:fixture.native.tokenizer))
        try p.start(AllowedPreparationFixtures.request());try p.step();p.close()
        let fresh=try AllowedNativeFixture(family:"state"),q=try fresh.pair(root:root,fresh:false);defer { try? q.remove() };let n=fresh.native;var validations=0
        q.host=try .init(configuration:n.configuration,owner:q.hostOwner,authorization:q.hostAuth,expectedClientRoot:q.core.clientID,allowNew:false,
            prepare:{_,_,_ in XCTFail("recovery prepared original request");throw PreparationError.identity},runtime:{try fresh.runtime($0,configuration:$1)},requestPolicy:n.preparer.policy,
            validatePrepared:{b,c in validations+=1;var changed=b;var a=try allowed(b);a.namespace=String(repeating:"b",count:32);changed.lane = .allowed(a);try n.preparer.validateStored(changed,configuration:c)})
        XCTAssertThrowsError(try q.recover());XCTAssertEqual(validations,1);XCTAssertEqual(q.host.recoveries,0);XCTAssertTrue(fresh.models.isEmpty)
        XCTAssertEqual(n.preparer.preparations,0);XCTAssertEqual(n.tokenizer.renders,0);XCTAssertEqual(n.tokenizer.requestTokenizations,0)
    } }
    func testJSONParserFiltersUndeclaredNameWithoutSuccessfulProposal() throws { try cpu {
        let f=try AllowedNativeFixture(family:"state"),b=try prepared(f.native,AllowedPreparationFixtures.request("unknown")),a=try allowed(b)
        let parser=try ResumableToolCallProcessor.prepare(configuration:a.parserConfiguration(),namespace:a.namespace);defer { parser.close() }
        let records=try parser.consume(AllowedPreparationFixtures.proposal).records + (parser.finish()?.records ?? [])
        let calls=records.compactMap { record -> ToolCall? in if case .toolCall(let call)=record { return call };return nil }
        XCTAssertEqual(calls.map(\.function.name),["beta"])
        XCTAssertFalse(calls.contains{$0.function.name=="alpha"});XCTAssertTrue(f.models.isEmpty)
    } }
    func testCancellationAndFinalReadyWinsMapping() throws { try cpu {
        let f=try AllowedNativeFixture(family:"state"),b=try prepared(f.native,AllowedPreparationFixtures.request())
        let provider=try ResumableMLXProvider.prepare(binding:b,runtime:f.runtime(b,configuration:f.native.configuration),owner:"owner",credit:ResumableMLXProvider.reservationBytes)
        defer { provider.close() };let c0=try XCTUnwrap(provider.pendingCandidate());try provider.acceptCommit(c0.commit,owner:"owner");let before=f.calls
        let cancelled=try XCTUnwrap(provider.cancel(owner:"owner",current:c0.commit,credit:ResumableMLXProvider.reservationBytes))
        XCTAssertEqual(try JSONDecoder().decode([WireEvent].self,from:cancelled.eventBytes),[.finished(.cancelled)]);XCTAssertEqual(f.calls,before)
        let zero=try AllowedNativeFixture(family:"state"),zb=try prepared(zero.native,AllowedPreparationFixtures.request("zero"))
        guard case .allowed(let runtime)=try zero.runtime(zb,configuration:zero.native.configuration) else { return XCTFail() }
        let coordinator=try AllowedToolCoordinator.prepare(binding:allowed(zb),runtime:runtime);defer { coordinator.close() }
        _=try coordinator.advance();XCTAssertEqual(coordinator.phase,.finalReady)
        let final=try XCTUnwrap(coordinator.cancel());XCTAssertEqual(final.events.last,.finished(.complete));XCTAssertTrue(final.events.contains{if case .usage=$0 { return true };return false})
        XCTAssertEqual(zero.calls,0);XCTAssertNil(try coordinator.advance())
    } }
}
