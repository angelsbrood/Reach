import Foundation
import XCTest
import ReachWire
import WireAdapterContract
import DurableHostWireAdapter
import DurableClientReceipts
import RequestPreparationContract
import RequestPreparationFixtures
import SchemaPreparationFixtures
import ResumableMLXProvider

final class SchemaRecoveryTests:XCTestCase {
    func testDeferredClientBeginDoesNotEnroll() throws { try onCPU {
        let f=try SchemaPreparationFixtures.pair();defer { try? f.remove() }
        try f.toClient(f.host.capabilities());_=try f.exchange(f.client.open(requestID:"open"));let phase=f.client.negotiation.phase
        for native:Data? in [nil,Data(#"{"type":"string"}"#.utf8)] {
            deferredRefusal { _=try f.client.begin(requestID:"begin",generation:"generation",operation:"operation",request:deferred(native)) }
            XCTAssertEqual(f.client.negotiation.phase,phase)
        }
        XCTAssertEqual(f.host.begins,0);XCTAssertNil(f.host.status)
        XCTAssertEqual(f.native.preparer.preparations,0);XCTAssertEqual(f.native.tokenizer.encodes,0);XCTAssertEqual(f.native.factories,0)
        XCTAssertTrue(try f.clientOwner.discover(binding:WireFixture.binding(f.core),authorization:f.clientAuth).isEmpty)
        for directory in ["requests","children"] { XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath:f.root+"/host/"+directory).isEmpty) }
    } }
    func testGuidedSubstitutionRefusesClientEnrollment() throws { try onCPU {
        for variant in ["text","schema","options"] {
            let f=try SchemaPreparationFixtures.pair();defer { try? f.remove() }
            try f.toClient(f.host.capabilities());_=try f.exchange(f.client.open(requestID:"open"))
            let bytes=try f.client.begin(requestID:"begin",generation:"generation",operation:"operation",request:SchemaPreparationFixtures.request())
            var decoder=FrameReassembler();var frame:DurableGenerateBegin=try decoder.feed(bytes)[0].decode()
            if variant=="text" { frame.payload.request=try SchemaPreparationFixtures.request(text:"Changed prompt") }
            if variant=="schema" { frame.payload.request.portableSchema=try SchemaPreparationFixtures.request("eight").portableSchema }
            if variant=="options" { frame.payload.request.options.maximumResponseTokens=255 }
            let reply=try XCTUnwrap(f.toHost(DurableMessage.begin(frame).encode(version:2)).first)
            XCTAssertThrowsError(try f.toClient(reply));XCTAssertEqual(f.native.model.calls,0)
            XCTAssertTrue(try f.clientOwner.discover(binding:WireFixture.binding(f.core),authorization:f.clientAuth).isEmpty)
        }
    } }
    func testDuplicateGuidedBeginAndChangedSameOperation() throws { try onCPU {
        let f=try SchemaPreparationFixtures.pair();defer { try? f.remove() };try f.start(SchemaPreparationFixtures.request())
        let binding=try f.stored(),bytes=try XCTUnwrap(f.beginBytes),again=try f.toHost(bytes)
        var d=FrameReassembler();let accepted:DurableGenerationAccepted=try d.feed(XCTUnwrap(again.first))[0].decode()
        XCTAssertEqual(accepted.payload.context,f.accepted?.context);XCTAssertEqual(accepted.payload.reference,f.accepted?.reference)
        XCTAssertEqual(accepted.payload.requestID,"begin-1")
        for variant in ["text","schema","options"] {
            var decoder=FrameReassembler();var frame:DurableGenerateBegin=try decoder.feed(bytes)[0].decode()
            if variant=="text" { frame.payload.request=try SchemaPreparationFixtures.request(text:"Changed") }
            if variant=="schema" { frame.payload.request.portableSchema=try SchemaPreparationFixtures.request("eight").portableSchema }
            if variant=="options" { frame.payload.request.options.maximumResponseTokens=255 }
            let reply=try f.toHost(DurableMessage.begin(frame).encode(version:2));var r=FrameReassembler()
            let refused:DurableRefused=try r.feed(XCTUnwrap(reply.first))[0].decode();XCTAssertEqual(refused.payload.correlation.operation,.begin)
        }
        XCTAssertEqual(try PreparationEncoding.encode(binding),try PreparationEncoding.encode(f.stored()));XCTAssertEqual(f.native.model.calls,0)
    } }
    func testRecoveryValidationPrecedesAttachAndAcceptance() throws { try onCPU {
        let initial=try SchemaPreparationFixtures.pair(),root=initial.root;try initial.start(SchemaPreparationFixtures.request());try initial.step();initial.close()
        let f=try SchemaPreparationFixtures.pair(root:root,fresh:false);defer { try? f.remove() };let n=f.native;var validations=0
        f.host=try .init(configuration:n.configuration,owner:f.hostOwner,authorization:f.hostAuth,expectedClientRoot:f.core.clientID,allowNew:false,
            prepare:{_,_,_ in XCTFail("recovery prepared request");throw PreparationError.identity},runtime:{try n.runtime($0,configuration:$1)},requestPolicy:n.preparer.policy,
            validatePrepared:{stored,configuration in
                validations+=1;var changed=stored;var g=try guided(stored);g.specification.tokenizerIdentity="drift";changed.lane = .guided(g)
                try n.preparer.validateStored(changed,configuration:configuration)
            })
        XCTAssertThrowsError(try f.recover());XCTAssertEqual(validations,1);XCTAssertEqual(f.host.recoveries,0)
        XCTAssertEqual(n.model.calls,0);XCTAssertEqual(n.factories,0);XCTAssertEqual(n.preparer.preparations,0);XCTAssertEqual(n.tokenizer.encodes,0)
    } }
    func testCompilerFailureAfterDeclarationBeforePrefill() throws { try onCPU {
        let f=try SchemaPreparationFixtures.pair();defer { try? f.remove() };var r=try SchemaPreparationFixtures.request()
        // Swift's portable regex validates this lookahead. The selected xgrammar
        // regex converter explicitly rejects it; assess does not compile it.
        r.portableSchema=try .init(jsonValue:.object(["type":.string("string"),"pattern":.string("^(?=a)a$")]))
        try f.start(r);XCTAssertNotNil(f.accepted);XCTAssertEqual(f.host.begins,1)
        let b=try f.stored();guard case .supported=ResumableMLXProvider.assess(b) else { return XCTFail() }
        XCTAssertEqual(f.native.factories,0);XCTAssertThrowsError(try f.step())
        XCTAssertEqual(f.native.factories,1);XCTAssertEqual(f.native.model.calls,0);XCTAssertEqual(f.native.model.prepares,0)
        XCTAssertFalse(f.terminal);XCTAssertTrue(f.batches.isEmpty)
    } }
    func testGuidedCancellationKeepsExistingEventMapping() throws { try onCPU {
        let f=try SchemaPreparationFixtures.native(),b=try prepared(f,SchemaPreparationFixtures.request())
        let provider=try ResumableMLXProvider.prepare(binding:b,runtime:f.runtime(b,configuration:f.configuration),owner:"owner",credit:ResumableMLXProvider.reservationBytes)
        defer { provider.close() };let c0=try XCTUnwrap(provider.pendingCandidate());try provider.acceptCommit(c0.commit,owner:"owner")
        let before=f.model.calls
        let cancelled=try XCTUnwrap(provider.cancel(owner:"owner",current:c0.commit,credit:ResumableMLXProvider.reservationBytes))
        XCTAssertEqual(try JSONDecoder().decode([WireEvent].self,from:cancelled.eventBytes),[.finished(.cancelled)])
        XCTAssertEqual(f.model.calls,before);try provider.acceptCommit(cancelled.commit,owner:"owner");XCTAssertTrue(provider.isTerminal)
    } }
}
