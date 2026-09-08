import Foundation
import XCTest
import ReachWire
import RequestPreparationContract
import RequestPreparationFixtures
import SchemaToolPreparationFixtures
import AllowedToolCoordinator
import ResumableMLXProvider
import WireAdapterContract
import DurableHostWireAdapter
import DurableClientReceipts

final class SchemaToolRecoveryTests:XCTestCase {
    func testBothDeferredSchemasRefuseNegotiatedEnrollment() throws { try cpu {
        let f=try SchemaToolNativeFixture(family:"llama"),p=try f.pair();defer { try? p.remove() }
        try p.toClient(p.host.capabilities());_=try p.exchange(p.client.open(requestID:"open"));let phase=p.client.negotiation.phase
        for response in [false,true] { for native:Data? in [nil,Data(#"{"type":"object"}"#.utf8)] {
            deferredRefusal { _=try p.client.begin(requestID:"begin",generation:"generation",operation:"operation",request:deferred(native,response:response)) }
            XCTAssertEqual(p.client.negotiation.phase,phase)
        } }
        XCTAssertEqual(p.host.begins,0);XCTAssertNil(p.host.status);XCTAssertTrue(f.models.isEmpty);XCTAssertEqual(f.native.tokenizer.encodes,0)
        XCTAssertTrue(try p.clientOwner.discover(binding:WireFixture.binding(p.core),authorization:p.clientAuth).isEmpty)
    } }
    func testCombinedSubstitutionDuplicateAndPreAttachDrift() throws { try cpu {
        for variant in ["response","tools","text","options"] {
            let f=try SchemaToolNativeFixture(family:"llama"),p=try f.pair();defer { try? p.remove() }
            try p.toClient(p.host.capabilities());_=try p.exchange(p.client.open(requestID:"open"))
            let original=try p.client.begin(requestID:"begin",generation:"generation",operation:"operation",request:SchemaToolPreparationFixtures.request())
            var decoder=FrameReassembler();var frame:DurableGenerateBegin=try decoder.feed(original)[0].decode()
            if variant=="response" { frame.payload.request.portableSchema=try SchemaToolPreparationFixtures.response(8) }
            if variant=="tools" { frame.payload.request.tools[0].description="Changed tool." }
            if variant=="text" { frame.payload.request=try SchemaToolPreparationFixtures.request(text:"Changed prompt") }
            if variant=="options" { frame.payload.request.options.maximumResponseTokens=95 }
            let reply=try XCTUnwrap(p.toHost(DurableMessage.begin(frame).encode(version:2)).first);XCTAssertThrowsError(try p.toClient(reply))
            XCTAssertTrue(try p.clientOwner.discover(binding:WireFixture.binding(p.core),authorization:p.clientAuth).isEmpty);XCTAssertEqual(f.calls,0)
        }
        let f=try SchemaToolNativeFixture(family:"llama"),p=try f.pair(),root=p.root;try p.start(SchemaToolPreparationFixtures.request())
        let saved=try p.stored(),bytes=try XCTUnwrap(p.beginBytes),reply=try p.toHost(bytes);var decoder=FrameReassembler()
        let again:DurableGenerationAccepted=try decoder.feed(XCTUnwrap(reply.first))[0].decode()
        XCTAssertEqual(again.payload.context,p.accepted?.context);XCTAssertEqual(again.payload.reference,p.accepted?.reference);XCTAssertEqual(again.payload.requestID,"begin-1")
        var d=FrameReassembler();var changed:DurableGenerateBegin=try d.feed(bytes)[0].decode();changed.payload.request.portableSchema=try SchemaToolPreparationFixtures.response(8)
        let rejected=try p.toHost(DurableMessage.begin(changed).encode(version:2));var rr=FrameReassembler();let no:DurableRefused=try rr.feed(XCTUnwrap(rejected.first))[0].decode()
        XCTAssertEqual(no.payload.correlation.operation,.begin);XCTAssertEqual(try PreparationEncoding.encode(saved),try PreparationEncoding.encode(p.stored()))
        try p.step();p.close()
        let fresh=try SchemaToolNativeFixture(family:"llama"),q=try fresh.pair(root:root,fresh:false);defer { try? q.remove() };let n=fresh.native;var validations=0
        q.host=try .init(configuration:n.configuration,owner:q.hostOwner,authorization:q.hostAuth,expectedClientRoot:q.core.clientID,allowNew:false,
            prepare:{_,_,_ in XCTFail("recovery prepared original request");throw PreparationError.identity},runtime:{try fresh.runtime($0,configuration:$1)},requestPolicy:n.preparer.policy,
            validatePrepared:{b,c in validations+=1;var changed=b;var a=try allowed(b);a.responseSchema=nil;changed.lane = .allowed(a);try n.preparer.validateStored(changed,configuration:c)})
        XCTAssertThrowsError(try q.recover());XCTAssertEqual(validations,1);XCTAssertEqual(q.host.recoveries,0);XCTAssertTrue(fresh.models.isEmpty);XCTAssertEqual(n.preparer.preparations,0)
    } }
    func testLazyFallbackCompilerErrorAfterProbeBeforeFallbackForwards() throws { try cpu {
        let f=try SchemaToolNativeFixture(family:"llama"),p=try f.pair();defer { try? p.remove() };try p.start(SchemaToolPreparationFixtures.request("lazy"))
        XCTAssertNotNil(p.accepted);XCTAssertTrue(f.models.isEmpty)
        guard case .supported=ResumableMLXProvider.assess(try p.stored()) else { return XCTFail() }
        XCTAssertThrowsError(try { for _ in 0..<20 { try p.step() } }())
        XCTAssertEqual(f.models.map{$0.0.kind.rawValue},["probe","schema"])
        XCTAssertGreaterThan(f.models[0].1.calls,0);XCTAssertEqual(f.models[1].1.calls,0);XCTAssertEqual(f.prepares,0)
        XCTAssertTrue(p.batches.isEmpty);XCTAssertFalse(p.terminal) // Thrown error is not an invented wire terminal.
    } }
    func testActiveCancellationHidesProbeAndStartsNoLaterPass() throws { try cpu {
        for schemaActive in [false,true] {
            let f=try SchemaToolNativeFixture(family:"llama");var r=try SchemaToolPreparationFixtures.request();r.options.maximumResponseTokens=4
            let b=try prepared(f.native,r),provider=try ResumableMLXProvider.prepare(binding:b,runtime:f.runtime(b,configuration:f.native.configuration),owner:"owner",credit:ResumableMLXProvider.reservationBytes)
            defer { provider.close() };var current=try XCTUnwrap(provider.pendingCandidate());try provider.acceptCommit(current.commit,owner:"owner")
            if schemaActive {
                for _ in 0..<20 {
                    if f.models.last?.0.kind == .schema { break }
                    current=try XCTUnwrap(provider.advance(owner:"owner",current:current.commit,credit:ResumableMLXProvider.reservationBytes))
                    XCTAssertEqual(try JSONDecoder().decode([WireEvent].self,from:current.eventBytes),[])
                    try provider.acceptCommit(current.commit,owner:"owner")
                }
                XCTAssertEqual(f.models.last?.0.kind.rawValue,"schema")
            }
            let before=f.calls,count=f.models.count
            let cancelled=try XCTUnwrap(provider.cancel(owner:"owner",current:current.commit,credit:ResumableMLXProvider.reservationBytes))
            XCTAssertEqual(try JSONDecoder().decode([WireEvent].self,from:cancelled.eventBytes),[.finished(.cancelled)])
            XCTAssertEqual(f.calls,before);XCTAssertEqual(f.models.count,count)
        }
    } }
}
