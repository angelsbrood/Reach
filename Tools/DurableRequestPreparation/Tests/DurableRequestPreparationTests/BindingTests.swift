import Foundation
import XCTest
import ReachWire
import WireAdapterContract
import DurableHostWireAdapter
import DurableClientReceipts
import ResumableMLXProvider
import RequestPreparationContract
import DurableRequestPreparation
import RequestPreparationFixtures

func pair() throws -> PreparationPair { try .init(root:PreparationFixtures.base()+"/unit-"+UUID().uuidString.lowercased(),fresh:true) }
final class BindingTests:XCTestCase {
    func testDeferredSchemaClientBeginRefusesBeforeEnrollment() throws { try withNative {
        let f=try pair();defer { try? f.remove() }
        try f.toClient(f.host.capabilities());_=try f.exchange(f.client.open(requestID:"open"))
        let phase=f.client.negotiation.phase
        for nativeJSON:Data? in [nil,Data(#"{"type":"integer"}"#.utf8)] {
            let request=try deferredSchemaRequest(nativeJSON)
            assertDeferredRefusal { _=try f.client.begin(requestID:"begin",generation:"generation",operation:"operation",request:request) }
            XCTAssertEqual(f.client.negotiation.phase,phase)
        }
        XCTAssertEqual(f.host.issues,1);XCTAssertEqual(f.host.begins,0);XCTAssertNil(f.host.status);XCTAssertNil(f.accepted)
        XCTAssertEqual(f.native.preparer.preparations,0);XCTAssertEqual(f.native.tokenizer.renders,0);XCTAssertEqual(f.native.tokenizer.encodes,0)
        XCTAssertEqual(f.native.model.calls,0);XCTAssertEqual(f.native.model.prepares,0);XCTAssertEqual(f.native.factories,0)
        XCTAssertTrue(try f.clientOwner.discover(binding:WireFixture.binding(f.core),authorization:f.clientAuth).isEmpty)
        for directory in ["requests","children"] { XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath:f.root+"/host/"+directory).isEmpty) }
    } }

    func testSameRouteSubstitutionRefusesBeforeClientEnrollment() throws { try withNative {
        for variant in ["text","options","schema"] {
            let f=try pair();defer { try? f.remove() }
            try f.toClient(f.host.capabilities());_=try f.exchange(f.client.open(requestID:"open"))
            let request=try PreparationFixtures.request(variant=="schema" ? "required" : "ordinary")
            let bytes=try f.client.begin(requestID:"begin",generation:"generation",operation:"operation",request:request)
            var r=FrameReassembler();var frame:DurableGenerateBegin=try r.feed(bytes)[0].decode()
            if variant=="text" { frame.payload.request=try PreparationFixtures.request("ordinary",text:"Substituted text") }
            if variant=="options" { frame.payload.request.options.maximumResponseTokens=3 }
            if variant=="schema" { frame.payload.request.tools=try PreparationFixtures.request("required",n:8).tools }
            let response=try XCTUnwrap(f.toHost(DurableMessage.begin(frame).encode(version:2)).first)
            XCTAssertThrowsError(try f.toClient(response))
            XCTAssertTrue(try f.clientOwner.discover(binding:WireFixture.binding(f.core),authorization:f.clientAuth).isEmpty)
            XCTAssertEqual(f.native.model.calls,0);XCTAssertEqual(f.host.begins,1)
        }
    } }
    func testPreparationRefusalHasNoGenerationAcceptanceOrClientJournal() throws { try withNative {
        for fault in ["throw","empty","oversized","oov"] {
            let f=try pair();defer { try? f.remove() };f.native.tokenizer.fault=fault
            XCTAssertThrowsError(try f.start(PreparationFixtures.request("ordinary")))
            XCTAssertEqual(f.host.begins,0);XCTAssertEqual(f.native.model.calls,0)
            XCTAssertTrue(try f.clientOwner.discover(binding:WireFixture.binding(f.core),authorization:f.clientAuth).isEmpty)
        }
    } }
    func testExactDuplicateBeginAndChangedRequestUnderSameIDs() throws { try withNative {
        let f=try pair();defer { try? f.remove() };try f.start(PreparationFixtures.request("ordinary"))
        let original=try f.stored(),bytes=try XCTUnwrap(f.beginBytes)
        let again=try f.toHost(bytes);var r=FrameReassembler();let accepted:DurableGenerationAccepted=try r.feed(XCTUnwrap(again.first))[0].decode()
        XCTAssertEqual(accepted.payload.context,f.accepted?.context)
        var rr=FrameReassembler();var changed:DurableGenerateBegin=try rr.feed(bytes)[0].decode();changed.payload.request.options.maximumResponseTokens=4
        let rejected=try f.toHost(DurableMessage.begin(changed).encode(version:2));var decoder=FrameReassembler()
        let refusal:DurableRefused=try decoder.feed(XCTUnwrap(rejected.first))[0].decode();XCTAssertEqual(refusal.payload.correlation.operation,.begin)
        XCTAssertEqual(try PreparationEncoding.encode(original),try PreparationEncoding.encode(f.stored()));XCTAssertEqual(f.native.model.calls,0)
    } }
    func testDescriptorDriftAndStoredContradictionsRefuseWithoutNativeWork() throws { try withNative {
        let f=try NativePreparationFixture(),d=f.preparer.policy.descriptor
        for field in ["model","configuration","weights","backend","dependency","tokenizerAlgorithm","template","codec","nativePolicy"] {
            let changed:RequestPreparationContract.ModelDescriptor=try altered(d){$0[field]="changed"}
            XCTAssertThrowsError(try RequestPreparation(descriptor:changed,actualDescriptor:d,native:f.preparer.native,tokenizer:f.tokenizer))
        }
        let original=try prepare(f,PreparationFixtures.request("ordinary"))
        for field in ["model","configuration","weights","input","backend","dependency"] {
            let b:ProviderBinding=try altered(original) { object in
                var lane=object["lane"] as! [String:Any],ordinary=lane["ordinary"] as! [String:Any],text=ordinary["_0"] as! [String:Any],model=text["model"] as! [String:Any],identity=model["identity"] as! [String:Any]
                identity[field]="changed";model["identity"]=identity;text["model"]=model;ordinary["_0"]=text;lane["ordinary"]=ordinary;object["lane"]=lane
            }
            XCTAssertThrowsError(try f.preparer.validateStored(b,configuration:f.configuration))
        }
        var alteredID=original;alteredID.requestID="s89:"+String(repeating:"a",count:64)+":00000000-0000-0000-0000-000000000089:"+String(repeating:"b",count:64)
        XCTAssertThrowsError(try f.preparer.validateStored(alteredID,configuration:f.configuration));XCTAssertEqual(f.model.calls,0)
    } }
    func testRecoveryValidationRunsBeforeAttachAndAcceptance() throws { try withNative {
        let initial=try pair(),root=initial.root;try initial.start(PreparationFixtures.request("ordinary"));try initial.step();initial.close()
        let f=try PreparationPair(root:root,fresh:false);defer { try? f.remove() };let n=f.native
        var validations=0
        f.host=try .init(configuration:n.configuration,owner:f.hostOwner,authorization:f.hostAuth,expectedClientRoot:f.core.clientID,allowNew:false,
            prepare:{_,_,_ in XCTFail("recovery entered prepare");throw PreparationError.identity},runtime:{try n.runtime($0,configuration:$1)},requestPolicy:n.preparer.policy,
            validatePrepared:{stored,configuration in
                validations+=1;var changed=stored;changed.requestID="wrong-selection";try n.preparer.validateStored(changed,configuration:configuration)
            })
        XCTAssertThrowsError(try f.recover());XCTAssertEqual(validations,1);XCTAssertEqual(f.host.recoveries,0)
        XCTAssertEqual(n.model.calls,0);XCTAssertEqual(n.preparer.preparations,0);XCTAssertEqual(n.tokenizer.renders,0)
    } }
}
