import Foundation
import XCTest
import MLX
@testable import ReachWire
import RequestPreparationContract
import DurableRequestPreparation
import RequestPreparationFixtures
import SchemaToolPreparationFixtures
import AllowedPreparationFixtures
import SchemaPreparationFixtures
import AllowedToolCoordinator
import ResumableMLXProvider

func cpu<T>(_ body:() throws -> T) rethrows -> T { try Device.withDefaultDevice(Device(.cpu)) { try body() } }
func prepared(_ f:NativePreparationFixture,_ r:WireGenerationRequest) throws -> ProviderBinding {
    try f.preparer.prepare(r,reference:.init(session:.init(modelID:f.configuration.model,profile:f.configuration.profile,sessionID:"session"),generationID:"generation",operationID:"s89-operation"),configuration:f.configuration)
}
func allowed(_ b:ProviderBinding) throws -> AllowedToolBinding { guard case .allowed(let a)=b.lane else { throw PreparationError.identity };return a }
func deferred(_ native:Data?,response:Bool) throws -> WireGenerationRequest {
    var r=try SchemaToolPreparationFixtures.request();let schema=WireGenerationSchema(deferredEncodingError:"S92 deferred schema",nativeJSON:native)
    if response { r.portableSchema=schema } else { r.tools[0].portableParameters=schema };return r
}
func deferredRefusal(_ body:() throws -> Void,file:StaticString=#filePath,line:UInt=#line) {
    XCTAssertThrowsError(try body(),file:file,line:line) { e in
        XCTAssertTrue(e is WirePortableValueError,file:file,line:line);XCTAssertEqual(String(describing:e),"S92 deferred schema",file:file,line:line)
    }
}
final class SchemaToolPreparationTests:XCTestCase {
    func testExplicitCombinedAdmissionAndPreservedOtherRoutes() throws { try cpu {
        let f=try SchemaToolNativeFixture(family:"llama").native,p=f.preparer.policy,r=try SchemaToolPreparationFixtures.request()
        for mode:WireToolCalling? in [nil,.allowed] { var x=r;x.options.toolCalling=mode;XCTAssertEqual(try p.route(x),"allowed") }
        for revision in [RequestPreparationContract.ModelDescriptor.legacyRevision,RequestPreparationContract.ModelDescriptor.schemaRevision,RequestPreparationContract.ModelDescriptor.allowedRevision] {
            let old=try NativePreparationFixture(revision:revision);XCTAssertThrowsError(try old.preparer.policy.route(r))
        }
        XCTAssertEqual(try p.route(PreparationFixtures.request("ordinary")),"ordinary")
        XCTAssertEqual(try p.route(PreparationFixtures.request("required")),"required")
        XCTAssertEqual(try p.route(AllowedPreparationFixtures.request()),"allowed")
        XCTAssertEqual(try p.route(SchemaPreparationFixtures.request()),"guided")
        for maximum in [nil,0,512] as [Int?] {
            var x=r;x.options.maximumResponseTokens=maximum;x.options.sampling=nil
            let a=try allowed(prepared(f,x));XCTAssertEqual(a.probeOptions.maximumTokens,maximum ?? 512);XCTAssertEqual(a.guidedOptions.model.maximumTokens,maximum ?? 512)
        }
        var bad:[WireGenerationRequest]=[]
        for mode:WireToolCalling in [.required,.disallowed] { var x=r;x.options.toolCalling=mode;bad.append(x) }
        for context in [nil,true] as [Bool?] { var x=r;x.context.includeSchemaInPrompt=context;bad.append(x) }
        var reasoning=r;reasoning.context.reasoning = .light;bad.append(reasoning)
        var duplicate=r;duplicate.tools.append(r.tools[0]);bad.append(duplicate)
        for o:WireGenerationOptions in [.init(maximumResponseTokens:-1),.init(maximumResponseTokens:513),.init(temperature:0.1),.init(temperature:.nan),.init(temperature:-1),.init(sampling:.topK(1,seed:0)),.init(sampling:.topP(0,seed:0))] { var x=r;x.options=o;bad.append(x) }
        let before=f.preparer.preparations
        for x in bad { XCTAssertThrowsError(try prepared(f,x)) };XCTAssertEqual(f.preparer.preparations,before);XCTAssertEqual(f.factories,0)
    } }
    func testDeferredResponseAndToolSchemasPrecedeOriginalPreparation() throws { try cpu {
        let f=try SchemaToolNativeFixture(family:"llama").native
        for response in [false,true] { for native:Data? in [nil,Data(#"{"type":"object"}"#.utf8)] {
            let r=try deferred(native,response:response)
            deferredRefusal { _=try f.preparer.policy.route(r) }
            deferredRefusal { _=try TranscriptPreparation.input(r,revision:SchemaToolPreparationFixtures.revision) }
            deferredRefusal { _=try prepared(f,r) }
        } }
        XCTAssertEqual(f.preparer.preparations,0);XCTAssertEqual(f.tokenizer.encodes,0);XCTAssertEqual(f.factories,0)
    } }
    func testOneSharedRequestAndStoredSchemaBudget() throws { try cpu {
        let f=try SchemaToolNativeFixture(family:"llama").native;var r=try SchemaToolPreparationFixtures.request()
        let choices:WireJSONValue = .object(["type":.string("string"),"enum":.array((0..<4200).map{.string(String($0))})])
        let tool=try WireGenerationSchema(jsonValue:.object(["title":.string("Large"),"type":.string("object"),"properties":.object(["value":choices]),"required":.array([.string("value")]),"x-order":.array([.string("value")]),"additionalProperties":.bool(false)]))
        let response=try WireGenerationSchema(jsonValue:choices)
        r.tools=[.init(name:"alpha",description:"",portableParameters:tool)];r.portableSchema=response
        let t=String(decoding:try PreparationEncoding.encode(tool),as:UTF8.self),s=String(decoding:try PreparationEncoding.encode(response),as:UTF8.self)
        XCTAssertNoThrow(try RequestBounds.validateStoredTools(names:["alpha"],schemas:[t]));XCTAssertNoThrow(try RequestBounds.canonicalStoredSchema(s))
        XCTAssertThrowsError(try RequestBounds.validateStoredTools(names:["alpha"],schemas:[t],responseSchema:s))
        XCTAssertThrowsError(try f.preparer.policy.route(r));XCTAssertThrowsError(try prepared(f,r))
        let large=try WireGenerationSchema(jsonValue:.object(["type":.string("string"),"enum":.array([.string(String(repeating:"x",count:34_000))])]))
        let big=String(decoding:try PreparationEncoding.encode(large),as:UTF8.self)
        XCTAssertThrowsError(try RequestBounds.validateStoredTools(names:["alpha"],schemas:[big],responseSchema:big))
        r=try SchemaToolPreparationFixtures.request();r.portableSchema=large
        if case .object(var object)=try PreparationEncoding.schemaValue(r.tools[0].portableParameters) {
            object["description"] = .string(String(repeating:"x",count:34_000));r.tools[0].portableParameters=try .init(jsonValue:.object(object))
        }
        XCTAssertThrowsError(try prepared(f,r));XCTAssertEqual(f.preparer.preparations,0);XCTAssertEqual(f.tokenizer.encodes,0)
    } }
    func testResponseOnlyChangePreservesPromptAndBindsSelectedDeclaration() throws { try cpu {
        let f=try SchemaToolNativeFixture(family:"llama").native,a=try prepared(f,SchemaToolPreparationFixtures.request()),b=try prepared(f,SchemaToolPreparationFixtures.request("eight"))
        let x=try allowed(a),y=try allowed(b)
        XCTAssertEqual(x.originalTokens,y.originalTokens);XCTAssertNotEqual(a.requestID,b.requestID);XCTAssertNotEqual(x.responseSchema,y.responseSchema)
        XCTAssertNotEqual(x.namespace,y.namespace);XCTAssertFalse(f.tokenizer.lastRendered.contains("S92Reply"))
        XCTAssertNotEqual(x.originalTokens,try allowed(prepared(f,SchemaToolPreparationFixtures.request(text:"Different text"))).originalTokens)
        for source in [nil,y.responseSchema," {}"] as [String?] {
            var altered=a;var lane=x;lane.responseSchema=source;altered.lane = .allowed(lane)
            XCTAssertThrowsError(try f.preparer.validateStored(altered,configuration:f.configuration))
        }
        var altered=a;var lane=x;lane.namespace=String(repeating:"a",count:32);altered.lane = .allowed(lane)
        XCTAssertThrowsError(try f.preparer.validateStored(altered,configuration:f.configuration));XCTAssertEqual(f.factories,0)
    } }
    func testS91FullBindingsRemainExact() throws { try cpu {
        for (family,variant,digest) in [("llama","llama","3dc6bc6198f3b82f57ccb5c5f1c31dec129945c77aa9d75bbf9467438193e077"),("state","calls","a212eec5e7b6f0d8906f09e2746aa2d990edf17e51d830435a0f04aa39b94a0a")] {
            let f=try AllowedNativeFixture(family:family)
            XCTAssertEqual(try PreparationEncoding.digest(prepared(f.native,AllowedPreparationFixtures.request(variant))),digest)
        }
    } }
}
