import Foundation
import XCTest
import MLX
@testable import ReachWire
import WireAdapterContract
import ResumableMLXProvider
import RequestPreparationContract
import DurableRequestPreparation
import RequestPreparationFixtures
import SchemaPreparationFixtures

func onCPU<T>(_ body:() throws -> T) rethrows -> T { try Device.withDefaultDevice(Device(.cpu)) { try body() } }
func prepared(_ f:NativePreparationFixture,_ request:WireGenerationRequest) throws -> ProviderBinding {
    try f.preparer.prepare(request,reference:.init(session:.init(modelID:f.configuration.model,profile:f.configuration.profile,sessionID:"session"),generationID:"generation",operationID:"s89-operation"),configuration:f.configuration)
}
func guided(_ b:ProviderBinding) throws -> ProviderGuidedBinding {
    guard case .guided(let g)=b.lane else { throw PreparationError.identity };return g
}
func edited<T:Codable>(_ original:T,_ edit:(inout [String:Any]) -> Void) throws -> T {
    var object=try JSONSerialization.jsonObject(with:PreparationEncoding.encode(original)) as! [String:Any];edit(&object)
    return try JSONDecoder().decode(T.self,from:JSONSerialization.data(withJSONObject:object,options:[.sortedKeys]))
}
func deferred(_ native:Data?) throws -> WireGenerationRequest {
    var r=try SchemaPreparationFixtures.request();r.portableSchema = .init(deferredEncodingError:"S90 deferred response schema",nativeJSON:native);return r
}
func deferredRefusal(_ body:() throws -> Void,file:StaticString=#filePath,line:UInt=#line) {
    XCTAssertThrowsError(try body(),file:file,line:line) { error in
        XCTAssertTrue(error is WirePortableValueError,file:file,line:line)
        XCTAssertEqual(String(describing:error),"S90 deferred response schema",file:file,line:line)
    }
}
final class SchemaPreparationTests:XCTestCase {
    func testExplicitRevisionAdmissionOptionsAndEarlyRefusals() throws { try onCPU {
        let f=try SchemaPreparationFixtures.native(),old=try NativePreparationFixture(),r=try SchemaPreparationFixtures.request(),p=f.preparer.policy
        XCTAssertEqual(try p.route(r),"guided");XCTAssertThrowsError(try old.preparer.policy.route(r))
        for maximum in [nil,0,512] as [Int?] {
            var request=r;request.options.maximumResponseTokens=maximum
            XCTAssertEqual(try guided(prepared(f,request)).options.model.maximumTokens,maximum ?? 512)
        }
        for mode:WireToolCalling? in [nil,.allowed,.disallowed] { var x=r;x.options.toolCalling=mode;XCTAssertEqual(try p.route(x),"guided") }
        for sampling:WireSampling? in [nil,.greedy] { var x=r;x.options.sampling=sampling;x.options.temperature=0;XCTAssertEqual(try p.route(x),"guided") }
        var bad:[WireGenerationRequest]=[]
        for prompt in [nil,true] as [Bool?] { var x=r;x.context.includeSchemaInPrompt=prompt;bad.append(x) }
        var tools=r;tools.tools=try PreparationFixtures.request("required").tools;bad.append(tools)
        var reasoning=r;reasoning.context.reasoning = .light;bad.append(reasoning)
        var required=r;required.options.toolCalling = .required;bad.append(required)
        for options:WireGenerationOptions in [.init(maximumResponseTokens:-1),.init(maximumResponseTokens:513),.init(temperature:0.1),.init(temperature:-1),.init(temperature:.nan),.init(temperature:.infinity),.init(sampling:.topK(1,seed:0)),.init(sampling:.topP(0,seed:0))] { var x=r;x.options=options;bad.append(x) }
        // Non-guided context controls keep the S89 nil-only rule in both revisions.
        var ordinary=try PreparationFixtures.request("ordinary");ordinary.context.includeSchemaInPrompt=false;bad.append(ordinary)
        let before=f.preparer.preparations,encodes=f.tokenizer.encodes
        for x in bad { XCTAssertThrowsError(try prepared(f,x)) }
        XCTAssertEqual(f.preparer.preparations,before);XCTAssertEqual(f.tokenizer.encodes,encodes);XCTAssertEqual(f.model.calls,0);XCTAssertEqual(f.factories,0)
    } }
    func testDeferredSchemaThrowingBoundaryBeforeTemplate() throws { try onCPU {
        let f=try SchemaPreparationFixtures.native()
        for native:Data? in [nil,Data(#"{"type":"string"}"#.utf8)] {
            let r=try deferred(native)
            deferredRefusal { _=try PreparationEncoding.schemaValue(r.portableSchema!) }
            deferredRefusal { _=try f.preparer.policy.route(r) }
            deferredRefusal { _=try TranscriptPreparation.input(r,revision:SchemaPreparationFixtures.revision) }
            deferredRefusal { _=try prepared(f,r) }
        }
        XCTAssertEqual(f.preparer.preparations,0);XCTAssertEqual(f.preparer.templateCalls,0);XCTAssertEqual(f.tokenizer.encodes,0)
        XCTAssertEqual(f.model.calls,0);XCTAssertEqual(f.model.prepares,0);XCTAssertEqual(f.factories,0)
    } }
    func testSchemaAndHistoryShareBudgetsBeforeSerialization() throws { try onCPU {
        let f=try SchemaPreparationFixtures.native()
        var strings=try SchemaPreparationFixtures.request(text:String(repeating:"x",count:34_000))
        strings.portableSchema=try .init(jsonValue:.object(["type":.string("string"),"enum":.array([.string(String(repeating:"s",count:34_000))])]))
        var nodes=try SchemaPreparationFixtures.request()
        nodes.portableSchema=try .init(jsonValue:.object(["type":.string("string"),"enum":.array((0..<5000).map{.string(String($0))})]))
        nodes.portableTranscript = .init(entries:[.prompt(.init(id:"p",segments:[.text(.init(id:"t",content:"hello"))],metadata:["values":.array(Array(repeating:.null,count:4000))]))])
        var depth=try SchemaPreparationFixtures.request();var tree:WireJSONValue = .object(["type":.string("string")])
        for _ in 0..<34 { tree = .object(["type":.string("array"),"items":tree]) };depth.portableSchema=try .init(jsonValue:tree)
        var serialized=try SchemaPreparationFixtures.request()
        serialized.portableSchema=try .init(jsonValue:.object(["type":.string("string"),"enum":.array((0..<8000).map{.string(String($0)+"xyz")})]))
        for request in [strings,nodes,depth,serialized] {
            XCTAssertThrowsError(try f.preparer.policy.route(request));XCTAssertThrowsError(try prepared(f,request))
            XCTAssertEqual(f.preparer.preparations,0);XCTAssertEqual(f.tokenizer.encodes,0)
        }
        XCTAssertEqual(f.preparer.preparations,0);XCTAssertEqual(f.tokenizer.encodes,0);XCTAssertEqual(f.factories,0)
    } }
    func testSchemaChangesGrammarAndIdentityWithoutPromptInjection() throws { try onCPU {
        let f=try SchemaPreparationFixtures.native(),r=try SchemaPreparationFixtures.request(),a=try prepared(f,r),b=try prepared(f,SchemaPreparationFixtures.request("eight"))
        XCTAssertEqual(try guided(a).tokens,try guided(b).tokens);XCTAssertNotEqual(a.requestID,b.requestID)
        XCTAssertNotEqual(try guided(a).specification.source,try guided(b).specification.source)
        XCTAssertEqual(try guided(a).specification.source,String(decoding:try PreparationEncoding.encode(PreparationEncoding.schemaValue(r.portableSchema!)),as:UTF8.self))
        XCTAssertFalse(f.tokenizer.lastRendered.contains("S90Reply"));XCTAssertFalse(f.tokenizer.lastRendered.contains(SchemaPreparationFixtures.phrase))
        let changed=try prepared(f,SchemaPreparationFixtures.request(text:"A changed prompt."));XCTAssertNotEqual(try guided(a).tokens,try guided(changed).tokens)
        var refs=r
        refs.portableSchema=try JSONDecoder().decode(WireGenerationSchema.self,from:Data(##"{"$defs":{"Child":{"additionalProperties":false,"properties":{},"required":[],"title":"Child","type":"object","x-order":[]}},"additionalProperties":false,"properties":{"x":{"$ref":"Child","description":"D"}},"required":["x"],"title":"Root","type":"object","x-order":["x"]}"##.utf8))
        let spec=try guided(prepared(f,refs)).specification.source
        XCTAssertTrue(spec.contains("$defs"));XCTAssertTrue(spec.contains("$ref"));XCTAssertTrue(spec.contains("x-order"))
        XCTAssertEqual(spec,try RequestBounds.canonicalStoredSchema(spec))
        XCTAssertEqual(try guided(prepared(f,SchemaPreparationFixtures.request("scalar"))).tokens,try guided(a).tokens)
    } }
    func testLegacyDescriptorRequestsTokensAndBindingsMatchAcceptedObservations() throws { try onCPU {
        let f=try NativePreparationFixture(),explicit=try NativePreparationFixture(revision:RequestPreparationContract.ModelDescriptor.legacyRevision)
        XCTAssertEqual(try PreparationEncoding.encode(f.preparer.policy.descriptor),try PreparationEncoding.encode(explicit.preparer.policy.descriptor))
        XCTAssertEqual(try f.preparer.policy.descriptor.identity,"dd49f639fa1a19d30923b66d61b8d0eb84cb54311e81606b4e92e17ddb69b540")
        // Full canonical bindings from S89 original ordinary/n7/n8 native snapshots;
        // they bind old request IDs, tokens, IDs, grammar/options and model policy.
        for (route,n,digest) in [("ordinary",7,"e87dfb08a8aebf1d431330b9db3f0ecdeb991b1691c7c2a46e8ec453056c6907"),("required",7,"d8b8879f81bf4e4a74da2fd070b3b37f67907b70cafae59f32b41190b1f99aaf"),("required",8,"3f2447d44f48f41b4e9bfc5672bdf3381a9d4a42dd0e5f50f068a74f19b29f44")] {
            let request=try PreparationFixtures.request(route,n:n),binding=try prepared(f,request)
            XCTAssertEqual(try PreparationEncoding.digest(binding),digest)
            XCTAssertEqual(try PreparationEncoding.encode(binding),try PreparationEncoding.encode(prepared(explicit,request)))
        }
    } }
    func testSelectedDescriptorAndStoredGuidedDriftRefuse() throws { try onCPU {
        let f=try SchemaPreparationFixtures.native(),d=f.preparer.policy.descriptor,b=try prepared(f,SchemaPreparationFixtures.request())
        for field in ["revision","model","configuration","weights","backend","dependency","template","tokenizerAlgorithm","codec","nativePolicy"] {
            let changed:RequestPreparationContract.ModelDescriptor=try edited(d){$0[field]="changed"}
            XCTAssertThrowsError(try RequestPreparation(descriptor:changed,actualDescriptor:d,native:f.preparer.native,tokenizer:f.tokenizer))
        }
        let changed:RequestPreparationContract.ModelDescriptor=try edited(d){$0["vocabulary"]=["changed"]}
        XCTAssertThrowsError(try RequestPreparation(descriptor:changed,actualDescriptor:d,native:f.preparer.native,tokenizer:f.tokenizer))
        let g=try guided(b)
        let mutations:[(inout [String:Any])->Void]=[
            {$0["tokens"]=[258]},{$0["entryID"]="wrong"},{$0["segmentID"]="wrong"},
            {var x=$0["model"] as! [String:Any];x["codecIdentity"]="wrong";$0["model"]=x},
            {var x=$0["specification"] as! [String:Any];x["source"]=" {\"type\":\"string\"}";$0["specification"]=x},
            {var x=$0["specification"] as! [String:Any];x["vocabulary"]=["wrong"];$0["specification"]=x},
            {var x=$0["specification"] as! [String:Any];x["eosTokenID"]=1;$0["specification"]=x},
            {var x=$0["specification"] as! [String:Any];x["unknownTokenID"]=2;$0["specification"]=x},
            {var x=$0["specification"] as! [String:Any];x["tokenizerIdentity"]="wrong";$0["specification"]=x},
            {var x=$0["specification"] as! [String:Any];x["fastForward"]=false;$0["specification"]=x},
            {var x=$0["options"] as! [String:Any];x["completionReserve"]=1;$0["options"]=x}]
        for mutation in mutations {
            var altered=b;altered.lane = .guided(try edited(g,mutation))
            XCTAssertThrowsError(try f.preparer.validateStored(altered,configuration:f.configuration))
        }
        let old=try NativePreparationFixture();XCTAssertThrowsError(try old.preparer.validateStored(b,configuration:old.configuration))
        XCTAssertEqual(f.factories,0);XCTAssertEqual(f.model.calls,0)
    } }
}
