import Foundation
import XCTest
import MLX
@testable import ReachWire
import AllowedToolCoordinator
import ResumableMLXProvider
import RequestPreparationContract
import DurableRequestPreparation
import RequestPreparationFixtures
import SchemaPreparationFixtures
import AllowedPreparationFixtures

func cpu<T>(_ body:() throws -> T) rethrows -> T { try Device.withDefaultDevice(Device(.cpu)) { try body() } }
func prepared(_ f:NativePreparationFixture,_ r:WireGenerationRequest) throws -> ProviderBinding {
    try f.preparer.prepare(r,reference:.init(session:.init(modelID:f.configuration.model,profile:f.configuration.profile,sessionID:"session"),generationID:"generation",operationID:"s89-operation"),configuration:f.configuration)
}
func allowed(_ b:ProviderBinding) throws -> AllowedToolBinding { guard case .allowed(let a)=b.lane else { throw PreparationError.identity };return a }
func edited<T:Codable>(_ value:T,_ edit:(inout [String:Any])->Void) throws -> T {
    var object=try JSONSerialization.jsonObject(with:PreparationEncoding.encode(value)) as! [String:Any];edit(&object)
    return try JSONDecoder().decode(T.self,from:JSONSerialization.data(withJSONObject:object,options:[.sortedKeys]))
}
func deferred(_ native:Data?) throws -> WireGenerationRequest {
    var r=try AllowedPreparationFixtures.request();r.tools[0].portableParameters = .init(deferredEncodingError:"S91 deferred tool schema",nativeJSON:native);return r
}
func deferredRefusal(_ body:() throws -> Void,file:StaticString=#filePath,line:UInt=#line) {
    XCTAssertThrowsError(try body(),file:file,line:line) { e in
        XCTAssertTrue(e is WirePortableValueError,file:file,line:line);XCTAssertEqual(String(describing:e),"S91 deferred tool schema",file:file,line:line)
    }
}
final class AllowedPreparationTests:XCTestCase {
    func testRevisionRoutingAndPerPassGreedyOptions() throws { try cpu {
        let f=try AllowedNativeFixture(family:"llama").native,p=f.preparer.policy,r=try AllowedPreparationFixtures.request()
        for mode:WireToolCalling? in [nil,.allowed,.required] {
            var x=r;x.options.toolCalling=mode;XCTAssertEqual(try p.route(x),mode == .required ? "required" : "allowed")
        }
        for revision in [RequestPreparationContract.ModelDescriptor.legacyRevision,RequestPreparationContract.ModelDescriptor.schemaRevision] {
            let old=try NativePreparationFixture(revision:revision);XCTAssertThrowsError(try old.preparer.policy.route(r))
        }
        for limit in [nil,0,512] as [Int?] {
            var x=r;x.options.maximumResponseTokens=limit;x.options.sampling=nil
            let a=try allowed(prepared(f,x));XCTAssertEqual(a.probeOptions.maximumTokens,limit ?? 512);XCTAssertEqual(a.guidedOptions.model.maximumTokens,limit ?? 512)
            XCTAssertEqual(a.probeOptions.temperature,0);XCTAssertEqual(a.format,.json);XCTAssertNil(a.responseSchema)
            XCTAssertEqual(try PreparationEncoding.encode(a.probeModel),try PreparationEncoding.encode(a.guidedModel));XCTAssertEqual(a.tokenizer.source,"{}")
        }
        XCTAssertEqual(try p.route(PreparationFixtures.request("ordinary")),"ordinary")
        XCTAssertEqual(try p.route(SchemaPreparationFixtures.request()),"guided")
        var bad:[WireGenerationRequest]=[]
        var disallowed=r;disallowed.options.toolCalling = .disallowed;bad.append(disallowed)
        var schema=r;schema.portableSchema=try SchemaPreparationFixtures.request().portableSchema;schema.context.includeSchemaInPrompt=false;bad.append(schema)
        var context=r;context.context.includeSchemaInPrompt=false;bad.append(context);context=r;context.context.reasoning = .light;bad.append(context)
        var duplicate=r;duplicate.tools.append(r.tools[0]);bad.append(duplicate)
        var many=r;many.tools=(0..<9).map { i in var tool=r.tools[0];tool.name="tool-\(i)";return tool };bad.append(many)
        for o:WireGenerationOptions in [.init(maximumResponseTokens:-1),.init(maximumResponseTokens:513),.init(temperature:.nan),.init(temperature:.infinity),.init(temperature:-1),.init(temperature:0.1),.init(sampling:.topK(1,seed:0)),.init(sampling:.topP(0,seed:0))] { var x=r;x.options=o;bad.append(x) }
        let before=f.preparer.preparations,encodes=f.tokenizer.encodes
        for x in bad { XCTAssertThrowsError(try prepared(f,x)) }
        XCTAssertEqual(f.preparer.preparations,before);XCTAssertEqual(f.tokenizer.encodes,encodes);XCTAssertEqual(f.factories,0)
    } }
    func testDeferredSchemasAndSharedBoundsPrecedeTemplate() throws { try cpu {
        let f=try AllowedNativeFixture(family:"state").native
        for native:Data? in [nil,Data(#"{"type":"object"}"#.utf8)] {
            let r=try deferred(native)
            deferredRefusal { _=try PreparationEncoding.schemaValue(r.tools[0].portableParameters) }
            deferredRefusal { _=try f.preparer.policy.route(r) }
            deferredRefusal { _=try TranscriptPreparation.input(r,revision:AllowedPreparationFixtures.revision) }
            deferredRefusal { _=try prepared(f,r) }
        }
        var long=try AllowedPreparationFixtures.request(text:String(repeating:"x",count:34_000))
        var value=try PreparationEncoding.schemaValue(long.tools[0].portableParameters)
        if case .object(var root)=value { root["description"] = .string(String(repeating:"s",count:34_000));value = .object(root) }
        long.tools[0].portableParameters=try .init(jsonValue:value)
        XCTAssertThrowsError(try f.preparer.policy.route(long));XCTAssertThrowsError(try prepared(f,long))
        XCTAssertEqual(f.preparer.preparations,0);XCTAssertEqual(f.tokenizer.renders,0);XCTAssertEqual(f.tokenizer.encodes,0);XCTAssertEqual(f.factories,0)
    } }
    func testActualTextAndToolDefinitionsDriveTokensAndStableIdentity() throws { try cpu {
        let f=try AllowedNativeFixture(family:"llama").native,r=try AllowedPreparationFixtures.request(),a=try prepared(f,r),original=try allowed(a)
        for variation in ["text","name","description","schema"] {
            var x=r
            if variation=="text" { x=try AllowedPreparationFixtures.request(text:"Different request.") }
            if variation=="name" { x.tools[0].name="renamed" }
            if variation=="description" { x.tools[0].description="Changed description." }
            if variation=="schema" { x=try AllowedPreparationFixtures.request("eight") }
            let b=try prepared(f,x);XCTAssertNotEqual(original.originalTokens,try allowed(b).originalTokens);XCTAssertNotEqual(a.requestID,b.requestID)
        }
        var uuid=r;uuid.id=UUID();let b=try prepared(f,uuid);XCTAssertEqual(original.originalTokens,try allowed(b).originalTokens);XCTAssertNotEqual(a.requestID,b.requestID)
        let again=try prepared(f,r);XCTAssertEqual(try PreparationEncoding.encode(a),try PreparationEncoding.encode(again))
        XCTAssertEqual(original.namespace,String(try PreparationEncoding.digest(["s91-parser-namespace-v1",a.requestID,a.operationID]).prefix(32)))
        XCTAssertEqual(original.entryID,"entry-"+(try PreparationEncoding.digest(["s91-entry-v1",a.requestID,a.operationID])))
        XCTAssertEqual(original.tools[0].schemaJSON,String(decoding:try PreparationEncoding.encode(PreparationEncoding.schemaValue(r.tools[0].portableParameters)),as:UTF8.self))
        XCTAssertEqual(f.model.calls,0)
    } }
    func testStoredSelectedDeclarationsRefuseDrift() throws { try cpu {
        let f=try AllowedNativeFixture(family:"state").native,b=try prepared(f,AllowedPreparationFixtures.request()),a=try allowed(b)
        let mutations:[(inout [String:Any])->Void]=[
            {$0["requestIdentity"]="wrong"},{$0["namespace"]=String(repeating:"a",count:32)},{$0["entryID"]="wrong"},{$0["format"]="xmlFunction"},{$0["responseSchema"]="{}"},
            {$0["originalTokens"]=[258]},{$0["preparationPolicy"]="wrong"},
            {var x=$0["probeModel"] as! [String:Any];x["codecIdentity"]="wrong";$0["probeModel"]=x},
            {var x=$0["guidedModel"] as! [String:Any];var i=x["identity"] as! [String:Any];i["weights"]="wrong";x["identity"]=i;$0["guidedModel"]=x},
            {var x=$0["probeOptions"] as! [String:Any];x["temperature"]=0.1;$0["probeOptions"]=x},
            {var x=$0["guidedOptions"] as! [String:Any];var m=x["model"] as! [String:Any];m["maximumTokens"]=255;x["model"]=m;$0["guidedOptions"]=x},
            {var x=$0["tokenizer"] as! [String:Any];x["tokenizerIdentity"]="wrong";$0["tokenizer"]=x},
            {var x=$0["tools"] as! [[String:Any]];x[1]=x[0];$0["tools"]=x},
            {var x=$0["tools"] as! [[String:Any]];x[0]["schemaJSON"]=" "+(x[0]["schemaJSON"] as! String);$0["tools"]=x}]
        for mutation in mutations {
            // Some malformed enum declarations can refuse while decoding, which
            // is also before the selected validation/attach boundary.
            XCTAssertThrowsError(try { var x=b;x.lane = .allowed(try edited(a,mutation));try f.preparer.validateStored(x,configuration:f.configuration) }())
        }
        let old=try NativePreparationFixture(revision:RequestPreparationContract.ModelDescriptor.schemaRevision)
        XCTAssertThrowsError(try old.preparer.validateStored(b,configuration:old.configuration));XCTAssertEqual(f.factories,0)
    } }
    func testS90FullBindingAndExplicitOldDefaultsRemainExact() throws { try cpu {
        let f=try NativePreparationFixture(revision:RequestPreparationContract.ModelDescriptor.schemaRevision)
        XCTAssertEqual(try f.preparer.policy.descriptor.identity,"2c7cfab4a231557905adbc2f2c23779505006defbfd030ac88e967d7f6a70e78")
        XCTAssertEqual(try PreparationEncoding.digest(prepared(f,SchemaPreparationFixtures.request())),"ebf2796ff64436ffec831ddea3cfd11c1f89e5b09cbe325147f6ac45e360f7a3")
        let legacy=try NativePreparationFixture();XCTAssertEqual(legacy.preparer.policy.descriptor.revision,RequestPreparationContract.ModelDescriptor.legacyRevision)
        XCTAssertEqual(try legacy.preparer.policy.descriptor.identity,"dd49f639fa1a19d30923b66d61b8d0eb84cb54311e81606b4e92e17ddb69b540")
    } }
}
