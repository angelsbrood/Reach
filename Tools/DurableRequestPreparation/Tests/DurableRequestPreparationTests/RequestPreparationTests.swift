import Foundation
import XCTest
import MLX
import MLXLMCommon
@testable import ReachWire
import WireAdapterContract
import ResumableMLXProvider
import RequestPreparationContract
import DurableRequestPreparation
import RequestPreparationFixtures

func withNative<T>(_ body:() throws -> T) rethrows -> T { try Device.withDefaultDevice(Device(.cpu)) { try body() } }
func prepare(_ f:NativePreparationFixture,_ request:WireGenerationRequest) throws -> ProviderBinding {
    try f.preparer.prepare(request,reference:.init(session:.init(modelID:f.configuration.model,profile:f.configuration.profile,sessionID:"session"),generationID:"generation",operationID:"operation"),configuration:f.configuration)
}
func tokenArray(_ b:ProviderBinding) -> [Int] {
    switch b.lane { case .ordinary(let x):return x.tokens;case .required(_,let t):return t;default:return [] }
}
func altered<T:Codable>(_ original:T,_ edit:(inout [String:Any]) -> Void) throws -> T {
    var object=try JSONSerialization.jsonObject(with:PreparationEncoding.encode(original)) as! [String:Any];edit(&object)
    return try JSONDecoder().decode(T.self,from:JSONSerialization.data(withJSONObject:object,options:[.sortedKeys]))
}
// Same retained-error fixture pattern as ReachWire FrameCodecTests. This local
// state cannot be manufactured by a successfully decoded peer schema.
func deferredSchemaRequest(_ nativeJSON:Data?) throws -> WireGenerationRequest {
    var request=try PreparationFixtures.request("required")
    request.tools[0].portableParameters = .init(deferredEncodingError:"S89 deferred portable conversion",nativeJSON:nativeJSON)
    return request
}
func assertDeferredRefusal(_ body:() throws -> Void,file:StaticString=#filePath,line:UInt=#line) {
    XCTAssertThrowsError(try body(),file:file,line:line) { error in
        XCTAssertTrue(error is WirePortableValueError,file:file,line:line)
        XCTAssertEqual(String(describing:error),"S89 deferred portable conversion",file:file,line:line)
    }
}
final class RequestPreparationTests:XCTestCase {
    func testDeferredSchemasThrowBeforePreparation() throws { try withNative {
        let f=try NativePreparationFixture()
        for nativeJSON:Data? in [nil,Data(#"{"type":"integer"}"#.utf8)] {
            let request=try deferredSchemaRequest(nativeJSON)
            assertDeferredRefusal { _=try PreparationEncoding.schemaValue(request.tools[0].portableParameters) }
            assertDeferredRefusal { _=try f.preparer.policy.route(request) }
            assertDeferredRefusal { _=try TranscriptPreparation.input(request) }
            assertDeferredRefusal { _=try prepare(f,request) }
        }
        XCTAssertEqual(f.preparer.preparations,0);XCTAssertEqual(f.preparer.templateCalls,0)
        XCTAssertEqual(f.tokenizer.renders,0);XCTAssertEqual(f.tokenizer.encodes,0)
        XCTAssertEqual(f.model.calls,0);XCTAssertEqual(f.model.prepares,0);XCTAssertEqual(f.factories,0)
        XCTAssertTrue(f.preparer.lastTokens.isEmpty)
    } }
    func testThrowingSchemaExtractionPreservesValuesAndBounds() throws { try withNative {
        let f=try NativePreparationFixture()
        // Token digests from the authenticated original S89 native snapshots:
        // ordinary-reference, required-reference and required-eight-snapshot.
        let cases=[("ordinary",7,"1c920e5cd3d298f9ad2eb1c11994a91f078b82ebf64e436c8e85c3adc2215bfa"),
                   ("required",7,"d10063d9dd4a969663796c8383b3de77a6f9619c0edf22c4d86184644023da22"),
                   ("required",8,"1d69a4a7338c6656904308bc15433cb3f65a791acc50d5da5843531c161560f3")]
        for (route,n,digest) in cases {
            let request=try PreparationFixtures.request(route,n:n)
            for tool in request.tools {
                XCTAssertEqual(try PreparationEncoding.encode(PreparationEncoding.schemaValue(tool.portableParameters)),try PreparationEncoding.encode(tool.portableParameters))
            }
            XCTAssertEqual(try PreparationEncoding.digest(tokenArray(prepare(f,request))),digest)
        }
        var request=try PreparationFixtures.request("required")
        guard case .object(var root)=try PreparationEncoding.schemaValue(request.tools[0].portableParameters) else { return XCTFail() }
        root["description"] = .string(String(repeating:"x",count:65_537))
        request.tools[0].portableParameters=try .init(jsonValue:.object(root))
        let preparations=f.preparer.preparations,encodes=f.tokenizer.encodes
        XCTAssertThrowsError(try f.preparer.policy.route(request))
        XCTAssertThrowsError(try prepare(f,request))
        XCTAssertEqual(f.preparer.preparations,preparations);XCTAssertEqual(f.tokenizer.encodes,encodes)
        XCTAssertEqual(f.model.calls,0);XCTAssertEqual(f.model.prepares,0)
    } }

    func testRealTextAndToolsChangeTokensAndCompleteRequestIdentity() throws { try withNative {
        let f=try NativePreparationFixture(),r=try PreparationFixtures.request("ordinary"),a=try prepare(f,r)
        let b=try prepare(f,PreparationFixtures.request("ordinary",text:"A different 🌿 request."))
        XCTAssertNotEqual(tokenArray(a),tokenArray(b));XCTAssertNotEqual(a.requestID,b.requestID)
        var uuid=r;uuid.id=UUID();let u=try prepare(f,uuid);XCTAssertEqual(tokenArray(a),tokenArray(u));XCTAssertNotEqual(a.requestID,u.requestID)
        var options=r;options.options.maximumResponseTokens=3;let o=try prepare(f,options)
        XCTAssertEqual(tokenArray(a),tokenArray(o));XCTAssertNotEqual(a.requestID,o.requestID)
        let seven=try prepare(f,PreparationFixtures.request("required",n:7)),eight=try prepare(f,PreparationFixtures.request("required",n:8))
        XCTAssertNotEqual(tokenArray(seven),tokenArray(eight));XCTAssertNotEqual(seven.requestID,eight.requestID)
        if case .required(let s,_)=seven.lane,case .required(let e,_)=eight.lane { XCTAssertNotEqual(s.specification.source,e.specification.source) } else { XCTFail() }
        for field in ["name","description"] {
            var changed=try PreparationFixtures.request("required")
            if field=="name" { changed.tools[0].name="beta" } else { changed.tools[0].description="Different description 🌙" }
            let c=try prepare(f,changed);XCTAssertNotEqual(tokenArray(seven),tokenArray(c));XCTAssertNotEqual(seven.requestID,c.requestID)
        }
        XCTAssertEqual(f.model.calls,0);XCTAssertEqual(f.model.prepares,0)
    } }
    func testOrderedUnicodeHistoryPreservesAssociationsAndObjectArguments() throws { try withNative {
        let f=try NativePreparationFixture();var r=try PreparationFixtures.request("ordinary")
        r.portableTranscript = .init(entries:[
            .instructions(.init(id:"sys",segments:[.text(.init(id:"s",content:"系统 🌙"))])),
            .prompt(.init(id:"u",segments:[.text(.init(id:"t",content:"café"))])),
            .toolCalls(.init(id:"calls",calls:[.init(id:"call-α",name:"lookup",argumentsJSON:"{\"q\":\"日本語\",\"n\":7}")])),
            .toolOutput(.init(id:"call-α",toolName:"lookup",segments:[.text(.init(id:"result",content:"réponse"))])),
            .response(.init(id:"assistant",segments:[.text(.init(id:"answer",content:"Got it."))])),
            .prompt(.init(id:"u2",segments:[.text(.init(id:"t2",content:"Continue."))]))])
        let binding=try prepare(f,r),rendered=f.tokenizer.lastRendered
        let line=try XCTUnwrap(rendered.split(separator:"\n").first)
        let object=try JSONSerialization.jsonObject(with:Data(line.utf8)) as! [String:Any],messages=object["messages"] as! [[String:Any]]
        XCTAssertEqual(messages.map{$0["role"] as! String},["system","user","assistant","tool","assistant","user"])
        XCTAssertEqual(messages[0]["content"] as? String,"系统 🌙");XCTAssertEqual(messages[3]["tool_call_id"] as? String,"call-α")
        let calls=messages[2]["tool_calls"] as! [[String:Any]],function=calls[0]["function"] as! [String:Any]
        XCTAssertEqual(calls[0]["id"] as? String,"call-α");XCTAssertEqual(function["name"] as? String,"lookup")
        XCTAssertEqual((function["arguments"] as? [String:Any])?["q"] as? String,"日本語")
        var changed=r;changed.portableTranscript.entries.swapAt(0,1)
        XCTAssertNotEqual(tokenArray(binding),try tokenArray(prepare(f,changed)))
        changed=r;var entries=changed.portableTranscript.entries
        if case .prompt(var p)=entries[1] { p.metadata=["historical":.string("inert")];entries[1] = .prompt(p) };changed.portableTranscript.entries=entries
        let metadata=try prepare(f,changed);XCTAssertEqual(tokenArray(binding),tokenArray(metadata));XCTAssertNotEqual(binding.requestID,metadata.requestID)
    } }
    func testHistoricalMalformedOrAmbiguousInputRefusesBeforeTemplate() throws { try withNative {
        let f=try NativePreparationFixture()
        let call=WireTranscript.Entry.toolCalls(.init(id:"calls",calls:[.init(id:"c",name:"alpha",argumentsJSON:"{}")]))
        let output=WireTranscript.Entry.toolOutput(.init(id:"c",toolName:"alpha",segments:[.text(.init(id:"t",content:"ok"))]))
        let variants:[[WireTranscript.Entry]]=[
            [output],[call],[call,output,output],[call,output,call,output],
            [.toolCalls(.init(id:"calls",calls:[.init(id:"c",name:"alpha",argumentsJSON:"[]")]))],
            [.toolCalls(.init(id:"calls",calls:[.init(id:"c",name:"alpha",argumentsJSON:"{bad")]))],
            [call,.toolOutput(.init(id:"c",toolName:"beta",segments:[]))],
            [call,.prompt(.init(id:"p",segments:[])),output]]
        for entries in variants { var r=try PreparationFixtures.request("ordinary");r.portableTranscript = .init(entries:entries);XCTAssertThrowsError(try prepare(f,r)) }
        XCTAssertEqual(f.tokenizer.renders,0);XCTAssertEqual(f.model.calls,0)
    } }
    func testOptionsResolveDeterministicallyAndRejectUnseededStochastic() throws { try withNative {
        let f=try NativePreparationFixture(),p=f.preparer.policy
        XCTAssertThrowsError(try AdapterContract.route(PreparationFixtures.request("ordinary")))
        XCTAssertThrowsError(try f.configuration.validate())
        XCTAssertEqual(try p.resolve(.init(sampling:.greedy),route:"ordinary").maximum,512)
        XCTAssertEqual(try p.resolve(.init(maximumResponseTokens:0,sampling:.greedy),route:"ordinary").maximum,0)
        XCTAssertEqual(try p.resolve(.init(sampling:.topK(8,seed:3)),route:"ordinary").temperature,0.6)
        XCTAssertEqual(try p.resolve(.init(sampling:.topP(0.5,seed:4)),route:"ordinary").seed,4)
        XCTAssertEqual(try p.resolve(.init(sampling:.topP(0,seed:nil)),route:"ordinary").temperature,0)
        XCTAssertEqual(try p.resolve(.init(temperature:0),route:"ordinary").temperature,0)
        XCTAssertEqual(try p.resolve(.init(),route:"required").temperature,0)
        for sampling:WireSampling in [.greedy,.topK(258,seed:3),.topP(0.7,seed:4),.topP(0,seed:nil)] {
            var request=try PreparationFixtures.request("ordinary");request.options.sampling=sampling
            if case .ordinary(let bound)=try prepare(f,request).lane { XCTAssertEqual(bound.options.maximumTokens,20) } else { XCTFail() }
        }
        for o:WireGenerationOptions in [.init(),.init(sampling:.topK(8,seed:nil)),.init(sampling:.topP(0.8,seed:nil)),.init(temperature:.nan),.init(temperature:.infinity),.init(temperature:-1),.init(maximumResponseTokens:-1),.init(maximumResponseTokens:513),.init(sampling:.topK(259,seed:1)),.init(sampling:.topP(1.1,seed:1))] { XCTAssertThrowsError(try p.resolve(o,route:"ordinary")) }
        for o:WireGenerationOptions in [.init(temperature:0.1),.init(sampling:.topK(1,seed:1)),.init(sampling:.topP(0,seed:1))] { XCTAssertThrowsError(try p.resolve(o,route:"required")) }
        for mode:WireToolCalling? in [nil,.allowed,.disallowed] { var r=try PreparationFixtures.request("ordinary");r.options.toolCalling=mode;XCTAssertEqual(try p.route(r),"ordinary") }
        var r=try PreparationFixtures.request("ordinary");r.options.toolCalling = .required;XCTAssertThrowsError(try p.route(r))
        r=try PreparationFixtures.request("required");r.options.toolCalling = .allowed;XCTAssertThrowsError(try p.route(r))
        r=try PreparationFixtures.request("required");r.tools.append(r.tools[0]);XCTAssertThrowsError(try p.route(r))
    } }
    func testUnsupportedContentAndBoundedTemplateFailures() throws { try withNative {
        let f=try NativePreparationFixture();var r=try PreparationFixtures.request("ordinary")
        r.portableSchema=try PreparationFixtures.request("required").tools[0].portableParameters;XCTAssertThrowsError(try prepare(f,r))
        r=try PreparationFixtures.request("ordinary");r.context.includeSchemaInPrompt=false;XCTAssertThrowsError(try prepare(f,r))
        r=try PreparationFixtures.request("ordinary",text:String(repeating:"x",count:65_537));XCTAssertThrowsError(try prepare(f,r))
        r=try PreparationFixtures.request("ordinary");r.portableTranscript = .init(entries:[.response(.init(id:"a",assetIDs:["asset"],segments:[]))]);XCTAssertThrowsError(try prepare(f,r))
        r.portableTranscript = .init(entries:[.prompt(.init(id:"p",segments:[],options:["temperature":.number(0.5)]))]);XCTAssertThrowsError(try prepare(f,r))
        r.portableTranscript = .init(entries:[.reasoning(.init(id:"r",segments:[]))]);XCTAssertThrowsError(try prepare(f,r))
        r.portableTranscript = .init(entries:[.prompt(.init(id:"p",segments:[.structure(.init(id:"s",source:"{}",content:.object([:])))]))]);XCTAssertThrowsError(try prepare(f,r))
        for fault in ["throw","empty","oversized","oov"] { f.tokenizer.fault=fault;XCTAssertThrowsError(try prepare(f,PreparationFixtures.request("ordinary"))) }
        let missing=PreparationTokenizer(template:"");XCTAssertThrowsError(try missing.applyChatTemplate(messages:[],tools:nil,additionalContext:["enable_thinking":false]))
        XCTAssertEqual(f.model.calls,0)
    } }
}
