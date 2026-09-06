import Foundation
import CryptoKit
import MLXLMCommon

let toolFixtureNamespace="0123456789abcdef0123456789abcdef"
struct ToolParsingFixture {
    let name:String
    let format:ToolCallFormat
    let chunks:[String]
    var tools:[[String:JSONValue]]? = nil
    var names:[String] = ["f"]
    var supplied:Set<String> = []
    func configuration() throws -> ResumableToolCallConfiguration { try .init(format:format,tools:tools) }
}
func toolChunks(_ text:String, width:Int) -> [String] {
    let characters=Array(text)
    return stride(from:0,to:characters.count,by:width).map { String(characters[$0..<min($0+width,characters.count)]) }
}
func toolSmokeFixtures() -> [ToolParsingFixture] {
    let texts:[ToolCallFormat:String]=[
        .json:#"<tool_call>{"name":"f","arguments":{"x":"中"}}</tool_call>"#,
        .lfm2:"<|tool_call_start|>[f(x='中')]<|tool_call_end|>",
        .xmlFunction:"<tool_call><function=f><parameter=x>中</parameter></function></tool_call>",
        .glm4:"<tool_call>f<arg_key>x</arg_key><arg_value>中</arg_value></tool_call>",
        .gemma:"<start_function_call>call:f{x:<escape>中<escape>}<end_function_call>",
        .gemma4:#"<|tool_call>call:f{x:<|"|>中<|"|>}<tool_call|>"#,
        .kimiK2:#"<|tool_calls_section_begin|>functions.f:0<|tool_call_argument_begin|>{"x":"中"}<|tool_calls_section_end|>"#,
        .minimaxM2:#"<minimax:tool_call><invoke name="f"><parameter name="x">中</parameter></invoke></minimax:tool_call>"#,
        .mistral:#"[TOOL_CALLS]f[ARGS]{"x":"中"}"#,
        .llama3:#"{"name":"f","parameters":{"x":"中"}}"#,
    ]
    return ToolCallFormat.allCases.map {
        let chars=Array(texts[$0]!)
        return .init(name:$0.rawValue,format:$0,chunks:[String(chars.prefix(1)),String(chars.dropFirst().dropLast()),String(chars.suffix(1))])
    }
}
func toolDeepFixtures() -> [ToolParsingFixture] {
    let schema:[[String:JSONValue]]=[["type":.string("function"),"function":.object([
        "name":.string("f"),"parameters":.object(["type":.string("object"),"properties":.object([
            "x":.object(["type":.string("integer")]),"enabled":.object(["type":.string("boolean")])])])])]]
    return [
        .init(name:"tagged",format:.json,chunks:toolChunks(#"A<tool_call>{"id":"keep","name":"first","arguments":{"q":"中 { \"quoted\" }","n":{"a":[1,{"b":"}"}]}}}</tool_call>between<tool_call>{"name":"second","arguments":{}}</tool_call>Z"#,width:7),names:["first","second"],supplied:["keep"]),
        .init(name:"bare",format:.json,chunks:toolChunks(#"prefix {"name":"f","arguments":{"q":"中 \" }","a":[1,2]}} tail"#,width:5)),
        .init(name:"xml-schema",format:.xmlFunction,chunks:toolChunks("<tool_call><function=f><parameter=x>7</parameter><parameter=enabled>true</parameter></function></tool_call>",width:9),tools:schema),
        .init(name:"inline",format:.llama3,chunks:["prefix <|python_tag|>{\"name\":\"f\",\"parameters\":{\"x\":",#""中 \" }"}}"#]),
        .init(name:"mistral-eos",format:.mistral,chunks:["before[TOOL_","CALLS]f[CALL_ID]keep[ARGS]{\"x\":",#""中"}[TOOL_CALLS]second[ARGS]{}after"#],names:["f","second"],supplied:["keep"]),
        .init(name:"lfm2-eos",format:.lfm2,chunks:["before<|tool_call_","start|>[f(x='中')]<|tool_call_start|>[second(x=", "'a]b')]after"],names:["f","second"]),
        .init(name:"invalid-eos",format:.json,chunks:["ordinary é e\u{301}","{plain}",#"{"not":"tool"}"#,"<tool_ca"],names:[]),
    ]
}

func encode<T:Encodable>(_ value:T) throws -> Data {
    let encoder=JSONEncoder(); encoder.outputFormatting=[.sortedKeys,.withoutEscapingSlashes]; return try encoder.encode(value)
}
func sha(_ data:Data) -> String { SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined() }
func require(_ condition:Bool,_ reason:String) throws { if !condition { throw NSError(domain:reason,code:1) } }
struct Continuation:Codable {
    let configuration:ResumableToolCallConfiguration
    let namespace:String
    let chunks:[String]
}
struct Expected:Codable {
    let batches:[[ResumableToolCallRecord]]
    let finalCheckpoint:Data
}
func fixture(_ name:String) throws -> (ToolParsingFixture,Int) {
    if name=="ids" {
        let collision="call_"+String(sha(Data("S75-ID-v1:\(toolFixtureNamespace):0".utf8)).prefix(32))
        func call(_ id:String?) -> String { "<tool_call>{"+(id.map { "\"id\":\""+$0+"\"," } ?? "")+"\"name\":\"f\",\"arguments\":{}}</tool_call>" }
        return (.init(name:name,format:.json,chunks:[call(collision),call(nil),call(""),call(collision),"tail"],names:["f","f","f","f"]),2)
    }
    let selected=name=="c0" || name=="finished" ? "tagged" : name
    guard let fixture=toolDeepFixtures().first(where:{ $0.name==selected }) else { throw NSError(domain:"unknown fixture",code:1) }
    let cuts=["c0":0,"tagged":4,"bare":5,"xml-schema":7,"inline":1,"mistral-eos":3,"lfm2-eos":3,"finished":fixture.chunks.count+1]
    guard let cut=cuts[name] else { throw NSError(domain:"unknown cut",code:1) }
    return (fixture,cut)
}
func details(_ data:Data) throws -> [String:Any] {
    let envelope=try JSONSerialization.jsonObject(with:data) as! [String:Any]
    let payload=Data(base64Encoded:envelope["payload"] as! String)!
    let document=try JSONSerialization.jsonObject(with:payload) as! [String:Any]
    let parser=document["parser"] as! [String:Any]
    let allocation=parser["allocation"] as! [String:Any]
    return ["state":parser["state"]!,"buffer_bytes":Data(base64Encoded:parser["buffer"] as! String)!.count,
        "issued_count":(parser["issued"] as! [Any]).count,"allocation_position":allocation["position"]!,
        "finished":document["finished"]!,"sequence":document["sequence"]!]
}
func main() throws {
    let args=CommandLine.arguments
    try require(args.count==6,"arguments")
    let mode=args[1], name=args[2], checkpointURL=URL(fileURLWithPath:args[3]), continuationURL=URL(fileURLWithPath:args[4]), expectedURL=URL(fileURLWithPath:args[5])
    let checkpoint:ResumableToolCallCheckpoint
    let suffix:[[ResumableToolCallRecord]]
    let final:ResumableToolCallCheckpoint
    if mode=="produce" {
        let (test,cut)=try fixture(name)
        let config=try test.configuration()
        let live=try ResumableToolCallProcessor.prepare(configuration:config,namespace:toolFixtureNamespace)
        var snapshots=[try live.capture()], batches:[[ResumableToolCallRecord]]=[]
        for chunk in test.chunks { let batch=try live.consume(chunk); snapshots.append(batch.checkpoint); batches.append(batch.records) }
        let end=try live.finish()!; snapshots.append(end.checkpoint); batches.append(end.records)
        checkpoint=snapshots[cut]; suffix=Array(batches.dropFirst(cut)); final=try live.capture()
        try checkpoint.data.write(to:checkpointURL)
        try encode(Continuation(configuration:config,namespace:toolFixtureNamespace,chunks:Array(test.chunks.dropFirst(min(cut,test.chunks.count))))).write(to:continuationURL)
        try encode(Expected(batches:suffix,finalCheckpoint:final.data)).write(to:expectedURL)
        let calls=batches.flatMap { $0 }.compactMap { if case .toolCall(let c)=$0 { return c }; return nil }
        try require(calls.map(\.function.name)==test.names,"explicit parsed function names")
        try require(Set(calls.compactMap(\.id)).count==test.names.count,"unique IDs")
        live.close()
    } else {
        try require(mode=="restore","mode")
        let input=try Data(contentsOf:continuationURL)
        try require(input.count<=1024*1024,"continuation fixture bound")
        let continuation=try JSONDecoder().decode(Continuation.self,from:input)
        checkpoint=try .init(data:Data(contentsOf:checkpointURL))
        let resumed=try ResumableToolCallProcessor.restore(checkpoint,configuration:continuation.configuration,namespace:continuation.namespace)
        try require(try resumed.capture()==checkpoint,"restore is settled and emits/allocates nothing")
        var batches:[[ResumableToolCallRecord]]=[]
        for chunk in continuation.chunks { batches.append(try resumed.consume(chunk).records) }
        if let end=try resumed.finish() { batches.append(end.records) }
        suffix=batches; final=try resumed.capture()
        try require(try resumed.finish()==nil,"drained finish")
        // Expected answers are read only after all continuation work completes.
        let expected=try JSONDecoder().decode(Expected.self,from:Data(contentsOf:expectedURL))
        try require(try encode(batches)==encode(expected.batches),"exact ordered UTF-8/call/ID suffix")
        try require(final.data==expected.finalCheckpoint,"exact final checkpoint")
        resumed.close()
    }
    var result=try details(checkpoint.data)
    result.merge(["result":"PASS","mode":mode,"case":name,"pid":ProcessInfo.processInfo.processIdentifier,
        "checkpoint_sha256":sha(checkpoint.data),"checkpoint_bytes":checkpoint.data.count,
        "suffix_batches":suffix.count,"suffix_records_sha256":try sha(encode(suffix)),"final_checkpoint_sha256":sha(final.data)]) { _,new in new }
    let output=try JSONSerialization.data(withJSONObject:result,options:[.sortedKeys])
    print(String(decoding:output,as:UTF8.self))
}
do { try main() } catch { FileHandle.standardError.write(Data("\(error)\n".utf8)); exit(1) }
