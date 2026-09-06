import CryptoKit
import Foundation
import Metal
import MLX
import MLXLLM
@testable import MLXLMCommon
@_spi(ResumableGuidedFixtures) @testable import MLXGuidedGeneration
import MLXNN

struct CheckFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
func check(_ value: Bool, _ label: String) throws {
    if !value { throw CheckFailure(label) }
}
func sgHash(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
func encoder() -> JSONEncoder {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return e
}
struct FixtureState { let position: Int; let running: MLXArray }
let stateKey = LMOutput.Key<FixtureState>("s77.fixture.state")
func codecs() throws -> ResumableStateCodecs {
    var result = ResumableStateCodecs()
    try result.register(stateKey, type: "position-running-v1", schema: 1, encode: {
        .init(metadata: try encoder().encode($0.position), tensors: [try .init(capturing: $0.running)])
    }, decode: {
        let position = try JSONDecoder().decode(Int.self, from: $0.metadata)
        try check((0...1_048_576).contains(position) && $0.tensors.count == 1, "typed state metadata")
        try check($0.tensors[0].shape == [2] && $0.tensors[0].dtype == "float32", "typed state tensor")
        return try .init(position: position, running: $0.tensors[0].restored())
    })
    return result
}

/// Calls/outputs are observation-only; they do not influence the forward calculation.
final class FixtureModel: Module, LanguageModel {
    let llama: LlamaModel?
    let weightsIdentity: String
    let weightBytes: Int
    let script: [Int]
    var calls = 0
    var prepares = 0
    var outputs: [[Float]] = []
    var inputs: [[Int]] = []
    var priorOffsets: [Int] = []

    init(kind: String, script: [Int]) throws {
        self.script = script
        if kind == "llama" {
            let model = LlamaModel(.init(hiddenSize: 16, hiddenLayers: 2, intermediateSize: 32,
                attentionHeads: 2, rmsNormEps: 0.00001, vocabularySize: 258, kvHeads: 1))
            var values: [(String, MLXArray)] = []
            var material = Data()
            var count = 0
            for (name, array) in model.parameters().flattened().sorted(by: { $0.0 < $1.0 }) {
                let salt = name.utf8.reduce(0) { ($0 + Int($1)) % 997 }
                let floats = (0..<array.size).map { index -> Float in
                    let value = Float((index * 73 + salt * 19) % 251 - 125) / 4096
                    return name.contains("norm") ? 1 + value : value
                }
                let fixed = MLXArray(floats, array.shape)
                values.append((name, fixed)); count += fixed.nbytes
                material.append(try encoder().encode([name, String(describing: array.shape)]))
                material.append(fixed.asData(access: .copy).data)
            }
            try model.update(parameters: ModuleParameters.unflattened(values), verify: .all)
            eval(model)
            self.llama = model; weightsIdentity = sgHash(material); weightBytes = count
        } else {
            try check(kind == "state", "fixture kind")
            llama = nil; weightsIdentity = sgHash(Data("native-structural-order-cache-state-v1".utf8)); weightBytes = 0
        }
        try check(weightBytes <= 128 * 1024 * 1024, "model tensor ceiling")
        super.init()
    }
    func newCache(parameters: GenerateParameters?) -> [KVCache] {
        llama?.newCache(parameters: parameters) ?? [KVCacheSimple()]
    }
    func prepare(_ input: LMInput, cache: [KVCache], state: LMOutput.State?, windowSize: Int?) throws -> PrepareResult {
        prepares += 1
        throw CheckFailure("resumable worker must not enter model.prepare")
    }
    func callAsFunction(_ input: LMInput.Text, cache: [KVCache]?, state: LMOutput.State?) -> LMOutput {
        calls += 1
        let inputIDs = input.tokens.asArray(Int.self)
        inputs.append(inputIDs); priorOffsets.append(cache?.first?.offset ?? 0)
        if let llama {
            let logits = llama(input.tokens, cache: cache)
            outputs.append(logits.asArray(Float.self))
            return .init(logits: logits)
        }
        let tokens = input.tokens.asType(.float32)
        let previous = state?[stateKey]
        var running = previous?.running ?? MLXArray([Float(0), 1])
        for token in inputIDs { running = running * 0.5 + Float(token) }
        let keys = broadcast(tokens.reshaped(1, 1, -1, 1), to: [1, 1, tokens.dim(1), 4])
        let pair = cache![0].update(keys: keys, values: keys * 0.5)
        let shift = pair.0.sum() * 0.03 + running.sum() * 0.07
        let consumed = (previous?.position ?? 0) + tokens.dim(1)
        let index = min(max(0, consumed - 5), script.count - 1)
        let mask = MLXArray.arange(258) .== script[index]
        let row = MLX.where(mask, MLXArray(Float(100)) + shift, MLXArray(Float(-100)) + sin(MLXArray.arange(258).asType(.float32)))
        let logits = broadcast(row.reshaped(1, 1, 258), to: [1, tokens.dim(1), 258])
        outputs.append(logits.asArray(Float.self))
        var next = LMOutput.State()
        next[stateKey] = .init(position: (previous?.position ?? 0) + tokens.dim(1), running: running)
        return .init(logits: logits, state: next)
    }
}

struct S74ByteTokenizer: Tokenizer {
    static let vocab = ["<eos>"] + (0...255).map { String(format: "<0x%02X>", $0) } + ["<unk>"]
    func encode(text: String, addSpecialTokens: Bool) -> [Int] { text.utf8.map { Int($0) + 1 } }
    func decode(tokenIds: [Int], skipSpecialTokens: Bool) -> String {
        String(decoding: tokenIds.filter { (1...256).contains($0) }.map { UInt8($0 - 1) }, as: UTF8.self)
    }
    func convertTokenToId(_ token: String) -> Int? { Self.vocab.firstIndex(of: token) }
    func convertIdToToken(_ id: Int) -> String? { Self.vocab.indices.contains(id) ? Self.vocab[id] : nil }
    var bosToken: String? { nil }
    var eosToken: String? { "<eos>" }
    var unknownToken: String? { "<unk>" }
    func applyChatTemplate(messages: [[String: any Sendable]], tools: [[String: any Sendable]]?,
                           additionalContext: [String: any Sendable]?) throws -> [Int] { [] }
}

func payload(_ checkpoint: Data) throws -> Any {
    let envelope = try JSONSerialization.jsonObject(with: checkpoint) as! [String: Any]
    let bytes=Data(base64Encoded:envelope["payload"] as! String)!
    try check(sgHash(bytes)==envelope["sha256"] as? String,"actual nested checksum")
    return try JSONSerialization.jsonObject(with:bytes)
}
func equivalent(_ lhs: Any, _ rhs: Any, path: String = "checkpoint") throws {
    if let a = lhs as? [String: Any], let b = rhs as? [String: Any] {
        try check(Set(a.keys) == Set(b.keys), "keys at \(path)")
        if a["shape"] != nil && a["dtype"] != nil && a["bytes"] != nil {
            let x = try JSONDecoder().decode(ResumableTensor.self, from: JSONSerialization.data(withJSONObject: a))
            let y = try JSONDecoder().decode(ResumableTensor.self, from: JSONSerialization.data(withJSONObject: b))
            try check(x.shape == y.shape && x.dtype == y.dtype, "tensor layout at \(path)")
            if x.dtype.contains("float") {
                try check(allClose(x.restored(), y.restored(), rtol: 1e-5, atol: 1e-6).item(Bool.self), "tensor values at \(path)")
            } else { try check(x.bytes == y.bytes, "exact integer tensor at \(path)") }
        } else {
            for key in a.keys.sorted() { try equivalent(a[key]!, b[key]!, path: path + "." + key) }
        }
    } else if let a = lhs as? [Any], let b = rhs as? [Any] {
        try check(a.count == b.count, "array count at \(path)")
        for i in a.indices { try equivalent(a[i], b[i], path: path + "[\(i)]") }
    } else {
        try check((lhs as? NSObject)?.isEqual(rhs) == true, "exact metadata at \(path)")
    }
}
func boundedRead(_ path: String, maximum: Int) throws -> Data {
    let url = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
    try check(url.path.hasPrefix(URL(fileURLWithPath: "/private/tmp").standardizedFileURL.resolvingSymlinksInPath().path + "/"), "private fixture path")
    let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max
    try check(size <= maximum, "fixture size")
    let result = try Data(contentsOf: url)
    try check(result.count <= maximum, "fixture size after read")
    return result
}


func sgSource(_ alternatives: [(String,[String:Any])]) throws -> String {
    let elements = try alternatives.map { name,schema -> [String:Any] in
        let escaped=String(decoding:try encoder().encode(name),as:UTF8.self)
        return ["type":"tag","begin":"{\"name\":\(escaped),\"arguments\":",
            "content":["type":"json_schema","json_schema":schema],"end":["}"]]
    }
    return String(decoding:try JSONSerialization.data(withJSONObject:["type":"structural_tag","format":["type":"or","elements":elements]],options:[.sortedKeys,.withoutEscapingSlashes]),as:UTF8.self)
}
func sgJSON(_ value: Any) throws -> String {
    String(decoding:try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys,.withoutEscapingSlashes,.fragmentsAllowed]),as:UTF8.self)
}
struct SGFixture {
    var name: String
    var kind = "state"
    var source: String
    var expected: String
    var expectedName: String
    var expectedArguments: [String:Any]
    var fastForward = true
    var rotating = true
    var maximum: Int
    var cancelAfter: Int?
    var grammarKind = "structural-tag"
}
func sgFixture(_ name: String) throws -> SGFixture {
    let singleName = "quoted\"\\name"
    let message = "中\"\\\n"
    let single: [String:Any] = ["$defs":["message":["type":"string","enum":[message]]],"type":"object",
        "properties":["message":["$ref":"#/$defs/message"],"values":["type":"array","items":["type":"integer","enum":[7]],"minItems":2,"maxItems":2]],
        "required":["message","values"],"additionalProperties":false]
    let numeric: [String:Any] = ["$defs":["payload":["type":"integer","enum":[7]]],"type":"object",
        "properties":["value":["$ref":"#/$defs/payload"]],"required":["value"],"additionalProperties":false]
    let text: [String:Any] = ["$defs":["payload":["type":"array","items":["type":"string","enum":["ok","中"]],"minItems":2,"maxItems":2]],
        "type":"object","properties":["kind":["type":"string","enum":["text"]],"value":["$ref":"#/$defs/payload"]],
        "required":["kind","value"],"additionalProperties":false]
    let alternatives: [(String,[String:Any])]
    let selected: String, args: [String:Any]
    switch name {
    case "single", "ff-off", "incomplete", "cancel", "zero", "llama":
        alternatives=[(singleName,single)]; selected=singleName; args=["message":message,"values":[7,7]]
    case "multi-text":
        alternatives=[("branch-int",numeric),("branch-text",text)]; selected="branch-text"; args=["kind":"text","value":["ok","中"]]
    case "multi-int":
        alternatives=[("branch-int",numeric),("branch-text",text)]; selected="branch-int"; args=["value":7]
    case "old-json", "old-literal":
        let source = name == "old-json" ? #"{"type":"string","enum":["中abc"]}"# : "root ::= \"\\\"中abc\\\"\""
        return .init(name:name,source:source,expected:"\"中abc\"",expectedName:"",expectedArguments:[:],
            rotating:false,maximum:9,grammarKind:name == "old-json" ? "json-schema" : "literal-fixture")
    default: throw CheckFailure("structural fixture name")
    }
    let expected="{\"name\":\(try sgJSON(selected)),\"arguments\":\(try sgJSON(args))}"
    return try .init(name:name,kind:name == "llama" ? "llama" : "state",source:sgSource(alternatives),expected:expected,
        expectedName:selected,expectedArguments:args,fastForward:name != "ff-off",rotating:name != "ff-off" && name != "multi-int" && name != "llama",
        maximum:name == "zero" ? 0 : name == "incomplete" ? expected.utf8.count : name == "llama" ? 160 : expected.utf8.count+1,
        cancelAfter:name == "cancel" ? 4 : nil)
}
struct SGSetup {
    var item: SGFixture
    let model: FixtureModel
    let identity: ResumableTokenIdentity
    var specification: ResumableGrammarSpecification
    var options: ResumableGuidedOptions
    let specs: [ResumableCacheSpec]
    let registry: ResumableStateCodecs
    let prompt = [1,2,3,4,5]
    init(_ item: SGFixture) throws {
        self.item=item
        let tokenizer=S74ByteTokenizer(), script=tokenizer.encode(text:item.expected)+[0]
        model=try FixtureModel(kind:item.kind,script:script)
        let backend="arm64-little-endian;swift6.4;"+ProcessInfo.processInfo.operatingSystemVersionString+";"+(MTLCreateSystemDefaultDevice()?.name ?? "unavailable")
        identity=try .init(model:item.kind,configuration:item.name+";s77-v1;"+sgHash(try encoder().encode(script)),
            weights:model.weightsIdentity,input:ResumableTokenIdentity.inputDigest(prompt),backend:backend,
            dependency:"lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;mlx:0bb916c67f4b9e5c682cbe02a42c701c93ab5021;xgrammar:v0.1.30")
        switch item.grammarKind {
        case "structural-tag": specification = .init(structuralTag:item.source,vocabulary:S74ByteTokenizer.vocab,vocabularyType:.byteFallback,
            tokenizerIdentity:"s77-byte-v1",eosTokenID:0,unknownTokenID:257,fastForward:item.fastForward)
        case "json-schema": specification = .init(jsonSchema:item.source,vocabulary:S74ByteTokenizer.vocab,vocabularyType:.byteFallback,
            tokenizerIdentity:"s77-byte-v1",eosTokenID:0,unknownTokenID:257,fastForward:item.fastForward)
        case "literal-fixture": specification = .literalFixture(item.source,vocabulary:S74ByteTokenizer.vocab,vocabularyType:.byteFallback,
            tokenizerIdentity:"s77-byte-v1",eosTokenID:0,unknownTokenID:257)
        default: throw CheckFailure("fixture grammar kind")
        }
        var closing=[Float](repeating:0,count:258);closing[0]=200;closing[35]=100;closing[126]=50
        let whitespace=WhitespaceTokenBias.compute(tokenizer:tokenizer)
        options = .init(model:.init(logitWidth:258,maximumTokens:item.maximum,prefillStepSize:2),completionReserve:item.kind == "llama" ? 32 : 0,
            closingBias:item.kind == "llama" ? closing : nil,whitespaceBias:whitespace.bias.asArray(Float.self),whitespaceTokenIDs:whitespace.tokenIDs)
        let spec=ResumableCacheSpec(kind:item.rotating ? .rotating : .simple,heads:1,keyDimension:item.kind == "llama" ? 8 : 4,
            valueDimension:item.kind == "llama" ? 8 : 4,maxSize:item.rotating ? 4 : 0,keep:item.rotating ? 1 : 0)
        specs=Array(repeating:spec,count:item.kind == "llama" ? 2 : 1)
        registry=item.kind == "state" ? try codecs() : .init()
    }
    func prepare() throws -> ResumableGuidedGeneration {
        try .prepare(model:model,tokens:prompt,identity:identity,cacheSpecs:specs,codecs:registry,tokenizer:S74ByteTokenizer(),specification:specification,options:options)
    }
    func restore(_ saved:ResumableGuidedCheckpoint) throws -> ResumableGuidedGeneration {
        try .restore(saved,model:model,identity:identity,cacheSpecs:specs,codecs:registry,tokenizer:S74ByteTokenizer(),specification:specification,options:options)
    }
}
struct SGObserved: Codable, Equatable {
    let token:Int?
    let origin:ResumableGuidedOrigin?
    let records:[ResumableGuidedRecord]
}
func sgStep(_ live:ResumableGuidedGeneration,item:SGFixture) throws -> ResumableGuidedGeneration.Batch? {
    live.consumedTokens == item.cancelAfter ? try live.cancel() : try live.advance()
}
func sgDrain(_ live:ResumableGuidedGeneration,item:SGFixture) throws -> [SGObserved] {
    var rows:[SGObserved]=[]
    while let b=try sgStep(live,item:item) { rows.append(.init(token:b.token,origin:b.origin,records:b.records)) }
    return rows
}
func sgCompare(_ a:Data,_ b:Data) throws {
    let left=try payload(a) as! [String:Any],right=try payload(b) as! [String:Any]
    for key in ["version","prerequisiteIdentity"] { try equivalent(left[key]!,right[key]!,path:key) }
    let lm=Data(base64Encoded:left["model"] as! String)!,rm=Data(base64Encoded:right["model"] as! String)!
    try equivalent(payload(lm),payload(rm),path:"model")
    var ls=left["guided"] as! [String:Any],rs=right["guided"] as! [String:Any]
    try check(ls.removeValue(forKey:"modelDigest") as? String==sgHash(lm),"actual model checksum binding")
    try check(rs.removeValue(forKey:"modelDigest") as? String==sgHash(rm),"expected model checksum binding")
    try equivalent(ls,rs,path:"guided")
}

// Separate actual native matcher: accept each recorded token once with FF disabled.
// It verifies prefix admissibility/termination without duplicating the guided loop.
func sgMatcher(_ d:ResumableGuidedDocument) throws {
    let gt=try GrammarTokenizer(vocab:d.guided.specification.vocabulary,vocabType:.byteFallback,eosTokenId:0)
    let matcher=try GrammarConstraint(tokenizer:gt,structuralTag:d.guided.specification.source,fastForward:false,hostTokenizer:S74ByteTokenizer())
    var ended=false
    for entry in d.guided.grammar.accepts {
        let mask=try matcher.computeMask()
        let allowed=(UInt32(bitPattern:mask.mask[entry.token/32]) >> UInt32(entry.token%32)) & 1 == 1
        try check(!ended && (!mask.needsApply || allowed),"independent structural prefix mask")
        let result=try matcher.commitToken(Int32(entry.token))
        try check(result.tokens.isEmpty,"independent matcher FF disabled");ended=result.isTerminated
    }
    try check(ended==d.guided.grammar.mask.terminated,"independent structural termination")
    if !ended {
        let mask=try matcher.computeMask()
        try check(mask.mask==d.guided.grammar.mask.words && mask.needsApply==d.guided.grammar.mask.needsApply,"independent frontier mask")
    }
}

func sgAssertResult(_ rows:[SGObserved],setup:SGSetup,final:ResumableGuidedCheckpoint) throws {
    let item=setup.item,d=try final.document(),generated=rows.filter { $0.origin != .ending }.compactMap(\.token)
    let endings=rows.flatMap(\.records).compactMap { r -> ResumableGuidedCompletion? in if case .terminal(let e)=r { return e };return nil }
    try check(endings.count==1 && endings[0].promptTokens==5,"one semantic terminal")
    let expectedInputs=item.maximum == 0 ? [] : [[1,2],[3,4],[5]]+generated.map { [$0] }
    try check(setup.model.inputs==expectedInputs,"independent sampled/forced single-token recurrence")
    var offset=0
    for (input,prior) in zip(expectedInputs,setup.model.priorOffsets) { try check(prior==offset,"independent cache offset");offset+=input.count }
    if item.kind == "state" && item.maximum>0 {
        let model=try ResumableGuidedModelCheckpoint(data:d.model).document()
        let running=try model.state!.first!.payload.tensors[0].restored().asArray(Float.self)
        var expected:[Float]=[0,1]
        for token in setup.prompt+generated { expected=expected.map { $0*0.5+Float(token) } }
        try check(running==expected,"independent typed-state recurrence")
    }
    let chunks=rows.flatMap(\.records).compactMap { r -> Data? in if case .text(let b)=r { return b };return nil }
    if item.kind == "state" {
        let count=item.cancelAfter ?? min(item.maximum,item.expected.utf8.count)
        let expectedTokens=Array(S74ByteTokenizer().encode(text:item.expected).prefix(count))
        try check(generated==expectedTokens,"explicit structural token bytes")
        // A byte tokenizer emits one complete Unicode scalar at a time. Incomplete
        // trailing UTF-8 remains withheld; no parse-equivalent replacement is used.
        var bytes=Data(),expectedChunks:[Data]=[]
        for id in expectedTokens {
            bytes.append(UInt8(id-1))
            if String(data:bytes,encoding:.utf8) != nil { expectedChunks.append(bytes);bytes=Data() }
        }
        try check(chunks==expectedChunks,"exact UTF-8 chunks")
        let expectedEnd:ResumableGuidedEnd=item.cancelAfter != nil ? .cancelled : item.maximum>item.expected.utf8.count ? .complete : .incomplete
        try check(endings[0].reason==expectedEnd,"accepted EOS vs budget/cancel")
        if expectedEnd == .complete && item.grammarKind == "structural-tag" {
            let all=chunks.reduce(into:Data()) { $0.append($1) }
            let parsed=try JSONSerialization.jsonObject(with:all) as! [String:Any]
            try check(parsed["name"] as? String==item.expectedName,"explicit offered name")
            try check(try sgJSON(parsed["arguments"]!)==sgJSON(item.expectedArguments),"root-local typed arguments")
        }
    }
    if item.grammarKind == "structural-tag" { try sgMatcher(d) }
    try check(setup.model.prepares==0 && Memory.peakMemory<=128*1024*1024,"native work/resource contract")
}

struct SGWorkerCase { let fixture:String;let boundary:String }
func sgWorkerCase(_ name:String) throws -> SGWorkerCase {
    let cases:[String:SGWorkerCase] = [
        "c0":.init(fixture:"single",boundary:"c0"),"pending":.init(fixture:"single",boundary:"pending"),
        "name":.init(fixture:"single",boundary:"name"),"arguments":.init(fixture:"single",boundary:"arguments"),
        "unicode":.init(fixture:"single",boundary:"unicode"),"alternative":.init(fixture:"multi-text",boundary:"alternative"),
        "complete":.init(fixture:"single",boundary:"terminal"),"incomplete":.init(fixture:"incomplete",boundary:"terminal"),
        "cancelled":.init(fixture:"cancel",boundary:"terminal"),"llama":.init(fixture:"llama",boundary:"pending"),
        "ff-off":.init(fixture:"ff-off",boundary:"arguments"),
        "old-json":.init(fixture:"old-json",boundary:"old-unicode"),"old-literal":.init(fixture:"old-literal",boundary:"old-unicode")]
    guard let item=cases[name] else { throw CheckFailure("worker case") };return item
}
func sgAtBoundary(_ checkpoint:ResumableGuidedCheckpoint,item:SGFixture,boundary:String) throws -> Bool {
    let state=try checkpoint.document().guided
    switch boundary {
    case "c0":return state.consumed==0
    case "pending":return state.grammar.accepts.count>state.consumed
    case "name":return state.consumed==10
    case "arguments":
        let r=item.expected.range(of:"\"arguments\":")!
        return state.consumed==item.expected[..<r.upperBound].utf8.count+3
    case "unicode":return state.text.value.emittedTokenCount<state.text.value.tokens.count
    case "alternative":
        let r=item.expected.range(of:"branch-text")!
        return state.consumed==item.expected[..<r.lowerBound].utf8.count+8
    case "terminal":return state.terminal != nil
    case "old-unicode":return state.consumed==2
    default:throw CheckFailure("boundary")
    }
}
struct SGExpected:Codable {
    let batches:[SGObserved]
    let inputs:[[Int]]
    let offsets:[Int]
    let logits:[[Float]]
    let finalCheckpoint:Data
    let weights:String
    let producerPID:Int32
}

func sgOldRefusal(_ path:String) throws {
    let checkpoint=try ResumableGuidedCheckpoint(data:boundedRead(path,maximum:16*1024*1024))
    let d=try checkpoint.document(),md=try ResumableGuidedModelCheckpoint(data:d.model).document()
    try check(d.guided.specification.kind=="structural-tag","new kind fixture")
    let dummy=try FixtureModel(kind:"state",script:[0])
    do {
        let restored=try ResumableGuidedGeneration.restore(checkpoint,model:dummy,identity:md.identity,cacheSpecs:md.specs,
            codecs:codecs(),tokenizer:S74ByteTokenizer(),specification:d.guided.specification,options:d.guided.options)
        restored.close();throw CheckFailure("old S74 unexpectedly accepted structural kind")
    } catch let error as ResumableTokenError {
        try check(error == .unsupported("guided grammar/tokenizer declaration"),"old S74 must refuse kind before model work")
    }
    try check(dummy.calls==0 && dummy.prepares==0,"old refusal model work")
    print("{\"result\":\"PASS\",\"old_s74_structural_restore\":\"refused\",\"envelope_decode\":\"accepted_only\",\"model_calls\":0}")
}

func sgWorker() throws {
    let args=Array(CommandLine.arguments.dropFirst())
    if args.count==2 && args[0]=="old-refusal" { try sgOldRefusal(args[1]);return }
    try check(args.count==4,"usage: produce|restore case checkpoint expected")
    let mode=args[0],name=args[1],selection=try sgWorkerCase(name),item=try sgFixture(selection.fixture),setup=try SGSetup(item)
    try check(["produce","restore"].contains(mode),"mode")
    let live:ResumableGuidedGeneration,saved:ResumableGuidedCheckpoint
    var prefix:[SGObserved]=[],prefixCalls=0
    if mode=="produce" {
        live=try setup.prepare()
        while try !sgAtBoundary(live.capture(),item:item,boundary:selection.boundary) {
            guard let b=try sgStep(live,item:item) else { throw CheckFailure("boundary not observed") }
            prefix.append(.init(token:b.token,origin:b.origin,records:b.records))
        }
        saved=try live.capture();prefixCalls=setup.model.calls
    } else {
        saved=try .init(data:boundedRead(args[2],maximum:16*1024*1024))
        live=try setup.restore(saved)
        try check(setup.model.calls==0 && setup.model.prepares==0 && setup.model.inputs.isEmpty,"restore has no model/prefill/sample work")
        try check(try live.capture()==saved,"restore preserves matcher/model/output state")
    }
    defer { live.close() }
    try check(try sgAtBoundary(saved,item:item,boundary:selection.boundary),"actual checkpoint boundary")
    let d=try saved.document(),pending=d.guided.grammar.accepts.count-d.guided.consumed
    let suffix=try sgDrain(live,item:item),final=try live.capture(),calls=setup.model.calls
    try check(try live.advance()==nil && live.cancel()==nil,"terminal redelivery")
    try check(setup.model.calls==calls && setup.model.prepares==0,"terminal model/prefill work")
    if selection.boundary=="terminal" { try check(suffix.isEmpty && (mode=="produce" || calls==0),"terminal frozen continuation") }
    if mode=="produce" {
        try sgAssertResult(prefix+suffix,setup:setup,final:final)
        let expected=SGExpected(batches:suffix,inputs:Array(setup.model.inputs.dropFirst(prefixCalls)),offsets:Array(setup.model.priorOffsets.dropFirst(prefixCalls)),
            logits:Array(setup.model.outputs.dropFirst(prefixCalls)),finalCheckpoint:final.data,weights:setup.model.weightsIdentity,
            producerPID:ProcessInfo.processInfo.processIdentifier)
        let bytes=try encoder().encode(expected)
        try check(bytes.count<=32*1024*1024 && bytes.count+saved.data.count<=64*1024*1024,"encoded fixture ceilings")
        try saved.data.write(to:URL(fileURLWithPath:args[2]),options:.atomic)
        try bytes.write(to:URL(fileURLWithPath:args[3]),options:.atomic)
    } else {
        // Expected evidence is opened only after fresh native continuation completes.
        let expected=try JSONDecoder().decode(SGExpected.self,from:boundedRead(args[3],maximum:32*1024*1024))
        try check(expected.producerPID != ProcessInfo.processInfo.processIdentifier,"distinct producer/restore processes")
        try check(suffix==expected.batches && setup.model.inputs==expected.inputs && setup.model.priorOffsets==expected.offsets,"exact token/origin/record/input/offset suffix")
        try check(setup.model.weightsIdentity==expected.weights && setup.model.outputs.count==expected.logits.count,"weights and forward count")
        for (a,b) in zip(setup.model.outputs,expected.logits) {
            try check(a.count==b.count,"logits shape")
            for (x,y) in zip(a,b) { try check(abs(x-y)<=1e-6+1e-5*abs(y),"logits tolerance") }
        }
        try sgCompare(final.data,expected.finalCheckpoint)
    }
    try check(Memory.peakMemory<=128*1024*1024,"tiny tensor ceiling")
    let end=try final.document().guided
    let row:[String:Any]=["result":"PASS","mode":mode,"case":name,"fixture":selection.fixture,"boundary":selection.boundary,
        "pid":ProcessInfo.processInfo.processIdentifier,"model_calls":setup.model.calls,"prepare_calls":setup.model.prepares,"prefix_calls":prefixCalls,
        "checkpoint_sha256":sgHash(saved.data),"checkpoint_bytes":saved.data.count,"specification_sha256":try sgHash(encoder().encode(setup.specification)),
        "consumed_at_cut":d.guided.consumed,"accepted_at_cut":d.guided.grammar.accepts.count,"pending_at_cut":pending,
        "incomplete_unicode_at_cut":d.guided.text.value.emittedTokenCount<d.guided.text.value.tokens.count,
        "ending":end.terminal!.rawValue,"sampled":end.sampled,"forced":end.forced,"intercepted":end.intercepted,
        "grammar_terminated":end.grammar.mask.terminated,"pending_final":end.grammar.accepts.count-end.consumed,
        "suffix_batches":suffix.count,"suffix_records_sha256":try sgHash(encoder().encode(suffix)),
        "weight_bytes":setup.model.weightBytes,"mlx_peak_bytes":Memory.peakMemory,"model_kind":item.kind,"cache":item.rotating ? "rotating" : "simple"]
    print(String(decoding:try JSONSerialization.data(withJSONObject:row,options:.sortedKeys),as:UTF8.self))
}
do { try Device.withDefaultDevice(Device(.gpu)) { try sgWorker() } }
catch { FileHandle.standardError.write(Data("STRUCTURAL_GUIDANCE_WORKER_FAIL: \(error)\n".utf8));exit(1) }
