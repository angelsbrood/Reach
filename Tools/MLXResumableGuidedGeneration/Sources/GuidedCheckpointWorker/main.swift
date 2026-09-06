import CryptoKit
import Foundation
import Metal
import MLX
import MLXLLM
import MLXLMCommon
@_spi(ResumableGuidedFixtures) import MLXGuidedGeneration
import MLXNN

struct CheckFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
func check(_ value: Bool, _ label: String) throws {
    if !value { throw CheckFailure(label) }
}
func hash(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
func encoder() -> JSONEncoder {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return e
}
struct FixtureState { let position: Int; let running: MLXArray }
let stateKey = LMOutput.Key<FixtureState>("s74.fixture.state")
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
            self.llama = model; weightsIdentity = hash(material); weightBytes = count
        } else {
            try check(kind == "state", "fixture kind")
            llama = nil; weightsIdentity = hash(Data("native-guided-order-cache-state-v1".utf8)); weightBytes = 0
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
    return try JSONSerialization.jsonObject(with: Data(base64Encoded: envelope["payload"] as! String)!)
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

struct GuidedCase {
    var literal=false
    var kind="state"
    var rotating=false
    var cut=0
    var maximum=12
}
func fixture(_ name:String) throws -> GuidedCase {
    switch name {
    case "json-c0": return .init()
    case "json-unicode": return .init(rotating:true,cut:2)
    case "json-visible": return .init(cut:4)
    case "json-terminal": return .init(rotating:true,cut:9)
    case "literal-pending": return .init(literal:true,rotating:true,cut:2)
    case "literal-visible": return .init(literal:true,cut:4)
    case "literal-incomplete": return .init(literal:true,rotating:true,cut:3,maximum:3)
    case "llama-json": return .init(kind:"llama",cut:4)
    default: throw CheckFailure("unknown guided fixture")
    }
}
struct ObservedBatch: Codable, Equatable {
    let token:Int?
    let origin:ResumableGuidedOrigin?
    let records:[ResumableGuidedRecord]
}
struct Expected: Codable {
    let batches:[ObservedBatch]
    let inputs:[[Int]]
    let offsets:[Int]
    let logits:[[Float]]
    let finalCheckpoint:Data
    let weights:String
    let producerPID:Int32
}
func compareComposite(_ a:Data,_ b:Data) throws {
    let left=try payload(a) as! [String:Any], right=try payload(b) as! [String:Any]
    for key in ["version","prerequisiteIdentity"] { try equivalent(left[key]!,right[key]!,path:key) }
    let lm=Data(base64Encoded:left["model"] as! String)!, rm=Data(base64Encoded:right["model"] as! String)!
    try equivalent(payload(lm),payload(rm),path:"model")
    var ls=left["guided"] as! [String:Any], rs=right["guided"] as! [String:Any]
    try check(ls.removeValue(forKey:"modelDigest") as? String==hash(lm),"left model binding")
    try check(rs.removeValue(forKey:"modelDigest") as? String==hash(rm),"right model binding")
    try equivalent(ls,rs,path:"guided")
}
func modelDocument(_ composite:Data) throws -> [String:Any] {
    let document=try payload(composite) as! [String:Any]
    return try payload(Data(base64Encoded:document["model"] as! String)!) as! [String:Any]
}
func run() throws {
    let args=Array(CommandLine.arguments.dropFirst())
    try check(args.count==4,"usage: produce|restore case checkpoint expected")
    let mode=args[0], name=args[1]
    try check(["produce","restore"].contains(mode),"worker mode")
    let item=try fixture(name)
    let tokenizer=S74ByteTokenizer()
    let script=tokenizer.encode(text:"\"中abc\"")+[0]
    let model=try FixtureModel(kind:item.kind,script:script)
    let prompt=[1,2,3,4,5]
    let backend="arm64-little-endian;swift6.4;"+ProcessInfo.processInfo.operatingSystemVersionString
        + ";"+(MTLCreateSystemDefaultDevice()?.name ?? "unavailable")
    let identity=try ResumableTokenIdentity(model:item.kind,configuration:name+";tiny-fixed-v1",weights:model.weightsIdentity,
        input:ResumableTokenIdentity.inputDigest(prompt),backend:backend,
        dependency:"lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;mlx:0bb916c67f4b9e5c682cbe02a42c701c93ab5021;xgrammar:v0.1.30")
    let spec=ResumableCacheSpec(kind:item.rotating ? .rotating : .simple,heads:1,
        keyDimension:item.kind=="llama" ? 8 : 4,valueDimension:item.kind=="llama" ? 8 : 4,
        maxSize:item.rotating ? 4 : 0,keep:item.rotating ? 1 : 0)
    let specs=Array(repeating:spec,count:item.kind=="llama" ? 2 : 1)
    let registry=item.kind=="state" ? try codecs() : ResumableStateCodecs()
    let grammar:ResumableGrammarSpecification = item.literal
        ? .literalFixture("root ::= \"\\\"中abc\\\"\"",vocabulary:S74ByteTokenizer.vocab,vocabularyType:.byteFallback,
            tokenizerIdentity:"s74-byte-fixture-v1",eosTokenID:0,unknownTokenID:257)
        : .init(jsonSchema:#"{"type":"string","enum":["中abc"]}"#,vocabulary:S74ByteTokenizer.vocab,vocabularyType:.byteFallback,
            tokenizerIdentity:"s74-byte-fixture-v1",eosTokenID:0,unknownTokenID:257)
    var closing=[Float](repeating:0,count:258); closing[0]=200; closing[35]=100
    let whitespace=WhitespaceTokenBias.compute(tokenizer:tokenizer)
    let options=ResumableGuidedOptions(model:.init(logitWidth:258,maximumTokens:item.maximum,prefillStepSize:2),
        completionReserve:item.kind=="llama" ? 64 : 0,closingBias:item.kind=="llama" ? closing : nil,
        whitespaceBias:whitespace.bias.asArray(Float.self),whitespaceTokenIDs:whitespace.tokenIDs)
    let checkpoint:ResumableGuidedCheckpoint
    let driver:ResumableGuidedGeneration
    var prefixCalls=0
    var prefix:[ObservedBatch]=[]
    if mode=="produce" {
        driver=try .prepare(model:model,tokens:prompt,identity:identity,cacheSpecs:specs,codecs:registry,
            tokenizer:tokenizer,specification:grammar,options:options)
        for _ in 0..<item.cut {
            if let batch=try driver.advance() { prefix.append(.init(token:batch.token,origin:batch.origin,records:batch.records)) }
        }
        checkpoint=try driver.capture(); prefixCalls=model.calls
        try checkpoint.data.write(to:URL(fileURLWithPath:args[2]),options:.atomic)
    } else {
        checkpoint=try .init(data:boundedRead(args[2],maximum:ResumableGuidedCheckpoint.maximumBytes))
        driver=try .restore(checkpoint,model:model,identity:identity,cacheSpecs:specs,codecs:registry,
            tokenizer:tokenizer,specification:grammar,options:options)
        try check(model.calls==0 && model.prepares==0 && model.inputs.isEmpty,"restore replayed model/prompt")
    }
    let document=try payload(checkpoint.data) as! [String:Any]
    let guided=document["guided"] as! [String:Any]
    let text=(guided["text"] as! [String:Any])["value"] as! [String:Any]
    if name=="json-unicode" || name=="literal-pending" {
        try check(text["tokens"] as? [Int]==[35,229],"actual split Unicode token buffer")
        try check(Data(base64Encoded:text["emitted"] as! String)==Data("\"".utf8),"incomplete bytes emitted")
    }
    if name=="literal-pending" { try check(driver.pendingForcedTokens==[185,174,98,99,100],"actual partially drained FF suffix") }
    if name=="literal-visible" { try check(driver.pendingForcedTokens==[98,99,100],"visible prefix still has pending FF") }
    let frozenHash=hash(checkpoint.data)
    var batches:[ObservedBatch]=[]
    while let b=try driver.advance() { batches.append(.init(token:b.token,origin:b.origin,records:b.records)) }
    let final=try driver.capture(); let calls=model.calls
    try check(try driver.advance()==nil && driver.advance()==nil && driver.cancel()==nil,"terminal redelivery")
    try check(model.calls==calls && model.prepares==0,"terminal/generic model work")
    try check(hash(checkpoint.data)==frozenHash,"older snapshot mutation")
    if name=="json-terminal" || name=="literal-incomplete" { try check(batches.isEmpty,"terminal restore produced records") }
    if mode=="produce" {
        let all=prefix+batches
        let generated=all.filter { $0.origin != .ending }.compactMap(\.token)
        let expectedInputs=[[1,2],[3,4],[5]]+generated.map { [$0] }
        try check(model.inputs==expectedInputs,"independent full single-token input schedule")
        var offset=0
        for (input,prior) in zip(expectedInputs,model.priorOffsets) {
            try check(prior==offset,"independent cache offset recurrence"); offset+=input.count
        }
        if item.kind=="state" {
            let d=try modelDocument(final.data)
            let entry=(d["state"] as! [[String:Any]])[0]["payload"] as! [String:Any]
            let tensors=entry["tensors"] as! [[String:Any]]
            let running=try JSONDecoder().decode(ResumableTensor.self,from:JSONSerialization.data(withJSONObject:tensors[0])).restored().asArray(Float.self)
            var expected:[Float]=[0,1]
            for token in prompt+generated { expected=expected.map { $0*0.5+Float(token) } }
            try check(running==expected,"independent typed-state recurrence")
        }
        if item.maximum>3 {
            try check(generated==Array(script.dropLast()),"schema accepted token sequence")
            let bytes=all.flatMap(\.records).compactMap { record -> Data? in if case .text(let b)=record { return b }; return nil }
            try check(bytes==["\"","中","a","b","c","\""].map { Data($0.utf8) },"ordered UTF-8 chunk oracle")
        }
        let expected=Expected(batches:batches,inputs:Array(model.inputs.dropFirst(prefixCalls)),offsets:Array(model.priorOffsets.dropFirst(prefixCalls)),
            logits:Array(model.outputs.dropFirst(prefixCalls)),finalCheckpoint:final.data,weights:model.weightsIdentity,producerPID:ProcessInfo.processInfo.processIdentifier)
        try encoder().encode(expected).write(to:URL(fileURLWithPath:args[3]),options:.atomic)
    } else {
        // Comparison evidence is intentionally not read until continuation has finished.
        let expected=try JSONDecoder().decode(Expected.self,from:boundedRead(args[3],maximum:32*1024*1024))
        try check(expected.producerPID != ProcessInfo.processInfo.processIdentifier,"fresh process")
        try check(batches==expected.batches && model.inputs==expected.inputs && model.priorOffsets==expected.offsets,"exact records/input sequence/offsets")
        try check(model.weightsIdentity==expected.weights && model.outputs.count==expected.logits.count,"weights/forward count")
        for (a,b) in zip(model.outputs,expected.logits) {
            try check(a.count==b.count,"logits shape")
            for (x,y) in zip(a,b) { try check(abs(x-y)<=1e-6+1e-5*abs(y),"logits tolerance") }
        }
        try compareComposite(final.data,expected.finalCheckpoint)
    }
    try check(Memory.peakMemory<=128*1024*1024,"tiny tensor bound")
    let ending=try (payload(final.data) as! [String:Any])["guided"] as! [String:Any]
    driver.close()
    let row:[String:Any]=["mode":mode,"case":name,"result":"PASS","pid":ProcessInfo.processInfo.processIdentifier,
        "model":item.kind,"cache":item.rotating ? "rotating" : "simple","cut":item.cut,"model_calls":model.calls,
        "prepare_calls":model.prepares,"prefix_calls":prefixCalls,"checkpoint_bytes":checkpoint.data.count,"checkpoint_sha256":frozenHash,
        "weight_bytes":model.weightBytes,"weights_sha256":model.weightsIdentity,"mlx_peak_bytes":Memory.peakMemory,
        "terminal":ending["terminal"]!,"sampled":ending["sampled"]!,"forced":ending["forced"]!,"intercepted":ending["intercepted"]!,
        "pending_at_cut":((guided["grammar"] as! [String:Any])["accepts"] as! [Any]).count-(guided["consumed"] as! Int),
        "suffix_batches":batches.count,"suffix_records_sha256":hash(try encoder().encode(batches)),"backend":backend]
    print(String(data:try JSONSerialization.data(withJSONObject:row,options:[.sortedKeys]),encoding:.utf8)!)
}

do { try Device.withDefaultDevice(Device(.gpu)) { try run() } }
catch { FileHandle.standardError.write(Data("GUIDED_WORKER_FAIL: \(error)\n".utf8)); exit(1) }
