import CryptoKit
import Foundation
import Metal
import MLX
import MLXLLM
@testable import MLXLMCommon
import MLXNN

struct CheckFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
func check(_ value: Bool, _ label: String) throws {
    if !value { throw CheckFailure(label) }
}
func tgHash(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
func encoder() -> JSONEncoder {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return e
}
struct FixtureState { let position: Int; let running: MLXArray }
let stateKey = LMOutput.Key<FixtureState>("s76.fixture.state")
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
    let vocabulary: Int
    var faultAt: Int?
    var calls = 0
    var prepares = 0
    var outputs: [[Float]] = []

    init(kind: String, script: [Int], vocabulary: Int) throws {
        self.script = script; self.vocabulary = vocabulary
        if kind == "llama" {
            let model = LlamaModel(.init(hiddenSize: 16, hiddenLayers: 2, intermediateSize: 32,
                attentionHeads: 2, rmsNormEps: 0.00001, vocabularySize: vocabulary, kvHeads: 1))
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
            self.llama = model; weightsIdentity = tgHash(material); weightBytes = count
        } else {
            try check(kind == "state", "fixture kind")
            llama = nil; weightsIdentity = tgHash(Data("native-forced-tool-cache-state-v1".utf8)); weightBytes = 0
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
        if let llama {
            let logits = llama(input.tokens, cache: cache)
            outputs.append(logits.asArray(Float.self))
            return .init(logits: logits)
        }
        let tokens = input.tokens.asType(.float32)
        let previous = state?[stateKey]
        let running = (previous?.running ?? MLXArray([Float(0), 1])) + tokens.sum()
        let keys = broadcast(tokens.reshaped(1, 1, -1, 1), to: [1, 1, tokens.dim(1), 4])
        let pair = cache![0].update(keys: keys, values: keys * 0.5)
        let shift = pair.0.sum() * 0.03 + running.sum() * 0.07
        let consumed = (previous?.position ?? 0) + tokens.dim(1)
        let index = min(max(0, consumed - 5), script.count - 1)
        let mask = MLXArray.arange(vocabulary) .== script[index]
        let row = MLX.where(mask, shift, MLXArray(-Float.infinity))
        let logits = broadcast(row.reshaped(1, 1, vocabulary), to: [1, tokens.dim(1), vocabulary])
        outputs.append(logits.asArray(Float.self))
        var next = LMOutput.State()
        next[stateKey] = .init(position: (previous?.position ?? 0) + tokens.dim(1), running: running)
        if faultAt == calls { next[LMOutput.Key<Int>("s76.intentional-unregistered-fault")] = 1 }
        return .init(logits: logits, state: next)
    }
}

struct TextFixtureTokenizer: Tokenizer {
    var pieces: [Int: String] = [1: "a", 2: "b", 3: "\n", 4: "  ", 5: ",",
        6: "<", 7: "stop", 8: ">hidden", 9: "{\"tool\":", 10: "<tool_call>",
        13: "e\u{301}", 14: "é", 15: "tail"]
    func encode(text: String, addSpecialTokens: Bool) -> [Int] { [] }
    func decode(tokenIds: [Int], skipSpecialTokens: Bool) -> String {
        var result = "", index = 0
        while index < tokenIds.count {
            if tokenIds[index] == 11 {
                if index + 1 < tokenIds.count && tokenIds[index + 1] == 12 {
                    result += "中"; index += 2; continue
                }
                result += "\u{fffd}"
            } else if tokenIds[index] == 12 { result += "\u{fffd}" }
            else { result += pieces[tokenIds[index]] ?? "" }
            index += 1
        }
        return result.replacingOccurrences(of: "  ,", with: " ,")
    }
    func convertTokenToId(_ token: String) -> Int? { nil }
    func convertIdToToken(_ id: Int) -> String? { pieces[id] }
    var bosToken: String? { nil }
    var eosToken: String? { nil }
    var unknownToken: String? { nil }
    func applyChatTemplate(messages: [[String: any Sendable]], tools: [[String: any Sendable]]?,
                           additionalContext: [String: any Sendable]?) throws -> [Int] { [] }
}

func payload(_ checkpoint: Data) throws -> Any {
    let envelope = try JSONSerialization.jsonObject(with: checkpoint) as! [String: Any]
    let bytes = Data(base64Encoded: envelope["payload"] as! String)!
    try check(tgHash(bytes) == envelope["sha256"] as? String, "actual envelope checksum")
    return try JSONSerialization.jsonObject(with: bytes)
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


let tgNamespace = "0123456789abcdef0123456789abcdef"
let tgFirstID = "call_777e803074536a79970e719934685f6f"

struct TGFixture {
    var name: String
    var kind = "state"
    var script: [Int]
    var tokenizer: TextFixtureTokenizer
    var configuration: ResumableToolCallConfiguration
    var rotating = true
    var stochastic = true
    var limit: Int
    var stops: Set<String> = []
    var stopIDs: Set<Int> = [30]
    var unknown: Int? = 31
    var cancelAfter: Int?
    var vocabulary = 64
}

func tgFixture(_ name: String) throws -> TGFixture {
    var tok = TextFixtureTokenizer()
    switch name {
    case "json":
        tok.pieces[16] = "<tool"
        tok.pieces[17] = "_call>{\"name\":\"alpha\",\"arguments\":{\"n\":1,\"s\":\""
        tok.pieces[18] = "\"},\"id\":\"\(tgFirstID)\"}</tool_call>"
        tok.pieces[19] = "between\n"
        tok.pieces[20] = "<tool_call>{\"name\":\"beta\",\"arguments\":{\"b\":true}}</tool_call>tail<tool_call>{\"name\":\"gamma\",\"arguments\":{\"items\":[1,2]},\"id\":\"\(tgFirstID)\"}</tool_call>"
        tok.pieces[21] = "<sto"; tok.pieces[22] = "p>hidden"
        return try .init(name: name, script: [16,17,11,12,18,19,20,21,22], tokenizer: tok,
            configuration: .init(format: .json), limit: 9, stops: ["<stop>"])
    case "xml":
        tok.pieces[16] = "before<tool_call><function=typed><parameter=n>"
        tok.pieces[17] = "1</parameter><parameter=x>1.5</parameter><parameter=s>e\u{301}"
        tok.pieces[18] = "</parameter></function></tool_call>after"
        let tools: [[String: JSONValue]] = [["type": .string("function"), "function": .object([
            "name": .string("typed"), "parameters": .object(["type": .string("object"), "properties": .object([
                "n": .object(["type": .string("integer")]), "x": .object(["type": .string("number")]),
                "s": .object(["type": .string("string")])])])])]]
        return try .init(name: name, script: [16,17,18], tokenizer: tok,
            configuration: .init(format: .xmlFunction, tools: tools), rotating: false, limit: 3)
    case "mistral", "cancel":
        tok.pieces[16] = "[TOOL_CALLS]eos [ARGS]{\"n\":"
        tok.pieces[17] = "7}"
        tok.pieces[18] = "<stop"; tok.pieces[19] = ">hidden"
        return try .init(name: name, script: name == "cancel" ? [16,17,18,19] : [16,17,30], tokenizer: tok,
            configuration: .init(format: .mistral), limit: name == "cancel" ? 4 : 3,
            stops: name == "cancel" ? ["<stop>"] : [], cancelAfter: name == "cancel" ? 3 : nil)
    case "length-flush":
        tok.pieces[16] = "hello<sto"
        return try .init(name: name, script: [16], tokenizer: tok, configuration: .init(format: .json),
            rotating: false, stochastic: false, limit: 1, stops: ["<stop>"])
    case "zero":
        return try .init(name: name, script: [1], tokenizer: tok, configuration: .init(format: .json), limit: 0)
    case "llama":
        tok.pieces = Dictionary(uniqueKeysWithValues: (0..<16).map { ($0, "p\($0) ") })
        return try .init(name: name, kind: "llama", script: [], tokenizer: tok, configuration: .init(format: .json),
            rotating: false, limit: 5, stopIDs: [], unknown: nil, vocabulary: 16)
    default: throw CheckFailure("fixture name")
    }
}

struct TGSetup {
    let item: TGFixture
    let model: FixtureModel
    let rawOptions: ResumableTokenOptions
    let specs: [ResumableCacheSpec]
    let registry: ResumableStateCodecs
    let identity: ResumableTokenIdentity
    let options: ResumableTextOptions
    let prompt = [1,2,1,3,4]

    init(_ item: TGFixture) throws {
        self.item = item
        model = try FixtureModel(kind: item.kind, script: item.script, vocabulary: item.vocabulary)
        rawOptions = .init(vocabularySize: item.vocabulary, maximumTokens: item.limit, prefillStepSize: 2,
            temperature: item.stochastic ? 0.7 : 0, topP: 0.9, topK: 8, minP: 0.05, seed: 91,
            repetitionPenalty: 1.1, repetitionContextSize: 3, presencePenalty: 0.15,
            presenceContextSize: 4, frequencyPenalty: 0.2, frequencyContextSize: 5)
        let spec = ResumableCacheSpec(kind: item.rotating ? .rotating : .simple, heads: 1,
            keyDimension: item.kind == "llama" ? 8 : 4, valueDimension: item.kind == "llama" ? 8 : 4,
            maxSize: item.rotating ? 4 : 0, keep: item.rotating ? 1 : 0)
        specs = Array(repeating: spec, count: item.kind == "llama" ? 2 : 1)
        registry = item.kind == "state" ? try codecs() : .init()
        let pieces = try encoder().encode(item.tokenizer.pieces)
        let definition = tgHash(pieces + (try encoder().encode(item.script)))
        let backend = "arm64-little-endian;swift6.4;" + ProcessInfo.processInfo.operatingSystemVersionString
            + ";" + (MTLCreateSystemDefaultDevice()?.name ?? "unavailable")
        identity = try .init(model: item.kind, configuration: item.name + ";s76-v1;" + definition,
            weights: model.weightsIdentity, input: ResumableTokenIdentity.inputDigest(prompt), backend: backend,
            dependency: "lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;mlx:0bb916c67f4b9e5c682cbe02a42c701c93ab5021")
        options = try .init(tokenizerIdentity: "s76-byte-v1;" + tgHash(pieces), stopTokenIDs: item.stopIDs,
            unknownTokenID: item.unknown, stopStrings: item.stops)
    }
    func prepare() throws -> ResumableToolGeneration {
        try .prepare(model: model, tokens: prompt, identity: identity, rawOptions: rawOptions, cacheSpecs: specs,
            codecs: registry, tokenizer: item.tokenizer, options: options, configuration: item.configuration, namespace: tgNamespace)
    }
    func restore(_ checkpoint: ResumableToolGenerationCheckpoint, namespace: String = tgNamespace,
                 configuration: ResumableToolCallConfiguration? = nil) throws -> ResumableToolGeneration {
        try .restore(checkpoint, model: model, identity: identity, rawOptions: rawOptions, cacheSpecs: specs,
            codecs: registry, tokenizer: item.tokenizer, options: options,
            configuration: configuration ?? item.configuration, namespace: namespace)
    }
    func text() throws -> ResumableTextOutput {
        try .prepare(model: model, tokens: prompt, identity: identity, rawOptions: rawOptions, cacheSpecs: specs,
            codecs: registry, tokenizer: item.tokenizer, options: options)
    }
}

struct TGObserved: Codable {
    let token: Int?
    let records: [ResumableToolGenerationRecord]
}

func tgStep(_ driver: ResumableToolGeneration, item: TGFixture) throws -> ResumableToolGeneration.Batch? {
    let d = try driver.capture().document()
    let count = try ResumableTextCheckpoint(data: d.text).document().output.rawCount
    if count == item.cancelAfter { return try driver.cancel() }
    return try driver.advance()
}
func tgDrain(_ driver: ResumableToolGeneration, item: TGFixture) throws -> [TGObserved] {
    var rows: [TGObserved] = []
    while let batch = try tgStep(driver, item: item) { rows.append(.init(token: batch.token, records: batch.records)) }
    return rows
}

// Separately advanced actual S73 plus S75 ordered oracle, with explicit cancel policy.
// It has no composite restore/capture logic, and feeds only freshly generated text.
func tgReference(_ item: TGFixture) throws -> ([TGObserved], Data, Data) {
    let s = try TGSetup(item), text = try s.text()
    let parser = try ResumableToolCallProcessor.prepare(configuration: item.configuration, namespace: tgNamespace)
    defer { text.close(); parser.close() }
    var rows: [TGObserved] = []
    var step = 0
    while true {
        let cancelling = step == item.cancelAfter
        guard let batch = try cancelling ? text.cancel() : text.advance() else { break }
        var records: [ResumableToolGenerationRecord] = []
        for record in batch.records {
            switch record {
            case .text(let bytes):
                if !cancelling && !bytes.isEmpty {
                    records += try parser.consume(String(decoding: bytes, as: UTF8.self)).records.map { .parsed($0) }
                }
            case .terminal(let completion):
                if !cancelling { records += try parser.finish()!.records.map { .parsed($0) } }
                records.append(.terminal(completion))
            }
        }
        rows.append(.init(token: batch.token, records: records)); step += 1
    }
    return (rows, try text.capture().data, try parser.capture().data)
}

func tgCompareText(_ actual: Data, _ expected: Data) throws {
    let a = try ResumableTextCheckpoint(data: actual).document()
    let b = try ResumableTextCheckpoint(data: expected).document()
    try equivalent(payload(a.raw), payload(b.raw), path: "raw")
    var ao = try JSONSerialization.jsonObject(with: encoder().encode(a.output)) as! [String: Any]
    var bo = try JSONSerialization.jsonObject(with: encoder().encode(b.output)) as! [String: Any]
    try check(ao.removeValue(forKey: "rawDigest") as? String == tgHash(a.raw), "actual raw digest")
    try check(bo.removeValue(forKey: "rawDigest") as? String == tgHash(b.raw), "expected raw digest")
    try equivalent(ao, bo, path: "text")
}
func tgCompare(_ actual: ResumableToolGenerationCheckpoint, _ expected: ResumableToolGenerationCheckpoint) throws {
    let a = try actual.document(), b = try expected.document()
    try check(a.forwardedChunks == b.forwardedChunks && a.disposition == b.disposition, "exact join metadata")
    try check(a.parser == b.parser, "exact parser checkpoint")
    try tgCompareText(a.text, b.text)
}

func tgExplicit(_ rows: [TGObserved], item: TGFixture) throws {
    let records = rows.flatMap(\.records)
    let calls = records.compactMap { r -> ToolCall? in if case .parsed(.toolCall(let call)) = r { return call }; return nil }
    let response = records.reduce(into: Data()) { d, r in if case .parsed(.response(let bytes)) = r { d.append(bytes) } }
    let endings = records.compactMap { r -> ResumableTextCompletion? in if case .terminal(let c) = r { return c }; return nil }
    try check(endings.count == 1 && endings[0].promptTokens == 5, "one semantic terminal")
    switch item.name {
    case "json":
        try check(calls.map(\.function.name) == ["alpha","beta","gamma"], "concrete generated JSON calls")
        try check(calls.map(\.id) == [tgFirstID, ToolCallIDSequence(namespace: tgNamespace).candidate(format: .json, at: 1),
            ToolCallIDSequence(namespace: tgNamespace).candidate(format: .json, at: 2)], "supplied and collision-resolved IDs")
        try check(calls[0].function.arguments["n"] == .int(1) && calls[0].function.arguments["s"] == .string("中"), "generated Unicode arguments")
        try check(calls[1].function.arguments["b"] == .bool(true) && calls[2].function.arguments["items"] == .array([.int(1),.int(2)]), "generated typed arguments")
        try check(response == Data("between\ntail".utf8), "JSON response bytes")
        let order = records.map { r -> String in
            switch r { case .parsed(.toolCall(let c)): return c.function.name
            case .parsed(.response(let d)): return String(decoding:d,as:UTF8.self)
            case .terminal: return "END" }
        }
        try check(order == ["alpha","between\n","beta","tail","gamma","END"], "ordered call-text-call")
        try check(endings[0].reason == .stop && endings[0].rawTokens == 9 && endings[0].generationTokens == 9, "stop before length counts")
    case "xml":
        try check(calls.map(\.function.name) == ["typed"] && response == Data("beforeafter".utf8), "schema-aware generated XML")
        guard case .int(1)? = calls[0].function.arguments["n"], case .double(let x)? = calls[0].function.arguments["x"],
            case .string(let s)? = calls[0].function.arguments["s"] else { throw CheckFailure("XML typed arguments") }
        try check(x.bitPattern == (1.5 as Double).bitPattern && Data(s.utf8) == Data("e\u{301}".utf8), "XML fractional number and UTF-8")
        try check(endings[0].reason == .length && endings[0].generationTokens == 3, "XML length counts")
    case "mistral":
        try check(calls.map(\.function.name) == ["eos"] && calls[0].function.arguments["n"] == .int(7), "specialized EOS generated call")
        try check(calls[0].id == ToolCallIDSequence(namespace:tgNamespace).candidate(format:.mistral,at:0), "Mistral ID")
        try check(response.isEmpty && endings[0].reason == .stop && endings[0].rawTokens == 3 && endings[0].generationTokens == 2, "intercepted EOS accounting")
    case "cancel":
        try check(calls.isEmpty && response.isEmpty && records.count == 1 && endings[0].reason == .cancelled,
            "cancel discards stop flush and cannot recover buffered call")
        try check(endings[0].rawTokens == 3 && endings[0].generationTokens == 3, "cancel counts")
    case "length-flush": try check(response == Data("hello<sto".utf8) && calls.isEmpty && endings[0].reason == .length, "normal stop-prefix flush")
    case "zero": try check(rows.count == 1 && rows[0].token == nil && records.count == 1 && endings[0].rawTokens == 0, "zero budget")
    case "llama": try check(calls.isEmpty && !response.isEmpty && endings[0].reason == .length, "tiny Llama prose composition")
    default: break
    }
}

struct TGWorkerCase {
    let fixture: String
    let cut: Int
}
func tgWorkerCase(_ name: String) throws -> TGWorkerCase {
    let cases: [String:TGWorkerCase] = [
        "c0":.init(fixture:"json",cut:0), "partial-tag":.init(fixture:"json",cut:1),
        "unicode":.init(fixture:"json",cut:3), "ids":.init(fixture:"json",cut:7),
        "stop-prefix":.init(fixture:"json",cut:8), "normal-terminal":.init(fixture:"json",cut:9),
        "schema":.init(fixture:"xml",cut:1), "specialized-eos":.init(fixture:"mistral",cut:2),
        "cancel-boundary":.init(fixture:"cancel",cut:3), "cancel-terminal":.init(fixture:"cancel",cut:4),
        "llama":.init(fixture:"llama",cut:2)]
    guard let item = cases[name] else { throw CheckFailure("worker case") }; return item
}
struct TGExpected: Codable {
    let batches: [TGObserved]
    let logits: [[Float?]]
    let final: Data
    let weights: String
    let producerPID: Int32
}
func tgWorker() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    try check(args.count == 4, "usage: produce|restore case checkpoint expected")
    let mode = args[0], name = args[1], item = try tgWorkerCase(name)
    try check(["produce","restore"].contains(mode),"worker mode")
    let fixture = try tgFixture(item.fixture), setup = try TGSetup(fixture)
    let driver: ResumableToolGeneration, checkpoint: ResumableToolGenerationCheckpoint
    var prefix: [TGObserved] = [], prefixCalls = 0
    if mode == "produce" {
        driver = try setup.prepare()
        for _ in 0..<item.cut {
            guard let row = try tgStep(driver,item:fixture) else { throw CheckFailure("cut beyond terminal") }
            prefix.append(.init(token:row.token,records:row.records))
        }
        checkpoint = try driver.capture(); prefixCalls = setup.model.calls
    } else {
        checkpoint = try .init(data:boundedRead(args[2],maximum:ResumableToolGenerationCheckpoint.maximumBytes))
        driver = try setup.restore(checkpoint)
        try check(setup.model.calls == 0 && setup.model.prepares == 0,"restore model/prefill calls")
        try check(try driver.capture() == checkpoint,"restore has no sample, parser mutation or delivery")
    }
    defer { driver.close() }
    let d = try checkpoint.document(), text = try ResumableTextCheckpoint(data:d.text).document()
    let parser = try ResumableToolCallCheckpoint(data:d.parser).document()
    let raw = try ResumableTokenCheckpoint(data:text.raw).document()
    switch name {
    case "partial-tag": try check(parser.parser.state == "potentialToolCall","actual partial generated tag")
    case "unicode":
        try check(text.output.segmentTokens.last == 11 && text.output.emittedTokenCount < text.output.segmentTokens.count,
            "actual incomplete Unicode state")
        try check(parser.parser.state == "collectingToolCall" && !parser.parser.buffer.isEmpty,"generated partial arguments")
    case "ids": try check(parser.parser.issued.count == 3 && parser.parser.allocation.position == 3,"advanced collision allocator")
    case "stop-prefix": try check(text.output.buffer == Data("<sto".utf8),"withheld generated stop prefix")
    case "specialized-eos", "cancel-boundary", "cancel-terminal":
        try check(!parser.finished && parser.parser.state == "collectingToolCall","frozen specialized EOS input")
        if name == "cancel-terminal" { try check(d.disposition == .cancelledFrozen,"cancel disposition") }
    default: break
    }
    let suffix = try tgDrain(driver,item:fixture), final = try driver.capture(), calls = setup.model.calls
    let terminal = try final.document()
    try check(try driver.advance() == nil && driver.cancel() == nil,"terminal no redelivery")
    try check(try driver.capture() == final && setup.model.calls == calls,"terminal no work")
    if name.contains("terminal") { try check(suffix.isEmpty && calls == 0 || mode == "produce" && suffix.isEmpty,"terminal suffix empty") }
    if name == "cancel-boundary" {
        try check(setup.model.calls == prefixCalls && suffix.count == 1 && suffix[0].records.count == 1,"cancel no model step or new parser records")
        try check(terminal.parser == d.parser && ResumableTextCheckpoint(data:terminal.text).document().raw == text.raw,"cancel freezes parser and RNG/model")
    }
    if mode == "produce" {
        try tgExplicit(prefix+suffix,item:fixture)
        let expected = TGExpected(batches:suffix,
            logits:Array(setup.model.outputs.dropFirst(prefixCalls)).map { $0.map { $0.isFinite ? $0 : nil } },
            final:final.data,weights:setup.model.weightsIdentity,producerPID:ProcessInfo.processInfo.processIdentifier)
        let bytes = try encoder().encode(expected)
        try check(bytes.count <= 48*1024*1024 && bytes.count+checkpoint.data.count <= 64*1024*1024,"encoded fixture limits")
        try checkpoint.data.write(to:URL(fileURLWithPath:args[2]),options:.atomic)
        try bytes.write(to:URL(fileURLWithPath:args[3]),options:.atomic)
    } else {
        // Comparison evidence is opened only after fresh native generation has ended.
        let expected = try JSONDecoder().decode(TGExpected.self,from:boundedRead(args[3],maximum:48*1024*1024))
        try check(expected.producerPID != ProcessInfo.processInfo.processIdentifier,"fresh process")
        try check(try encoder().encode(suffix) == encoder().encode(expected.batches),"exact raw suffix and lossless ordered records")
        try check(setup.model.weightsIdentity == expected.weights && setup.model.outputs.count == expected.logits.count,"weights and forward count")
        for (actual,wanted) in zip(setup.model.outputs,expected.logits) {
            try check(actual.count == wanted.count,"logits shape")
            for (a,b) in zip(actual,wanted) {
                if let b { try check(abs(a-b) <= 1e-6+1e-5*abs(b),"logits tolerance") }
                else { try check(a == -Float.infinity,"masked logits") }
            }
        }
        try tgCompare(final,.init(data:expected.final))
    }
    try check(Memory.peakMemory <= 128*1024*1024,"tiny model tensor ceiling")
    let result: [String:Any] = ["result":"PASS","mode":mode,"case":name,"fixture":item.fixture,"cut":item.cut,
        "pid":ProcessInfo.processInfo.processIdentifier,"model_calls":setup.model.calls,"prepare_calls":setup.model.prepares,
        "prefix_calls":prefixCalls,"checkpoint_bytes":checkpoint.data.count,"checkpoint_sha256":tgHash(checkpoint.data),
        "suffix_batches":suffix.count,"suffix_records_sha256":try tgHash(encoder().encode(suffix)),
        "parser_state":parser.parser.state,"parser_buffer_bytes":parser.parser.buffer.count,"issued_ids":parser.parser.issued.count,
        "allocation_position":parser.parser.allocation.position,"forwarded_chunks":d.forwardedChunks,"parser_sequence":parser.sequence,
        "disposition":d.disposition.rawValue,"raw_count":text.output.rawCount,"generation_count":text.output.generationCount,
        "random_draws":raw.randomDraws,"typed_state_entries":raw.state?.count ?? 0,"cache_kind":fixture.rotating ? "rotating" : "simple",
        "weight_bytes":setup.model.weightBytes,"mlx_peak_bytes":Memory.peakMemory,"final_checkpoint_bytes":final.data.count]
    print(String(decoding:try JSONSerialization.data(withJSONObject:result,options:[.sortedKeys]),as:UTF8.self))
}
do { try Device.withDefaultDevice(Device(.gpu)) { try tgWorker() } }
catch { FileHandle.standardError.write(Data("TOOL_GENERATION_WORKER_FAIL: \(error)\n".utf8)); exit(1) }
