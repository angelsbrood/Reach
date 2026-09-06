import CryptoKit
import Foundation
import Metal
import MLX
import MLXLLM
import MLXLMCommon
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
let stateKey = LMOutput.Key<FixtureState>("s73.fixture.state")
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

    init(kind: String, script: [Int]) throws {
        self.script = script
        if kind == "llama" {
            let model = LlamaModel(.init(hiddenSize: 16, hiddenLayers: 2, intermediateSize: 32,
                attentionHeads: 2, rmsNormEps: 0.00001, vocabularySize: 16, kvHeads: 1))
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
            llama = nil; weightsIdentity = hash(Data("native-forced-text-cache-state-v1".utf8)); weightBytes = 0
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
        let mask = MLXArray.arange(16) .== script[index]
        let row = MLX.where(mask, shift, MLXArray(-Float.infinity))
        let logits = broadcast(row.reshaped(1, 1, 16), to: [1, tokens.dim(1), 16])
        outputs.append(logits.asArray(Float.self))
        var next = LMOutput.State()
        next[stateKey] = .init(position: (previous?.position ?? 0) + tokens.dim(1), running: running)
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

struct WorkerCase {
    let kind: String
    let script: [Int]
    let rotating: Bool
    let stochastic: Bool
    let cut: Int
    let stops: Set<String>
}
func fixture(_ name: String) throws -> WorkerCase {
    let unicode = [1,11,12,2,3,4,5,9,10,13,14,15]
    let stop = [1,6,7,8,15,2,3,4,5,9,10,1]
    switch name {
    case "unicode-c0": return .init(kind: "state", script: unicode, rotating: false, stochastic: false, cut: 0, stops: [])
    case "unicode-buffer": return .init(kind: "state", script: unicode, rotating: true, stochastic: true, cut: 2, stops: [])
    case "unicode-visible": return .init(kind: "state", script: unicode, rotating: false, stochastic: false, cut: 3, stops: [])
    case "unicode-terminal": return .init(kind: "state", script: unicode, rotating: true, stochastic: true, cut: 12, stops: [])
    case "stop-buffer": return .init(kind: "state", script: stop, rotating: true, stochastic: false, cut: 2, stops: ["<stop>"])
    case "stop-long-prefix": return .init(kind: "state", script: stop, rotating: false, stochastic: true, cut: 3, stops: ["<stop>"])
    case "stop-terminal": return .init(kind: "state", script: stop, rotating: true, stochastic: true, cut: 4, stops: ["<stop>"])
    case "llama-c0": return .init(kind: "llama", script: [], rotating: true, stochastic: false, cut: 0, stops: [])
    case "llama-visible": return .init(kind: "llama", script: [], rotating: false, stochastic: true, cut: 3, stops: [])
    default: throw CheckFailure("unknown worker case")
    }
}
struct ObservedBatch: Codable, Equatable {
    let token: Int?
    let records: [ResumableTextRecord]
}
struct Expected: Codable {
    let batches: [ObservedBatch]
    let logits: [[Float?]]
    let finalCheckpoint: Data
    let weights: String
    let producerPID: Int32
}

func compareComposite(_ actual: Data, _ expected: Data) throws {
    let a = try payload(actual) as! [String: Any], b = try payload(expected) as! [String: Any]
    for key in ["version", "rawSchema", "rawCandidate"] { try equivalent(a[key]!, b[key]!, path: key) }
    let ar = Data(base64Encoded: a["raw"] as! String)!, br = Data(base64Encoded: b["raw"] as! String)!
    try equivalent(payload(ar), payload(br), path: "raw")
    var ao = a["output"] as! [String: Any], bo = b["output"] as! [String: Any]
    // These fingerprints bind each actual child's bytes, including float tensor bytes.
    // Float continuation is compared above using the accepted same-backend tolerance.
    try check(ao.removeValue(forKey: "rawDigest") as? String == hash(ar), "actual raw binding")
    try check(bo.removeValue(forKey: "rawDigest") as? String == hash(br), "expected raw binding")
    try equivalent(ao, bo, path: "output")
}

func run() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    try check(args.count == 4, "usage: produce|restore case checkpoint expected")
    let mode = args[0], name = args[1]
    try check(["produce", "restore"].contains(mode), "worker mode")
    let item = try fixture(name)
    let model = try FixtureModel(kind: item.kind, script: item.script)
    let prompt = [1,2,1,3,4]
    let rawOptions = ResumableTokenOptions(vocabularySize: 16, maximumTokens: 12, prefillStepSize: 2,
        temperature: item.stochastic ? 0.7 : 0, topP: 0.9, topK: 8, minP: 0.05, seed: 91,
        repetitionPenalty: 1.1, repetitionContextSize: 3, presencePenalty: 0.15,
        presenceContextSize: 4, frequencyPenalty: 0.2, frequencyContextSize: 5)
    let spec = ResumableCacheSpec(kind: item.rotating ? .rotating : .simple, heads: 1,
        keyDimension: item.kind == "llama" ? 8 : 4, valueDimension: item.kind == "llama" ? 8 : 4,
        maxSize: item.rotating ? 4 : 0, keep: item.rotating ? 1 : 0)
    let specs = Array(repeating: spec, count: item.kind == "llama" ? 2 : 1)
    let registry = item.kind == "state" ? try codecs() : ResumableStateCodecs()
    let backend = "arm64-little-endian;swift6.4;" + ProcessInfo.processInfo.operatingSystemVersionString
        + ";" + (MTLCreateSystemDefaultDevice()?.name ?? "unavailable")
    let identity = try ResumableTokenIdentity(model: item.kind, configuration: name + ";tiny-fixed-v1",
        weights: model.weightsIdentity, input: ResumableTokenIdentity.inputDigest(prompt),
        backend: backend, dependency: "lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;mlx:0bb916c67f4b9e5c682cbe02a42c701c93ab5021")
    let tokenizer = TextFixtureTokenizer()
    let outputOptions = try ResumableTextOptions(tokenizerIdentity: "s73-deterministic-byte-fixture-v1", stopStrings: item.stops)
    let checkpoint: ResumableTextCheckpoint
    let driver: ResumableTextOutput
    var prefixCalls = 0
    if mode == "produce" {
        driver = try .prepare(model: model, tokens: prompt, identity: identity, rawOptions: rawOptions,
            cacheSpecs: specs, codecs: registry, tokenizer: tokenizer, options: outputOptions)
        for _ in 0..<item.cut { _ = try driver.advance() }
        checkpoint = try driver.capture()
        prefixCalls = model.calls
        try checkpoint.data.write(to: URL(fileURLWithPath: args[2]), options: .atomic)
    } else {
        checkpoint = try .init(data: boundedRead(args[2], maximum: ResumableTextCheckpoint.maximumBytes))
        driver = try .restore(checkpoint, model: model, identity: identity, rawOptions: rawOptions,
            cacheSpecs: specs, codecs: registry, tokenizer: tokenizer, options: outputOptions)
        try check(model.calls == 0 && model.prepares == 0, "restore called model/prefill")
    }
    let document = try payload(checkpoint.data) as! [String: Any]
    let output = document["output"] as! [String: Any]
    if name == "unicode-buffer" {
        try check(output["segmentTokens"] as? [Int] == [1,11], "split Unicode segment tokens")
        try check(Data(base64Encoded: output["segment"] as! String) == Data("a".utf8), "suppressed incomplete Unicode")
        try check(output["emittedTokenCount"] as? Int == 1, "split Unicode emitted cursor")
    }
    if name == "stop-buffer" || name == "stop-long-prefix" {
        let wanted = name == "stop-buffer" ? "<" : "<stop"
        try check(Data(base64Encoded: output["buffer"] as! String) == Data(wanted.utf8), "split stop buffer")
    }
    let frozenHash = hash(checkpoint.data)
    var batches: [ObservedBatch] = []
    while let batch = try driver.advance() { batches.append(.init(token: batch.token, records: batch.records)) }
    let final = try driver.capture()
    let calls = model.calls
    try check(try driver.advance() == nil && driver.advance() == nil && driver.cancel() == nil, "terminal redelivery")
    try check(model.calls == calls, "terminal started work")
    try check(hash(checkpoint.data) == frozenHash, "older snapshot mutation")
    try check(model.prepares == 0, "generic prefill used")
    if name.hasSuffix("terminal") { try check(batches.isEmpty, "terminal snapshot redelivered output") }
    if name == "unicode-c0" {
        let actual = batches.flatMap(\.records).compactMap { record -> Data? in
            if case .text(let bytes) = record { return bytes }; return nil
        }
        let expected = ["a","中","b","\n","  ",",","{\"tool\":","<tool_call>","e\u{301}","é","tail"].map { Data($0.utf8) }
        try check(actual == expected, "forced Unicode/newline/literal byte oracle")
    }
    if mode == "produce" {
        let expected = Expected(batches: batches, logits: Array(model.outputs.dropFirst(prefixCalls)).map { $0.map { $0.isFinite ? $0 : nil } },
            finalCheckpoint: final.data, weights: model.weightsIdentity, producerPID: ProcessInfo.processInfo.processIdentifier)
        try encoder().encode(expected).write(to: URL(fileURLWithPath: args[3]), options: .atomic)
    } else {
        let expected = try JSONDecoder().decode(Expected.self, from: boundedRead(args[3], maximum: 32 * 1024 * 1024))
        try check(expected.producerPID != ProcessInfo.processInfo.processIdentifier, "separate process")
        try check(batches == expected.batches && model.weightsIdentity == expected.weights, "exact token/chunk/semantic records and weights")
        try check(model.outputs.count == expected.logits.count, "forward count")
        for (actual, wanted) in zip(model.outputs, expected.logits) {
            try check(actual.count == wanted.count, "logits count")
            for (a, b) in zip(actual, wanted) {
                if let b { try check(abs(a - b) <= 1e-6 + 1e-5 * abs(b), "logits tolerance") }
                else { try check(a == -Float.infinity, "masked logit") }
            }
        }
        try compareComposite(final.data, expected.finalCheckpoint)
    }
    try check(Memory.peakMemory <= 128 * 1024 * 1024, "tiny tensor ceiling")
    driver.close()
    let result: [String: Any] = ["mode": mode, "case": name, "result": "PASS", "pid": ProcessInfo.processInfo.processIdentifier,
        "model": item.kind, "cache": item.rotating ? "rotating" : "simple", "sampling": item.stochastic ? "stochastic" : "greedy",
        "cut": item.cut, "model_calls": model.calls, "prepare_calls": model.prepares, "prefix_calls": prefixCalls,
        "checkpoint_bytes": checkpoint.data.count, "checkpoint_sha256": frozenHash,
        "weight_bytes": model.weightBytes, "mlx_peak_bytes": Memory.peakMemory, "weights_sha256": model.weightsIdentity,
        "backend": backend, "suffix_batch_count": batches.count, "suffix_records_sha256": hash(try encoder().encode(batches))]
    print(String(data: try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), encoding: .utf8)!)
}

do { try Device.withDefaultDevice(Device(.gpu)) { try run() } }
catch {
    FileHandle.standardError.write(Data("TEXT_OUTPUT_WORKER_FAIL: \(error)\n".utf8))
    exit(1)
}
