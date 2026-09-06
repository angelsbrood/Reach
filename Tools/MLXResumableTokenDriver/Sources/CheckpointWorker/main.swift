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
let stateKey = LMOutput.Key<FixtureState>("s72.fixture.state")
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
    var calls = 0
    var prepares = 0
    var outputs: [[Float]] = []

    init(kind: String) throws {
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
            llama = nil; weightsIdentity = hash(Data("analytic-sin-cache-state-v1".utf8)); weightBytes = 0
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
        let row = sin(MLXArray.arange(16).asType(.float32) * 0.37 + shift) * 1.7
        let logits = broadcast(row.reshaped(1, 1, 16), to: [1, tokens.dim(1), 16])
        outputs.append(logits.asArray(Float.self))
        var next = LMOutput.State()
        next[stateKey] = .init(position: (previous?.position ?? 0) + tokens.dim(1), running: running)
        return .init(logits: logits, state: next)
    }
}

struct Expected: Codable {
    let tokens: [Int]
    let logits: [[Float]]
    let finalCheckpoint: Data
    let weights: String
    let producerPID: Int32
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

func run() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    if args == ["metal"] {
        let value = (MLXArray([Float(1), 2, 3]) * 2).sum()
        eval(value); try check(value.item(Float.self) == 12, "tiny Metal evaluation")
        print("NATIVE_METAL_PASS sum=12"); return
    }
    try check(args.count == 7, "usage: produce|restore llama|state simple|rotating greedy|stochastic cut checkpoint expected")
    let mode = args[0], kind = args[1]
    try check(["produce", "restore"].contains(mode), "worker mode")
    try check(["simple", "rotating"].contains(args[2]), "cache family")
    try check(["greedy", "stochastic"].contains(args[3]), "sampler kind")
    let rotating = args[2] == "rotating", stochastic = args[3] == "stochastic"
    guard let cut = Int(args[4]), (0...12).contains(cut) else { throw CheckFailure("cut") }
    let model = try FixtureModel(kind: kind)
    let prompt = [1, 2, 1, 3, 4]
    let options = ResumableTokenOptions(vocabularySize: 16, maximumTokens: 12, prefillStepSize: 2,
        temperature: stochastic ? 0.7 : 0, topP: 0.9, topK: 8, minP: 0.05, seed: 91,
        repetitionPenalty: 1.1, repetitionContextSize: 3, presencePenalty: 0.15,
        presenceContextSize: 4, frequencyPenalty: 0.2, frequencyContextSize: 5)
    let spec = ResumableCacheSpec(kind: rotating ? .rotating : .simple, heads: 1,
        keyDimension: kind == "llama" ? 8 : 4, valueDimension: kind == "llama" ? 8 : 4,
        maxSize: rotating ? 4 : 0, keep: rotating ? 1 : 0)
    let specs = Array(repeating: spec, count: kind == "llama" ? 2 : 1)
    let registry = kind == "state" ? try codecs() : ResumableStateCodecs()
    let backend = "arm64-little-endian;swift6.4;" + ProcessInfo.processInfo.operatingSystemVersionString
        + ";" + (MTLCreateSystemDefaultDevice()?.name ?? "unavailable")
    let identity = try ResumableTokenIdentity(model: kind, configuration: "tiny-fixed-v1",
        weights: model.weightsIdentity, input: ResumableTokenIdentity.inputDigest(prompt),
        backend: backend, dependency: "lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;mlx:0bb916c67f4b9e5c682cbe02a42c701c93ab5021")
    let checkpoint: ResumableTokenCheckpoint
    let driver: ResumableTokenDriver
    var prefixCalls = 0
    if mode == "produce" {
        driver = try .prepare(model: model, tokens: prompt, identity: identity, options: options,
            cacheSpecs: specs, codecs: registry)
        for _ in 0..<cut { _ = try driver.advance() }
        checkpoint = try driver.capture()
        prefixCalls = model.calls
        try checkpoint.data.write(to: URL(fileURLWithPath: args[5]), options: .atomic)
    } else {
        checkpoint = try .init(data: boundedRead(args[5], maximum: ResumableTokenCheckpoint.maximumBytes))
        driver = try .restore(checkpoint, model: model, identity: identity, options: options,
            cacheSpecs: specs, codecs: registry)
        try check(model.calls == 0 && model.prepares == 0, "restore called model/prefill")
    }
    let frozenHash = hash(checkpoint.data)
    var tokens: [Int] = []
    while let step = try driver.advance() { tokens.append(step.token) }
    let final = try driver.capture()
    let calls = model.calls
    try check(try driver.advance() == nil && driver.advance() == nil, "exhausted advance")
    try check(model.calls == calls, "exhaustion started work")
    try check(hash(checkpoint.data) == frozenHash, "checkpoint mutated after source advance")
    try check(model.prepares == 0, "prefill entry point used")
    if mode == "produce" {
        let expected = Expected(tokens: tokens, logits: Array(model.outputs.dropFirst(prefixCalls)),
            finalCheckpoint: final.data, weights: model.weightsIdentity, producerPID: ProcessInfo.processInfo.processIdentifier)
        try encoder().encode(expected).write(to: URL(fileURLWithPath: args[6]), options: .atomic)
    } else {
        let expected = try JSONDecoder().decode(Expected.self, from: boundedRead(args[6], maximum: 16 * 1024 * 1024))
        try check(expected.producerPID != ProcessInfo.processInfo.processIdentifier, "separate process")
        try check(tokens == expected.tokens && model.weightsIdentity == expected.weights, "exact continuation/weights")
        try check(model.outputs.count == expected.logits.count, "forward count")
        for (actual, wanted) in zip(model.outputs, expected.logits) {
            try check(actual.count == wanted.count, "logits count")
            for (a, b) in zip(actual, wanted) {
                try check(abs(a - b) <= 1e-6 + 1e-5 * abs(b), "logits tolerance")
            }
        }
        try equivalent(payload(final.data), payload(expected.finalCheckpoint))
    }
    try check(Memory.peakMemory <= 128 * 1024 * 1024, "tiny model/state memory ceiling")
    driver.close()
    let result: [String: Any] = ["mode": mode, "model": kind, "cache": args[2], "sampling": args[3],
        "cut": cut, "result": "PASS", "pid": ProcessInfo.processInfo.processIdentifier,
        "model_calls": model.calls, "prepare_calls": model.prepares, "prefix_calls": prefixCalls,
        "checkpoint_bytes": checkpoint.data.count, "checkpoint_sha256": frozenHash,
        "weight_bytes": model.weightBytes, "mlx_peak_bytes": Memory.peakMemory, "weights_sha256": model.weightsIdentity,
        "backend": backend, "suffix": tokens]
    print(String(data: try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), encoding: .utf8)!)
}

do {
    try Device.withDefaultDevice(Device(.gpu)) { try run() }
} catch {
    FileHandle.standardError.write(Data("CHECKPOINT_WORKER_FAIL: \(error)\n".utf8))
    exit(1)
}
