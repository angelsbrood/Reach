import CryptoKit
import Foundation
import Metal
import MLX
import MLXLLM
@testable import MLXLMCommon
@testable import MLXGuidedGeneration
@testable import RequiredToolCoordinator
import ReachWire
import MLXNN

public struct CheckFailure: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}
public func check(_ value: Bool, _ label: String) throws {
    if !value { throw CheckFailure(label) }
}
public func sgHash(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
public func encoder() -> JSONEncoder {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return e
}
struct FixtureState { let position: Int; let running: MLXArray }
let stateKey = LMOutput.Key<FixtureState>("s78.fixture.state")
public func codecs() throws -> ResumableStateCodecs {
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
public final class FixtureModel: Module, LanguageModel {
    public let llama: LlamaModel?
    public let weightsIdentity: String
    public let weightBytes: Int
    public let script: [Int]
    public var calls = 0
    public var prepares = 0
    public var outputs: [[Float]] = []
    public var inputs: [[Int]] = []
    public var priorOffsets: [Int] = []

    public init(kind: String, script: [Int]) throws {
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
    public func newCache(parameters: GenerateParameters?) -> [KVCache] {
        llama?.newCache(parameters: parameters) ?? [KVCacheSimple()]
    }
    public func prepare(_ input: LMInput, cache: [KVCache], state: LMOutput.State?, windowSize: Int?) throws -> PrepareResult {
        prepares += 1
        throw CheckFailure("resumable worker must not enter model.prepare")
    }
    public func callAsFunction(_ input: LMInput.Text, cache: [KVCache]?, state: LMOutput.State?) -> LMOutput {
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

public struct S74ByteTokenizer: Tokenizer {
    public init() {}
    public static let vocab = ["<eos>"] + (0...255).map { String(format: "<0x%02X>", $0) } + ["<unk>"]
    public func encode(text: String, addSpecialTokens: Bool) -> [Int] { text.utf8.map { Int($0) + 1 } }
    public func decode(tokenIds: [Int], skipSpecialTokens: Bool) -> String {
        String(decoding: tokenIds.filter { (1...256).contains($0) }.map { UInt8($0 - 1) }, as: UTF8.self)
    }
    public func convertTokenToId(_ token: String) -> Int? { Self.vocab.firstIndex(of: token) }
    public func convertIdToToken(_ id: Int) -> String? { Self.vocab.indices.contains(id) ? Self.vocab[id] : nil }
    public var bosToken: String? { nil }
    public var eosToken: String? { "<eos>" }
    public var unknownToken: String? { "<unk>" }
    public func applyChatTemplate(messages: [[String: any Sendable]], tools: [[String: any Sendable]]?,
                           additionalContext: [String: any Sendable]?) throws -> [Int] { [] }
}

public func payload(_ checkpoint: Data) throws -> Any {
    let envelope = try JSONSerialization.jsonObject(with: checkpoint) as! [String: Any]
    let bytes=Data(base64Encoded:envelope["payload"] as! String)!
    try check(sgHash(bytes)==envelope["sha256"] as? String,"actual nested checksum")
    return try JSONSerialization.jsonObject(with:bytes)
}
public func equivalent(_ lhs: Any, _ rhs: Any, path: String = "checkpoint") throws {
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
public func boundedRead(_ path: String, maximum: Int) throws -> Data {
    let url = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
    try check(url.path.hasPrefix(URL(fileURLWithPath: "/private/tmp").standardizedFileURL.resolvingSymlinksInPath().path + "/"), "private fixture path")
    let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max
    try check(size <= maximum, "fixture size")
    let result = try Data(contentsOf: url)
    try check(result.count <= maximum, "fixture size after read")
    return result
}

public func rtJSON(_ value: Any) throws -> String {
    String(decoding: try JSONSerialization.data(withJSONObject: value,
        options: [.sortedKeys, .withoutEscapingSlashes, .fragmentsAllowed]), as: UTF8.self)
}

public struct RTFixture {
    public var name: String
    public var kind = "state"
    public var tools: [RequiredToolDefinition]
    public var expected: String
    public var expectedName: String
    public var expectedArguments: String
    public var maximum: Int
    public var fastForward = true
    public var rotating = true
    public var cancelAfter: Int?
}

public func rtFixture(_ name: String) throws -> RTFixture {
    let offered = "quoted\"\\name", message = "中\"\\\n"
    let single: [String: Any] = ["$defs": ["message": ["type": "string", "enum": [message]]], "type": "object",
        "properties": ["message": ["$ref": "#/$defs/message"], "values": ["type": "array", "items": ["type": "integer", "enum": [7]], "minItems": 2, "maxItems": 2]],
        "required": ["message", "values"], "additionalProperties": false]
    let numeric: [String: Any] = ["$defs": ["payload": ["type": "integer", "enum": [7]]], "type": "object",
        "properties": ["value": ["$ref": "#/$defs/payload"]], "required": ["value"], "additionalProperties": false]
    let text: [String: Any] = ["$defs": ["payload": ["type": "array", "items": ["type": "string", "enum": ["ok", "中"]], "minItems": 2, "maxItems": 2]],
        "type": "object", "properties": ["kind": ["type": "string", "enum": ["text"]], "value": ["$ref": "#/$defs/payload"]],
        "required": ["kind", "value"], "additionalProperties": false]
    let alternatives: [(String, [String: Any])], selected: String, args: [String: Any]
    switch name {
    case "multi-int": alternatives = [("branch-int", numeric), ("branch-text", text)]; selected = "branch-int"; args = ["value": 7]
    case "multi-text": alternatives = [("branch-int", numeric), ("branch-text", text)]; selected = "branch-text"; args = ["kind": "text", "value": ["ok", "中"]]
    case "single", "newline", "llama", "zero", "incomplete", "partial-budget", "cancel", "ff-off":
        alternatives = [(offered, single)]; selected = offered; args = ["message": message, "values": [7, 7]]
    default: throw CheckFailure("unknown required fixture")
    }
    var expected = "{\"name\":\(try rtJSON(selected)),\"arguments\":\(try rtJSON(args))}"
    if name == "newline" { expected = expected.replacingOccurrences(of: ",\"values\":", with: ",\n\"values\":") }
    return try .init(name: name, kind: name == "llama" ? "llama" : "state",
        tools: alternatives.map { .init(name: $0.0, schemaJSON: try rtJSON($0.1)) },
        expected: expected, expectedName: selected, expectedArguments: rtJSON(args),
        maximum: name == "zero" ? 0 : name == "partial-budget" ? 15 : name == "incomplete" ? expected.utf8.count : name == "llama" ? 160 : expected.utf8.count + 1,
        fastForward: name != "ff-off", rotating: name != "llama" && name != "ff-off" && name != "multi-int", cancelAfter: name == "cancel" ? 4 : nil)
}

public struct RTSetup {
    public let item: RTFixture
    public let model: FixtureModel
    public var binding: RequiredToolBinding
    public let registry: ResumableStateCodecs
    public let prompt = [1, 2, 3, 4, 5]

    public init(_ item: RTFixture) throws {
        self.item = item
        let tokenizer = S74ByteTokenizer(), script = tokenizer.encode(text: item.expected) + [0]
        model = try FixtureModel(kind: item.kind, script: script)
        let backend = "arm64-little-endian;swift6.4;" + ProcessInfo.processInfo.operatingSystemVersionString + ";" + (MTLCreateSystemDefaultDevice()?.name ?? "unavailable")
        let identity = try ResumableTokenIdentity(model: item.kind, configuration: item.name + ";s78-v1;" + sgHash(encoder().encode(script)),
            weights: model.weightsIdentity, input: ResumableTokenIdentity.inputDigest(prompt), backend: backend,
            dependency: "lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;mlx:0bb916c67f4b9e5c682cbe02a42c701c93ab5021;xgrammar:v0.1.30")
        var closing = [Float](repeating: 0, count: 258); closing[0] = 200; closing[35] = 100; closing[126] = 50
        let whitespace = WhitespaceTokenBias.compute(tokenizer: tokenizer)
        let options = ResumableGuidedOptions(model: .init(logitWidth: 258, maximumTokens: item.maximum, prefillStepSize: 2),
            completionReserve: item.kind == "llama" ? 32 : 0, closingBias: item.kind == "llama" ? closing : nil,
            whitespaceBias: whitespace.bias.asArray(Float.self), whitespaceTokenIDs: whitespace.tokenIDs)
        let spec = ResumableCacheSpec(kind: item.rotating ? .rotating : .simple, heads: 1,
            keyDimension: item.kind == "llama" ? 8 : 4, valueDimension: item.kind == "llama" ? 8 : 4,
            maxSize: item.rotating ? 4 : 0, keep: item.rotating ? 1 : 0)
        registry = item.kind == "state" ? try codecs() : .init()
        binding = try .init(requestIdentity: "s78-request:" + item.name, entryID: "entry-stable-001", callID: "call-stable-002", tools: item.tools,
            identity: identity, cacheSpecs: Array(repeating: spec, count: item.kind == "llama" ? 2 : 1),
            codecIdentity: item.kind == "state" ? "s78.fixture.state:position-running-v1:1" : "none-v1",
            vocabulary: S74ByteTokenizer.vocab, vocabularyType: .byteFallback, tokenizerIdentity: "s78-byte-v1",
            eosTokenID: 0, unknownTokenID: 257, fastForward: item.fastForward, options: options)
    }
    public func prepare() throws -> RequiredToolCoordinator {
        try .prepare(binding: binding, model: model, tokens: prompt, tokenizer: S74ByteTokenizer(), codecs: registry)
    }
    public func restore(_ checkpoint: RequiredToolCheckpoint) throws -> RequiredToolCoordinator {
        try .restore(checkpoint, expected: binding, model: model, tokenizer: S74ByteTokenizer(), codecs: registry)
    }
}

public struct RTSnapshot: Codable, Equatable {
    public let phase: RequiredToolPhase
    public let consumed: Int
    public let accepted: Int
    public let pending: Int
    public let sampled: Int
    public let forced: Int
    public let intercepted: Int
    public let incompleteUnicode: Bool
    public let newlineReset: Bool
    public let whole: Data
    public let outcome: ResumableGuidedEnd?
}
public func rtSnapshot(_ saved: RequiredToolCheckpoint) throws -> RTSnapshot {
    let d = try saved.document(), s = try ResumableGuidedCheckpoint(data: d.child).document().guided
    return .init(phase: d.control.phase, consumed: s.consumed, accepted: s.grammar.accepts.count,
        pending: s.grammar.accepts.count - s.consumed, sampled: s.sampled, forced: s.forced, intercepted: s.intercepted,
        incompleteUnicode: s.text.value.emittedTokenCount < s.text.value.tokens.count,
        newlineReset: d.control.whole.contains(10) && s.text.value.emitted.count < d.control.whole.count,
        whole: d.control.whole, outcome: s.terminal)
}
public func rtStep(_ live: RequiredToolCoordinator, item: RTFixture) throws -> RequiredToolCoordinator.Batch? {
    let s = try rtSnapshot(live.capture())
    return s.phase == .generating && s.consumed == item.cancelAfter ? try live.cancel() : try live.advance()
}
public struct RTObserved: Codable, Equatable {
    public let events: [WireEvent]
    public let state: RTSnapshot
}
public func rtObserve(_ batch: RequiredToolCoordinator.Batch) throws -> RTObserved {
    try .init(events: batch.events, state: rtSnapshot(batch.checkpoint))
}
public func rtDrain(_ live: RequiredToolCoordinator, item: RTFixture, cancelReady: Bool = false) throws -> [RTObserved] {
    var rows: [RTObserved] = []
    while let b = try (cancelReady && live.phase == .ready ? live.cancel() : rtStep(live, item: item)) { rows.append(try rtObserve(b)) }
    return rows
}

public func rtAssertResult(_ rows: [RTObserved], setup: RTSetup, final: RequiredToolCheckpoint) throws {
    let d = try final.document(), child = try ResumableGuidedCheckpoint(data: d.child).document()
    let generated = child.guided.grammar.accepts.prefix(child.guided.consumed).filter { $0.origin != .ending }.map(\.token)
    let expectedInputs = setup.item.maximum == 0 ? [] : [[1, 2], [3, 4], [5]] + generated.map { [$0] }
    try check(setup.model.inputs == expectedInputs, "independent single-token input recurrence")
    var offset = 0
    for (input, prior) in zip(expectedInputs, setup.model.priorOffsets) {
        try check(prior == offset, "independent cache offset"); offset += input.count
    }
    let events = rows.flatMap(\.events)
    let ending: ResumableGuidedEnd = setup.item.cancelAfter != nil ? .cancelled : setup.item.maximum <= setup.item.expected.utf8.count ? .incomplete : .complete
    try check(d.control.outcome == ending && d.control.phase == .emitted, "explicit outcome")
    if setup.item.kind == "state" {
        let count = setup.item.cancelAfter ?? min(setup.item.maximum, setup.item.expected.utf8.count)
        try check(generated == Array(S74ByteTokenizer().encode(text: setup.item.expected).prefix(count)), "actual explicit structural token prefix")
        if setup.item.maximum > 0 {
            let md = try ResumableGuidedModelCheckpoint(data: child.model).document()
            let actual = try md.state!.first!.payload.tensors[0].restored().asArray(Float.self)
            var recurrence: [Float] = [0, 1]
            for token in setup.prompt + generated { recurrence = recurrence.map { $0 * 0.5 + Float(token) } }
            try check(actual == recurrence, "independent typed-state recurrence")
        }
        if ending == .complete { try check(d.control.whole == Data(setup.item.expected.utf8), "exact whole private streaming output") }
    }
    switch ending {
    case .complete:
        let expected: [WireEvent] = [
            .toolCallAppendArguments(entryID: setup.binding.entryID, id: setup.binding.callID, name: setup.item.expectedName,
                content: setup.item.expectedArguments, tokenCount: 1),
            .usage(inputTokens: setup.prompt.count, outputTokens: generated.count), .finished(.complete)]
        try check(events == expected, "explicit whole call IDs/name/normalized arguments/usage/order")
        try check(child.guided.intercepted == 1 && child.guided.sampled + child.guided.forced == generated.count && child.guided.consumed == generated.count + 1,
            "usage excludes intercepted EOS")
        try check(rows.filter { !$0.events.isEmpty }.count == 1 && rows.contains { $0.state.phase == .ready && $0.events.isEmpty }, "ready then atomic settled provider batch")
    case .incomplete: try check(events == [.finished(.error(RequiredToolCoordinator.incompleteMessage))], "incomplete has only legible error ending")
    case .cancelled: try check(events == [.finished(.cancelled)], "cancellation has no partial call, text or usage")
    }
    try check(setup.model.prepares == 0 && Memory.peakMemory <= 128 * 1024 * 1024, "native model/resource contract")
}

public func rtCompare(_ actual: Data, _ expected: Data) throws {
    let a = try RequiredToolCheckpoint(data: actual).document(), b = try RequiredToolCheckpoint(data: expected).document()
    var ac = a.control, bc = b.control
    try check(ac.childDigest == sgHash(a.child) && bc.childDigest == sgHash(b.child), "outer-child checksum")
    ac.childDigest = ""; bc.childDigest = ""
    try check(try encoder().encode(ac) == encoder().encode(bc), "exact outer control/events/binding state")
    let x = try ResumableGuidedCheckpoint(data: a.child).document(), y = try ResumableGuidedCheckpoint(data: b.child).document()
    try equivalent(payload(x.model), payload(y.model), path: "child.model")
    var xs = x.guided, ys = y.guided
    try check(xs.modelDigest == sgHash(x.model) && ys.modelDigest == sgHash(y.model), "child-model checksum")
    xs.modelDigest = ""; ys.modelDigest = ""
    try check(try encoder().encode(xs) == encoder().encode(ys), "exact child guidance state")
}

public struct RTCase {
    public let fixture: String
    public let boundary: String
    public var cancelReady = false
}
public func rtCase(_ name: String) throws -> RTCase {
    let cases: [String: RTCase] = [
        "c0": .init(fixture: "single", boundary: "c0"), "pending": .init(fixture: "single", boundary: "pending"),
        "name": .init(fixture: "single", boundary: "name"), "arguments": .init(fixture: "single", boundary: "arguments"),
        "unicode": .init(fixture: "single", boundary: "unicode"), "newline": .init(fixture: "newline", boundary: "newline"),
        "before-eos": .init(fixture: "single", boundary: "before-eos"), "ready": .init(fixture: "single", boundary: "ready"),
        "emitted": .init(fixture: "single", boundary: "emitted"), "ready-cancel": .init(fixture: "single", boundary: "ready", cancelReady: true),
        "cancelled": .init(fixture: "cancel", boundary: "emitted"), "incomplete": .init(fixture: "incomplete", boundary: "emitted"),
        "zero": .init(fixture: "zero", boundary: "c0"), "partial-budget": .init(fixture: "partial-budget", boundary: "pending"),
        "multi-int": .init(fixture: "multi-int", boundary: "arguments"), "multi-text": .init(fixture: "multi-text", boundary: "arguments"),
        "llama": .init(fixture: "llama", boundary: "pending"), "ff-off": .init(fixture: "ff-off", boundary: "arguments")]
    guard let selected = cases[name] else { throw CheckFailure("unknown worker case") }; return selected
}
public func rtAtBoundary(_ checkpoint: RequiredToolCheckpoint, item: RTFixture, boundary: String) throws -> Bool {
    let s = try rtSnapshot(checkpoint)
    switch boundary {
    case "c0": return s.consumed == 0 && s.phase == .generating
    case "pending": return s.pending > 0
    case "name": return s.consumed == 10
    case "arguments":
        let r = item.expected.range(of: "\"arguments\":")!
        return s.consumed == item.expected[..<r.upperBound].utf8.count + 3
    case "unicode": return s.incompleteUnicode
    case "newline": return s.newlineReset
    case "before-eos": return s.consumed == item.expected.utf8.count && s.outcome == nil
    case "ready": return s.phase == .ready
    case "emitted": return s.phase == .emitted
    default: throw CheckFailure("unknown settled boundary")
    }
}
public func rtPrefix(_ live: RequiredToolCoordinator, item: RTFixture, boundary: String) throws -> [RTObserved] {
    var rows: [RTObserved] = []
    while try !rtAtBoundary(live.capture(), item: item, boundary: boundary) {
        guard let batch = try rtStep(live, item: item) else { throw CheckFailure("actual boundary was not observed") }
        rows.append(try rtObserve(batch))
    }
    return rows
}
