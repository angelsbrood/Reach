import CryptoKit
import Foundation
import Metal
import MLX
import MLXLLM
@testable import MLXLMCommon
@testable import MLXGuidedGeneration
@testable import RequiredToolCoordinator
@testable import AllowedToolCoordinator
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
let stateKey = LMOutput.Key<FixtureState>("s79.fixture.state")
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
    public let promptCount: Int
    public var faultAt: Int?
    public var runningStates: [[Float]] = []
    public var calls = 0
    public var prepares = 0
    public var outputs: [[Float]] = []
    public var inputs: [[Int]] = []
    public var priorOffsets: [Int] = []

    public init(kind: String, script: [Int], promptCount: Int) throws {
        self.script = script; self.promptCount = promptCount
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
        let index = min(max(0, consumed - promptCount), script.count - 1)
        let mask = MLXArray.arange(258) .== script[index]
        let row = MLX.where(mask, MLXArray(Float(100)) + shift, MLXArray(Float(-100)) + sin(MLXArray.arange(258).asType(.float32)))
        let logits = broadcast(row.reshaped(1, 1, 258), to: [1, tokens.dim(1), 258])
        outputs.append(logits.asArray(Float.self))
        var next = LMOutput.State()
        next[stateKey] = .init(position: (previous?.position ?? 0) + tokens.dim(1), running: running)
        runningStates.append(running.asArray(Float.self))
        if faultAt == calls { next[LMOutput.Key<Int>("s79.intentional-fault")] = 1 }
        return .init(logits: logits, state: next)
    }
}

public struct S79ByteTokenizer: Tokenizer {
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

public let atNamespace = "0123456789abcdef0123456789abcdef"
public func atID(_ index: Int) -> String { "call_" + String(sgHash(Data("S75-ID-v1:\(atNamespace):\(index)".utf8)).prefix(32)) }
public func atJSON(_ value: Any) throws -> String {
    String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes, .fragmentsAllowed]), as: UTF8.self)
}
public struct ATFixture {
    public let name: String
    public let probe: String
    public let responseSchema: String?
    public let probeLimit: Int
    public let guidedLimit: Int
    public let llama: Bool
    public let expectedNames: [String]
    public let expectedIDs: [String]
}
public func atTools() throws -> [RequiredToolDefinition] {
    let alpha: [String: Any] = ["$defs": ["p": ["type": "integer", "enum": [7]]], "type": "object",
        "properties": ["n": ["$ref": "#/$defs/p"]], "required": ["n"], "additionalProperties": false]
    let beta: [String: Any] = ["$defs": ["p": ["type": "string", "enum": ["中\"\\\n"]]], "type": "object",
        "properties": ["message": ["$ref": "#/$defs/p"], "values": ["type": "array", "items": ["type": "integer", "enum": [7]], "minItems": 2, "maxItems": 2]],
        "required": ["message", "values"], "additionalProperties": false]
    return try [.init(name: "alpha", schemaJSON: atJSON(alpha)), .init(name: "beta", schemaJSON: atJSON(beta))]
}
public func atArguments(_ name: String) throws -> String {
    name == "alpha" ? "{\"n\":7}" : try atJSON(["message": "中\"\\\n", "values": [7, 7]])
}
public func atEnvelope(_ name: String) throws -> String {
    let args = try atArguments(name)
    return "{\"name\":\(try atJSON(name)),\"arguments\":\(args)}".replacingOccurrences(of: ",\"values\":", with: ",\n\"values\":")
}
public let atSchemaOutput = "{\n\"value\":\"中\"}"
public func atFixture(_ name: String) throws -> ATFixture {
    let first = "<tool_call>{\"name\":\"alpha\",\"arguments\":{\"n\":1.5,\"count\":1},\"id\":\"\(atID(0))\"}</tool_call>"
    let second = "<tool_call>{\"name\":\"beta\",\"arguments\":{\"message\":\"proposal中\"}}</tool_call>"
    let repeated = "<tool_call>{\"name\":\"alpha\",\"arguments\":{\"n\":-2},\"id\":\"\(atID(0))\"}</tool_call>"
    let schema = #"{"type":"object","properties":{"value":{"type":"string","enum":["中"]}},"required":["value"],"additionalProperties":false}"#
    let probe: String, names: [String], ids: [String]
    switch name {
    case "prose", "schema", "schema-incomplete", "llama", "length", "zero": probe = "hello\n中"; names = []; ids = []
    case "single", "precedence", "guided-incomplete": probe = "前\n" + first + "tail"; names = ["alpha"]; ids = [atID(0)]
    case "multi", "second-incomplete": probe = "前\n" + first + "between\n" + second + repeated + "tail"; names = ["alpha", "beta", "alpha"]; ids = [atID(0), atID(1), atID(2)]
    case "unknown": probe = "<tool_call><function=alpha></function></tool_call><tool_call><function=unoffered></function></tool_call>"; names = []; ids = []
    default: throw CheckFailure("unknown allowed fixture")
    }
    return .init(name: name, probe: probe, responseSchema: ["schema", "schema-incomplete", "precedence", "llama"].contains(name) ? schema : nil,
        probeLimit: name == "zero" ? 0 : probe.utf8.count + (name == "length" ? 0 : 1),
        guidedLimit: name == "guided-incomplete" ? try atEnvelope("alpha").utf8.count : name == "second-incomplete" ? try atEnvelope("alpha").utf8.count + 1 : name == "schema-incomplete" ? 2 : 160,
        llama: name == "llama", expectedNames: names, expectedIDs: ids)
}
public struct ATModelTrace: Codable {
    public let kind: String
    public let index: Int
    public let inputDigest: String
    public let inputs: [[Int]]
    public let offsets: [Int]
    public let logits: [[Float]]
    public let weights: String
}
public final class ATFactory {
    public let fixture: ATFixture
    public var models: [(AllowedPreparedPass, FixtureModel)] = []
    public init(_ fixture: ATFixture) { self.fixture = fixture }
    public func make(_ pass: AllowedPreparedPass) throws -> FixtureModel {
        let text: String
        if pass.kind == .probe { text = fixture.probe }
        else if pass.kind == .schema { text = atSchemaOutput }
        else {
            let messages = try JSONDecoder().decode([AllowedToolReplayInput.Message].self, from: pass.messages)
            let user = messages[1].content
            let start = user.range(of: "Tool name: ")!.upperBound, end = user.range(of: "\nProposed arguments:")!.lowerBound
            let name = String(user[start..<end]); try check(["alpha", "beta"].contains(name), "actual repair-message selected name")
            text = try atEnvelope(name)
        }
        let model = try FixtureModel(kind: fixture.llama && pass.kind != .probe ? "llama" : "state",
            script: S79ByteTokenizer().encode(text: text) + [0], promptCount: pass.tokens.count)
        models.append((pass, model)); return model
    }
    public var calls: Int { models.reduce(0) { $0 + $1.1.calls } }
    public var prepares: Int { models.reduce(0) { $0 + $1.1.prepares } }
    public func traces(dropping prior: [Int] = []) -> [ATModelTrace] {
        models.enumerated().map { i, pair in
            let skip = i < prior.count ? prior[i] : 0, p = pair.0, m = pair.1
            return .init(kind: p.kind.rawValue, index: p.index, inputDigest: p.inputDigest,
                inputs: Array(m.inputs.dropFirst(skip)), offsets: Array(m.priorOffsets.dropFirst(skip)),
                logits: Array(m.outputs.dropFirst(skip)), weights: m.weightsIdentity)
        }.filter { !$0.inputs.isEmpty }
    }
}
public struct ATSetup {
    public let item: ATFixture
    public let factory: ATFactory
    public var binding: AllowedToolBinding
    public let runtime: AllowedToolRuntime
    public init(_ item: ATFixture) throws {
        self.item = item; factory = ATFactory(item)
        let prompt = [1, 2, 3, 4, 5], tokenizer = S79ByteTokenizer()
        let state = try FixtureModel(kind: "state", script: [0], promptCount: 5)
        let guided = item.llama ? try FixtureModel(kind: "llama", script: [0], promptCount: 5) : state
        let backend = "arm64-little-endian;swift6.4;" + ProcessInfo.processInfo.operatingSystemVersionString + ";" + (MTLCreateSystemDefaultDevice()?.name ?? "unavailable")
        func identity(_ m: FixtureModel, _ kind: String) throws -> ResumableTokenIdentity {
            try .init(model: kind, configuration: "S79-fixed-native-fixture-v1:" + item.name, weights: m.weightsIdentity,
                input: ResumableTokenIdentity.inputDigest(prompt), backend: backend,
                dependency: "lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;mlx:0bb916c67f4b9e5c682cbe02a42c701c93ab5021;xgrammar:v0.1.30")
        }
        let probeSpecs = [ResumableCacheSpec(kind: .rotating, heads: 1, keyDimension: 4, valueDimension: 4, maxSize: 4, keep: 1)]
        let guidedSpec = ResumableCacheSpec(kind: .simple, heads: 1, keyDimension: item.llama ? 8 : 4, valueDimension: item.llama ? 8 : 4)
        let raw = ResumableTokenOptions(vocabularySize: 258, maximumTokens: item.probeLimit, prefillStepSize: 2)
        let text = try ResumableTextOptions(tokenizerIdentity: "s79-byte-v1", stopTokenIDs: [0], unknownTokenID: 257)
        let tokenSpec = ResumableGrammarSpecification(jsonSchema: "{}", vocabulary: S79ByteTokenizer.vocab, vocabularyType: .byteFallback,
            tokenizerIdentity: "s79-byte-v1", eosTokenID: 0, unknownTokenID: 257, fastForward: true)
        var closing = [Float](repeating: 0, count: 258); closing[0] = 200; closing[35] = 100; closing[126] = 50
        let whitespace = WhitespaceTokenBias.compute(tokenizer: tokenizer)
        let options = ResumableGuidedOptions(model: .init(logitWidth: 258, maximumTokens: item.guidedLimit, prefillStepSize: 64),
            completionReserve: item.llama ? 32 : 0, closingBias: item.llama ? closing : nil,
            whitespaceBias: whitespace.bias.asArray(Float.self), whitespaceTokenIDs: whitespace.tokenIDs)
        binding = try .init(requestIdentity: "s79-request:" + item.name, entryID: "entry-allowed-stable", namespace: atNamespace, tools: atTools(),
            responseSchema: item.responseSchema, originalTokens: prompt,
            probeModel: .init(identity: identity(state, "state"), cacheSpecs: probeSpecs, codecIdentity: "s79.fixture.state:position-running-v1:1"),
            guidedModel: .init(identity: identity(guided, item.llama ? "llama" : "state"), cacheSpecs: Array(repeating: guidedSpec, count: item.llama ? 2 : 1), codecIdentity: item.llama ? "none-v1" : "s79.fixture.state:position-running-v1:1"),
            probeOptions: raw, textOptions: text, format: item.name == "unknown" ? .xmlFunction : .json, tokenizer: tokenSpec, guidedOptions: options)
        let f = factory
        runtime = try .init(tokenizer: tokenizer, probeCodecs: codecs(), guidedCodecs: item.llama ? .init() : codecs(), model: { try f.make($0) })
    }
    public func prepare() throws -> AllowedToolCoordinator { try .prepare(binding: binding, runtime: runtime) }
    public func restore(_ saved: AllowedToolCheckpoint) throws -> AllowedToolCoordinator { try .restore(saved, expected: binding, runtime: runtime) }
}


import ResumableMLXProvider
public func atExpectedProposals(_ item: ATFixture) -> [ToolCall] {
    let first = ToolCall(function: .init(name: "alpha", arguments: ["n": .double(1.5), "count": .int(1)]), id: atID(0))
    let second = ToolCall(function: .init(name: "beta", arguments: ["message": .string("proposal中")]), id: atID(1))
    let third = ToolCall(function: .init(name: "alpha", arguments: ["n": .int(-2)]), id: atID(2))
    switch item.name {
    case "single", "precedence", "guided-incomplete": return [first]
    case "multi", "second-incomplete": return [first, second, third]
    case "unknown": return [.init(function: .init(name: "alpha", arguments: [String: JSONValue]()), id: atID(0)), .init(function: .init(name: "unoffered", arguments: [String: JSONValue]()), id: atID(1))]
    default: return []
    }
}
public func atExpectedMessages(_ proposal: ToolCall) throws -> Data {
    let arguments = String(decoding: try encoder().encode(proposal.function.arguments), as: UTF8.self)
    let system = "You repair proposed JSON tool arguments without inventing a different tool."
    let user = "Correct the proposed tool call while preserving every value its schema permits. Return only the required JSON envelope.\nTool name: \(proposal.function.name)\nProposed arguments: \(arguments)"
    return try JSONSerialization.data(withJSONObject: [["role": "system", "content": system], ["role": "user", "content": user]], options: [.sortedKeys, .withoutEscapingSlashes])
}
public func atCompare(_ a: Data, _ b: Data) throws {
    let left = try AllowedToolCheckpoint(data: a).document(), right = try AllowedToolCheckpoint(data: b).document()
    var lc = left.control, rc = right.control
    try check(lc.childDigest == sgHash(left.child) && rc.childDigest == sgHash(right.child), "outer retained-child digest")
    lc.childDigest = ""; rc.childDigest = ""
    try check(try encoder().encode(lc) == encoder().encode(rc), "exact outer binding/history/route/prefix/usage/current-input")
    if lc.childKind == .probe {
        let x = try ResumableToolGenerationCheckpoint(data: left.child).document(), y = try ResumableToolGenerationCheckpoint(data: right.child).document()
        try check(x.parser == y.parser && x.forwardedChunks == y.forwardedChunks && x.disposition == y.disposition, "exact retained parser/join")
        let tx = try ResumableTextCheckpoint(data: x.text).document(), ty = try ResumableTextCheckpoint(data: y.text).document()
        try equivalent(payload(tx.raw), payload(ty.raw), path: "probe.raw")
        var xo = tx.output, yo = ty.output
        try check(xo.rawDigest == sgHash(tx.raw) && yo.rawDigest == sgHash(ty.raw), "text-raw digest")
        xo.rawDigest = ""; yo.rawDigest = ""
        try check(try encoder().encode(xo) == encoder().encode(yo), "exact probe output frontier")
    } else {
        let x = try ResumableGuidedCheckpoint(data: left.child).document(), y = try ResumableGuidedCheckpoint(data: right.child).document()
        try equivalent(payload(x.model), payload(y.model), path: "guided.model")
        var xo = x.guided, yo = y.guided
        try check(xo.modelDigest == sgHash(x.model) && yo.modelDigest == sgHash(y.model), "guided-model digest")
        xo.modelDigest = ""; yo.modelDigest = ""
        try check(try encoder().encode(xo) == encoder().encode(yo), "exact retained guidance")
    }
}
public func atCompareTraces(_ actual: [ATModelTrace], _ expected: [ATModelTrace]) throws {
    try check(actual.count == expected.count, "native model pass suffix count")
    for (a, b) in zip(actual, expected) {
        try check(a.kind == b.kind && a.index == b.index && a.inputDigest == b.inputDigest && a.weights == b.weights,
            "native model pass/weights/input binding")
        try check(a.inputs == b.inputs && a.offsets == b.offsets && a.logits.count == b.logits.count, "exact input/cache-offset suffix")
        for (x, y) in zip(a.logits, b.logits) {
            try check(x.count == y.count, "logit shape")
            for (u, v) in zip(x, y) { try check(abs(u-v) <= 1e-6 + 1e-5*abs(v), "logit float tolerance") }
        }
    }
}

public final class PFNativeFactory {
    public var models: [FixtureModel] = []
    public var text = ""
    public var llama = false
    public var promptCount = 5
    public func make() throws -> FixtureModel {
        let model = try FixtureModel(kind: llama ? "llama" : "state", script: S79ByteTokenizer().encode(text: text) + [0], promptCount: promptCount)
        models.append(model); return model
    }
}
public struct PFSetup {
    public let name: String
    public let at: ATSetup
    public let native: PFNativeFactory
    public var binding: ProviderBinding
    public let runtime: ProviderRuntime
    public init(_ name: String) throws {
        self.name = name
        at = try ATSetup(atFixture(name == "allowed" ? "multi" : name == "llama" ? "llama" : "schema"))
        native = PFNativeFactory()
        let f = native, base = at.binding, tokenizer = S79ByteTokenizer()
        var model = base.guidedModel, options = base.guidedOptions
        let lane: ProviderRouteBinding
        if name.hasPrefix("ordinary") {
            model = base.probeModel
            native.text = name == "ordinary-cancel" ? "helloST" : "hello\n中"
            var raw = base.probeOptions
            raw.maximumTokens = name == "ordinary-zero" ? 0 : native.text.utf8.count + (name == "ordinary-length" ? 0 : 1)
            let text = try ResumableTextOptions(tokenizerIdentity: "s79-byte-v1", stopTokenIDs: [0], unknownTokenID: 257,
                stopStrings: name == "ordinary-cancel" ? ["STOP"] : [])
            lane = .ordinary(.init(model: model, tokens: base.originalTokens, options: raw, text: text, entryID: "response-stable", segmentID: "segment-stable"))
            runtime = try .ordinary(.init(tokenizer: tokenizer, codecs: codecs(), model: { try f.make() }))
        } else if name == "required" {
            native.text = try atEnvelope("alpha")
            let required = try RequiredToolBinding(requestIdentity: "s80-required", entryID: "tool-entry-stable", callID: "s80-call-stable",
                tools: [atTools()[0]], identity: model.identity, cacheSpecs: model.cacheSpecs, codecIdentity: model.codecIdentity,
                vocabulary: base.tokenizer.vocabulary, vocabularyType: base.tokenizer.vocabularyType, tokenizerIdentity: base.tokenizer.tokenizerIdentity,
                eosTokenID: 0, unknownTokenID: 257, fastForward: true, options: options)
            lane = .required(required, tokens: base.originalTokens)
            runtime = try .required(.init(tokenizer: tokenizer, codecs: codecs(), model: { try f.make() }))
        } else if name == "allowed" {
            lane = .allowed(base); runtime = .allowed(at.runtime)
        } else {
            native.llama = name == "llama"
            native.text = name == "guided-structural" ? try atEnvelope("alpha") : atSchemaOutput
            if name == "guided-incomplete" { options.model.maximumTokens = 2 }
            let source = name == "guided-structural" ? try base.specification(tool: 0) : try base.specification(tool: nil)
            lane = .guided(.init(model: model, tokens: base.originalTokens, specification: source, options: options,
                entryID: "response-stable", segmentID: "segment-stable"))
            runtime = try .guided(.init(tokenizer: tokenizer, codecs: native.llama ? .init() : codecs(), model: { try f.make() }))
        }
        binding = .init(operationID: "s80-operation:" + name, requestID: "s80-request:" + name, lane: lane)
    }
    public var calls: Int { native.models.reduce(0) { $0 + $1.calls } + at.factory.calls }
    public var prefills: Int { native.models.reduce(0) { $0 + $1.prepares } + at.factory.prepares }
    public var factories: Int { native.models.count + at.factory.models.count }
    public func prepare(owner: String = "owner-1") throws -> ResumableMLXProvider {
        try .prepare(binding: binding, runtime: runtime, owner: owner, credit: ResumableMLXProvider.reservationBytes)
    }
    public func restore(_ saved: ProviderCandidate, owner: String = "owner-2") throws -> ResumableMLXProvider {
        try .restore(committed: saved, expected: binding, runtime: runtime, owner: owner)
    }
    public func traceCounts() -> [Int] { native.models.map(\.calls) + at.factory.models.map { $0.1.calls } }
    public func traces(dropping previous: [Int] = []) -> [ATModelTrace] {
        if name == "allowed" { return at.factory.traces(dropping: previous) }
        return native.models.enumerated().map { i, m in
            let count = i < previous.count ? previous[i] : 0
            return .init(kind: binding.lane.route.rawValue, index: 0, inputDigest: "original-five-tokens",
                inputs: Array(m.inputs.dropFirst(count)), offsets: Array(m.priorOffsets.dropFirst(count)),
                logits: Array(m.outputs.dropFirst(count)), weights: m.weightsIdentity)
        }.filter { !$0.inputs.isEmpty }
    }
}

import Darwin
import Security
import DurableHostStore

public func skeys() throws -> StoreKeys {
    func random() throws -> Data {
        var data = Data(count: 32)
        let code = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        try check(code == errSecSuccess, "synthetic key CSPRNG"); return data
    }
    return try StoreKeys(metadata: random(), content: random())
}
public func fixturePath() -> String {
    FileManager.default.temporaryDirectory.appendingPathComponent("store-" + UUID().uuidString.lowercased()).path
}
public func drain(_ generation: DurableGeneration) throws -> [StoreReplayFrame] {
    let frames = try generation.replay(after: generation.deliveredThrough)
    try generation.acknowledgeDelivery(through: generation.store.snapshot().high)
    return frames
}
public func finish(_ generation: DurableGeneration) throws -> [StoreReplayFrame] {
    var frames = try drain(generation)
    for _ in 0..<500 {
        if try generation.store.snapshot().terminal { return frames }
        _ = try generation.advance(); frames += try drain(generation)
    }
    throw CheckFailure("bounded generation did not terminate")
}
public func assertOutcome(_ frames: [StoreReplayFrame], setup: PFSetup) throws {
    let events = try frames.flatMap { try JSONDecoder().decode([WireEvent].self, from: $0.eventBytes) }
    let text = events.compactMap { e -> String? in if case .responseAppend(_, let s, _, _) = e { return s }; return nil }.joined()
    let calls = events.filter { if case .toolCallAppendArguments = $0 { return true }; return false }
    let usage = events.filter { if case .usage = $0 { return true }; return false }
    var input = 5, output = 0
    switch setup.binding.lane.route {
    case .ordinary:
        try check(text == setup.native.text && calls.isEmpty, "ordinary exact output"); output = text.utf8.count
    case .guided:
        try check(try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: String] == ["value":"中"], "guided exact value")
        try check(calls.isEmpty, "guided no tool effect"); output = text.utf8.count
    case .required:
        try check(calls == [.toolCallAppendArguments(entryID: "tool-entry-stable", id: "s80-call-stable", name: "alpha", content: "{\"n\":7}", tokenCount: 1)], "required stable call")
        try check(text.isEmpty, "required private syntax"); output = try atEnvelope("alpha").utf8.count
    case .allowed:
        let proposals = atExpectedProposals(setup.at.item)
        let expected: [WireEvent] = try proposals.map { .toolCallAppendArguments(entryID: setup.at.binding.entryID, id: $0.id!, name: $0.function.name, content: try atArguments($0.function.name), tokenCount: 1) }
        try check(calls == expected && text == "前\nbetween\ntail", "allowed exact calls and prose")
        output = setup.at.item.probe.utf8.count
        for p in proposals {
            input += S79ByteTokenizer().encode(text: AllowedToolReplayInput.policy + "\n" + String(decoding: try atExpectedMessages(p), as: UTF8.self)).count
            output += try atEnvelope(p.function.name).utf8.count
        }
    }
    try check(usage == [.usage(inputTokens: input, outputTokens: output)], "exact native usage")
    try check(events.suffix(2) == [.usage(inputTokens: input, outputTokens: output), .finished(.complete)], "atomic terminal tail")
    try check(events.filter { if case .finished = $0 { return true }; return false }.count == 1, "one finish")
}
