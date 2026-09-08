import Foundation
import Darwin
import MLX
import MLXLLM
import MLXLMCommon
import MLXGuidedGeneration
import LifecycleFixtures
import ReachWire
import ResumableMLXProvider
import RequestPreparationContract
import DurableRequestPreparation
import WireAdapterContract
import DurableHostWireAdapter
import DurableClientWireAdapter
import DurableSessionLifecycle
import DurableClientReceipts
import DurableStoreBootstrap
import DurableRootKeys
import RecoveryContract

/// A real configured serialization template, followed by UTF-8 byte tokens.
/// Bounded append prevents oversized intermediate template allocation.
public final class PreparationTokenizer: Tokenizer, @unchecked Sendable {
    public static let configuredTemplate="s89-json-chat-v1:sorted-json(messages,tools,enable_thinking=false) + LF + assistant-prefix"
    public let template:String
    public var fault:String?
    public var repairPrefix:String? // Observation only; does not affect token bytes.
    public private(set) var repairEncodes=0
    public private(set) var renders=0,encodes=0,requestTokenizations=0,lastRendered=""
    public init(template:String=PreparationTokenizer.configuredTemplate) { self.template=template }
    public var bosToken:String? { nil }; public var eosToken:String? { "<eos>" };public var unknownToken:String? { "<unk>" }
    public func encode(text:String,addSpecialTokens:Bool) -> [Int] { encodes+=1;if let repairPrefix,text.hasPrefix(repairPrefix) { repairEncodes+=1 };return text.utf8.map { Int($0)+1 } }
    public func decode(tokenIds:[Int],skipSpecialTokens:Bool) -> String { String(decoding:tokenIds.filter{(1...256).contains($0)}.map{UInt8($0-1)},as:UTF8.self) }
    public func convertTokenToId(_ token:String) -> Int? { S79ByteTokenizer.vocab.firstIndex(of:token) }
    public func convertIdToToken(_ id:Int) -> String? { S79ByteTokenizer.vocab.indices.contains(id) ? S79ByteTokenizer.vocab[id] : nil }
    public func applyChatTemplate(messages:[[String:any Sendable]],tools:[[String:any Sendable]]?,additionalContext:[String:any Sendable]?) throws -> [Int] {
        guard !template.isEmpty else { throw TokenizerError.missingChatTemplate }
        guard template==Self.configuredTemplate,additionalContext?["enable_thinking"] as? Bool == false else { throw PreparationError.template }
        renders+=1
        if fault=="throw" { throw PreparationError.template }
        var bytes=Data()
        func append(_ s:String) throws { guard bytes.count+s.utf8.count<=65_536 else { throw PreparationError.oversized };bytes.append(contentsOf:s.utf8) }
        func render(_ value:Any,_ depth:Int=0) throws {
            guard depth<=40 else { throw PreparationError.oversized }
            if let object=value as? [String:Any] {
                try append("{");for (i,key) in object.keys.sorted().enumerated() { if i>0 { try append(",") };try render(key,depth+1);try append(":");try render(object[key]!,depth+1) };try append("}")
            } else if let array=value as? [Any] {
                try append("[");for (i,x) in array.enumerated() { if i>0 { try append(",") };try render(x,depth+1) };try append("]")
            } else if let string=value as? String {
                try append("\"")
                for scalar in string.unicodeScalars {
                    switch scalar.value {
                    case 34:try append("\\\"")
                    case 92:try append("\\\\")
                    case 0...31:try append(String(format:"\\u%04x",scalar.value))
                    default:try append(String(scalar))
                    }
                }
                try append("\"")
            } else {
                let encoded=try JSONSerialization.data(withJSONObject:value,options:[.fragmentsAllowed,.sortedKeys,.withoutEscapingSlashes])
                guard bytes.count+encoded.count<=65_536 else { throw PreparationError.oversized };bytes.append(encoded)
            }
        }
        try render(["messages":messages,"tools":tools ?? [],"enable_thinking":false] as [String:Any])
        try append("\n{\"role\":\"assistant\",\"content\":")
        lastRendered=String(decoding:bytes,as:UTF8.self)
        switch fault { case "empty":return [];case "oversized":return Array(repeating:1,count:2049);case "oov":return [258];default:requestTokenizations+=1;return encode(text:lastRendered,addSpecialTokens:false) }
    }
}

public final class NativePreparationFixture {
    public let tokenizer:PreparationTokenizer,model:FixtureModel,preparer:RequestPreparation
    public private(set) var factories=0
    public init(revision:String=RequestPreparationContract.ModelDescriptor.legacyRevision) throws {
        let tokenizer=PreparationTokenizer(),model=try FixtureModel(kind:"llama",script:[0],promptCount:0)
        self.tokenizer=tokenizer;self.model=model
        let config=LlamaConfiguration(hiddenSize:16,hiddenLayers:2,intermediateSize:32,attentionHeads:2,rmsNormEps:0.00001,vocabularySize:258,kvHeads:1)
        let configuration=try PreparationEncoding.digest(config)
        let backend="arm64-little-endian;swift6.4;cpu;"+ProcessInfo.processInfo.operatingSystemVersionString
        let dependency="lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;mlx:0bb916c67f4b9e5c682cbe02a42c701c93ab5021;mlx-c:0726ca922fc902c4c61ef9c27d94132be418e945;core:ce45c52505c8158ea48d2a54e8caae05efd86bfe;xgrammar:v0.1.30;numerics:0c0290ff6b24942dadb83a929ffaaa1481df04a2;arguments:6a52f3251125d74daf04fcbd5e6f08a75d074382;native35:e1199349f22a4da30d791aa683692d295d6fb9a21f1643ffd9ac176ded97ff37"
        func descriptor(_ native:String) throws -> RequestPreparationContract.ModelDescriptor {
            try .init(model:"s89-tiny-llama",configuration:configuration,weights:model.weightsIdentity,backend:backend,dependency:dependency,
                tokenizerAlgorithm:"utf8-byte-plus-one;no-bos;v1",template:tokenizer.template,vocabulary:S79ByteTokenizer.vocab,codec:"none-v1",nativePolicy:native,revision:revision)
        }
        let preliminary=try descriptor("pending"),text=try ResumableTextOptions(tokenizerIdentity:preliminary.tokenizerIdentity,stopTokenIDs:[0],unknownTokenID:257)
        var closing=[Float](repeating:0,count:258);closing[0]=200;closing[35]=100;closing[126]=50
        let whitespace=WhitespaceTokenBias.compute(tokenizer:tokenizer)
        let native=SelectedNativePolicy(caches:Array(repeating:.init(kind:.simple,heads:1,keyDimension:8,valueDimension:8),count:2),text:text,
            guided:.init(model:.init(logitWidth:258,maximumTokens:0,prefillStepSize:64),completionReserve:32,closingBias:closing,
                whitespaceBias:whitespace.bias.asArray(Float.self),whitespaceTokenIDs:whitespace.tokenIDs),codec:"none-v1",prefill:64)
        let selected=try descriptor(native.identity)
        preparer=try .init(descriptor:selected,actualDescriptor:selected,native:native,tokenizer:tokenizer)
    }
    /// Owner-built structural fixture attestation; legacy construction is unchanged.
    public init(tokenizer:PreparationTokenizer,model:FixtureModel,descriptor:RequestPreparationContract.ModelDescriptor,native:SelectedNativePolicy) throws {
        self.tokenizer=tokenizer;self.model=model
        preparer=try .init(descriptor:descriptor,actualDescriptor:descriptor,native:native,tokenizer:tokenizer)
    }
    public var configuration:AdapterConfiguration { .init(dialect:2,model:preparer.policy.descriptor.model,optIn:true,ready:true) }
    public func runtime(_ binding:ProviderBinding,configuration:AdapterConfiguration) throws -> ProviderRuntime {
        try preparer.validateStored(binding,configuration:configuration)
        let runtime=ProviderNativeRuntime(tokenizer:tokenizer,codecs:.init(),model:{ self.factories+=1;return self.model })
        switch binding.lane { case .ordinary:return .ordinary(runtime);case .required:return .required(runtime);case .guided:return .guided(runtime);case .allowed:return .allowed(.init(tokenizer:tokenizer,probeCodecs:.init(),guidedCodecs:.init(),model:{ _ in self.factories+=1;return self.model })) }
    }
}

public enum PreparationFixtures {
    public static func base() throws -> String {
        guard let p=ProcessInfo.processInfo.environment["S89_FIXTURES"],p.hasPrefix("/private/tmp/reach-durable-request-preparation."),p.hasSuffix("/private/fixtures") else { throw PreparationError.identity }
        try RootKeyCodec.directory(p);guard try RootKeyCodec.canonicalExisting(p)==p else { throw PreparationError.identity };return p
    }
    public static func root(_ path:String) throws {
        guard try RootKeyCodec.parent(path)==base(),let leaf=path.split(separator:"/").last,leaf.count<=80,
              leaf.allSatisfy({$0.isLowercase || $0.isNumber || $0=="-"}) else { throw PreparationError.identity }
    }
    public static func request(_ route:String,n:Int=7,text:String="Hello 🌙 — retain café and 日本語.",maximum:Int?=nil) throws -> WireGenerationRequest {
        let schema=try WireGenerationSchema(jsonValue:.object(["title":.string("Alpha"),"type":.string("object"),"properties":.object(["n":.object(["type":.string("integer"),"minimum":.integer(Int64(n)),"maximum":.integer(Int64(n))])]),"required":.array([.string("n")]),"x-order":.array([.string("n")]),"additionalProperties":.bool(false)]))
        return .init(id:UUID(uuidString:route=="ordinary" ? "00000000-0000-0000-0000-000000000089" : "00000000-0000-0000-0000-000000000090")!,
            portableTranscript:.init(entries:[.instructions(.init(id:"system",segments:[.text(.init(id:"system-text",content:"Answer precisely."))])),.prompt(.init(id:"prompt",segments:[.text(.init(id:"prompt-text",content:text))]))]),
            tools:route=="required" ? [.init(name:"alpha",description:"Return the requested integer.",portableParameters:schema)] : [],
            options:.init(maximumResponseTokens:maximum ?? (route=="required" ? 128 : 20),sampling:route=="required" ? .greedy : .topK(8,seed:89),toolCalling:route=="required" ? .required : .disallowed))
    }
}

/// Same actual encoded host/client adapters and S82/S83/S86 stores, with known
/// non-secret disposable keys. No Keychain API or bootstrap acquisition runs.
public final class PreparationPair {
    public let root:String,core:BootstrapCore,native:NativePreparationFixture
    public let hostOwner:DurableSessionLifecycle,clientOwner:DurableClientReceipts
    public let hostAuth:LifecycleAuthorization,clientAuth:ClientAuthorization
    public var host:DurableHostWireAdapter,client:DurableClientWireAdapter
    public private(set) var batches:[DurableBatchPayload]=[]
    public private(set) var accepted:DurableGenerationAcceptedPayload?
    public private(set) var beginBytes:Data?,ticket:Data?
    public init(root:String,fresh:Bool,revision:String=RequestPreparationContract.ModelDescriptor.legacyRevision,native selected:NativePreparationFixture?=nil) throws {
        try PreparationFixtures.root(root);self.root=root
        if fresh { guard mkdir(root,0o700)==0 else { throw PreparationError.identity } }
        let hostClock=try FixtureLifecycleClock(id:"s89-host",time:1_000_000_000),clientClock=try FixtureClientClock(id:"s89-client",time:1_000_000_000)
        let policy=BootstrapPolicy(boot:try ClientEnvironment.bootIdentity(),hostClock:hostClock.policy,clientClock:clientClock.policy)
        if fresh {
            core=BootstrapCore(container:root+"/nonexistent-fixture.keychain-db",policy:policy)
            try PreparationEncoding.encode(core).write(to:URL(fileURLWithPath:root+"/fixture-core.json"),options:.withoutOverwriting)
        } else {
            core=try JSONDecoder().decode(BootstrapCore.self,from:Data(contentsOf:URL(fileURLWithPath:root+"/fixture-core.json")))
        }
        try core.validate(expected:policy)
        hostAuth = .init(caller:.init(principal:"s89-local",device:"device",app:"fixture"),allowed:true)
        clientAuth = .init(caller:.init(principal:"s89-local",device:"device",app:"fixture"))
        let identity=try LifecycleIdentity(incarnation:core.hostID,clock:hostClock),keys=try LifecycleKeys(catalog:Data(repeating:1,count:32),ticket:Data(repeating:2,count:32))
        hostOwner=try fresh ? .initialize(at:root+"/host",identity:identity,keys:keys,clock:hostClock) : .reopen(at:root+"/host",identity:identity,keys:keys,clock:hostClock)
        clientOwner=try .init(path:root+"/client",create:fresh,environment:.init(rootID:core.clientID,clock:clientClock),metadataKey:Data(repeating:3,count:32),clock:clientClock)
        native=try selected ?? NativePreparationFixture(revision:revision);let n=native
        host=try .init(configuration:n.configuration,owner:hostOwner,authorization:hostAuth,expectedClientRoot:core.clientID,allowNew:fresh,
            prepare:{try n.preparer.prepare($0,reference:$1,configuration:$2)},runtime:{try n.runtime($0,configuration:$1)},requestPolicy:n.preparer.policy,
            validatePrepared:{try n.preparer.validateStored($0,configuration:$1)})
        client=try .init(configuration:n.configuration,owner:clientOwner,authorization:clientAuth,core:core,parent:PreparationFixtures.base(),allowNew:fresh,requestPolicy:n.preparer.policy)
    }
    public func toHost(_ bytes:Data) throws -> [Data] {
        var result:[Data]=[];for start in stride(from:0,to:bytes.count,by:113) { result += try host.receive(Data(bytes[start..<min(start+113,bytes.count)])) };return result
    }
    public func toClient(_ bytes:Data) throws { for start in stride(from:0,to:bytes.count,by:127) { try client.receive(Data(bytes[start..<min(start+127,bytes.count)])) } }
    @discardableResult public func exchange(_ bytes:Data) throws -> Data {
        let result=try toHost(bytes);guard result.count==1 else { throw PreparationError.identity };try toClient(result[0]);return result[0]
    }
    public func start(_ request:WireGenerationRequest) throws {
        try toClient(host.capabilities())
        let open=try exchange(client.open(requestID:"open-1"));var reassembler=FrameReassembler()
        let opened:DurableSessionOpened=try reassembler.feed(open)[0].decode();ticket=opened.payload.ticket
        beginBytes=try client.begin(requestID:"begin-1",generation:"generation-1",operation:"s89-operation",request:request)
        let reply=try exchange(beginBytes!);var r=FrameReassembler();let a:DurableGenerationAccepted=try r.feed(reply)[0].decode();accepted=a.payload
    }
    public func recover() throws {
        try toClient(host.capabilities());let reply=try exchange(client.recover(requestID:"recover-1"))
        var r=FrameReassembler();let a:DurableGenerationAccepted=try r.feed(reply)[0].decode();accepted=a.payload
    }
    public func step() throws {
        _=try exchange(client.receipt(requestID:"receipt"));_=try host.step()
        for bytes in try host.replay() {
            var r=FrameReassembler();let batch:DurableBatch=try r.feed(bytes)[0].decode();batches.append(batch.payload);try toClient(bytes)
        }
    }
    public var terminal:Bool { (try? client.witness().terminal) ?? false }
    public func stored() throws -> ProviderBinding {
        guard let accepted else { throw PreparationError.identity }
        let joins=try clientOwner.discover(binding:WireFixture.binding(core),authorization:clientAuth)
        guard joins.count==1 else { throw PreparationError.identity }
        let join=try clientOwner.recoverHostJoin(joins[0],in:PreparationFixtures.base(),binding:WireFixture.binding(core),authorization:clientAuth)
        return try hostOwner.wireProviderBinding(ticket:.init(data:join.ticket),authorization:hostAuth,generation:accepted.reference.generationID)
    }
    public func close() { clientOwner.close();hostOwner.close() }
    public func remove() throws {
        close();try PreparationFixtures.root(root);try FileManager.default.removeItem(atPath:root)
        let sidecar=try PreparationFixtures.base()+"/tickets-"+core.identifier
        if FileManager.default.fileExists(atPath:sidecar) { try FileManager.default.removeItem(atPath:sidecar) }
    }
    deinit { close() }
}
