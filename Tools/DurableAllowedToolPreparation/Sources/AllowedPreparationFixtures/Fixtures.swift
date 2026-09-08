import Foundation
import MLX
import MLXLMCommon
import MLXGuidedGeneration
import LifecycleFixtures
import AllowedToolCoordinator
import ReachWire
import ResumableMLXProvider
import RequestPreparationContract
import DurableRequestPreparation
import RequestPreparationFixtures
import WireAdapterContract
import DurableHostWireAdapter

public enum AllowedPreparationFixtures {
    public static let revision=RequestPreparationContract.ModelDescriptor.allowedRevision
    public static let message=String(repeating:"Retain ordered values. ",count:8)
    public static let proposal="<tool_call>{\"name\":\"alpha\",\"arguments\":{\"n\":1}}</tool_call><tool_call>{\"name\":\"beta\",\"arguments\":{\"message\":\"hint\"}}</tool_call>"
    public static func scripts() throws -> [String:[Int]] {
        let alpha="{\"name\":\"alpha\",\"arguments\":{\"n\":7}}"
        let beta="{\"name\":\"beta\",\"arguments\":"+String(decoding:try PreparationEncoding.encode(["message":message]),as:UTF8.self)+"}"
        return ["probe":proposal,"tool-0":alpha,"tool-1":beta].mapValues { $0.utf8.map{Int($0)+1}+[0] }
    }
    public static func request(_ variant:String="calls",text:String="Choose an optional tool if appropriate.") throws -> WireGenerationRequest {
        guard ["calls","eight","zero","short","llama","unknown"].contains(variant) else { throw PreparationError.unsupported }
        var request=try PreparationFixtures.request("required",n:variant=="eight" ? 8 : 7,text:text)
        let beta=try WireGenerationSchema(jsonValue:.object(["title":.string("Beta"),"type":.string("object"),"properties":.object(["message":.object(["type":.string("string"),"enum":.array([.string(message)])])]),"required":.array([.string("message")]),"x-order":.array([.string("message")]),"additionalProperties":.bool(false)]))
        request.tools.append(.init(name:"beta",description:"Return the retained message.",portableParameters:beta))
        request.options = .init(maximumResponseTokens:variant=="zero" ? 0 : (variant=="short" ? 160 : (variant=="llama" ? 32 : 256)),sampling:.greedy,toolCalling:.allowed)
        if variant=="unknown" { request.tools[0].name="gamma" }
        return request
    }
    public static func events(_ batches:[DurableBatchPayload]) throws -> [WireEvent] {
        try batches.flatMap{try JSONDecoder().decode([WireEvent].self,from:$0.bytes)}
    }
}

public struct AllowedNativeTrace:Encodable {
    public let kind:String,index:Int,inputDigest:String,preparedTokens:[Int],weights:String
    public let inputs:[[Int]],offsets:[Int],logits:[[Float]],running:[[Float]],calls:Int,prepares:Int
}

/// Both families use the actual S91 preparer and same-model allowed declaration.
/// State scripts select syntax; native logits still depend on input/cache/state.
public final class AllowedNativeFixture {
    public let family:String,native:NativePreparationFixture
    public private(set) var models:[(AllowedPreparedPass,FixtureModel)]=[]
    private let scripts:[String:[Int]]
    public init(family:String) throws {
        guard ["llama","state"].contains(family) else { throw PreparationError.unsupported }
        self.family=family;scripts=try AllowedPreparationFixtures.scripts()
        if family=="llama" { native=try .init(revision:AllowedPreparationFixtures.revision) }
        else {
            let tokenizer=PreparationTokenizer(),state=try FixtureModel(kind:"state",script:[0],promptCount:0)
            // This complete immutable structural selection is bound independently
            // of every request, runtime observation and comparison oracle.
            struct Configuration:Encodable { let model="native-structural-order-cache-state-v1",passSelection="probe / tool-index-0-or-1",promptCount="authenticated-pass.tokens.count";let scripts:[String:[Int]] }
            let configuration=try PreparationEncoding.digest(Configuration(scripts:scripts))
            let backend="arm64-little-endian;swift6.4;cpu;"+ProcessInfo.processInfo.operatingSystemVersionString
            let dependency="lm:83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8;mlx:0bb916c67f4b9e5c682cbe02a42c701c93ab5021;mlx-c:0726ca922fc902c4c61ef9c27d94132be418e945;core:ce45c52505c8158ea48d2a54e8caae05efd86bfe;xgrammar:v0.1.30;numerics:0c0290ff6b24942dadb83a929ffaaa1481df04a2;arguments:6a52f3251125d74daf04fcbd5e6f08a75d074382;native35:e1199349f22a4da30d791aa683692d295d6fb9a21f1643ffd9ac176ded97ff37"
            func descriptor(_ policy:String) throws -> RequestPreparationContract.ModelDescriptor {
                try .init(model:"s91-structural-allowed",configuration:configuration,weights:state.weightsIdentity,backend:backend,dependency:dependency,
                    tokenizerAlgorithm:"utf8-byte-plus-one;no-bos;v1",template:tokenizer.template,vocabulary:S79ByteTokenizer.vocab,codec:"s79.fixture.state:position-running-v1:1",nativePolicy:policy,revision:AllowedPreparationFixtures.revision)
            }
            let d=try descriptor("pending"),text=try ResumableTextOptions(tokenizerIdentity:d.tokenizerIdentity,stopTokenIDs:[0],unknownTokenID:257)
            let whitespace=WhitespaceTokenBias.compute(tokenizer:tokenizer)
            let policy=SelectedNativePolicy(caches:[.init(kind:.simple,heads:1,keyDimension:4,valueDimension:4)],text:text,
                guided:.init(model:.init(logitWidth:258,maximumTokens:0,prefillStepSize:64),completionReserve:0,whitespaceBias:whitespace.bias.asArray(Float.self),whitespaceTokenIDs:whitespace.tokenIDs),codec:d.codec,prefill:64)
            native=try .init(tokenizer:tokenizer,model:state,descriptor:descriptor(policy.identity),native:policy)
        }
        native.tokenizer.repairPrefix=AllowedToolReplayInput.policy+"\n"
    }
    public var calls:Int { models.reduce(0){$0+$1.1.calls} }
    public var prepares:Int { models.reduce(0){$0+$1.1.prepares} }
    public func traces() -> [AllowedNativeTrace] {
        models.map { p,m in .init(kind:p.kind.rawValue,index:p.index,inputDigest:p.inputDigest,preparedTokens:p.tokens,weights:m.weightsIdentity,
            inputs:m.inputs,offsets:m.priorOffsets,logits:m.outputs,running:m.runningStates,calls:m.calls,prepares:m.prepares) }
    }
    public func runtime(_ binding:ProviderBinding,configuration:AdapterConfiguration) throws -> ProviderRuntime {
        try native.preparer.validateStored(binding,configuration:configuration)
        guard case .allowed=binding.lane else { throw PreparationError.unsupported }
        return .allowed(.init(tokenizer:native.tokenizer,probeCodecs:family=="state" ? try codecs() : .init(),guidedCodecs:family=="state" ? try codecs() : .init(),model:{ [self] pass in
            let d=native.preparer.policy.descriptor
            let expected=try ResumableTokenIdentity(model:d.model,configuration:d.configuration,weights:d.weights,input:ResumableTokenIdentity.inputDigest(pass.tokens),backend:d.backend,dependency:d.dependency)
            guard pass.identity==expected,pass.inputDigest==expected.input else { throw PreparationError.identity }
            let key:String
            if pass.kind == .probe && pass.index==0 { key="probe" }
            else if pass.kind == .tool && (0...1).contains(pass.index) { key="tool-"+String(pass.index) }
            else { throw PreparationError.unsupported }
            guard let script=scripts[key] else { throw PreparationError.identity }
            let model=try FixtureModel(kind:family,script:script,promptCount:pass.tokens.count)
            guard model.weightsIdentity==d.weights else { throw PreparationError.identity }
            models.append((pass,model));return model
        }))
    }
    public func pair(root:String?=nil,fresh:Bool=true) throws -> PreparationPair {
        let pair=try PreparationPair(root:root ?? (PreparationFixtures.base()+"/allowed-unit-"+UUID().uuidString.lowercased()),fresh:fresh,native:native)
        // Only fixture runtime glue changes. Preparation, ownership, persistence,
        // wire handling and selected-declaration validation remain shared products.
        pair.host=try .init(configuration:native.configuration,owner:pair.hostOwner,authorization:pair.hostAuth,expectedClientRoot:pair.core.clientID,allowNew:fresh,
            prepare:{try self.native.preparer.prepare($0,reference:$1,configuration:$2)},runtime:{try self.runtime($0,configuration:$1)},requestPolicy:native.preparer.policy,
            validatePrepared:{try self.native.preparer.validateStored($0,configuration:$1)})
        return pair
    }
}
