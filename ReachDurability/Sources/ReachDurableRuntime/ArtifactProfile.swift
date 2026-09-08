import Foundation
import MLX
import MLXNN
import MLXLLM
import MLXLMCommon
import MLXGuidedGeneration
import DurableRootKeys
import RequestPreparationContract
import DurableRequestPreparation
import RequiredToolCoordinator
import AllowedToolCoordinator
import ResumableMLXProvider
import WireAdapterContract

struct ArtifactManifest:Codable,Equatable {
    let version:Int,profile:String,artifacts:[String:String]
}
/// A single deliberately small, artifact-backed Llama profile. No downloader,
/// registry, symbolic weights, scripts, or caller-selected native policies.
final class SelectedArtifactProfile {
    static let name="local-llama-258-v1"
    static let vocabulary=["<eos>"]+(0...255).map{String(format:"<0x%02X>",$0)}+["<unk>"]
    static let fileNames:Set<String>=["config.json","weights.safetensors","tokenizer.json","template.txt"]
    static var configuration:LlamaConfiguration { .init(hiddenSize:16,hiddenLayers:2,intermediateSize:32,attentionHeads:2,rmsNormEps:0.00001,vocabularySize:258,kvHeads:1) }
    let manifest:ArtifactManifest,manifestDigest:String,model:LlamaModel,tokenizer:ArtifactTokenizer,preparer:RequestPreparation
    var observations:[NativeObservation]=[]
    init(at path:String) throws {
        try LocalFiles.directory(path)
        guard Set(try FileManager.default.contentsOfDirectory(atPath:path))==Self.fileNames.union(["profile.json"]) else { throw LocalRuntimeError.invalid }
        let manifestBytes=try LocalFiles.read(path+"/profile.json",maximum:16384)
        manifest=try JSONDecoder().decode(ArtifactManifest.self,from:manifestBytes)
        guard manifest.version==1,manifest.profile==Self.name,Set(manifest.artifacts.keys)==Self.fileNames,
            manifest.artifacts.values.allSatisfy(PreparationEncoding.isDigest) else { throw LocalRuntimeError.unsupported }
        let artifactManifest=manifest
        manifestDigest=try PreparationEncoding.digest(artifactManifest)
        var artifacts:[String:Data]=[:]
        for name in Self.fileNames {
            let bytes=try LocalFiles.read(path+"/"+name,maximum:name=="weights.safetensors" ? 128<<20 : 65536)
            guard PreparationEncoding.hash(bytes)==manifest.artifacts[name] else { throw LocalRuntimeError.invalid };artifacts[name]=bytes
        }
        // Validate before entering model constructors or the native tensor reader.
        let expectedConfig=try JSONSerialization.data(withJSONObject:JSONSerialization.jsonObject(with:PreparationEncoding.encode(Self.configuration)),options:[.sortedKeys,.withoutEscapingSlashes])
        let normalized=try JSONSerialization.data(withJSONObject:JSONSerialization.jsonObject(with:artifacts["config.json"]!),options:[.sortedKeys,.withoutEscapingSlashes])
        guard normalized==expectedConfig else { throw LocalRuntimeError.unsupported }
        struct TokenizerFile:Codable,Equatable { let algorithm:String,vocabulary:[String],bos:Int?,eos:Int,unknown:Int }
        let tokenFile=try JSONDecoder().decode(TokenizerFile.self,from:artifacts["tokenizer.json"]!)
        guard tokenFile==TokenizerFile(algorithm:"utf8-byte-plus-one;no-bos;v1",vocabulary:Self.vocabulary,bos:nil,eos:0,unknown:257),
            String(data:artifacts["template.txt"]!,encoding:.utf8)==ArtifactTokenizer.configuredTemplate else { throw LocalRuntimeError.unsupported }
        let selectedTokenizer=ArtifactTokenizer(template:String(decoding:artifacts["template.txt"]!,as:UTF8.self));tokenizer=selectedTokenizer
        let configuration=try JSONDecoder().decode(LlamaConfiguration.self,from:artifacts["config.json"]!)
        model=LlamaModel(configuration)
        let expected=Dictionary(uniqueKeysWithValues:model.parameters().flattened().map{($0.0,$0.1.shape)})
        let weightData=artifacts["weights.safetensors"]!
        try Self.validateTensorHeader(weightData,expected:expected)
        let weights=try MLX.loadArrays(data:weightData)
        guard Set(weights.keys)==Set(expected.keys),weights.allSatisfy({$0.value.shape==expected[$0.key] && $0.value.dtype == .float32}),
            weights.values.reduce(0,{$0+$1.nbytes})<=128<<20,weights.values.allSatisfy({$0.asArray(Float.self).allSatisfy(\.isFinite)}) else { throw LocalRuntimeError.unsupported }
        try model.update(parameters:ModuleParameters.unflattened(weights.map{($0.key,$0.value)}),verify:.all);eval(model)
        let backend="arm64-little-endian;cpu;"+ProcessInfo.processInfo.operatingSystemVersionString
        let dependency=DurableRuntimeRevision.current+";native20:"+DurableRuntimeRevision.nativeDigest+";mlx:0bb916c67f4b9e5c682cbe02a42c701c93ab5021"
        func descriptor(_ policy:String) throws -> RequestPreparationContract.ModelDescriptor {
            try .init(model:Self.name,configuration:artifactManifest.artifacts["config.json"]!,weights:artifactManifest.artifacts["weights.safetensors"]!,backend:backend,dependency:dependency,
                tokenizerAlgorithm:tokenFile.algorithm+";artifact:"+artifactManifest.artifacts["tokenizer.json"]!,template:selectedTokenizer.template,vocabulary:Self.vocabulary,codec:"none-v1",nativePolicy:policy,revision:RequestPreparationContract.ModelDescriptor.schemaToolRevision)
        }
        let initial=try descriptor("pending"),text=try ResumableTextOptions(tokenizerIdentity:initial.tokenizerIdentity,stopTokenIDs:[0],unknownTokenID:257)
        var closing=[Float](repeating:0,count:258);closing[0]=200;closing[35]=100;closing[126]=50
        let whitespace=WhitespaceTokenBias.compute(tokenizer:tokenizer)
        let native=SelectedNativePolicy(caches:Array(repeating:.init(kind:.simple,heads:1,keyDimension:8,valueDimension:8),count:2),text:text,
            guided:.init(model:.init(logitWidth:258,maximumTokens:0,prefillStepSize:64),completionReserve:32,closingBias:closing,whitespaceBias:whitespace.bias.asArray(Float.self),whitespaceTokenIDs:whitespace.tokenIDs),codec:"none-v1",prefill:64)
        let selected=try descriptor(native.identity)
        preparer=try .init(descriptor:selected,actualDescriptor:selected,native:native,tokenizer:tokenizer)
        guard Memory.peakMemory<=128<<20 else { throw LocalRuntimeError.unsupported }
    }
    private static func validateTensorHeader(_ bytes:Data,expected:[String:[Int]]) throws {
        guard bytes.count>=8 else { throw LocalRuntimeError.invalid }
        let length=bytes.prefix(8).enumerated().reduce(UInt64(0)){$0 | UInt64($1.element)<<UInt64($1.offset*8)}
        guard length>0,length<=65536,length<=UInt64(bytes.count-8) else { throw LocalRuntimeError.invalid }
        guard var header=try JSONSerialization.jsonObject(with:Data(bytes[8..<8+Int(length)])) as? [String:Any] else { throw LocalRuntimeError.invalid }
        if let metadata=header.removeValue(forKey:"__metadata__") { guard metadata is NSNull || metadata is [String:String] else { throw LocalRuntimeError.invalid } }
        guard Set(header.keys)==Set(expected.keys) else { throw LocalRuntimeError.unsupported }
        var ranges:[Range<Int>]=[]
        for (name,value) in header {
            guard let tensor=value as? [String:Any],Set(tensor.keys)==["dtype","shape","data_offsets"],tensor["dtype"] as? String=="F32",
                let shape=tensor["shape"] as? [Int],shape==expected[name],let offsets=tensor["data_offsets"] as? [Int],offsets.count==2,
                offsets[0]>=0,offsets[1]>=offsets[0],offsets[1]-offsets[0]==shape.reduce(1,*)*4,offsets[1]<=bytes.count-8-Int(length) else { throw LocalRuntimeError.invalid }
            ranges.append(offsets[0]..<offsets[1])
        }
        var end=0
        for range in ranges.sorted(by:{$0.lowerBound<$1.lowerBound}) { guard range.lowerBound==end else { throw LocalRuntimeError.invalid };end=range.upperBound }
        guard end==bytes.count-8-Int(length) else { throw LocalRuntimeError.invalid }
    }
    func runtime(_ binding:ProviderBinding,configuration:AdapterConfiguration) throws -> ProviderRuntime {
        try preparer.validateStored(binding,configuration:configuration)
        func observed(_ kind:String,_ index:Int,_ tokens:[Int]) -> ObservedLlama {
            let entry=NativeObservation(kind:kind,index:index,preparedTokens:tokens);observations.append(entry)
            return ObservedLlama(model:model,observation:entry)
        }
        switch binding.lane {
        case .ordinary(let b):return .ordinary(.init(tokenizer:tokenizer,codecs:.init(),model:{observed("ordinary",0,b.tokens)}))
        case .guided(let b):return .guided(.init(tokenizer:tokenizer,codecs:.init(),model:{observed("schema",0,b.tokens)}))
        case .required(_,let tokens):return .required(.init(tokenizer:tokenizer,codecs:.init(),model:{observed("required",0,tokens)}))
        case .allowed:
            return .allowed(.init(tokenizer:tokenizer,probeCodecs:.init(),guidedCodecs:.init(),model:{pass in
                let d=self.preparer.policy.descriptor
                guard pass.identity==(try .init(model:d.model,configuration:d.configuration,weights:d.weights,input:ResumableTokenIdentity.inputDigest(pass.tokens),backend:d.backend,dependency:d.dependency)) else { throw LocalRuntimeError.invalid }
                return observed(pass.kind.rawValue,pass.index,pass.tokens)
            }))
        }
    }
}

final class NativeObservation:Encodable {
    let kind:String,index:Int,preparedTokens:[Int]
    var calls=0,prepares=0,offsets:[Int]=[],inputDigests:[String]=[]
    init(kind:String,index:Int,preparedTokens:[Int]) { self.kind=kind;self.index=index;self.preparedTokens=preparedTokens }
}
/// Observation-only wrapper; all logits come from loaded Llama weights.
final class ObservedLlama:Module,LanguageModel {
    let model:LlamaModel,observation:NativeObservation
    init(model:LlamaModel,observation:NativeObservation) { self.model=model;self.observation=observation;super.init() }
    func newCache(parameters:GenerateParameters?) -> [KVCache] { model.newCache(parameters:parameters) }
    func prepare(_ input:LMInput,cache:[KVCache],state:LMOutput.State?,windowSize:Int?) throws -> PrepareResult {
        observation.prepares+=1;return try model.prepare(input,cache:cache,state:state,windowSize:windowSize)
    }
    func callAsFunction(_ input:LMInput.Text,cache:[KVCache]?,state:LMOutput.State?) -> LMOutput {
        observation.calls+=1;observation.offsets.append(cache?.first?.offset ?? 0)
        observation.inputDigests.append(RootKeyCodec.hash(input.tokens.asType(.int32).asData(access:.copy).data))
        return .init(logits:model(input.tokens,cache:cache))
    }
}
