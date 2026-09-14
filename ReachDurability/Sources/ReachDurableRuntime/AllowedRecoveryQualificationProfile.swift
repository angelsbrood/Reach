import Foundation
import MLX
import MLXNN
import MLXLMCommon
import MLXGuidedGeneration
import AllowedToolCoordinator
import DurableRequestPreparation
import RequestPreparationContract
import ResumableMLXProvider
import WireAdapterContract
import RecoveryAuthorityContract

/// The fixture is selectable only by the separate executable's typed factory.
/// The ordinary daemon has no configuration switch that supplies this factory.
public struct AllowedRecoveryQualificationFactory {
    private let loader:(String) throws -> AllowedRecoveryQualificationProfile
    public init(load:@escaping (String) throws -> AllowedRecoveryQualificationProfile) { loader=load }
    func load(_ path:String) throws -> AllowedRecoveryQualificationProfile { try loader(path) }
}

enum NativeRecoverySelection {
    case artifact,allowedFixture
    init(_ fixture:AllowedRecoveryQualificationFactory?) { self=fixture == nil ? .artifact : .allowedFixture }
    var model:String { self == .artifact ? TransportContract.model : AllowedRecoveryQualificationProfile.modelIdentity }
}

protocol NativeRecoverySelectedProfile:AnyObject {
    var manifestDigest:String { get }
    var preparer:RequestPreparation { get }
    var tokenizer:ArtifactTokenizer { get }
    var observations:[NativeObservation] { get }
    func runtime(_ binding:ProviderBinding,configuration:AdapterConfiguration) throws -> ProviderRuntime
}
extension SelectedArtifactProfile:NativeRecoverySelectedProfile {}

/// A prescribed, configuration-bound state model. It shares orchestration but
/// cannot be selected as the normal artifact model or supply other native lanes.
public final class AllowedRecoveryQualificationProfile:NativeRecoverySelectedProfile {
    public static let modelIdentity="s104-structural-allowed-v1"
    public static let codecIdentity="s79.fixture.state:position-running-v1:1"
    public static func executableDigest() throws -> String { try LocalFiles.executable().sha256 }
    public static func readConfiguration(at path:String) throws -> Data {
        try LocalFiles.directory(path)
        guard Set(try FileManager.default.contentsOfDirectory(atPath:path))==["configuration.json"] else { throw AuthorityError.scope }
        return try LocalFiles.read(path+"/configuration.json",maximum:16<<10)
    }
    public static func writeConfiguration(_ bytes:Data,at path:String) throws {
        guard bytes.count<=16<<10 else { throw AuthorityError.scope }
        try LocalFiles.createDirectory(path);try LocalFiles.writeNew(bytes,to:path+"/configuration.json")
    }
    let manifestDigest:String,preparer:RequestPreparation,tokenizer:ArtifactTokenizer
    var observations:[NativeObservation]=[]
    private let codecs:ResumableStateCodecs
    private let factory:(AllowedPreparedPass) throws -> any LanguageModel
    public init(configuration:Data,descriptor:RequestPreparationContract.ModelDescriptor,
                native:SelectedNativePolicy,tokenizer:ArtifactTokenizer,codecs:ResumableStateCodecs,
                model:@escaping (AllowedPreparedPass) throws -> any LanguageModel) throws {
        guard native.prefill==256,native.guided.model.prefillStepSize==256,descriptor.model==Self.modelIdentity,descriptor.codec==Self.codecIdentity,
              descriptor.revision==RequestPreparationContract.ModelDescriptor.schemaToolRevision,
              configuration.count<=16<<10,PreparationEncoding.hash(configuration)==descriptor.configuration else { throw AuthorityError.scope }
        manifestDigest=PreparationEncoding.hash(configuration);self.tokenizer=tokenizer;self.codecs=codecs;factory=model
        preparer=try .init(descriptor:descriptor,actualDescriptor:descriptor,native:native,tokenizer:tokenizer)
    }
    func runtime(_ binding:ProviderBinding,configuration:AdapterConfiguration) throws -> ProviderRuntime {
        try NativeRecoveryRuntime.validateFixture(binding)
        try preparer.validateStored(binding,configuration:configuration)
        guard case .allowed(let allowed)=binding.lane else { throw AuthorityError.scope }
        return .allowed(.init(tokenizer:tokenizer,probeCodecs:codecs,guidedCodecs:codecs,model:{ [self] pass in
            try validateAllowedRecoveryPass(pass,binding:allowed,tokenizer:tokenizer)
            let d=preparer.policy.descriptor
            let expected=try ResumableTokenIdentity(model:d.model,configuration:d.configuration,weights:d.weights,
                input:ResumableTokenIdentity.inputDigest(pass.tokens),backend:d.backend,dependency:d.dependency)
            guard (1...512).contains(pass.tokens.count),pass.identity==expected,pass.inputDigest==expected.input,
                  pass.kind == .probe && pass.index==0 || pass.kind == .tool && pass.index==0 else { throw AuthorityError.scope }
            let model=try factory(pass),observation=NativeObservation(kind:pass.kind.rawValue,index:pass.index,preparedTokens:pass.tokens)
            observations.append(observation)
            return AllowedObservedModel(model:model,observation:observation)
        }))
    }
}

private final class AllowedObservedModel:Module,LanguageModel {
    let model:any LanguageModel,observation:NativeObservation
    init(model:any LanguageModel,observation:NativeObservation) { self.model=model;self.observation=observation;super.init() }
    func newCache(parameters:GenerateParameters?) -> [KVCache] { model.newCache(parameters:parameters) }
    func prepare(_ input:LMInput,cache:[KVCache],state:LMOutput.State?,windowSize:Int?) throws -> PrepareResult {
        observation.prepares+=1;return try model.prepare(input,cache:cache,state:state,windowSize:windowSize)
    }
    func callAsFunction(_ input:LMInput.Text,cache:[KVCache]?,state:LMOutput.State?) -> LMOutput {
        observation.calls+=1;observation.offsets.append(cache?.first?.offset ?? 0)
        observation.inputDigests.append(PreparationEncoding.hash(input.tokens.asType(.int32).asData(access:.copy).data))
        return model(input,cache:cache,state:state)
    }
}

extension NativeRecoveryRuntime {
    static func selectedProfile(at path:String,fixture:AllowedRecoveryQualificationFactory?) throws -> any NativeRecoverySelectedProfile {
        if let fixture { return try fixture.load(path) }
        return try SelectedArtifactProfile(at:path,nativeRecovery:true)
    }
}
