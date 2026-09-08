import Foundation
import Darwin
import XCTest
import MLX
import MLXLLM
import MLXNN
import ReachWire
@testable import ReachDurableRuntime
import RequestPreparationContract

/// Test-only artifact authoring. Runtime never constructs deterministic weights
/// or selects a script/case to produce model output.
enum ArtifactFixtures {
    static func base() throws -> String {
        guard let path=ProcessInfo.processInfo.environment["S93_TEST_ROOT"],(path.hasPrefix("/private/tmp/reach-s93.") || path.hasPrefix("/private/tmp/reach-s94.") || path.hasPrefix("/private/tmp/reach-s95.")),path.hasSuffix("/fixtures") else { throw LocalRuntimeError.invalid }
        try LocalFiles.directory(path);return path
    }
    static func encode<T:Encodable>(_ value:T) throws -> Data { let e=JSONEncoder();e.outputFormatting=[.sortedKeys,.withoutEscapingSlashes];return try e.encode(value) }
    static func artifacts() throws -> String {
        let path=try base()+"/model"
        if FileManager.default.fileExists(atPath:path) { return path }
        try LocalFiles.createDirectory(path)
        let model=LlamaModel(SelectedArtifactProfile.configuration)
        var weights:[String:MLXArray]=[:]
        for (name,array) in model.parameters().flattened().sorted(by:{$0.0<$1.0}) {
            let salt=name.utf8.reduce(0){($0+Int($1))%997}
            let values=(0..<array.size).map { index -> Float in
                let value=Float((index*73+salt*19)%251-125)/4096
                return name.contains("norm") ? 1+value : value
            }
            weights[name]=MLXArray(values,array.shape)
        }
        try MLX.save(arrays:weights,url:URL(fileURLWithPath:path+"/weights.safetensors"));guard chmod(path+"/weights.safetensors",0o600)==0 else { throw LocalRuntimeError.invalid }
        try LocalFiles.writeNew(encode(SelectedArtifactProfile.configuration),to:path+"/config.json")
        let tokenizer:[String:Any]=["algorithm":"utf8-byte-plus-one;no-bos;v1","vocabulary":SelectedArtifactProfile.vocabulary,"eos":0,"unknown":257]
        try LocalFiles.writeNew(JSONSerialization.data(withJSONObject:tokenizer,options:[.sortedKeys,.withoutEscapingSlashes]),to:path+"/tokenizer.json")
        try LocalFiles.writeNew(Data(ArtifactTokenizer.configuredTemplate.utf8),to:path+"/template.txt")
        var hashes:[String:String]=[:]
        for name in SelectedArtifactProfile.fileNames { hashes[name]=PreparationEncoding.hash(try LocalFiles.read(path+"/"+name,maximum:128<<20)) }
        try LocalFiles.writeNew(encode(ArtifactManifest(version:1,profile:SelectedArtifactProfile.name,artifacts:hashes)),to:path+"/profile.json")
        let selected = try SelectedArtifactProfile(at: path)
        try LocalFiles.writeNew(encode(IndependentPublicModel(descriptor:selected.preparer.policy.descriptor,artifactDigest:selected.manifestDigest)),to:base()+"/public-model.json")
        return path
    }
    static func request(_ route:String,maximum:Int?=nil) throws -> WireGenerationRequest {
        guard ["ordinary","guided","required","allowed","combined","zero","short","lazy"].contains(route) else { throw LocalRuntimeError.invalid }
        let schema=try WireGenerationSchema(jsonValue:.object(["title":.string("Answer"),"type":.string("object"),"properties":.object([
            "n":.object(["type":.string("integer"),"minimum":.integer(7),"maximum":.integer(7)]),
            "text":.object(["type":.string("string"),"enum":.array([.string("Retained local answer.")])])]),
            "required":.array([.string("n"),.string("text")]),"x-order":.array([.string("n"),.string("text")]),"additionalProperties":.bool(false)]))
        let parameter=try WireGenerationSchema(jsonValue:.object(["title":.string("Alpha"),"type":.string("object"),"properties":.object(["n":.object(["type":.string("integer"),"minimum":.integer(7),"maximum":.integer(7)])]),"required":.array([.string("n")]),"x-order":.array([.string("n")]),"additionalProperties":.bool(false)]))
        let combined=["combined","zero","short","lazy"].contains(route)
        let response=route=="lazy" ? try WireGenerationSchema(jsonValue:.object(["type":.string("string"),"pattern":.string("^(?=a)a$")])) : schema
        return .init(id:UUID(uuidString:"00000000-0000-0000-0000-000000000093")!,portableTranscript:.init(entries:[.instructions(.init(id:"system",segments:[.text(.init(id:"system-text",content:"Answer precisely."))])),.prompt(.init(id:"prompt",segments:[.text(.init(id:"prompt-text",content:"Retain café and 日本語."))]))]),
            tools:(["required","allowed"].contains(route) || combined) ? [.init(name:"alpha",description:"Return the selected integer.",portableParameters:parameter)] : [],
            portableSchema:(route=="guided" || combined) ? response : nil,
            options:.init(temperature:0,maximumResponseTokens:maximum ?? (route=="zero" ? 0 : (["short","lazy"].contains(route) ? 1 : (["guided","combined"].contains(route) ? 96 : 64))),sampling:.greedy,toolCalling:route=="required" ? .required : .allowed),context:.init(includeSchemaInPrompt:(route=="guided" || combined) ? false : nil))
    }
    static func writeRequests() throws {
        let folder=try base()+"/requests"
        if !FileManager.default.fileExists(atPath:folder) { try LocalFiles.createDirectory(folder) }
        for route in ["ordinary","guided","required","allowed","combined","zero","short","lazy"] {
            let path=folder+"/"+route+".json"
            if !FileManager.default.fileExists(atPath:path) { try LocalFiles.writeNew(encode(request(route)),to:path) }
        }
    }
}
