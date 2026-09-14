import Foundation
import MLX
import MLXLMCommon
import MLXGuidedGeneration
import AllowedToolCoordinator
import ReachDurableRuntime
import RequestPreparationContract
import DurableRequestPreparation

public enum S104Fixture {
    public struct Configuration:Codable,Equatable {
        public let version:Int,profile:String,variant:String,executable:String
        public let algorithm:String,passSelection:String,promptCount:String,scripts:[String:[Int]]
        static func make(executable:String,variant:String) throws -> Self {
            guard ["success","exhaustion"].contains(variant) else { throw CheckFailure("fixture variant") }
            let probe="P<tool_call>{\"name\":\"a\",\"arguments\":{}}</tool_call>"
            let guided=variant == "success" ? "{\"name\":\"a\",\"arguments\":{\"n\":7}}" : "{\"name\":\"a\",\"arguments\":{\"m\":\""+String(repeating:"x",count:40)+"\"}}"
            return .init(version:1,profile:AllowedRecoveryQualificationProfile.modelIdentity,variant:variant,executable:executable,
                algorithm:"native-structural-order-cache-state-v1;dim4;position-running-v1",
                passSelection:"probe / tool-index-0;original-identity-and-exact-repair-input",
                promptCount:"authenticated-pass.tokens.count",scripts:["probe":probe,"tool-0":guided].mapValues{$0.utf8.map{Int($0)+1}+[0]})
        }
    }
    public static var factory:AllowedRecoveryQualificationFactory { .init(load:load) }
    public static func write(at path:String,variant:String) throws {
        let config=try Configuration.make(executable:AllowedRecoveryQualificationProfile.executableDigest(),variant:variant)
        try AllowedRecoveryQualificationProfile.writeConfiguration(PreparationEncoding.encode(config),at:path)
    }
    public static func load(_ path:String) throws -> AllowedRecoveryQualificationProfile {
        let bytes=try AllowedRecoveryQualificationProfile.readConfiguration(at:path)
        let c=try JSONDecoder().decode(Configuration.self,from:bytes)
        guard try c==Configuration.make(executable:AllowedRecoveryQualificationProfile.executableDigest(),variant:c.variant),
              try PreparationEncoding.encode(c)==bytes else { throw CheckFailure("immutable fixture configuration") }
        let tokenizer=ArtifactTokenizer(),weights=sgHash(Data("native-structural-order-cache-state-v1".utf8))
        let configuration=PreparationEncoding.hash(bytes)
        func descriptor(_ policy:String) throws -> RequestPreparationContract.ModelDescriptor {
            try .init(model:AllowedRecoveryQualificationProfile.modelIdentity,configuration:configuration,weights:weights,
                backend:"arm64-little-endian;cpu;"+ProcessInfo.processInfo.operatingSystemVersionString,
                dependency:DurableRuntimeRevision.current+";native20:"+DurableRuntimeRevision.nativeDigest+";executable:"+c.executable,
                tokenizerAlgorithm:"utf8-byte-plus-one;no-bos;v1",template:tokenizer.template,vocabulary:S79ByteTokenizer.vocab,
                codec:AllowedRecoveryQualificationProfile.codecIdentity,nativePolicy:policy,revision:RequestPreparationContract.ModelDescriptor.schemaToolRevision)
        }
        let initial=try descriptor("pending"),text=try ResumableTextOptions(tokenizerIdentity:initial.tokenizerIdentity,stopTokenIDs:[0],unknownTokenID:257)
        let whitespace=WhitespaceTokenBias.compute(tokenizer:tokenizer)
        let native=SelectedNativePolicy(caches:[.init(kind:.simple,heads:1,keyDimension:4,valueDimension:4)],text:text,
            guided:.init(model:.init(logitWidth:258,maximumTokens:0,prefillStepSize:256),completionReserve:0,
                whitespaceBias:whitespace.bias.asArray(Float.self),whitespaceTokenIDs:whitespace.tokenIDs),codec:initial.codec,prefill:256)
        let d=try descriptor(native.identity)
        return try .init(configuration:bytes,descriptor:d,native:native,tokenizer:tokenizer,codecs:codecs(),model:{ pass in
            let key:String
            if pass.kind == .probe,pass.index==0,pass.messages.isEmpty,pass.proposalID==nil { key="probe" }
            else if pass.kind == .tool,pass.index==0,let id=pass.proposalID,!id.isEmpty {
                let messages=try JSONDecoder().decode([AllowedToolReplayInput.Message].self,from:pass.messages)
                guard messages.count==2,messages[0].role=="system",messages[1].role=="user",
                      messages[1].content.contains("\nTool name: a\nProposed arguments:") else { throw CheckFailure("exact selected repair messages") }
                // The coordinator independently re-derives these exact tokens
                // from the retained authenticated proposal before this factory.
                key="tool-0"
            } else { throw CheckFailure("fixture selected pass") }
            guard let script=c.scripts[key] else { throw CheckFailure("fixture script join") }
            return try FixtureModel(kind:"state",script:script,promptCount:pass.tokens.count)
        })
    }
}
