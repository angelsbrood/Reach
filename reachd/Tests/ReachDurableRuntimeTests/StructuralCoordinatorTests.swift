import Foundation
import XCTest
import MLX
import MLXNN
import MLXLMCommon
import MLXGuidedGeneration
import ReachWire
import AllowedToolCoordinator
import ResumableMLXProvider
import RequestPreparationContract
import DurableRequestPreparation
import WireAdapterContract
@testable import ReachDurableRuntime

private struct BranchState { let position:Int,running:MLXArray }
private let branchKey=LMOutput.Key<BranchState>("s93.test-only.branch")
private func branchCodecs() throws -> ResumableStateCodecs {
    var result=ResumableStateCodecs()
    try result.register(branchKey,type:"position-running-v1",schema:1,encode:{.init(metadata:try PreparationEncoding.encode($0.position),tensors:[try .init(capturing:$0.running)])},decode:{
        guard $0.tensors.count==1,$0.tensors[0].shape==[2],$0.tensors[0].dtype=="float32" else { throw LocalRuntimeError.invalid }
        return try .init(position:JSONDecoder().decode(Int.self,from:$0.metadata),running:$0.tensors[0].restored())
    });return result
}
/// Deterministic test-only branch selection. This is not Llama inference.
/// Cache and typed running state still participate in native logits/checkpoints.
private final class BranchModel:Module,LanguageModel {
    let script:[Int],prompt:Int
    var calls=0
    init(_ script:[Int],prompt:Int) { self.script=script;self.prompt=prompt;super.init() }
    func newCache(parameters:GenerateParameters?) -> [KVCache] { [KVCacheSimple()] }
    func prepare(_ input:LMInput,cache:[KVCache],state:LMOutput.State?,windowSize:Int?) throws -> PrepareResult { throw LocalRuntimeError.invalid }
    func callAsFunction(_ input:LMInput.Text,cache:[KVCache]?,state:LMOutput.State?) -> LMOutput {
        calls+=1;let tokens=input.tokens.asType(.float32),previous=state?[branchKey]
        var running=previous?.running ?? MLXArray([Float(0),1])
        for token in input.tokens.asArray(Int.self) { running=running*0.5+Float(token) }
        let keys=broadcast(tokens.reshaped(1,1,-1,1),to:[1,1,tokens.dim(1),4]),pair=cache![0].update(keys:keys,values:keys*0.5)
        let shift=pair.0.sum()*0.03+running.sum()*0.07,consumed=(previous?.position ?? 0)+tokens.dim(1)
        let index=min(max(0,consumed-prompt),script.count-1),mask=MLXArray.arange(258) .== script[index]
        let row=MLX.where(mask,MLXArray(Float(100))+shift,MLXArray(Float(-100))+sin(MLXArray.arange(258).asType(.float32)))
        var next=LMOutput.State();next[branchKey] = .init(position:consumed,running:running)
        return .init(logits:broadcast(row.reshaped(1,1,258),to:[1,tokens.dim(1),258]),state:next)
    }
}
final class StructuralCoordinatorTests:XCTestCase {
    func testToolsFirstHidesProbePreservesOrderAndDoesNotCompileUnusedSchema() throws { try LocalDurableRuntime.withCPU {
        let proposal="PRIVATE PROBE PROSE. <tool_call>{\"name\":\"alpha\",\"arguments\":{\"n\":1}}</tool_call><tool_call>{\"name\":\"beta\",\"arguments\":{\"message\":\"hint\"}}</tool_call>"
        let scripts=["probe":proposal,"tool-0":"{\"name\":\"alpha\",\"arguments\":{\"n\":7}}","tool-1":"{\"name\":\"beta\",\"arguments\":{\"message\":\"retained\"}}"].mapValues{$0.utf8.map{Int($0)+1}+[0]}
        let tokenizer=ArtifactTokenizer(),weights=PreparationEncoding.hash(Data("native-structural-order-cache-state-v1".utf8))
        func descriptor(_ policy:String) throws -> RequestPreparationContract.ModelDescriptor {
            try .init(model:"s93-test-only-structural",configuration:PreparationEncoding.digest(scripts),weights:weights,backend:"cpu-structural-test",dependency:DurableRuntimeRevision.nativeDigest,tokenizerAlgorithm:"utf8-byte-plus-one;no-bos;v1",template:tokenizer.template,vocabulary:SelectedArtifactProfile.vocabulary,codec:"s93.test-only.branch:position-running-v1:1",nativePolicy:policy,revision:RequestPreparationContract.ModelDescriptor.schemaToolRevision)
        }
        let pending=try descriptor("pending"),text=try ResumableTextOptions(tokenizerIdentity:pending.tokenizerIdentity,stopTokenIDs:[0],unknownTokenID:257),ws=WhitespaceTokenBias.compute(tokenizer:tokenizer)
        let native=SelectedNativePolicy(caches:[.init(kind:.simple,heads:1,keyDimension:4,valueDimension:4)],text:text,guided:.init(model:.init(logitWidth:258,maximumTokens:0,prefillStepSize:64),completionReserve:0,whitespaceBias:ws.bias.asArray(Float.self),whitespaceTokenIDs:ws.tokenIDs),codec:pending.codec,prefill:64)
        let d=try descriptor(native.identity),preparer=try RequestPreparation(descriptor:d,actualDescriptor:d,native:native,tokenizer:tokenizer),configuration=AdapterConfiguration(dialect:2,model:d.model,optIn:true,ready:true)
        var request=try ArtifactFixtures.request("lazy",maximum:256)
        request.tools.append(.init(name:"beta",description:"Return the retained message.",portableParameters:try .init(jsonValue:.object(["title":.string("Beta"),"type":.string("object"),"properties":.object(["message":.object(["type":.string("string"),"enum":.array([.string("retained")])])]),"required":.array([.string("message")]),"x-order":.array([.string("message")]),"additionalProperties":.bool(false)]))))
        let binding=try preparer.prepare(request,reference:.init(session:.init(modelID:d.model,profile:configuration.profile,sessionID:"session"),generationID:"generation",operationID:"structural-operation"),configuration:configuration)
        var passes:[String]=[],models:[BranchModel]=[]
        let runtime=ProviderRuntime.allowed(.init(tokenizer:tokenizer,probeCodecs:try branchCodecs(),guidedCodecs:try branchCodecs(),model:{ pass in
            let key=pass.kind == .probe ? "probe" : pass.kind.rawValue+"-"+String(pass.index)
            guard let script=scripts[key] else { throw LocalRuntimeError.unsupported }
            passes.append(key);let model=BranchModel(script,prompt:pass.tokens.count);models.append(model);return model
        }))
        let provider=try ResumableMLXProvider.prepare(binding:binding,runtime:runtime,owner:"structural",credit:ResumableMLXProvider.reservationBytes);defer { provider.close() }
        var events:[WireEvent]=[],steps=0
        while let candidate=try provider.pendingCandidate() {
            events+=try JSONDecoder().decode([WireEvent].self,from:candidate.eventBytes)
            try provider.acceptCommit(candidate.commit,owner:"structural")
            if provider.isTerminal { break }
            steps+=1;guard steps<2048 else { throw LocalRuntimeError.invalid }
            _=try provider.advance(owner:"structural",current:candidate.commit,credit:ResumableMLXProvider.reservationBytes)
        }
        XCTAssertTrue(provider.isTerminal);XCTAssertEqual(passes,["probe","tool-0","tool-1"])
        let calls=events.compactMap { event -> (String,String,String)? in if case .toolCallAppendArguments(_,let id,let name,let arguments,_)=event { return (id,name,arguments) };return nil }
        XCTAssertEqual(calls.map{$0.1},["alpha","beta"]);XCTAssertEqual(Set(calls.map{$0.0}).count,2)
        XCTAssertEqual(calls.map{$0.2},["{\"n\":7}","{\"message\":\"retained\"}"])
        XCTAssertFalse(events.contains { if case .responseAppend=$0 { return true };return false })
        XCTAssertEqual(events.last,.finished(.complete));XCTAssertTrue(models.allSatisfy{$0.calls>0})
        XCTAssertFalse(tokenizer.lastRendered.contains("(?=a)"));XCTAssertEqual(preparer.preparations,1)
    } }
}
