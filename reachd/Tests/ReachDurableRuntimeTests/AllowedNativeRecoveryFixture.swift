import Foundation
import XCTest
import MLX
import MLXLMCommon
import MLXGuidedGeneration
import AllowedRecoveryFixture
import AllowedToolCoordinator
import DurableRequestPreparation
import RequestPreparationContract
import ReachWire
import WireAdapterContract
import ResumableMLXProvider
import RecoveryAuthorityContract
import HostClientContract
@testable import ReachDurableRuntime
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts

/// Unit composition of the same prescribed fixture algorithm. The separate
/// executable's original binary/configuration binding is verified by CLI gates.
final class AllowedNativeTestProfile {
    let native:AllowedRecoveryQualificationProfile
    let length:Int?,probeText:String
    init(length:Int?=nil,probe:String?=nil) throws {
        self.length=length;probeText=probe ?? "P<tool_call>{\"name\":\"a\",\"arguments\":{}}</tool_call>"
        let guide=length.map { "{\"name\":\"a\",\"arguments\":{\"m\":\""+String(repeating:"x",count:$0)+"\"}}" } ?? "{\"name\":\"a\",\"arguments\":{\"n\":7}}"
        let scripts=["probe":probeText,"tool-0":guide].mapValues{$0.utf8.map{Int($0)+1}+[0]}
        let bytes=try PreparationEncoding.encode(scripts),tokenizer=ArtifactTokenizer()
        func descriptor(_ policy:String) throws -> RequestPreparationContract.ModelDescriptor {
            try .init(model:AllowedRecoveryQualificationProfile.modelIdentity,configuration:PreparationEncoding.hash(bytes),
                weights:sgHash(Data("native-structural-order-cache-state-v1".utf8)),backend:"s104-unit-cpu",
                dependency:"s104-actual-linked-fixture-unit",tokenizerAlgorithm:"utf8-byte-plus-one;no-bos;v1",template:tokenizer.template,
                vocabulary:S79ByteTokenizer.vocab,codec:AllowedRecoveryQualificationProfile.codecIdentity,nativePolicy:policy,
                revision:RequestPreparationContract.ModelDescriptor.schemaToolRevision)
        }
        let initial=try descriptor("pending"),text=try ResumableTextOptions(tokenizerIdentity:initial.tokenizerIdentity,stopTokenIDs:[0],unknownTokenID:257)
        let whitespace=WhitespaceTokenBias.compute(tokenizer:tokenizer)
        let policy=SelectedNativePolicy(caches:[.init(kind:.simple,heads:1,keyDimension:4,valueDimension:4)],text:text,
            guided:.init(model:.init(logitWidth:258,maximumTokens:0,prefillStepSize:256),completionReserve:0,
                whitespaceBias:whitespace.bias.asArray(Float.self),whitespaceTokenIDs:whitespace.tokenIDs),codec:initial.codec,prefill:256)
        native=try .init(configuration:bytes,descriptor:descriptor(policy.identity),native:policy,tokenizer:tokenizer,codecs:codecs(),model:{pass in
            let key=pass.kind == .probe ? "probe" : "tool-"+String(pass.index)
            guard let script=scripts[key] else { throw AuthorityError.scope }
            return try FixtureModel(kind:"state",script:script,promptCount:pass.tokens.count)
        })
    }
    static func request(maximum:Int=64,length:Int?=nil,name:String="a") throws -> WireGenerationRequest {
        var request=try RequiredNativeRecoveryTests.request(maximum:maximum)
        request.options.toolCalling = .allowed
        request.tools[0].name=name
        if let length {
            let schema=try WireGenerationSchema(jsonValue:.object(["title":.string("A"),"type":.string("object"),"x-order":.array([.string("m")]),"properties":.object(["m":.object(["type":.string("string"),"enum":.array([.string(String(repeating:"x",count:length))])])]),"required":.array([.string("m")]),"additionalProperties":.bool(false)]))
            request.tools=[.init(name:name,description:"Return the retained string.",portableParameters:schema)]
        }
        return request
    }
    func binding(_ request:WireGenerationRequest?=nil) throws -> ProviderBinding {
        let config=AdapterConfiguration(dialect:2,model:native.preparer.policy.descriptor.model,optIn:true,ready:true)
        return try native.preparer.prepare(request ?? Self.request(length:length),reference:.init(session:.init(modelID:config.model,profile:config.profile,sessionID:"fixture"),generationID:"fixture",operationID:"native-unit-operation"),configuration:config)
    }
    func runtime(_ binding:ProviderBinding) throws -> ProviderRuntime {
        try native.runtime(binding,configuration:.init(dialect:2,model:native.preparer.policy.descriptor.model,optIn:true,ready:true))
    }
    var calls:Int { native.observations.reduce(0){$0+$1.calls} }
}

final class AllowedNativeTestRun {
    let fixture:NativeRecoveryFixture,original:AuthorityAdmission
    var profile:AllowedNativeTestProfile,owner:GenerationAuthorityOwner,action:GenerationAuthorityAction
    var host:NativeLifecycleOwner,client:NativeClientOwner,generation:GuardedNativeGeneration
    init(profile:AllowedNativeTestProfile,request:WireGenerationRequest?=nil) throws {
        self.profile=profile;fixture=try .init(prepared:profile.binding(request));original=try fixture.provision();owner=fixture.owner
        action=try fixture.action(.reopen);host=try fixture.openHost(action);client=try fixture.openClient(action)
        try action.finish();action=try fixture.action(.prepare)
        let localFixture=fixture
        generation=try GuardedNativeGeneration.start(store:host.store,action:action,runtime:{try profile.runtime(localFixture.provider)})
        try fixture.deliver(host,client,generation,action)
    }
    var progress:ProviderAllowedProgress { get throws { try generation.allowedProgress(action:action) } }
    func advanceUnit(until stop:(ProviderAllowedProgress)->Bool={_ in false},deliver:Bool=true) throws {
        let phase=try progress.phase,prior=profile.calls
        try action.finish();action=try fixture.action(.advance,owner:owner)
        for _ in 0..<(phase=="probe" || phase=="guided" ? 2 : 1) {
            try generation.advance(action:action);try host.synchronize(action:action)
            if deliver { try fixture.deliver(host,client,generation,action) }
            let p=try progress
            if p.phase != phase || stop(p) { break }
        }
        XCTAssertLessThanOrEqual(profile.calls-prior,2)
    }
    func advance(to phase:String) throws {
        for _ in 0..<100 {
            let p=try progress
            if p.phase==phase { return }
            guard p.phase != "finalEmitted" else { throw AuthorityError.state }
            try advanceUnit()
        }
        throw AuthorityError.state
    }
    func reopen() throws {
        let selected=try progress
        generation.close();host.close();client.close();try action.finish()
        owner=try .init(scope:fixture.scope,clock:fixture.receiverClock)
        action=try fixture.action(.reopen,owner:owner);host=try fixture.openHost(action);client=try fixture.openClient(action)
        profile=try .init(length:profile.length,probe:profile.probeText)
        generation=try .restore(store:host.store,action:action,runtime:{try self.profile.runtime(self.fixture.provider)})
        XCTAssertEqual(try progress,selected);XCTAssertEqual(profile.calls,0)
        XCTAssertEqual(profile.native.tokenizer.requestTokenizations,0);XCTAssertEqual(profile.native.tokenizer.renders,0)
        XCTAssertEqual(try AuthorityCodec.encode(host.admission),try AuthorityCodec.encode(original))
        try fixture.deliver(host,client,generation,action)
    }
    func terminalReplayAndDuplicate(expectedCalls:Int) throws {
        generation.close();host.close();client.close();try action.finish()
        owner=try .init(scope:fixture.scope,clock:fixture.receiverClock);action=try fixture.action(.reopen,owner:owner)
        host=try fixture.openHost(action);client=try fixture.openClient(action)
        var factories=0
        generation=try .restore(store:host.store,action:action,runtime:{factories+=1;throw AuthorityError.state})
        try fixture.deliver(host,client,generation,action)
        let receipt=try client.witness(action:action),inbox=try client.inbox(action:action)
        XCTAssertTrue(receipt.terminal);XCTAssertEqual(receipt.registrations,expectedCalls);XCTAssertEqual(factories,0)
        generation.close();host.close();client.close();try action.finish()
        owner=try .init(scope:fixture.scope,clock:fixture.receiverClock);action=try fixture.action(.reopen,owner:owner)
        host=try fixture.openHost(action);client=try fixture.openClient(action)
        for f in try host.store.replay(after:0) {
            try client.accept(.init(firstSequence:f.firstSequence,count:f.count,providerCommit:f.providerCommit,eventBytes:f.eventBytes),action:action)
        }
        XCTAssertEqual(try client.witness(action:action),receipt)
        XCTAssertEqual(try AuthorityCodec.encode(client.inbox(action:action)),try AuthorityCodec.encode(inbox))
        try host.acceptReceipt(receipt,action:action)
    }
    deinit { generation.close();host.close();client.close();try? action.finish() }
}
