import Foundation
import XCTest
import MLX
import ReachWire
import WireAdapterContract
import ResumableMLXProvider
import RecoveryAuthorityContract
@testable import ReachDurableRuntime
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts

/// Small composition double for failure/ownership tests; the actual artifact
/// variant and the CLI feasibility/reboot gates separately exercise tiny Llama.
final class SchemaToolNativeTestRun {
    let fixture:NativeRecoveryFixture,original:AuthorityAdmission,actual:Bool
    var profile:SelectedArtifactProfile?,owner:GenerationAuthorityOwner,action:GenerationAuthorityAction
    var host:NativeLifecycleOwner,client:NativeClientOwner,generation:GuardedNativeGeneration
    static func request(maximum:Int=64,lazy:Bool=false) throws -> WireGenerationRequest {
        var r=try AllowedNativeTestProfile.request(maximum:maximum)
        r.portableSchema=try lazy ? WireGenerationSchema(jsonValue:.object(["type":.string("string"),"pattern":.string("^(?=a)a$")])) : SchemaNativeRecoveryTests.request().portableSchema
        r.context.includeSchemaInPrompt=false
        return r
    }
    init(maximum:Int=64,actual:Bool=false,lazy:Bool=false) throws {
        self.actual=actual;fixture=try .init(request:Self.request(maximum:maximum,lazy:lazy));original=try fixture.provision();owner=fixture.owner
        let f=fixture
        profile=try actual ? SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true) : nil
        let p=profile
        action=try fixture.action(.reopen);host=try fixture.openHost(action);client=try fixture.openClient(action)
        try action.finish();action=try fixture.action(.prepare)
        generation=try GuardedNativeGeneration.start(store:host.store,action:action,runtime:{
            if let p { return try p.runtime(f.provider,configuration:.init(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)) }
            return f.runtime()
        })
        try fixture.deliver(host,client,generation,action)
    }
    var calls:Int { profile?.observations.reduce(0){$0+$1.calls} ?? fixture.counter.calls }
    var progress:ProviderAllowedProgress { get throws { try generation.allowedProgress(action:action) } }
    func advanceUnit(until stop:(ProviderAllowedProgress)->Bool={_ in false},deliver:Bool=true) throws {
        let phase=try progress.phase,before=calls
        try action.finish();action=try fixture.action(.advance,owner:owner)
        for _ in 0..<(phase=="probe" || phase=="guided" ? 2 : 1) {
            try generation.advance(action:action);try host.synchronize(action:action)
            if deliver { try fixture.deliver(host,client,generation,action) }
            let p=try progress
            try NativeRecoveryAllowed.validate(p,binding:fixture.provider)
            if p.phase != phase || stop(p) { break }
        }
        XCTAssertLessThanOrEqual(calls-before,2)
    }
    func advance(to phase:String) throws {
        for _ in 0..<62 {
            let p=try progress
            if p.phase==phase {return}
            guard p.phase != "finalEmitted" else {throw AuthorityError.state}
            try advanceUnit()
        }
        throw AuthorityError.state
    }
    func reopen(terminal:Bool=false) throws {
        let selected=try host.store.snapshot().candidate!,beforeReceipt=try client.witness(action:action)
        let p=terminal ? nil : try progress
        generation.close();host.close();client.close();try action.finish()
        owner=try .init(scope:fixture.scope,clock:fixture.receiverClock);action=try fixture.action(.reopen,owner:owner)
        host=try fixture.openHost(action);client=try fixture.openClient(action)
        if actual && !terminal { profile=try .init(at:ArtifactFixtures.artifacts(),nativeRecovery:true) }
        let before=calls
        generation=try .restore(store:host.store,action:action,runtime:{
            guard !terminal else { XCTFail("terminal factory invoked");throw AuthorityError.state }
            if let p=self.profile { return try p.runtime(self.fixture.provider,configuration:.init(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)) }
            return self.fixture.runtime()
        })
        XCTAssertEqual(calls,before);XCTAssertEqual(try host.store.snapshot().candidate!.commit,selected.commit)
        if let p { XCTAssertEqual(try progress,p) }
        XCTAssertEqual(try client.witness(action:action),beforeReceipt)
        XCTAssertEqual(try AuthorityCodec.encode(host.admission),try AuthorityCodec.encode(original))
        try fixture.deliver(host,client,generation,action)
        if let profile {XCTAssertEqual(profile.tokenizer.requestTokenizations,0);XCTAssertEqual(profile.tokenizer.renders,0)}
    }
    func terminalReplayAndDuplicate() throws {
        let expected=try client.witness(action:action),inbox=try client.inbox(action:action)
        try reopen(terminal:true)
        XCTAssertTrue(expected.terminal);XCTAssertEqual(expected.registrations,0)
        XCTAssertEqual(try client.witness(action:action),expected)
        for f in try host.store.replay(after:0) {
            try client.accept(.init(firstSequence:f.firstSequence,count:f.count,providerCommit:f.providerCommit,eventBytes:f.eventBytes),action:action)
        }
        XCTAssertEqual(try client.witness(action:action),expected)
        XCTAssertEqual(try AuthorityCodec.encode(client.inbox(action:action)),try AuthorityCodec.encode(inbox))
        try host.acceptReceipt(expected,action:action)
    }
    deinit {generation.close();host.close();client.close();try? action.finish()}
}
