import Foundation
import Darwin
import Dispatch
import CryptoKit
import ClockPolicy
import MLX
import ReachWire
import DurableRootKeys
import DurableStoreBootstrap
import DurableSessionLifecycle
import DurableHostStore
import DurableClientReceipts
import HostClientContract
import ResumableMLXProvider
import WireAdapterContract
import RequestPreparationContract
import RecoveryAuthorityContract

extension RecoveryAuthorityChannel {
    static func exchange(_ action: GenerationAuthorityAction) throws {
        try write(AuthorityControl(stage:"challenge",challenge:action.request))
        do {
            let r=try AuthorityCodec.decode(AuthorityControl.self,read())
            guard r.stage == "certificate", let certificate=r.certificate else { throw AuthorityError.ineligible }
            try action.receive(certificate)
        } catch { action.observeWitnessLoss(); throw error }
    }
    static func observe(_ action: GenerationAuthorityAction) throws {
        try write(AuthorityControl(stage:"observe-witness"))
        do {
            let r=try AuthorityCodec.decode(AuthorityControl.self,read())
            guard r.stage == "witness-observation", r.lost != true, let identity=r.identity else { throw AuthorityError.ineligible }
            try action.observeWitnessIdentity(identity)
        } catch { action.observeWitnessLoss(); throw error }
    }
}
public enum NativeRecoveryRuntime {
    static func validateFixture(_ provider: ProviderBinding) throws {
        try NativeRecoveryBinding.validate(provider)
    }
    /// Independent fixture preparation is completed and compared before originals.
    public static func prepareFixture(model: String, request: String, operation: String, output: String, publicModel: String,fixture:AllowedRecoveryQualificationFactory? = nil) throws {
        try LocalDurableRuntime.withCPU {
            let p=try selectedProfile(at:model,fixture:fixture), input=try LocalDurableRuntime.request(from:request)
            let binding=try prepare(p,input:input,operation:operation)
            let e=try AuthorityExecution(operation:operation,provider:AuthorityCodec.encode(binding))
            try LocalFiles.writeNew(AuthorityCodec.encode(e),to:output)
            try LocalFiles.writeNew(AuthorityCodec.encode(IndependentPublicModel(descriptor:p.preparer.policy.descriptor,artifactDigest:p.manifestDigest)),to:publicModel)
        }
    }
    static func prepare(_ p: any NativeRecoverySelectedProfile, input: WireGenerationRequest, operation: String) throws -> ProviderBinding {
        guard try ["ordinary","guided","required","allowed"].contains(p.preparer.policy.route(input)) else { throw AuthorityError.state }
        let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
        let reference=DurableGenerationReference(session:.init(modelID:config.model,profile:config.profile,sessionID:"00000000-0000-0000-0000-000000000001"),generationID:"fixture-generation",operationID:operation)
        let b=try p.preparer.prepare(input,reference:reference,configuration:config)
        try validateFixture(b); guard p.observations.isEmpty else { throw AuthorityError.state }; return b
    }
    public static func admit(hostReceipt: String, hostDigest: String, clientReceipt: String, clientDigest: String,
        secretDescriptor: Int32, request: String, export: String,fixture:AllowedRecoveryQualificationFactory? = nil,witness:NativeWitnessSelection? = nil) throws {
        try NativeRecoveryRoots.validateWitness(witness,hostReceipt:hostReceipt,hostDigest:hostDigest,clientReceipt:clientReceipt,clientDigest:clientDigest,fixture:fixture)

        let credential=try UnlockCredential(consumingDescriptor:secretDescriptor); defer { credential.close() }
        let scope=try NativeRecoveryRoots.originalScope(hostReceipt:hostReceipt,hostDigest:hostDigest,clientReceipt:clientReceipt,clientDigest:clientDigest)
        let root=try NativeRecoveryRootAccess(receipt:hostReceipt,expectedDigest:hostDigest,fixture:fixture)
        guard root.core.role == .host, let execution=scope.provision.execution else { throw AuthorityError.scope }
        try witness?.validate(scope.provision,fixture:fixture)
        let clock=SystemClock()
        let owner=try GenerationAuthorityOwner(scope:scope,clock:clock,validateOwnedRoots:{ try root.validateCurrent() }), action=try owner.begin(.admitHost)
        try NativeWitnessAccess.exchange(action,selection:witness,clock:clock)
        let binding=try LocalDurableRuntime.withCPU { () -> ProviderBinding in
            try action.check()
            guard AuthorityCodec.hash(try LocalFiles.read(request,maximum:64<<10)) == scope.provision.requestInputDigest else { throw AuthorityError.scope }
            let p=try selectedProfile(at:root.configuration.artifactPath,fixture:fixture); try action.check()
            guard p.manifestDigest == root.configuration.model.artifactDigest, p.preparer.policy.descriptor == root.configuration.model.descriptor else { throw AuthorityError.scope }
            let b=try prepare(p,input:LocalDurableRuntime.request(from:request),operation:execution.operation)
            try action.check(); guard try AuthorityCodec.encode(b) == execution.provider else { throw AuthorityError.scope }; return b
        }
        var issued: AuthorityIssued?, issuer: Data?
        try root.withKeys(scope:scope,owner:owner,credential:credential,original:true) { keys in
            let caller=CallerIdentity(principal:"uid:"+String(getuid()),device:"native-pair:"+scope.provision.pair,app:AuthorityCodec.nativeProfile)
            issued=try DurableSessionLifecycle.admitNativeRecovery(at:root.core.root+"/bootstrap/host",identity:.init(recoveryAuthority:root.core.nativeStorage()),keys:LocalRuntimeOwner.hostKeys(keys),scope:scope,caller:caller,provider:binding,action:action)
            issuer=try keys.key(.hostTicket).use { try AuthorityIssued.issuerKey(ticketKey:$0,native:true).publicKey.rawRepresentation }
        }
        guard let issued, let issuer else { throw AuthorityError.partial }
        let a=try issued.verify(issuer:issuer,expectedDigest:AuthorityCodec.digest(issued))
        try action.publication(a)
        let bytes=try AuthorityCodec.encode(issued)
        var info=stat()
        if lstat(export,&info) == 0 { guard try LocalFiles.read(export,maximum:64<<10) == bytes else { throw AuthorityError.partial } }
        else { guard errno == ENOENT else { throw AuthorityError.invalid }; try LocalFiles.writeNew(bytes,to:export) }
        try action.publication(a)
        struct Report: Encodable { let stage="original-admission"; let profile=AuthorityCodec.nativeProfile; let issuer:Data, exportDigest:String, admission:String, provider:String }
        let result=try Report(issuer:issuer,exportDigest:AuthorityCodec.digest(issued),admission:a.digest,provider:AuthorityCodec.hash(bindingBytes(binding)))
        let output=try AuthorityCodec.encode(result); try action.publication(a)
        try FileHandle.standardOutput.write(contentsOf:output+Data([10])); try action.finish()
    }
    private static func bindingBytes(_ binding: ProviderBinding) throws -> Data { try AuthorityCodec.encode(binding) }
    public static func accept(hostReceipt: String, hostDigest: String, clientReceipt: String, clientDigest: String,
        secretDescriptor: Int32, export: String, originalIssuer: Data, successfulExportDigest: String,fixture:AllowedRecoveryQualificationFactory? = nil,witness:NativeWitnessSelection? = nil) throws {
        try NativeRecoveryRoots.validateWitness(witness,hostReceipt:hostReceipt,hostDigest:hostDigest,clientReceipt:clientReceipt,clientDigest:clientDigest,fixture:fixture)

        let credential=try UnlockCredential(consumingDescriptor:secretDescriptor); defer { credential.close() }
        let scope=try NativeRecoveryRoots.originalScope(hostReceipt:hostReceipt,hostDigest:hostDigest,clientReceipt:clientReceipt,clientDigest:clientDigest)
        let root=try NativeRecoveryRootAccess(receipt:clientReceipt,expectedDigest:clientDigest,fixture:fixture)
        guard root.core.role == .client else { throw AuthorityError.scope }
        try witness?.validate(scope.provision,fixture:fixture)
        let clock=SystemClock()
        let owner=try GenerationAuthorityOwner(scope:scope,clock:clock,validateOwnedRoots:{ try root.validateCurrent() }), action=try owner.begin(.acceptClient)
        try NativeWitnessAccess.exchange(action,selection:witness,clock:clock)
        let issued=try AuthorityCodec.decode(AuthorityIssued.self,LocalFiles.read(export,maximum:64<<10))
        let acceptance=try AuthorityAcceptance(issued:issued,originalIssuer:originalIssuer,originalSuccessfulExportDigest:successfulExportDigest)
        let a=try acceptance.admission(); guard a.scope == scope else { throw AuthorityError.scope }
        try root.withKeys(scope:scope,owner:owner,credential:credential,original:true) { keys in
            try DurableClientReceipts.acceptNativeRecovery(at:root.core.root+"/bootstrap/client",parent:root.core.root,
                environment:.init(recoveryAuthority:root.core.nativeStorage()),metadataKey:keys.key(.clientMetadata).use{$0},acceptance:acceptance,action:action)
        }
        struct Report: Encodable { let stage="original-acceptance"; let admission:String, hostDeadline:UInt64, clientDeadline:UInt64 }
        let records=try scope.provision.originals.records()
        let bytes=try AuthorityCodec.encode(Report(admission:a.digest,hostDeadline:records.host.deadline,clientDeadline:records.client.deadline))
        try action.publication(a); try FileHandle.standardOutput.write(contentsOf:bytes+Data([10])); try action.finish()
    }
    public static func run(hostReceipt: String, hostDigest: String, clientReceipt: String, clientDigest: String,
        hostSecret: Int32, clientSecret: Int32, original: Bool, stopAfterCalls: Int, leaveHostAhead: Bool,
        report: String, fault: String, stopWithPendingGuided: Bool=false,
        requiredBoundary: String="none", duplicateExact: Bool=false,allowedBoundary:String="none",fixture:AllowedRecoveryQualificationFactory? = nil,witness:NativeWitnessSelection? = nil) throws {
        try witness?.requireOrdinaryOptions(stopWithPendingGuided:stopWithPendingGuided,requiredBoundary:requiredBoundary,allowedBoundary:allowedBoundary,duplicateExact:duplicateExact,fault:fault,fixture:fixture)
        try NativeRecoveryRoots.validateWitness(witness,hostReceipt:hostReceipt,hostDigest:hostDigest,clientReceipt:clientReceipt,clientDigest:clientDigest,fixture:fixture)

        guard (0...20).contains(stopAfterCalls), ["none","before-native","after-native","after-commit","before-publication","after-next-pass-native"].contains(fault),
              ["none","generating","ready","emitted"].contains(requiredBoundary),
              requiredBoundary == "none" || !stopWithPendingGuided && stopAfterCalls == 0,
              ["none","probe","route-ready","guided","ready","emitted"].contains(allowedBoundary),
              allowedBoundary == "none" || requiredBoundary == "none" && !stopWithPendingGuided && stopAfterCalls == 0 else { throw AuthorityError.invalid }
        try LocalDurableRuntime.withCPU {
            let h=try NativeRecoveryRootAccess(receipt:hostReceipt,expectedDigest:hostDigest,fixture:fixture), c=try NativeRecoveryRootAccess(receipt:clientReceipt,expectedDigest:clientDigest,fixture:fixture)
            guard h.core.role == .host, c.core.role == .client else { throw AuthorityError.scope }
            let scope=try h.scope(); guard try c.scope() == scope else { throw AuthorityError.scope }
            if original { guard scope.host.boot == (try RootKeyCodec.boot()) else { throw AuthorityError.scope } }
            let hs=try UnlockCredential(consumingDescriptor:hostSecret), cs=try UnlockCredential(consumingDescriptor:clientSecret)
            defer { hs.close(); cs.close() }
            try witness?.validate(scope.provision,fixture:fixture)
            let clock=SystemClock()
            let owner=try GenerationAuthorityOwner(scope:scope,clock:clock,validateOwnedRoots:{ try h.validateCurrent(); try c.validateCurrent() })
            var actionBegan=DispatchTime.now().uptimeNanoseconds
            var action=try owner.begin(.reopen)
            var profile: (any NativeRecoverySelectedProfile)?, generation: GuardedNativeGeneration?, failureStage="reopen"
            var before:[HandoffBatch]=[], replayedBeforeNative=0, faultUsed=false, didCut=false
            var guidedProgress:[ProviderGuidedProgress]=[]
            var requiredInitial:ProviderRequiredProgress?, requiredProgress:ProviderRequiredProgress?
            var requiredSteps:[NativeRequiredStepReference]=[], duplicateApplied=false
            var allowedInitial:ProviderAllowedProgress?,allowedProgress:ProviderAllowedProgress?,allowedOperation="none"
            var allowedSteps:[NativeRequiredStepReference]=[]
            var finalReport: NativeRecoveryReport?, finalAdmission: AuthorityAdmission?
            var calls: Int { profile?.observations.reduce(0){$0+$1.calls} ?? 0 }
            func renew(_ op: GenerationOperation) throws {
                try action.finish(); actionBegan=DispatchTime.now().uptimeNanoseconds
                action=try owner.begin(op); try NativeWitnessAccess.exchange(action,selection:witness,clock:clock)
            }
            func boundary(_ point: String) throws {
                guard point == fault, !faultUsed else { return }; faultUsed=true
                struct Boundary: Encodable { let stage="boundary"; let point:String, nativeCalls:Int; let guided:ProviderGuidedProgress?, required:ProviderRequiredProgress?,allowed:ProviderAllowedProgress?; let allowedOperation:String,traces:[NativeObservation] }
                try RecoveryAuthorityChannel.write(Boundary(point:point,nativeCalls:calls,guided:guidedProgress.last,required:requiredProgress,allowed:allowedProgress,allowedOperation:allowedOperation,traces:profile?.observations ?? []))
                let command=try AuthorityCodec.decode(AuthorityControl.self,RecoveryAuthorityChannel.read())
                try NativeWitnessAccess.continueAction(command.stage,action:action,selection:witness)
            }
            do {
                try NativeWitnessAccess.exchange(action,selection:witness,clock:clock)
                try h.withKeys(scope:scope,owner:owner,credential:hs,original:false) { hostKeys in
                    try c.withKeys(scope:scope,owner:owner,credential:cs,original:false) { clientKeys in
                        let host=try NativeLifecycleOwner(path:h.core.root+"/bootstrap/host",identity:.init(recoveryAuthority:h.core.nativeStorage()),keys:LocalRuntimeOwner.hostKeys(hostKeys),scope:scope,action:action)
                        defer { generation?.close(); host.close() }
                        let client=try NativeClientOwner(path:c.core.root+"/bootstrap/client",parent:c.core.root,environment:.init(recoveryAuthority:c.core.nativeStorage()),metadataKey:clientKeys.key(.clientMetadata).use{$0},scope:scope,action:action)
                        defer { client.close() }
                        guard client.admission == host.admission else { throw AuthorityError.scope }
                        if stopWithPendingGuided && host.provider.lane.route != .guided { throw AuthorityError.scope }
                        if requiredBoundary != "none" && host.provider.lane.route != .required { throw AuthorityError.scope }
                        if allowedBoundary != "none" && host.provider.lane.route != .allowed { throw AuthorityError.scope }
                        if fault == "after-next-pass-native" && host.provider.lane.route != .allowed { throw AuthorityError.scope }
                        if duplicateExact && !["required","allowed"].contains(host.provider.lane.route.rawValue) { throw AuthorityError.scope }
                        func refreshAllowed() throws {
                            if host.provider.lane.route == .allowed,let generation {
                                let value=try generation.allowedProgress(action:action)
                                try NativeRecoveryAllowed.validate(value,binding:host.provider)
                                allowedProgress=value;if allowedInitial==nil { allowedInitial=value }
                            }
                        }
                        func observeAllowed(_ operation:String,_ priorCalls:Int,_ prior:ProviderAllowedProgress?) throws {
                            guard let progress=allowedProgress,let profile,let candidate=try host.store.snapshot().candidate else { return }
                            let step=try NativeAllowedStepObservation(index:allowedSteps.count,action:owner.actionCount,operation:operation,
                                began:actionBegan,priorCalls:priorCalls,traces:profile.observations,prior:prior,progress:progress,
                                candidate:candidate,evaluation:action.publication(host.admission))
                            let directory=report+".steps"
                            if allowedSteps.isEmpty { try LocalFiles.createDirectory(directory) }
                            try action.check();allowedSteps.append(try step.write(to:directory));try action.publication(host.admission)
                        }
                        func allowedCut() throws -> Bool {
                            guard allowedBoundary != "none",let p=allowedProgress,case .allowed(let binding)=host.provider.lane else { return false }
                            switch allowedBoundary {
                            case "probe":
                                guard p.phase=="probe",p.probe.rawTokens>0 else { return false }
                                return try binding.responseSchema==nil ? p.proseDelivered>0 : p.proseDelivered==0 && client.witness(action:action).high==0
                            case "route-ready":return p.phase=="routeReady"
                            case "guided":
                                guard p.phase=="guided",(p.guided?.consumedTokens ?? 0)>0,(p.guided?.pendingTokens ?? 0)>0,!p.whole.isEmpty else { return false }
                                if p.route=="schema" {
                                    for batch in try client.inbox(action:action) {
                                        for event in try JSONDecoder().decode([WireEvent].self,from:batch.bytes).dropFirst(batch.skip) {
                                            if case .responseAppend(_,let text,_,_)=event,!text.isEmpty { return true }
                                        }
                                    }
                                    return false
                                }
                                return true
                            case "ready":return p.phase=="finalReady"
                            case "emitted":return p.phase=="finalEmitted"
                            default:return false
                            }
                        }
                        func refreshRequired() throws {
                            if host.provider.lane.route == .required, let generation {
                                requiredProgress=try generation.requiredProgress(action:action)
                                if requiredInitial == nil { requiredInitial=requiredProgress }
                            }
                        }
                        func observeRequired(_ operation:String,_ priorCalls:Int,_ prior:ProviderRequiredProgress?) throws {
                            guard let progress=requiredProgress,let profile else { return }
                            let state=try host.store.snapshot()
                            guard let candidate=state.candidate else { throw AuthorityError.state }
                            let evaluation=try action.publication(host.admission)
                            let step=try NativeRequiredStepObservation(index:requiredSteps.count,operation:operation,
                                began:actionBegan,priorCalls:priorCalls,traces:profile.observations,
                                prior:prior,progress:progress,candidate:candidate,evaluation:evaluation)
                            let directory=report+".steps"
                            if requiredSteps.isEmpty { try LocalFiles.createDirectory(directory) }
                            try action.check()
                            requiredSteps.append(try step.write(to:directory))
                            try action.publication(host.admission)
                        }
                        func requiredCut() -> Bool {
                            guard requiredBoundary != "none",let p=requiredProgress,p.phase==requiredBoundary else { return false }
                            if requiredBoundary == "generating" {
                                return p.guided.consumedTokens>0 && !p.whole.isEmpty && p.guided.modelOffsets.allSatisfy({$0>0})
                            }
                            return true
                        }
                        func inspectGuided() throws {
                            if host.provider.lane.route == .guided, let generation, let profile {
                                guidedProgress.append(try generation.guidedProgress(action:action,tokenizer:profile.tokenizer))
                            }
                        }
                        func pendingGuidedCut() throws -> Bool {
                            guard stopWithPendingGuided, let v=guidedProgress.last, v.terminalReason == nil,
                                  v.consumedTokens>0, v.pendingTokens>0, !v.cumulativeEmittedBytes.isEmpty,
                                  v.modelOffsets.allSatisfy({$0>0}) else { return false }
                            for batch in try client.inbox(action:action) {
                                for event in try JSONDecoder().decode([WireEvent].self,from:batch.bytes).dropFirst(batch.skip) {
                                    if case .responseAppend(_,let text,_,_) = event, !text.isEmpty { return true }
                                }
                            }
                            return false
                        }
                        host.store.fault={ p in
                            if p == .afterNativeBeforeCommit {
                                if allowedOperation == "next-pass" { try boundary("after-next-pass-native") }
                                try boundary("after-native")
                            }
                            if p == .afterCommitBeforeAck { try boundary("after-commit") }
                        }
                        client.fault={ p in if p == .beforePublication { try boundary("before-publication") } }
                        before=try client.inbox(action:action)
                        func deliver() throws {
                            try host.store.authorize(action)
                            let w=try client.witness(action:action)
                            for f in try host.store.replay(after:w.high) {
                                try client.accept(.init(firstSequence:f.firstSequence,count:f.count,providerCommit:f.providerCommit,eventBytes:f.eventBytes,skipPrefix:f.skipPrefix),action:action)
                                if calls == 0 { replayedBeforeNative += f.count-f.skipPrefix }
                            }
                            let accepted=try client.witness(action:action)
                            try host.acceptReceipt(accepted,action:action)
                            try generation?.acknowledgeDelivery(through:accepted.high,action:action)
                        }
                        // Durable replay is resolved before the artifact/model factory.
                        try deliver()
                        let selected=try host.store.snapshot()
                        if original { guard selected.candidate == nil else { throw AuthorityError.state } }
                        else { guard selected.candidate != nil else { throw AuthorityError.state } }
                        if duplicateExact { guard selected.terminal else { throw AuthorityError.state } }
                        if !selected.terminal {
                            failureStage="model-restore"
                            try action.check(); let p=try selectedProfile(at:h.configuration.artifactPath,fixture:fixture); try action.check(); profile=p
                            guard p.manifestDigest == h.configuration.model.artifactDigest, p.preparer.policy.descriptor == h.configuration.model.descriptor else { throw AuthorityError.scope }
                            let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
                            let factory={ try p.runtime(host.provider,configuration:config) }
                            if original { try renew(.prepare); generation=try GuardedNativeGeneration.start(store:host.store,action:action,runtime:factory) }
                            else { generation=try GuardedNativeGeneration.restore(store:host.store,action:action,runtime:factory) }
                            try host.synchronize(action:action); try deliver(); try inspectGuided(); try refreshRequired();try refreshAllowed()
                            try observeRequired(original ? "prepare" : "restore",0,nil)
                            try observeAllowed(original ? "prepare" : "restore",0,nil)
                        }
                        while try !host.store.snapshot().terminal {
                            let phase=allowedProgress?.phase,actionCalls=calls
                            let unit=phase == "probe" || phase == "guided" ? 2 : 1
                            failureStage="advance";try renew(.advance);try host.store.authorize(action)
                            for _ in 0..<unit {
                                let priorCalls=calls,priorRequired=requiredProgress,priorAllowed=allowedProgress
                                allowedOperation=priorAllowed?.phase == "routeReady" ? "next-pass" : priorAllowed?.phase == "finalReady" ? "ready-deliver" : "advance"
                                try boundary("before-native");try generation!.advance(action:action)
                                try host.synchronize(action:action);try inspectGuided();try refreshRequired();try refreshAllowed()
                                let stop=try (stopAfterCalls > 0 && calls >= stopAfterCalls) || pendingGuidedCut() || requiredCut() || allowedCut()
                                if !stop || !leaveHostAhead { try deliver() }
                                try observeRequired("advance",priorCalls,priorRequired)
                                try observeAllowed(allowedOperation,priorCalls,priorAllowed)
                                if stop { didCut=true;break }
                                // Preserve guarded work/commit/ack/delivery/receipt
                                // between both advances; phase changes end the unit.
                                if allowedProgress?.phase != phase { break }
                            }
                            if host.provider.lane.route == .allowed {
                                guard calls-actionCalls<=2,DispatchTime.now().uptimeNanoseconds-actionBegan<10_000_000_000 else { throw AuthorityError.state }
                                try action.publication(host.admission)
                            }
                            if didCut { break }
                        }
                        if selected.terminal {
                            try renew(.terminalReplay); try host.store.authorize(action); try deliver()
                            if duplicateExact {
                                let inbox=try client.inbox(action:action),receipt=try client.witness(action:action)
                                for f in try host.store.replay(after:0) {
                                    try client.accept(.init(firstSequence:f.firstSequence,count:f.count,providerCommit:f.providerCommit,eventBytes:f.eventBytes,skipPrefix:f.skipPrefix),action:action)
                                }
                                let after=try client.witness(action:action)
                                guard try AuthorityCodec.encode(client.inbox(action:action))==AuthorityCodec.encode(inbox),
                                      after==receipt,(host.provider.lane.route == .required ? after.registrations==1 : (0...1).contains(after.registrations)),profile==nil,calls==0 else { throw AuthorityError.state }
                                try host.acceptReceipt(after,action:action);duplicateApplied=true
                            }
                        }
                        if (stopWithPendingGuided || requiredBoundary != "none" || allowedBoundary != "none") && !didCut { throw AuthorityError.state }
                        failureStage="publication"
                        let w=try client.witness(action:action), state=try host.store.snapshot()
                        let records=try scope.provision.originals.records()
                        let result=NativeRecoveryReport(stage:didCut && !state.terminal ? "checkpoint" : "complete",profile:AuthorityCodec.nativeProfile,
                            original:original,receiverBoot:try RootKeyCodec.boot(),originalBoot:scope.host.boot,admission:try host.admission.digest,
                            provider:host.provider,hostDeadline:records.host.deadline,clientDeadline:records.client.deadline,
                            hostHigh:state.high,client:w,nativeCalls:calls,modelLoads:profile == nil ? 0 : 1,
                            modelPrepares:profile?.observations.reduce(0){$0+$1.prepares} ?? 0,
                            requestPreparations:0,templateCalls:profile?.tokenizer.renders ?? 0,requestTokenizations:profile?.tokenizer.requestTokenizations ?? 0,
                            issues:0,begins:0,recoveries:original ? 0 : 1,actions:owner.actionCount,replayedBeforeNative:replayedBeforeNative,
                            beforeInbox:before,inbox:try client.inbox(action:action),traces:profile?.observations ?? [],nativePeak:Memory.peakMemory,
                            timers:try host.timerBytes(action:action),guidedProgress:guidedProgress,
                            requiredInitial:requiredInitial,requiredProgress:requiredProgress,requiredSteps:requiredSteps,
                            allowedInitial:allowedInitial,allowedProgress:allowedProgress,allowedSteps:allowedSteps,
                            repairEncodes:profile?.tokenizer.repairEncodes ?? 0,
                            duplicateExact:duplicateApplied,selectedCommit:state.candidate?.commit.identity,
                            evaluation:try action.publication(host.admission))
                        finalReport=result; finalAdmission=host.admission

                    }
                }
                guard var result=finalReport, let admission=finalAdmission else { throw AuthorityError.partial }
                // Both original key transactions have relocked and rechecked their
                // current root/selection before any output leaves the worker.
                result.evaluation=try action.publication(admission)
                let data=try AuthorityCodec.encode(result)
                try action.publication(admission); try LocalFiles.writeNew(data,to:report); try action.publication(admission)
                try FileHandle.standardOutput.write(contentsOf:data+Data([10])); try action.publication(admission)
                if result.stage == "checkpoint" {
                    _=try RecoveryAuthorityChannel.read(); throw AuthorityError.state
                }
                try action.finish()
            } catch {
                struct Failure: Encodable { let stage="native-refusal"; let boundary:String, nativeCalls:Int, modelLoads:Int, diskState="requires-authenticated-reconciliation" }
                try? RecoveryAuthorityChannel.write(Failure(boundary:failureStage,nativeCalls:calls,modelLoads:profile == nil ? 0 : 1))
                throw error
            }
        }
    }
}
struct NativeRecoveryReport: Encodable {
    let stage:String,profile:String,original:Bool,receiverBoot:String,originalBoot:String,admission:String,provider:ProviderBinding
    let hostDeadline:UInt64,clientDeadline:UInt64,hostHigh:UInt64,client:HandoffWitness
    let nativeCalls:Int,modelLoads:Int,modelPrepares:Int,requestPreparations:Int,templateCalls:Int,requestTokenizations:Int,issues:Int,begins:Int,recoveries:Int,actions:Int,replayedBeforeNative:Int
    let beforeInbox:[HandoffBatch],inbox:[HandoffBatch],traces:[NativeObservation],nativePeak:Int,timers:Data
    let guidedProgress:[ProviderGuidedProgress]
    let requiredInitial:ProviderRequiredProgress?, requiredProgress:ProviderRequiredProgress?, requiredSteps:[NativeRequiredStepReference]
    let allowedInitial:ProviderAllowedProgress?,allowedProgress:ProviderAllowedProgress?,allowedSteps:[NativeRequiredStepReference]
    let repairEncodes:Int
    let duplicateExact:Bool, selectedCommit:String?
    var evaluation:Evaluation
}
