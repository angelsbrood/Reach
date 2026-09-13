import Foundation
import Darwin
import CryptoKit
import ClockPolicy
import DurableRootKeys
import DurableStoreBootstrap
import DurableSessionLifecycle
import DurableClientReceipts
import ResumableMLXProvider
import WireAdapterContract
import RequestPreparationContract
import ReachWire
import RecoveryAuthorityContract

struct AuthorityControl: Codable {
    var stage: String
    var challenge: Data? = nil, certificate: Data? = nil, originals: Data? = nil
    var identity: ClockPolicy.Identity? = nil
    var subject: String? = nil, hostSeconds: UInt64? = nil, clientSeconds: UInt64? = nil
    var lost: Bool? = nil
}
public enum RecoveryAuthorityChannel {
    public static func read() throws -> Data {
        var data=Data()
        while true {
            guard let byte=try FileHandle.standardInput.read(upToCount:1), !byte.isEmpty else { throw AuthorityError.partial }
            if byte[0] == 10 { return data }
            guard data.count < 64<<10 else { throw AuthorityError.invalid }; data.append(byte)
        }
    }
    public static func write<T: Encodable>(_ value: T) throws {
        try FileHandle.standardOutput.write(contentsOf:AuthorityCodec.encode(value)+Data([10]))
    }
    static func exchange(_ action: RecoveryAuthorityAction) throws {
        try write(AuthorityControl(stage:"challenge",challenge:action.request))
        do {
            let response=try AuthorityCodec.decode(AuthorityControl.self,read())
            guard response.stage == "certificate", let certificate=response.certificate else { throw AuthorityError.ineligible }
            try action.receive(certificate)
        } catch { action.observeWitnessLoss(); throw error }
    }
    static func observe(_ action: RecoveryAuthorityAction) throws {
        try write(AuthorityControl(stage:"observe-witness"))
        do {
            let response=try AuthorityCodec.decode(AuthorityControl.self,read())
            guard response.stage == "witness-observation", response.lost != true, let identity=response.identity else { throw AuthorityError.ineligible }
            try action.observeWitnessIdentity(identity)
        } catch { action.observeWitnessLoss(); throw error }
    }
}
public enum RecoveryAuthorityRuntime {
    /// Host-only owned qualification witness: process-memory keys/registrations,
    /// original bounded durations, no external service or clock override.
    public static func witness() throws {
        let witness=try Witness(clock:SystemClock())
        try RecoveryAuthorityChannel.write(AuthorityControl(stage:"witness-ready",identity:witness.identity))
        while true {
            let request=try AuthorityCodec.decode(AuthorityControl.self,RecoveryAuthorityChannel.read())
            switch request.stage {
            case "register":
                guard let subject=request.subject, let h=request.hostSeconds, let c=request.clientSeconds,
                      (1...86400).contains(h), (1...86400).contains(c) else { throw AuthorityError.invalid }
                let originals=try Originals(pin:witness.identity,host:witness.register(subject:subject,role:.host,cap:h*1_000_000_000),
                    client:witness.register(subject:subject,role:.client,cap:c*1_000_000_000))
                try RecoveryAuthorityChannel.write(AuthorityControl(stage:"originals",originals:AuthorityCodec.encode(originals)))
            case "challenge":
                guard let challenge=request.challenge else { throw AuthorityError.invalid }
                try RecoveryAuthorityChannel.write(AuthorityControl(stage:"certificate",certificate:witness.respond(to:challenge)))
            case "observe-witness":
                _=try witness.observe()
                try RecoveryAuthorityChannel.write(AuthorityControl(stage:"witness-observation",identity:witness.identity))
            case "quit": try RecoveryAuthorityChannel.write(AuthorityControl(stage:"witness-bye")); return
            default: throw AuthorityError.invalid
            }
        }
    }
    public static func admit(hostReceipt: String, hostDigest: String, clientReceipt: String, clientDigest: String,
        secretDescriptor: Int32, model: String, request: String, export: String) throws {
        let credential=try UnlockCredential(consumingDescriptor:secretDescriptor); defer { credential.close() }
        let scope=try RecoveryAuthorityRoots.originalScope(hostReceipt:hostReceipt,hostDigest:hostDigest,clientReceipt:clientReceipt,clientDigest:clientDigest)
        let selected=try RecoveryAuthorityRootAccess(receipt:hostReceipt,expectedDigest:hostDigest)
        guard selected.core.role == .host, AuthorityCodec.hash(try LocalFiles.read(request,maximum:64<<10)) == scope.provision.requestInputDigest else { throw AuthorityError.scope }
        // Normal original artifact loading and request preparation occur before
        // the fresh action, and never occur in the authentication entrypoint.
        let provider=try LocalDurableRuntime.withCPU { () -> ProviderBinding in
            let profile=try SelectedArtifactProfile(at:model)
            guard profile.manifestDigest == selected.configuration.model.artifactDigest,
                  profile.preparer.policy.descriptor == selected.configuration.model.descriptor else { throw AuthorityError.invalid }
            let input=try LocalDurableRuntime.request(from:request)
            guard try profile.preparer.policy.route(input) == "ordinary" else { throw AuthorityError.state }
            let config=AdapterConfiguration(dialect:2,model:profile.preparer.policy.descriptor.model,optIn:true,ready:true)
            let reference=DurableGenerationReference(session:.init(modelID:config.model,profile:config.profile,sessionID:scope.namespace),
                generationID:scope.generation,operationID:"operation-"+scope.provision.pair)
            let provider=try profile.preparer.prepare(input,reference:reference,configuration:config)
            guard profile.observations.isEmpty else { throw AuthorityError.state }
            return provider
        }
        let action=try RecoveryAuthorityAction(scope:scope,operation:.admitHost,clock:SystemClock())
        try RecoveryAuthorityChannel.exchange(action)
        var issued:AuthorityIssued?, issuer:Data?
        try selected.withKeys(scope:scope,action:action,credential:credential,original:true) { keys in
            let caller=CallerIdentity(principal:"uid:"+String(getuid()),device:"authority-pair:"+scope.provision.pair,app:AuthorityCodec.profile)
            issued=try DurableSessionLifecycle.admitRecoveryAuthority(at:selected.core.root+"/bootstrap/host",
                identity:.init(recoveryAuthority:selected.core.authorityStorage()),keys:LocalRuntimeOwner.hostKeys(keys),
                scope:scope,caller:caller,provider:provider,action:action)
            issuer=try keys.key(.hostTicket).use { try AuthorityIssued.issuerKey(ticketKey:$0).publicKey.rawRepresentation }
        }
        guard let issued, let issuer else { throw AuthorityError.partial }
        let a=try issued.verify(issuer:issuer,expectedDigest:AuthorityCodec.digest(issued))
        try action.publication(a)
        let bytes=try AuthorityCodec.encode(issued)
        var info=stat()
        if lstat(export,&info) == 0 { guard try LocalFiles.read(export,maximum:64<<10) == bytes else { throw AuthorityError.partial } }
        else { guard errno == ENOENT else { throw AuthorityError.invalid }; try LocalFiles.writeNew(bytes,to:export) }
        // Export IO charges the original r0 and cannot renew the registration.
        try action.publication(a)
        struct Report: Encodable { let stage="original-admission"; let profile=AuthorityCodec.profile; let issuer:Data, exportDigest:String; let diagnostic:AuthorityDiagnostic }
        let report=try Report(issuer:issuer,exportDigest:AuthorityCodec.digest(issued),diagnostic:AuthorityDiagnostic(admission:a,phase:"preparing",action:action))
        let output=try AuthorityCodec.encode(report)
        try action.publication(a); try FileHandle.standardOutput.write(contentsOf:output+Data([10])); try action.finish()
    }
    public static func accept(hostReceipt: String, hostDigest: String, clientReceipt: String, clientDigest: String,
        secretDescriptor: Int32, export: String, originalIssuer: Data, successfulExportDigest: String) throws {
        let credential=try UnlockCredential(consumingDescriptor:secretDescriptor); defer { credential.close() }
        let scope=try RecoveryAuthorityRoots.originalScope(hostReceipt:hostReceipt,hostDigest:hostDigest,clientReceipt:clientReceipt,clientDigest:clientDigest)
        let selected=try RecoveryAuthorityRootAccess(receipt:clientReceipt,expectedDigest:clientDigest)
        guard selected.core.role == .client else { throw AuthorityError.scope }
        let issued=try AuthorityCodec.decode(AuthorityIssued.self,LocalFiles.read(export,maximum:64<<10))
        let acceptance=try AuthorityAcceptance(issued:issued,originalIssuer:originalIssuer,originalSuccessfulExportDigest:successfulExportDigest)
        let a=try acceptance.admission(); guard a.scope == scope else { throw AuthorityError.scope }
        let action=try RecoveryAuthorityAction(scope:scope,operation:.acceptClient,clock:SystemClock())
        try RecoveryAuthorityChannel.exchange(action)
        try selected.withKeys(scope:scope,action:action,credential:credential,original:true) { keys in
            try DurableClientReceipts.acceptRecoveryAuthority(at:selected.core.root+"/bootstrap/client",parent:selected.core.root,
                environment:.init(recoveryAuthority:selected.core.authorityStorage()),metadataKey:keys.key(.clientMetadata).use{$0},acceptance:acceptance,action:action)
        }
        let report=try AuthorityDiagnostic(admission:a,phase:"registered-empty",action:action)
        let bytes=try AuthorityCodec.encode(report); try action.publication(a)
        try FileHandle.standardOutput.write(contentsOf:bytes+Data([10])); try action.finish()
    }
    /// Recovery accepts only its original ownership selection and fresh witness
    /// replies. It cannot import a replacement scope, issuer, ticket or deadline.
    public static func authenticate(receipt: String, expectedDigest: String, secretDescriptor: Int32,
        blockMilliseconds: Int, observeWitness: Bool) throws {
        guard (0...12000).contains(blockMilliseconds) else { throw AuthorityError.invalid }
        let credential=try UnlockCredential(consumingDescriptor:secretDescriptor); defer { credential.close() }
        let selected=try RecoveryAuthorityRootAccess(receipt:receipt,expectedDigest:expectedDigest), scope=try selected.scope()
        let operation:AuthorityOperation=selected.core.role == .host ? .authenticateHost : .authenticateClient
        let action=try RecoveryAuthorityAction(scope:scope,operation:operation,clock:SystemClock())
        try RecoveryAuthorityChannel.exchange(action)
        var report:AuthorityDiagnostic?
        func blocking() throws {
            if blockMilliseconds > 0 { Thread.sleep(forTimeInterval:Double(blockMilliseconds)/1000) }
            if observeWitness { try RecoveryAuthorityChannel.observe(action) }
        }
        try selected.withKeys(scope:scope,action:action,credential:credential,original:false) { keys in
            let storage=try selected.core.authorityStorage()
            if selected.core.role == .host {
                report=try DurableSessionLifecycle.authenticateRecoveryAuthority(at:selected.core.root+"/bootstrap/host",
                    identity:.init(recoveryAuthority:storage),keys:LocalRuntimeOwner.hostKeys(keys),scope:scope,action:action,blocking:blocking)
            } else {
                report=try DurableClientReceipts.authenticateRecoveryAuthority(at:selected.core.root+"/bootstrap/client",parent:selected.core.root,
                    environment:.init(recoveryAuthority:storage),metadataKey:keys.key(.clientMetadata).use{$0},scope:scope,action:action,blocking:blocking)
            }
        }
        guard var report else { throw AuthorityError.partial }
        try report.refresh(action:action) // Includes key relocking and final original-selection reads.
        let bytes=try AuthorityCodec.encode(report); try report.refresh(action:action)
        try FileHandle.standardOutput.write(contentsOf:bytes+Data([10])); try action.finish()
    }
}
