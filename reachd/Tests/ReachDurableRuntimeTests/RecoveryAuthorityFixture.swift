import Foundation
import CryptoKit
import ClockPolicy
import XCTest
import ReachWire
import WireAdapterContract
import ResumableMLXProvider
import DurableRootKeys
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts
@testable import ReachDurableRuntime
import RecoveryAuthorityContract

final class AuthorityFixtureClock: PolicyClock {
    var value: Sample
    init(boot: String = UUID().uuidString.lowercased(), time: UInt64) {
        value = .init(boot:boot,incarnation:UUID().uuidString.lowercased(),nanoseconds:time)
    }
    func sample() throws -> Sample { value }
    func advance(_ n: UInt64) { value = .init(boot:value.boot,incarnation:value.incarnation,nanoseconds:value.nanoseconds+n) }
}
final class RecoveryAuthorityFixture {
    let base: String, host: String, client: String
    let witnessClock = AuthorityFixtureClock(time:100_000_000_000)
    let receiverClock = AuthorityFixtureClock(time:200_000_000_000)
    let witness: Witness, scope: AuthorityScope
    let hostIdentity: LifecycleIdentity, clientEnvironment: ClientEnvironment, hostKeys: LifecycleKeys
    let catalogKey=clientRandomKey(), ticketKey=clientRandomKey(), clientKey=clientRandomKey()
    let provider: ProviderBinding
    let caller=CallerIdentity(principal:"fixture",device:"original",app:AuthorityCodec.profile)
    init(hostCap: UInt64 = 90, clientCap: UInt64 = 150) throws {
        base=try ArtifactFixtures.base()+"/authority-"+UUID().uuidString.lowercased(); host=base+"/host"; client=base+"/client"
        for p in [base,host,client,host+"/bootstrap",client+"/bootstrap"] { try LocalFiles.createDirectory(p) }
        witness=try Witness(clock:witnessClock)
        let pair=UUID().uuidString.lowercased(), hostID=UUID().uuidString.lowercased(), clientID=UUID().uuidString.lowercased()
        let originals=try Originals(pin:witness.identity,host:witness.register(subject:pair,role:.host,cap:hostCap*1_000_000_000),client:witness.register(subject:pair,role:.client,cap:clientCap*1_000_000_000))
        let provision=try AuthorityProvision(originals:originals,hostID:hostID,clientID:clientID,publicModelDigest:String(repeating:"a",count:64),requestInputDigest:String(repeating:"b",count:64))
        let boot=try RootKeyCodec.boot()
        scope=try AuthorityScope(provision:provision,
            host:.init(role:"host",identifier:UUID().uuidString.lowercased(),localID:hostID,root:host,boot:boot,core:String(repeating:"c",count:64)),
            client:.init(role:"client",identifier:UUID().uuidString.lowercased(),localID:clientID,root:client,boot:boot,core:String(repeating:"d",count:64)))
        hostIdentity=try .init(recoveryAuthority:.init(provision:provision,root:scope.host,quota:1<<30))
        clientEnvironment=try .init(recoveryAuthority:.init(provision:provision,root:scope.client,quota:1<<30))
        hostKeys=try .init(catalog:catalogKey,ticket:ticketKey)
        try DurableSessionLifecycle.initializeRecoveryAuthority(at:host+"/bootstrap/host",identity:hostIdentity,keys:hostKeys)
        try DurableClientReceipts.initializeRecoveryAuthority(at:client+"/bootstrap/client",environment:clientEnvironment,metadataKey:clientKey)
        let scope=self.scope
        provider=try LocalDurableRuntime.withCPU {
            let selected=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts())
            let config=AdapterConfiguration(dialect:2,model:selected.preparer.policy.descriptor.model,optIn:true,ready:true)
            let reference=DurableGenerationReference(session:.init(modelID:config.model,profile:config.profile,sessionID:scope.namespace),generationID:scope.generation,operationID:"operation-"+scope.provision.pair)
            return try selected.preparer.prepare(ArtifactFixtures.request("ordinary"),reference:reference,configuration:config)
        }
    }
    deinit { try? FileManager.default.removeItem(atPath:base) }
    func action(_ operation: AuthorityOperation, clock: AuthorityFixtureClock? = nil) throws -> RecoveryAuthorityAction {
        let a=try RecoveryAuthorityAction(scope:scope,operation:operation,clock:clock ?? receiverClock)
        try a.receive(witness.respond(to:a.request)); return a
    }
    func admit(fault: LifecycleFaultHook = { _ in }) throws -> AuthorityIssued {
        let a=try action(.admitHost); defer { try? a.finish() }
        return try DurableSessionLifecycle.admitRecoveryAuthority(at:host+"/bootstrap/host",identity:hostIdentity,keys:hostKeys,scope:scope,caller:caller,provider:provider,action:a,fault:fault)
    }
    func acceptance(_ issued: AuthorityIssued) throws -> AuthorityAcceptance {
        try .init(issued:issued,originalIssuer:AuthorityIssued.issuerKey(ticketKey:ticketKey).publicKey.rawRepresentation,originalSuccessfulExportDigest:AuthorityCodec.digest(issued))
    }
    func accept(_ issued: AuthorityIssued, fault: RecoveryContract.RecoveryHook = { _ in }) throws {
        let a=try action(.acceptClient); defer { try? a.finish() }
        try DurableClientReceipts.acceptRecoveryAuthority(at:client+"/bootstrap/client",parent:client,environment:clientEnvironment,metadataKey:clientKey,acceptance:acceptance(issued),action:a,fault:fault)
    }
    func authenticate(_ role: String, action: RecoveryAuthorityAction? = nil, blocking: () throws -> Void = {}) throws -> AuthorityDiagnostic {
        let a=try action ?? self.action(role == "host" ? .authenticateHost : .authenticateClient); defer { try? a.finish() }
        if role == "host" {
            return try DurableSessionLifecycle.authenticateRecoveryAuthority(at:host+"/bootstrap/host",identity:hostIdentity,keys:hostKeys,scope:scope,action:a,blocking:blocking)
        }
        return try DurableClientReceipts.authenticateRecoveryAuthority(at:client+"/bootstrap/client",parent:client,environment:clientEnvironment,metadataKey:clientKey,scope:scope,action:a,blocking:blocking)
    }
    func hashes() throws -> [String:String] {
        var values:[String:String]=[:]
        for case let url as URL in FileManager.default.enumerator(at:URL(fileURLWithPath:base),includingPropertiesForKeys:[.isRegularFileKey])! {
            if try url.resourceValues(forKeys:[.isRegularFileKey]).isRegularFile == true { values[url.path]=AuthorityCodec.hash(try Data(contentsOf:url)) }
        }
        return values
    }
    func catalog(_ body: (inout CatalogDocument) throws -> Void) throws {
        let fs=try LifecycleFileSystem(path:host+"/bootstrap/host",create:false); defer { fs.close() }
        var d=try LifecycleCatalog.read(fs,identity:hostIdentity,keys:hostKeys); try body(&d)
        let cipher=try LifecycleCrypto.seal(lcEncode(d),role:"catalog",record:UUID().uuidString.lowercased(),identity:hostIdentity,key:SymmetricKey(data:catalogKey))
        try cipher.write(to:URL(fileURLWithPath:host+"/bootstrap/host/current"))
    }
    func clientManifest(_ body: (inout ClientManifest) throws -> Void) throws {
        let fs=try ClientFileSystem(path:client+"/bootstrap/client",create:false); defer { fs.close() }
        let key=SymmetricKey(data:clientKey)
        let (bytes,_)=try ClientCrypto.open(fs.read("current"),role:"manifest",environment:clientEnvironment,key:key,rootKey:key)
        var m=try JSONDecoder().decode(ClientManifest.self,from:bytes); try body(&m)
        let cipher=try ClientCrypto.seal(crEncode(m),role:"manifest",record:clientEnvironment.rootID,generation:ClientCrypto.zero,revision:m.revision,environment:clientEnvironment,key:key,rootKey:key)
        try cipher.write(to:URL(fileURLWithPath:client+"/bootstrap/client/current"))
    }
}
import RecoveryContract
