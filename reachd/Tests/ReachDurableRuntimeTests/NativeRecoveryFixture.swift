import Foundation
import CryptoKit
import ClockPolicy
import MLX
import MLXNN
import MLXLMCommon
import ReachWire
import WireAdapterContract
import ResumableMLXProvider
import DurableRootKeys
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts
@testable import ReachDurableRuntime
import RecoveryAuthorityContract

/// Deterministic unit double; never used by the native VM qualification.
final class NativeUnitCounter { var calls=0; var models=0 }
private final class NativeUnitModel: Module, LanguageModel {
    let counter: NativeUnitCounter
    init(_ counter: NativeUnitCounter) { self.counter=counter; counter.models += 1; super.init() }
    func newCache(parameters: GenerateParameters?) -> [KVCache] { [KVCacheSimple(),KVCacheSimple()] }
    func prepare(_ input: LMInput, cache: [KVCache], state: LMOutput.State?, windowSize: Int?) throws -> PrepareResult { throw AuthorityError.state }
    func callAsFunction(_ input: LMInput.Text, cache: [KVCache]?, state: LMOutput.State?) -> LMOutput {
        counter.calls += 1
        let values=broadcast(input.tokens.asType(.float32).reshaped(1,1,-1,1),to:[1,1,input.tokens.dim(1),8])
        for c in cache ?? [] { _=c.update(keys:values,values:values) }
        var logits=[Float](repeating:-10,count:258); logits[66]=10
        return .init(logits:broadcast(MLXArray(logits).reshaped(1,1,258),to:[1,input.tokens.dim(1),258]))
    }
}
final class NativeRecoveryFixture {
    let base: String, host: String, client: String
    let witnessClock=AuthorityFixtureClock(time:100_000_000_000), receiverClock=AuthorityFixtureClock(time:200_000_000_000)
    let witness: Witness, scope: AuthorityScope, owner: GenerationAuthorityOwner
    let hostIdentity: LifecycleIdentity, clientEnvironment: ClientEnvironment, hostKeys: LifecycleKeys
    let catalogKey=clientRandomKey(), ticketKey=clientRandomKey(), clientKey=clientRandomKey()
    let provider: ProviderBinding
    let counter=NativeUnitCounter()
    let caller=CallerIdentity(principal:"fixture",device:"original",app:AuthorityCodec.nativeProfile)
    init(hostCap: UInt64=90, clientCap: UInt64=150, request: WireGenerationRequest?=nil) throws {
        base=try ArtifactFixtures.base()+"/native-"+UUID().uuidString.lowercased(); host=base+"/host"; client=base+"/client"
        for path in [base,host,client,host+"/bootstrap",client+"/bootstrap"] { try LocalFiles.createDirectory(path) }
        provider=try LocalDurableRuntime.withCPU {
            let p=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts(),nativeRecovery:true)
            let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
            let input=request ?? WireGenerationRequest(id:UUID(uuidString:"00000000-0000-0000-0000-000000000101")!,portableTranscript:.init(entries:[.prompt(.init(id:"prompt",segments:[.text(.init(id:"text",content:"Hi."))]))]),options:.init(temperature:0,maximumResponseTokens:16,sampling:.greedy))
            return try p.preparer.prepare(input,reference:.init(session:.init(modelID:config.model,profile:config.profile,sessionID:"fixture"),generationID:"fixture",operationID:"native-unit-operation"),configuration:config)
        }
        try NativeRecoveryRuntime.validateFixture(provider)
        witness=try Witness(clock:witnessClock)
        let pair=UUID().uuidString.lowercased(), h=UUID().uuidString.lowercased(), c=UUID().uuidString.lowercased()
        let originals=try Originals(pin:witness.identity,host:witness.register(subject:pair,role:.host,cap:hostCap*1_000_000_000),client:witness.register(subject:pair,role:.client,cap:clientCap*1_000_000_000))
        let p=try AuthorityProvision(originals:originals,hostID:h,clientID:c,publicModelDigest:String(repeating:"a",count:64),requestInputDigest:String(repeating:"b",count:64),execution:.init(operation:provider.operationID,provider:AuthorityCodec.encode(provider)))
        let boot=try RootKeyCodec.boot()
        scope=try .init(provision:p,host:.init(role:"host",identifier:UUID().uuidString.lowercased(),localID:h,root:host,boot:boot,core:String(repeating:"c",count:64)),client:.init(role:"client",identifier:UUID().uuidString.lowercased(),localID:c,root:client,boot:boot,core:String(repeating:"d",count:64)))
        owner=try .init(scope:scope,clock:receiverClock)
        hostIdentity=try .init(recoveryAuthority:.init(provision:p,root:scope.host,quota:1<<30))
        clientEnvironment=try .init(recoveryAuthority:.init(provision:p,root:scope.client,quota:1<<30))
        hostKeys=try .init(catalog:catalogKey,ticket:ticketKey)
        try DurableSessionLifecycle.initializeNativeRecovery(at:host+"/bootstrap/host",identity:hostIdentity,keys:hostKeys)
        try DurableClientReceipts.initializeNativeRecovery(at:client+"/bootstrap/client",environment:clientEnvironment,metadataKey:clientKey)
    }
    deinit { try? FileManager.default.removeItem(atPath:base) }
    func action(_ op: GenerationOperation, owner: GenerationAuthorityOwner?=nil) throws -> GenerationAuthorityAction {
        let a=try (owner ?? self.owner).begin(op); try a.receive(witness.respond(to:a.request)); return a
    }
    func provision() throws -> AuthorityAdmission {
        let a=try action(.admitHost)
        let issued=try DurableSessionLifecycle.admitNativeRecovery(at:host+"/bootstrap/host",identity:hostIdentity,keys:hostKeys,scope:scope,caller:caller,provider:provider,action:a)
        try a.finish()
        let acceptance=try AuthorityAcceptance(issued:issued,originalIssuer:AuthorityIssued.issuerKey(ticketKey:ticketKey,native:true).publicKey.rawRepresentation,originalSuccessfulExportDigest:AuthorityCodec.digest(issued))
        let b=try action(.acceptClient)
        try DurableClientReceipts.acceptNativeRecovery(at:client+"/bootstrap/client",parent:client,environment:clientEnvironment,metadataKey:clientKey,acceptance:acceptance,action:b)
        try b.finish(); return try acceptance.admission()
    }
    func openHost(_ a: GenerationAuthorityAction, fault: @escaping StoreFaultHook={_ in}) throws -> NativeLifecycleOwner {
        try .init(path:host+"/bootstrap/host",identity:hostIdentity,keys:hostKeys,scope:scope,action:a,storeFault:fault)
    }
    func openClient(_ a: GenerationAuthorityAction) throws -> NativeClientOwner {
        try .init(path:client+"/bootstrap/client",parent:client,environment:clientEnvironment,metadataKey:clientKey,scope:scope,action:a)
    }
    func runtime() -> ProviderRuntime {
        let native=ProviderNativeRuntime(tokenizer:ArtifactTokenizer(),codecs:.init(),model:{ NativeUnitModel(self.counter) })
        return provider.lane.route == .guided ? .guided(native) : .ordinary(native)
    }
    func deliver(_ h: NativeLifecycleOwner, _ c: NativeClientOwner, _ g: GuardedNativeGeneration?, _ a: GenerationAuthorityAction) throws {
        try h.store.authorize(a)
        let w=try c.witness(action:a)
        for f in try h.store.replay(after:w.high) { try c.accept(.init(firstSequence:f.firstSequence,count:f.count,providerCommit:f.providerCommit,eventBytes:f.eventBytes,skipPrefix:f.skipPrefix),action:a) }
        let receipt=try c.witness(action:a); try h.acceptReceipt(receipt,action:a); try g?.acknowledgeDelivery(through:receipt.high,action:a)
    }
    func hashes() throws -> [String:String] {
        var result:[String:String]=[:]
        for case let url as URL in FileManager.default.enumerator(at:URL(fileURLWithPath:base),includingPropertiesForKeys:[.isRegularFileKey])! {
            if try url.resourceValues(forKeys:[.isRegularFileKey]).isRegularFile == true { result[url.path]=AuthorityCodec.hash(try Data(contentsOf:url)) }
        }
        return result
    }
}
