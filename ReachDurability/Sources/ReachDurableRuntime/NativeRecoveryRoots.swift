import Foundation
import Darwin
import CryptoKit
import ClockPolicy
import DurableRootKeys
import DurableStoreBootstrap
import DurableSessionLifecycle
import DurableClientReceipts
import RequestPreparationContract
@_exported import RecoveryAuthorityContract

struct NativeConfiguration: Codable {
    let version: Int, profile: String, provision: AuthorityProvision, model: IndependentPublicModel, artifactPath: String
    func validate(selection:NativeRecoverySelection = .artifact) throws {
        try provision.validate(); try model.descriptor.validate()
        guard version == 2, provision.native, artifactPath.hasPrefix("/"), profile == AuthorityCodec.nativeProfile, AuthorityCodec.hash(try AuthorityCodec.encode(model)) == provision.publicModelDigest,
              model.descriptor.model == selection.model, PreparationEncoding.isDigest(model.artifactDigest) else { throw AuthorityError.invalid }
    }
    func digest(selection:NativeRecoverySelection) throws -> String { try validate(selection:selection);return try AuthorityCodec.digest(self) }
    static func load(_ path: String,selection:NativeRecoverySelection = .artifact) throws -> Self {
        let value=try AuthorityCodec.decode(Self.self,LocalFiles.read(path,maximum:64<<10)); try value.validate(selection:selection); return value
    }
}
struct NativeSelection: Codable {
    let version: Int, profile: String, role: String, configuration: String, executable: FrozenWorker
}
struct NativeScopeRecord: Codable {
    let version: Int, scope: AuthorityScope, mac: Data
    init(scope: AuthorityScope, key: RootKeyMaterial) throws {
        version=1; self.scope=scope
        let bytes=try Self.message(scope)
        mac=key.use { Data(HMAC<SHA256>.authenticationCode(for:bytes,using:SymmetricKey(data:$0))) }
    }
    private static func message(_ scope: AuthorityScope) throws -> Data { Data("S101/original-local-scope/v2\0".utf8)+(try AuthorityCodec.encode(scope)) }
    func verify(key: RootKeyMaterial, scope expected: AuthorityScope) throws {
        guard version == 1, scope == expected, mac.count == 32 else { throw AuthorityError.scope }
        let bytes=try Self.message(scope)
        try key.use { guard HMAC<SHA256>.isValidAuthenticationCode(mac,authenticating:bytes,using:SymmetricKey(data:$0)) else { throw AuthorityError.scope } }
    }
}
extension RoleBootstrapCore {
    func nativeRoot() throws -> AuthorityRoot {
        try validateForNativeRecovery()
        return try .init(role:role.rawValue,identifier:identifier,localID:localID,root:root,boot:boot,core:binding())
    }
    func nativeStorage() throws -> AuthorityStorageIdentity {
        guard let authority else { throw AuthorityError.scope }
        return try .init(provision:authority,root:nativeRoot(),quota:quota)
    }
}
public enum NativeRecoveryRoots {
    public static func provision(originals: Data, publicModel: String, request: String, model: String, prepared: String, output: String, fixture:AllowedRecoveryQualificationFactory? = nil, witness:NativeWitnessSelection? = nil) throws {
        try witness?.requireArtifact(fixture:fixture)
        let records=try AuthorityCodec.decode(ClockPolicy.Originals.self,originals)
        let execution=try AuthorityCodec.decode(AuthorityExecution.self,LocalFiles.read(prepared,maximum:64<<10))
        let binding=try AuthorityCodec.decode(ProviderBinding.self,execution.provider)
        try NativeRecoveryRuntime.validateFixture(binding)
        try witness?.validate(originals:records,binding:binding,fixture:fixture)
        let modelBytes=try LocalFiles.read(publicModel,maximum:64<<10)
        let declaration=try AuthorityCodec.decode(IndependentPublicModel.self,modelBytes)
        let requestBytes=try LocalFiles.read(request,maximum:64<<10)
        _=try LocalDurableRuntime.request(from:request)
        let p=try AuthorityProvision(originals:records,hostID:UUID().uuidString.lowercased(),clientID:UUID().uuidString.lowercased(),
            publicModelDigest:AuthorityCodec.hash(modelBytes),requestInputDigest:AuthorityCodec.hash(requestBytes),execution:execution)
        let config=NativeConfiguration(version:2,profile:AuthorityCodec.nativeProfile,provision:p,model:declaration,artifactPath:model); try config.validate(selection:NativeRecoverySelection(fixture))
        try LocalFiles.writeNew(AuthorityCodec.encode(config),to:output)
    }
    public static func initialize(root: String, role: String, configuration path: String, receipt: String, secretDescriptor: Int32, fixture:AllowedRecoveryQualificationFactory? = nil) throws -> String {
        guard let role=BootstrapRole(rawValue:role) else { throw AuthorityError.invalid }
        let credential=try UnlockCredential(consumingDescriptor:secretDescriptor); defer { credential.close() }
        try TransportContract.currentUser()
        let modelSelection=NativeRecoverySelection(fixture)
        let config=try NativeConfiguration.load(path,selection:modelSelection), executable=try LocalFiles.executable()
        try LocalFiles.createDirectory(root)
        var container:OwnedFileKeychain?, lease:RoleLifecycleLease?
        do {
            for name in [role.rawValue,"keys"] { try LocalFiles.createDirectory(root+"/"+name) }
            try LocalFiles.writeNew(AuthorityCodec.encode(config),to:root+"/agreement.json")
            let selection=try NativeSelection(version:1,profile:AuthorityCodec.nativeProfile,role:role.rawValue,configuration:config.digest(selection:modelSelection),executable:executable)
            try LocalFiles.writeNew(AuthorityCodec.encode(selection),to:root+"/"+role.rawValue+"/selection.json")
            _=LocalFiles.excludeBackup(root)
            let lifecycle=try RoleLifecycleIdentity(root:root,receipt:receipt,executable:executable)
            let originals=try config.provision.originals.records()
            let core=try RoleBootstrapCore(role:role,localID:role == .host ? config.provision.hostID : config.provision.clientID,
                root:root,agreement:config.provision.digest,selection:AuthorityCodec.digest(selection),
                origin:role == .host ? originals.host.anchor : originals.client.anchor,epoch:config.provision.originals.pin.epoch,
                boot:RootKeyCodec.boot(),quota:1<<30,lifecycle:lifecycle,unlockPolicy:UnlockCredential.policy,authority:config.provision)
            lease=try RoleLifecycleLease.create(core:core)
            let before=try KeychainMetadata.read()
            let created=try credential.consume { try OwnedFileKeychain.create(at:core.container,password:String(decoding:$0,as:UTF8.self)) }
            container=created
            let ready=try RoleBootstrapStore.create(core:core,provider:{
                MacKeychainProvider(container:created,initialAccess:Dictionary(uniqueKeysWithValues:core.keys.map { ($0.role,[executable]) }))
            },initializeStore:{ keys in
                let storage=try core.nativeStorage()
                if role == .host {
                    try DurableSessionLifecycle.initializeNativeRecovery(at:root+"/bootstrap/host",identity:.init(recoveryAuthority:storage),keys:LocalRuntimeOwner.hostKeys(keys))
                } else {
                    try DurableClientReceipts.initializeNativeRecovery(at:root+"/bootstrap/client",environment:.init(recoveryAuthority:storage),metadataKey:keys.key(.clientMetadata).use{$0})
                }
            },lifecycle:lease)
            guard try KeychainMetadata.read().preserves(before,owned:[core.container]) else { throw AuthorityError.invalid }
            guard let lease else { throw AuthorityError.invalid }
            let digest=try lease.publish(ready); lease.close(); return digest
        } catch {
            // Exact creator rollback only; failure leaves the original material for diagnosis.
            if let container { try container.deleteOwned() }
            try FileManager.default.removeItem(atPath:root); try lease?.rollbackCreation(); throw error
        }
    }
    static func receipt(_ path: String, expectedDigest: String) throws -> RoleOwnershipReceipt {
        let r=try RootKeyCodec.decode(RoleOwnershipReceipt.self,LocalFiles.read(path,maximum:64<<10),limit:64<<10)
        guard try r.digestForNativeRecovery() == expectedDigest, r.ready.core.lifecycle?.receipt == path else { throw AuthorityError.scope }
        return r
    }
    public static func originalScope(hostReceipt: String, hostDigest: String, clientReceipt: String, clientDigest: String) throws -> AuthorityScope {
        let h=try receipt(hostReceipt,expectedDigest:hostDigest).ready.core, c=try receipt(clientReceipt,expectedDigest:clientDigest).ready.core
        guard let provision=h.authority, provision == c.authority, h.role == .host, c.role == .client,
              h.boot == (try RootKeyCodec.boot()), c.boot == h.boot else { throw AuthorityError.scope }
        return try .init(provision:provision,host:h.nativeRoot(),client:c.nativeRoot())
    }
    /// Content-free retirement still authenticates the exact original executable,
    /// configuration, provision and selection. No model is constructed here.
    static func validateSelection(_ core:RoleBootstrapCore) throws -> NativeConfiguration {
        let config=try AuthorityCodec.decode(NativeConfiguration.self,LocalFiles.read(core.root+"/agreement.json",maximum:64<<10))
        let selection:NativeRecoverySelection=config.model.descriptor.model == AllowedRecoveryQualificationProfile.modelIdentity ? .allowedFixture : .artifact
        return try validateSelection(core,modelSelection:selection)
    }
    static func validateSelection(_ core: RoleBootstrapCore,modelSelection:NativeRecoverySelection) throws -> NativeConfiguration {
        try core.validateForNativeRecovery()
        guard let lifecycle=core.lifecycle else { throw AuthorityError.scope }
        let config=try NativeConfiguration.load(core.root+"/agreement.json",selection:modelSelection)
        let selected=try AuthorityCodec.decode(NativeSelection.self,LocalFiles.read(core.root+"/"+core.role.rawValue+"/selection.json",maximum:64<<10))
        guard selected.version == 1, selected.profile == AuthorityCodec.nativeProfile, selected.role == core.role.rawValue,
              selected.configuration == (try config.digest(selection:modelSelection)), selected.executable == lifecycle.executable,
              selected.executable == (try LocalFiles.executable()), core.selection == (try AuthorityCodec.digest(selected)),
              core.authority == config.provision, core.agreement == (try config.provision.digest) else { throw AuthorityError.scope }
        return config
    }
}

/// Own-role lifetime and original-key scope are retained until after all IO.
/// No ordinary independent/native resources or maintenance owner is acquired.
final class NativeRecoveryRootAccess {
    let receipt:RoleOwnershipReceipt, lease:RoleLifecycleLease, current:OwnedAfterBootRoot
    let configuration:NativeConfiguration
    private let selectedDigest:String
    private let modelSelection:NativeRecoverySelection
    var core:RoleBootstrapCore { receipt.ready.core }
    init(receipt path: String, expectedDigest: String,fixture:AllowedRecoveryQualificationFactory? = nil) throws {
        modelSelection=NativeRecoverySelection(fixture)
        try TransportContract.currentUser(); selectedDigest=expectedDigest
        (receipt,lease)=try RoleLifecycleLease.selectNativeRecovery(receipt:path,expectedDigest:expectedDigest)
        guard let current=try OwnedAfterBootRoot.open(receipt.container.identity) else { throw AuthorityError.state }
        self.current=current
        configuration=try NativeRecoveryRoots.validateSelection(receipt.ready.core,modelSelection:modelSelection)
    }
    deinit { lease.close() }
    func validateCurrent() throws { try current.check(); try lease.confirmNativeBoundary(receipt,expectedDigest:selectedDigest) }
    func scope() throws -> AuthorityScope {
        let value=try AuthorityCodec.decode(NativeScopeRecord.self,LocalFiles.read(core.root+"/"+core.role.rawValue+"/scope.json",maximum:64<<10))
        try core.nativeStorage().check(value.scope,role:core.role.rawValue)
        return value.scope // Still untrusted until original keys verify its MAC inside the action.
    }
    func withKeys(scope: AuthorityScope, owner: GenerationAuthorityOwner, credential: UnlockCredential,
        original: Bool, body: (BootstrapKeys) throws -> Void) throws {
        try core.nativeStorage().check(scope,role:core.role.rawValue)
        func check() throws { guard owner.scope == scope else { throw AuthorityError.scope }; try owner.checkCurrent() }
        func verify() throws {
            try check(); try current.check(); try lease.confirmNativeRecoveryReady(receipt.ready)
            _=try NativeRecoveryRoots.validateSelection(core,modelSelection:modelSelection); try check()
        }
        try verify()
        try OwnedRecoveryAuthorityAccess.perform(receipt.container,expectedDigest:receipt.container.digest(),current:current,credential:credential,verifySelection:verify) { provider in
            let keys=try RoleBootstrapStore.acquireNativeRecovery(ready:receipt.ready,lease:lease,provider:provider); try check()
            let key=try keys.key(core.role == .host ? .hostCatalog : .clientMetadata)
            let path=core.root+"/"+core.role.rawValue+"/scope.json"
            var info=stat()
            if lstat(path,&info) != 0 {
                guard errno == ENOENT, original else { throw AuthorityError.partial }
                let record=try NativeScopeRecord(scope:scope,key:key)
                try check(); try LocalFiles.writeNew(AuthorityCodec.encode(record),to:path); try check()
            }
            let record=try AuthorityCodec.decode(NativeScopeRecord.self,LocalFiles.read(path,maximum:64<<10)); try check()
            try record.verify(key:key,scope:scope); try check()
            try body(keys); try check()
        }
        try check()
    }
}

import ResumableMLXProvider
