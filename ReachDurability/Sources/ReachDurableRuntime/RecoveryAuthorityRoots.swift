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

struct AuthorityConfiguration: Codable {
    let version: Int, profile: String, provision: AuthorityProvision, model: IndependentPublicModel
    func validate() throws {
        try provision.validate(); try model.descriptor.validate()
        guard version == 1, profile == AuthorityCodec.profile, AuthorityCodec.hash(try AuthorityCodec.encode(model)) == provision.publicModelDigest,
              model.descriptor.model == TransportContract.model, PreparationEncoding.isDigest(model.artifactDigest) else { throw AuthorityError.invalid }
    }
    var digest: String { get throws { try validate(); return try AuthorityCodec.digest(self) } }
    static func load(_ path: String) throws -> Self {
        let value=try AuthorityCodec.decode(Self.self,LocalFiles.read(path,maximum:64<<10)); try value.validate(); return value
    }
}
struct AuthoritySelection: Codable {
    let version: Int, profile: String, role: String, configuration: String, executable: FrozenWorker
}
struct AuthorityScopeRecord: Codable {
    let version: Int, scope: AuthorityScope, mac: Data
    init(scope: AuthorityScope, key: RootKeyMaterial) throws {
        version=1; self.scope=scope
        let bytes=try Self.message(scope)
        mac=key.use { Data(HMAC<SHA256>.authenticationCode(for:bytes,using:SymmetricKey(data:$0))) }
    }
    private static func message(_ scope: AuthorityScope) throws -> Data { Data("S100/original-local-scope/v1\0".utf8)+(try AuthorityCodec.encode(scope)) }
    func verify(key: RootKeyMaterial, scope expected: AuthorityScope) throws {
        guard version == 1, scope == expected, mac.count == 32 else { throw AuthorityError.scope }
        let bytes=try Self.message(scope)
        try key.use { guard HMAC<SHA256>.isValidAuthenticationCode(mac,authenticating:bytes,using:SymmetricKey(data:$0)) else { throw AuthorityError.scope } }
    }
}
extension RoleBootstrapCore {
    func authorityRoot() throws -> AuthorityRoot {
        try validateForRecoveryAuthority()
        return try .init(role:role.rawValue,identifier:identifier,localID:localID,root:root,boot:boot,core:binding())
    }
    func authorityStorage() throws -> AuthorityStorageIdentity {
        guard let authority else { throw AuthorityError.scope }
        return try .init(provision:authority,root:authorityRoot(),quota:quota)
    }
}
public enum RecoveryAuthorityRoots {
    public static func provision(originals: Data, publicModel: String, request: String, output: String) throws {
        let records=try AuthorityCodec.decode(ClockPolicy.Originals.self,originals)
        let modelBytes=try LocalFiles.read(publicModel,maximum:64<<10)
        let model=try AuthorityCodec.decode(IndependentPublicModel.self,modelBytes)
        let requestBytes=try LocalFiles.read(request,maximum:64<<10)
        _=try LocalDurableRuntime.request(from:request)
        let p=try AuthorityProvision(originals:records,hostID:UUID().uuidString.lowercased(),clientID:UUID().uuidString.lowercased(),
            publicModelDigest:AuthorityCodec.hash(modelBytes),requestInputDigest:AuthorityCodec.hash(requestBytes))
        let config=AuthorityConfiguration(version:1,profile:AuthorityCodec.profile,provision:p,model:model); try config.validate()
        try LocalFiles.writeNew(AuthorityCodec.encode(config),to:output)
    }
    public static func initialize(root: String, role: String, configuration path: String, receipt: String, secretDescriptor: Int32) throws -> String {
        guard let role=BootstrapRole(rawValue:role) else { throw AuthorityError.invalid }
        let credential=try UnlockCredential(consumingDescriptor:secretDescriptor); defer { credential.close() }
        try TransportContract.currentUser()
        let config=try AuthorityConfiguration.load(path), executable=try LocalFiles.executable()
        try LocalFiles.createDirectory(root)
        var container:OwnedFileKeychain?, lease:RoleLifecycleLease?
        do {
            for name in [role.rawValue,"keys"] { try LocalFiles.createDirectory(root+"/"+name) }
            try LocalFiles.writeNew(AuthorityCodec.encode(config),to:root+"/agreement.json")
            let selection=try AuthoritySelection(version:1,profile:AuthorityCodec.profile,role:role.rawValue,configuration:config.digest,executable:executable)
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
                let storage=try core.authorityStorage()
                if role == .host {
                    try DurableSessionLifecycle.initializeRecoveryAuthority(at:root+"/bootstrap/host",identity:.init(recoveryAuthority:storage),keys:LocalRuntimeOwner.hostKeys(keys))
                } else {
                    try DurableClientReceipts.initializeRecoveryAuthority(at:root+"/bootstrap/client",environment:.init(recoveryAuthority:storage),metadataKey:keys.key(.clientMetadata).use{$0})
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
        guard try r.digestForRecoveryAuthority() == expectedDigest, r.ready.core.lifecycle?.receipt == path else { throw AuthorityError.scope }
        return r
    }
    public static func originalScope(hostReceipt: String, hostDigest: String, clientReceipt: String, clientDigest: String) throws -> AuthorityScope {
        let h=try receipt(hostReceipt,expectedDigest:hostDigest).ready.core, c=try receipt(clientReceipt,expectedDigest:clientDigest).ready.core
        guard let provision=h.authority, provision == c.authority, h.role == .host, c.role == .client,
              h.boot == (try RootKeyCodec.boot()), c.boot == h.boot else { throw AuthorityError.scope }
        return try .init(provision:provision,host:h.authorityRoot(),client:c.authorityRoot())
    }
    static func validateSelection(_ core: RoleBootstrapCore) throws -> AuthorityConfiguration {
        try core.validateForRecoveryAuthority()
        guard let lifecycle=core.lifecycle else { throw AuthorityError.scope }
        let config=try AuthorityConfiguration.load(core.root+"/agreement.json")
        let selected=try AuthorityCodec.decode(AuthoritySelection.self,LocalFiles.read(core.root+"/"+core.role.rawValue+"/selection.json",maximum:64<<10))
        guard selected.version == 1, selected.profile == AuthorityCodec.profile, selected.role == core.role.rawValue,
              selected.configuration == (try config.digest), selected.executable == lifecycle.executable,
              selected.executable == (try LocalFiles.executable()), core.selection == (try AuthorityCodec.digest(selected)),
              core.authority == config.provision, core.agreement == (try config.provision.digest) else { throw AuthorityError.scope }
        return config
    }
}

/// Own-role lifetime and original-key scope are retained until after all IO.
/// No ordinary independent/native resources or maintenance owner is acquired.
final class RecoveryAuthorityRootAccess {
    let receipt:RoleOwnershipReceipt, lease:RoleLifecycleLease, current:OwnedAfterBootRoot
    let configuration:AuthorityConfiguration
    var core:RoleBootstrapCore { receipt.ready.core }
    init(receipt path: String, expectedDigest: String) throws {
        try TransportContract.currentUser()
        (receipt,lease)=try RoleLifecycleLease.selectRecoveryAuthority(receipt:path,expectedDigest:expectedDigest)
        guard let current=try OwnedAfterBootRoot.open(receipt.container.identity) else { throw AuthorityError.state }
        self.current=current
        configuration=try RecoveryAuthorityRoots.validateSelection(receipt.ready.core)
    }
    deinit { lease.close() }
    func scope() throws -> AuthorityScope {
        let value=try AuthorityCodec.decode(AuthorityScopeRecord.self,LocalFiles.read(core.root+"/"+core.role.rawValue+"/scope.json",maximum:64<<10))
        try core.authorityStorage().check(value.scope,role:core.role.rawValue)
        return value.scope // Still untrusted until original keys verify its MAC inside the action.
    }
    func withKeys(scope: AuthorityScope, action: RecoveryAuthorityAction, credential: UnlockCredential,
        original: Bool, body: (BootstrapKeys) throws -> Void) throws {
        try core.authorityStorage().check(scope,role:core.role.rawValue)
        func check() throws { try action.check(scope:scope,operation:action.operation) }
        func verify() throws {
            try check(); try current.check(); try lease.confirmRecoveryAuthorityReady(receipt.ready)
            _=try RecoveryAuthorityRoots.validateSelection(core); try check()
        }
        try verify()
        try OwnedRecoveryAuthorityAccess.perform(receipt.container,expectedDigest:receipt.container.digest(),current:current,credential:credential,verifySelection:verify) { provider in
            let keys=try RoleBootstrapStore.acquireRecoveryAuthority(ready:receipt.ready,lease:lease,provider:provider); try check()
            let key=try keys.key(core.role == .host ? .hostCatalog : .clientMetadata)
            let path=core.root+"/"+core.role.rawValue+"/scope.json"
            var info=stat()
            if lstat(path,&info) != 0 {
                guard errno == ENOENT, original else { throw AuthorityError.partial }
                let record=try AuthorityScopeRecord(scope:scope,key:key)
                try check(); try LocalFiles.writeNew(AuthorityCodec.encode(record),to:path); try check()
            }
            let record=try AuthorityCodec.decode(AuthorityScopeRecord.self,LocalFiles.read(path,maximum:64<<10)); try check()
            try record.verify(key:key,scope:scope); try check()
            try body(keys); try check()
        }
        try check()
    }
}
