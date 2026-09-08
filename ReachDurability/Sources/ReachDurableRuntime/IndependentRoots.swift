import Foundation
import Darwin
import DurableRootKeys
import DurableStoreBootstrap
import DurableClientReceipts
import DurableSessionLifecycle
import RequestPreparationContract

/// One foreground creator retains only its own original deletion capability.
public final class IndependentRootOwner {
    public let root: String, role: TransportRole, backupExcluded: Bool
    public let ready: RoleBootstrapReady
    public let ownershipReceiptDigest: String?
    private let container: OwnedFileKeychain, keys: BootstrapKeys, metadata: KeychainMetadata, inode: UInt64
    private var retired=false, containerDeleted=false
    public init(root: String, role: TransportRole, provisioned: String, modelSource: String? = nil, ownerReceipt: String? = nil) throws {
        try TransportContract.currentUser()
        guard (role == .host) == (modelSource != nil) else { throw TransportRuntimeError.invalid }
        let executable=try LocalFiles.executable(), agreement=try IndependentPairAgreement.load(provisioned+"/agreement.json")
        let archive=try LocalFiles.read(provisioned+"/identity.p12",maximum:1<<20)
        try LocalFiles.createDirectory(root); self.root=root; self.role=role
        var info=stat(); guard lstat(root,&info)==0 else { throw TransportRuntimeError.invalid }; inode=UInt64(info.st_ino)
        var owned: OwnedFileKeychain?
        var lifecycleLease: RoleLifecycleLease?
        do {
            for name in [role.rawValue,"keys"] { try LocalFiles.createDirectory(root+"/"+name) }
            try LocalFiles.writeNew(RootKeyCodec.encode(agreement,limit:64<<10),to:root+"/agreement.json")
            try LocalFiles.writeNew(archive,to:root+"/"+role.rawValue+"/identity.p12")
            let selection=try TransportSelectionBinding(revision:IndependentContract.revision,role:role,bootstrap:agreement.digest,
                profileDigest:agreement.model.artifactDigest,archiveDigest:PreparationEncoding.hash(archive),executable:executable,
                descriptor:agreement.model.descriptor,pins:agreement.pins,port:agreement.port)
            try selection.validate(role:role)
            _=try TransportIdentity(root:root,selection:selection,audit:TransportRoleAudit(role))
            if let modelSource {
                try LocalFiles.createDirectory(root+"/model")
                for name in SelectedArtifactProfile.fileNames.union(["profile.json"]) {
                    try LocalFiles.writeNew(LocalFiles.read(modelSource+"/"+name,maximum:name=="weights.safetensors" ? 128<<20 : 65536),to:root+"/model/"+name)
                }
                let profile=try SelectedArtifactProfile(at:root+"/model")
                guard profile.manifestDigest==agreement.model.artifactDigest, profile.preparer.policy.descriptor==agreement.model.descriptor else { throw TransportRuntimeError.invalid }
            }
            backupExcluded=LocalFiles.excludeBackup(root)
            metadata=try KeychainMetadata.read()
            let lifecycle=try ownerReceipt.map { try RoleLifecycleIdentity(root:root,receipt:$0,executable:executable) }
            let core=try RoleBootstrapCore(role:role == .host ? .host : .client,localID:role == .host ? agreement.hostID : agreement.clientID,
                root:root,agreement:agreement.digest,selection:PreparationEncoding.digest(selection),
                origin:clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW),epoch:UUID().uuidString.lowercased(),boot:RootKeyCodec.boot(),quota:1<<30,lifecycle:lifecycle)
            if lifecycle != nil { lifecycleLease=try RoleLifecycleLease.create(core:core) }
            let clock=try RoleMonotonicClock(origin:core.origin,epoch:core.epoch,boot:core.boot)
            let created=try OwnedFileKeychain.create(at:core.container,password:RootKeyCodec.random().map{String(format:"%02x",$0)}.joined())
            owned=created
            guard try KeychainMetadata.read().preserves(metadata,owned:[created.location]) else { throw TransportRuntimeError.invalid }
            try LocalFiles.writeNew(RootKeyCodec.encode(selection,limit:64<<10),to:root+"/"+role.rawValue+"/selection.json")
            var retained: BootstrapKeys?
            ready=try RoleBootstrapStore.create(core:core,provider:{
                MacKeychainProvider(container:created,initialAccess:Dictionary(uniqueKeysWithValues:core.keys.map{($0.role,[executable])}))
            },initializeStore:{ material in
                retained=material
                if role == .host {
                    let host=try DurableSessionLifecycle.initialize(at:root+"/bootstrap/host",identity:.init(incarnation:core.localID,clock:clock,quota:core.quota),keys:LocalRuntimeOwner.hostKeys(material),clock:clock)
                    host.close()
                } else {
                    let client=try DurableClientReceipts(path:root+"/bootstrap/client",create:true,
                        environment:.init(rootID:core.localID,clock:clock,quota:core.quota,authorityMode:.independent,pairDigest:agreement.digest,retentionCap:agreement.retentionCap),
                        metadataKey:material.key(.clientMetadata).use{$0},clock:clock)
                    client.close()
                }
            },lifecycle:lifecycleLease)
            ownershipReceiptDigest=try lifecycleLease?.publish(ready)
            lifecycleLease?.close()
            guard let retained else { throw TransportRuntimeError.invalid }; keys=retained; container=created
        } catch {
            if let owned { try owned.deleteOwned() }
            try FileManager.default.removeItem(atPath:root)
            try lifecycleLease?.rollbackCreation(); throw error
        }
    }
    public func retire() throws {
        guard ready.core.version == 1 else { throw TransportRuntimeError.invalid }
        if retired { return }
        try LocalFiles.directory(root)
        var info=stat(); guard lstat(root,&info)==0, UInt64(info.st_ino)==inode else { throw TransportRuntimeError.invalid }
        let core=ready.core, clock=try RoleMonotonicClock(origin:ready.core.origin,epoch:ready.core.epoch,boot:ready.core.boot)
        // Reacquiring the local journal refuses while a worker still owns it.
        let close: () -> Void
        if role == .host {
            let host=try DurableSessionLifecycle.reopen(at:root+"/bootstrap/host",identity:.init(incarnation:core.localID,clock:clock,quota:core.quota),keys:LocalRuntimeOwner.hostKeys(keys),clock:clock)
            close={ host.close() }
        } else {
            let agreement=try IndependentPairAgreement.load(root+"/agreement.json")
            let client=try DurableClientReceipts(path:root+"/bootstrap/client",create:false,
                environment:.init(rootID:core.localID,clock:clock,quota:core.quota,authorityMode:.independent,pairDigest:core.agreement,retentionCap:agreement.retentionCap),
                metadataKey:keys.key(.clientMetadata).use{$0},clock:clock)
            close={ client.close() }
        }
        defer { close() }
        if !containerDeleted { try container.deleteOwned(); containerDeleted=true }
        let after=try KeychainMetadata.read()
        guard after.preserves(metadata,owned:[container.location]),after.excludes([container.location]) else { throw TransportRuntimeError.invalid }
        try FileManager.default.removeItem(atPath:root); retired=true
    }
}
private final class IndependentRoleProvider: RootKeyProvider {
    let provider: MacKeychainProvider, audit: TransportRoleAudit
    init(_ provider: MacKeychainProvider, audit: TransportRoleAudit) { self.provider=provider;self.audit=audit }
    func create(_ reference: RootKeyReference,binding: String) throws -> RootKeyMaterial { throw TransportRuntimeError.invalid }
    func load(_ reference: RootKeyReference,binding: String) throws -> RootKeyMaterial {
        try audit.load(reference.role); return try provider.load(reference,binding:binding)
    }
}
struct AcquiredIndependentRoot {
    let lifecycle: RoleLifecycleLease?
    let agreement: IndependentPairAgreement, acquisition: RoleBootstrapAcquisition, selection: TransportSelectionBinding, audit: TransportRoleAudit
    init(root: String, role: TransportRole) throws {
        try TransportContract.currentUser(); try LocalFiles.directory(root)
        let ready=try RoleBootstrapStore.inspect(at:root,role:role == .host ? .host : .client)
        lifecycle=try ready.core.version == 2 ? RoleLifecycleLease.acquire(ready:ready) : nil
        let agreement=try IndependentPairAgreement.load(root+"/agreement.json"), audit=TransportRoleAudit(role)
        let selection=try RootKeyCodec.decode(TransportSelectionBinding.self,LocalFiles.read(root+"/"+role.rawValue+"/selection.json",maximum:64<<10),limit:64<<10)
        try selection.validate(role:role)
        guard selection.revision==IndependentContract.revision,selection.executable==(try LocalFiles.executable()),
              selection.bootstrap==(try agreement.digest),selection.profileDigest==agreement.model.artifactDigest,
              selection.descriptor==agreement.model.descriptor,selection.pins==agreement.pins,selection.port==agreement.port else { throw TransportRuntimeError.invalid }
        acquisition=try RoleBootstrapStore.acquire(at:root,role:role == .host ? .host : .client,validate:{ core in
            guard core.localID==(role == .host ? agreement.hostID : agreement.clientID),core.agreement==(try agreement.digest),
                  core.selection==(try PreparationEncoding.digest(selection)) else { throw TransportRuntimeError.invalid }
            _=try RoleMonotonicClock(origin:core.origin,epoch:core.epoch,boot:core.boot)
        },provider:{ core in IndependentRoleProvider(MacKeychainProvider(container:try .openExisting(at:core.container)),audit:audit) },lifecycle:lifecycle)
        self.agreement=agreement; self.selection=selection; self.audit=audit
    }
}
