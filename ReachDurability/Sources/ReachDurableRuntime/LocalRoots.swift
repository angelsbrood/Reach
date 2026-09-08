import Foundation
import Darwin
import MLX
import DurableRootKeys
import DurableStoreBootstrap
import DurableSessionLifecycle
import DurableClientReceipts
import RequestPreparationContract

struct LocalSelection:Codable {
    let revision:String,profileDigest:String,bootstrap:String,executable:FrozenWorker,confirmation:Data
    struct Binding:Encodable { let revision:String,profileDigest:String,bootstrap:String,executable:FrozenWorker }
    var binding:Binding { .init(revision:revision,profileDigest:profileDigest,bootstrap:bootstrap,executable:executable) }
}
struct LocalInvocation {
    let principal:String,device:String,app:String
    init() throws {
        guard getuid()==geteuid(),getgid()==getegid() else { throw LocalRuntimeError.refused }
        principal="uid:"+String(getuid());device="boot:"+(try RootKeyCodec.boot());app="reach.durable-local.v1"
    }
    var host:LifecycleAuthorization { .init(caller:.init(principal:principal,device:device,app:app),allowed:true) }
    var client:ClientAuthorization { .init(caller:.init(principal:principal,device:device,app:app),allowed:true) }
}
/// Foreground initialization owner retains the exact file-Keychain cleanup
/// capability. It holds no host/client lifecycle lock while commands run.
public final class LocalRuntimeOwner {
    public let root:String,backupExcluded:Bool
    private let container:OwnedFileKeychain,ready:BootstrapReady,keys:BootstrapKeys,rootInode:UInt64
    private var retired=false
    private let metadataBefore:KeychainMetadata
    public init(root:String,modelSource:String) throws {
        _=try LocalInvocation();let executable=try LocalFiles.executable()
        _=try RootKeyCodec.parent(root);try LocalFiles.directory(modelSource)
        let profile=try SelectedArtifactProfile(at:modelSource)
        try LocalFiles.createDirectory(root);self.root=root
        var info=stat();guard lstat(root,&info)==0 else { throw LocalRuntimeError.invalid };rootInode=UInt64(info.st_ino)
        // Failed initialization leaves an incomplete role that cannot reopen;
        // its exact creator still removes any newly created Keychain below.
        try LocalFiles.createDirectory(root+"/model");try LocalFiles.createDirectory(root+"/keys")
        for name in SelectedArtifactProfile.fileNames.union(["profile.json"]) {
            try LocalFiles.writeNew(LocalFiles.read(modelSource+"/"+name,maximum:name=="weights.safetensors" ? 128<<20 : 65536),to:root+"/model/"+name)
        }
        let installed=try SelectedArtifactProfile(at:root+"/model")
        guard installed.manifestDigest==profile.manifestDigest else { throw LocalRuntimeError.invalid }
        backupExcluded=LocalFiles.excludeBackup(root)
        metadataBefore=try KeychainMetadata.read()
        let password=try RootKeyCodec.random().map{String(format:"%02x",$0)}.joined()
        let created=try OwnedFileKeychain.create(at:root+"/keys/local.keychain-db",password:password)
        guard try KeychainMetadata.read().preserves(metadataBefore,owned:[created.location]) else { try created.deleteOwned();throw LocalRuntimeError.invalid }
        var retained:BootstrapKeys?
        do {
            let value=try DurableStoreBootstrap.create(optIn:true,at:root+"/bootstrap",container:created.location,policy:.current(),provider:{_ in
                MacKeychainProvider(container:created,initialAccess:Dictionary(uniqueKeysWithValues:RootKeyRole.allCases.map{($0,[executable])}))
            },initializeStores:{core,material in
                retained=material
                let hostClock=SystemLifecycleClock(),clientClock=SystemClientClock()
                let host=try DurableSessionLifecycle.initialize(at:root+"/bootstrap/host",identity:.init(incarnation:core.hostID,clock:hostClock,quota:core.policy.hostQuota),
                    keys:Self.hostKeys(material),clock:hostClock);defer { host.close() }
                let client=try DurableClientReceipts(path:root+"/bootstrap/client",create:true,environment:.init(rootID:core.clientID,clock:clientClock,quota:core.policy.clientQuota),
                    metadataKey:material.key(.clientMetadata).use{$0},clock:clientClock);client.close()
            })
            guard let value,let material=retained else { throw LocalRuntimeError.incomplete }
            ready=value;keys=material;container=created
            let binding=LocalSelection.Binding(revision:DurableRuntimeRevision.current,profileDigest:installed.manifestDigest,bootstrap:try value.core.binding(),executable:executable)
            let confirmation=try material.key(.hostCatalog).confirmation(value.core.reference(.hostCatalog),binding:PreparationEncoding.digest(binding))
            let selection=LocalSelection(revision:binding.revision,profileDigest:binding.profileDigest,bootstrap:binding.bootstrap,executable:executable,confirmation:confirmation)
            try LocalFiles.writeNew(PreparationEncoding.encode(selection),to:root+"/selection.json")
        } catch { try created.deleteOwned();throw error }
    }
    static func hostKeys(_ material:BootstrapKeys) throws -> LifecycleKeys {
        try .init(catalog:material.key(.hostCatalog).use{$0},ticket:material.key(.hostTicket).use{$0})
    }
    /// Refuse active lifecycle owners; exact creator cleanup never searches for keys.
    public func retire() throws {
        if retired { return }
        try LocalFiles.directory(root);var info=stat()
        guard lstat(root,&info)==0,UInt64(info.st_ino)==rootInode else { throw LocalRuntimeError.invalid }
        let hostClock=SystemLifecycleClock(),clientClock=SystemClientClock()
        let host=try DurableSessionLifecycle.reopen(at:root+"/bootstrap/host",identity:.init(incarnation:ready.core.hostID,clock:hostClock,quota:ready.core.policy.hostQuota),keys:Self.hostKeys(keys),clock:hostClock)
        defer { host.close() }
        let client=try DurableClientReceipts(path:root+"/bootstrap/client",create:false,environment:.init(rootID:ready.core.clientID,clock:clientClock,quota:ready.core.policy.clientQuota),metadataKey:keys.key(.clientMetadata).use{$0},clock:clientClock)
        defer { client.close() }
        try container.deleteOwned()
        let after=try KeychainMetadata.read()
        guard after.preserves(metadataBefore,owned:[container.location]),after.excludes([container.location]) else { throw LocalRuntimeError.invalid }
        // Both lock-bearing owners remain held until their owned directory tree
        // is removed. A successor therefore cannot acquire before teardown.
        try FileManager.default.removeItem(atPath:root);retired=true
    }
}

struct AcquiredLocalRoot {
    let core:BootstrapCore,hostKeys:BootstrapKeys,clientKeys:BootstrapKeys,profile:SelectedArtifactProfile
    init(_ root:String) throws {
        _=try LocalInvocation();try LocalFiles.directory(root)
        let executable=try LocalFiles.executable(),profile=try SelectedArtifactProfile(at:root+"/model")
        let selection=try JSONDecoder().decode(LocalSelection.self,from:LocalFiles.read(root+"/selection.json",maximum:16384))
        guard selection.revision==DurableRuntimeRevision.current,selection.profileDigest==profile.manifestDigest,selection.executable==executable else { throw LocalRuntimeError.invalid }
        let expected=root+"/keys/local.keychain-db",policy=try BootstrapPolicy.current()
        func provider(_ core:BootstrapCore) throws -> any RootKeyProvider {
            guard core.container==expected,core.policy.hostClock=="system-monotonic-raw-ns-v1",core.policy.clientClock=="system-monotonic-raw-ns-v1" else { throw LocalRuntimeError.invalid }
            return MacKeychainProvider(container:try .openExisting(at:expected))
        }
        guard let host=try DurableStoreBootstrap.acquire(optIn:true,at:root+"/bootstrap",role:.host,policy:policy,provider:provider),
            let client=try DurableStoreBootstrap.acquire(optIn:true,at:root+"/bootstrap",role:.client,policy:policy,provider:provider),host.descriptor==client.descriptor,
            selection.bootstrap==(try host.descriptor.core.binding()) else { throw LocalRuntimeError.incomplete }
        try host.keys.key(.hostCatalog).confirm(selection.confirmation,reference:host.descriptor.core.reference(.hostCatalog),binding:PreparationEncoding.digest(selection.binding))
        core=host.descriptor.core;hostKeys=host.keys;clientKeys=client.keys;self.profile=profile
    }
}
