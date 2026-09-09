import Foundation
import DurableRootKeys

private struct RoleIntent: Codable { let state: String, core: RoleBootstrapCore }
public enum RoleBootstrapStore {
    /// Bounded bootstrap metadata only: no key/provider or journal-content access.
    public static func inspect(at root: String, role: BootstrapRole) throws -> RoleBootstrapReady {
        let fs = try RoleBootstrapFileSystem(path:root+"/bootstrap",fresh:false,role:role); defer { fs.close() }
        let names = try fs.scan()
        guard names.contains("ready.json"), !names.contains("selection.tmp") else { throw BootstrapError.incomplete }
        let ready = try RootKeyCodec.decode(RoleBootstrapReady.self,fs.read("ready.json"),limit:BootstrapLimits.record)
        let intent = try RootKeyCodec.decode(RoleIntent.self,fs.read("intent.json"),limit:BootstrapLimits.record)
        guard intent.state == "creating", intent.core == ready.core else { throw BootstrapError.invalid }
        try ready.validate(role:role,root:root); return ready
    }
    /// Public bootstrap metadata only, admitted solely for explicit old-boot cleanup.
    public static func inspectForAfterBootRetirement(at root: String, role: BootstrapRole) throws -> RoleBootstrapReady {
        let fs = try RoleBootstrapFileSystem(path:root+"/bootstrap",fresh:false,role:role); defer { fs.close() }
        let names = try fs.scan()
        guard names.contains("ready.json"), !names.contains("selection.tmp") else { throw BootstrapError.incomplete }
        let ready = try RootKeyCodec.decode(RoleBootstrapReady.self,fs.read("ready.json"),limit:BootstrapLimits.record)
        let intent = try RootKeyCodec.decode(RoleIntent.self,fs.read("intent.json"),limit:BootstrapLimits.record)
        try ready.core.validateForAfterBootRetirement()
        guard ready.core.root == root, ready.core.role == role, intent.state == "creating", intent.core == ready.core,
              ready.state == "ready", ready.confirmations.count == ready.core.keys.count,
              ready.confirmations.allSatisfy({ $0.count == 32 }) else { throw BootstrapError.invalid }
        return ready
    }
    public static func create(core: RoleBootstrapCore, provider: () throws -> any RootKeyProvider,
        initializeStore: (BootstrapKeys) throws -> Void, lifecycle: RoleLifecycleLease? = nil, hook: BootstrapHook = { _ in }) throws -> RoleBootstrapReady {
        try core.validate(role:core.role,root:core.root)
        if core.version != 1 { guard let lifecycle else { throw BootstrapError.incomplete }; try lifecycle.confirmCreating(core) }
        let fs=try RoleBootstrapFileSystem(path:core.root+"/bootstrap",fresh:true,role:core.role); defer { fs.close() }
        try hook(.beforeIntentWrite)
        try fs.write("intent.json",bytes:RootKeyCodec.encode(RoleIntent(state:"creating",core:core),limit:BootstrapLimits.record),hook:hook)
        try fs.sync(); try hook(.afterIntent)
        let store=try provider(), binding=try core.binding()
        var values:[RootKeyRole:RootKeyMaterial]=[:], confirmations:[Data]=[], independent=Set<Data>()
        for (i,reference) in core.keys.enumerated() {
            let key=try store.create(reference,binding:binding)
            try key.use { try RootKeyCodec.require(independent.insert($0).inserted) }
            values[reference.role]=key; confirmations.append(try key.confirmation(reference,binding:binding))
            if i==0 { try hook(.afterFirstKey) }
        }
        try initializeStore(BootstrapKeys(values)); try fs.syncJournals(); try hook(.afterStores)
        let ready=RoleBootstrapReady(state:"ready",core:core,confirmations:confirmations)
        try ready.validate(role:core.role,root:core.root)
        try fs.write("selection.tmp",bytes:RootKeyCodec.encode(ready,limit:BootstrapLimits.record),hook:hook)
        try fs.selectReady(hook:hook); try hook(.afterReady); return ready
    }
    public static func acquire(at root: String, role: BootstrapRole, validate: (RoleBootstrapCore) throws -> Void,
        provider: (RoleBootstrapCore) throws -> any RootKeyProvider, lifecycle: RoleLifecycleLease? = nil) throws -> RoleBootstrapAcquisition {
        let fs=try RoleBootstrapFileSystem(path:root+"/bootstrap",fresh:false,role:role); defer { fs.close() }
        let names=try fs.scan()
        guard names.contains("ready.json"), !names.contains("selection.tmp") else { throw BootstrapError.incomplete }
        let ready=try RootKeyCodec.decode(RoleBootstrapReady.self,fs.read("ready.json"),limit:BootstrapLimits.record)
        let intent=try RootKeyCodec.decode(RoleIntent.self,fs.read("intent.json"),limit:BootstrapLimits.record)
        guard intent.state=="creating", intent.core==ready.core else { throw BootstrapError.invalid }
        try ready.validate(role:role,root:root)
        if ready.core.version != 1 { guard let lifecycle else { throw BootstrapError.incomplete }; try lifecycle.confirmReady(ready) }
        try validate(ready.core)
        let journal=try fs.journal(role), store=try provider(ready.core), binding=try ready.core.binding()
        var values:[RootKeyRole:RootKeyMaterial]=[:]
        for (i,reference) in ready.core.keys.enumerated() {
            let key=try store.load(reference,binding:binding)
            try key.confirm(ready.confirmations[i],reference:reference,binding:binding); values[reference.role]=key
        }
        return .init(ready:ready,keys:BootstrapKeys(values),journal:journal)
    }
}
