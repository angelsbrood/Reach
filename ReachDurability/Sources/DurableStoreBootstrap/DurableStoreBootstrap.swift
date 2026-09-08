import Foundation
import DurableRootKeys

/// Synchronous creation/selection only. No pair-wide lock survives acquisition.
public enum DurableStoreBootstrap {
    public static func create(optIn: Bool, at path: String, container: String, policy: BootstrapPolicy,
        provider: (BootstrapCore) throws -> any RootKeyProvider,
        initializeStores: (BootstrapCore,BootstrapKeys) throws -> Void,
        hook: BootstrapHook = { _ in }) throws -> BootstrapReady? {
        guard optIn else { return nil }
        try policy.validate()
        let fs = try BootstrapFileSystem(path:path,fresh:true); defer { fs.close() }
        let core = BootstrapCore(container:container,policy:policy); try core.validate(expected:policy)
        try fs.intent(core,hook:hook)
        let store = try provider(core), binding = try core.binding()
        var values: [RootKeyRole:RootKeyMaterial] = [:], confirmations: [Data] = [], independent = Set<Data>()
        for (index,reference) in core.keys.enumerated() {
            let key = try store.create(reference,binding:binding)
            try key.use { try RootKeyCodec.require(independent.insert($0).inserted) }
            values[reference.role] = key; confirmations.append(try key.confirmation(reference,binding:binding))
            if index == 0 { try hook(.afterFirstKey) }
        }
        try initializeStores(core,BootstrapKeys(values)); try fs.syncJournals(); try hook(.afterStores)
        let selected = BootstrapReady(core:core,confirmations:confirmations); try selected.validate(expected:policy)
        try fs.ready(selected,hook:hook); return selected
    }
    public static func acquire(optIn: Bool, at path: String, role: BootstrapRole, policy: BootstrapPolicy,
        provider: (BootstrapCore) throws -> any RootKeyProvider) throws -> BootstrapAcquisition? {
        guard optIn else { return nil }
        try policy.validate()
        let fs = try BootstrapFileSystem(path:path,fresh:false); defer { fs.close() }
        let selected = try fs.loadReady(expected:policy), binding = try selected.core.binding()
        let journal = try fs.journal(role)
        let required: [RootKeyRole] = role == .host ? [.hostCatalog,.hostTicket] : [.clientMetadata]
        let store = try provider(selected.core); var values: [RootKeyRole:RootKeyMaterial] = [:]
        for keyRole in required {
            guard let i = selected.core.keys.firstIndex(where: { $0.role == keyRole }) else { throw BootstrapError.invalid }
            let reference = selected.core.keys[i], key = try store.load(reference,binding:binding)
            try key.confirm(selected.confirmations[i],reference:reference,binding:binding); values[keyRole] = key
        }
        return .init(descriptor:selected,keys:BootstrapKeys(values),journal:journal)
    }
}
