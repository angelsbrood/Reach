import Foundation
import RecoveryAuthorityContract

extension DurableHostStore {
    /// The actual StoreManifest and encryption, with no provider, reusable store
    /// object, candidate, replay read or owner-epoch advancement.
    public static func initializeEmptyAuthority(at path: String, identity: StoreIdentity, keys: StoreKeys,
        scope: AuthorityScope, action: RecoveryAuthorityAction) throws {
        try action.check(scope:scope,operation:.admitHost)
        guard identity.authority == (try scope.digest), identity.bootID == scope.host.boot else { throw AuthorityError.scope }
        let files=try StoreFileSystem(path:path,create:true); defer { files.close() }
        try action.check(scope:scope,operation:.admitHost)
        let manifest=try StoreManifest(version:2,authority:scope.digest,storeID:identity.storeID,bootID:identity.bootID,bindingDigest:identity.bindingDigest,epoch:1)
        let temporary="t-"+UUID().uuidString.lowercased()+".bin"
        let cipher=try StoreCrypto.seal(storeEncode(manifest),identity:identity,role:"manifest",record:UUID().uuidString.lowercased(),epoch:nil,keys:keys)
        try files.writeNew(temporary,bytes:cipher); try action.check(scope:scope,operation:.admitHost)
        try files.replaceCurrent(with:temporary); try files.syncDirectory(); try action.check(scope:scope,operation:.admitHost)
        try checkEmptyAuthority(files,identity:identity,keys:keys,scope:scope)
        try action.check(scope:scope,operation:.admitHost)
    }
    public static func authenticateEmptyAuthority(at path: String, identity: StoreIdentity, keys: StoreKeys,
        scope: AuthorityScope, action: RecoveryAuthorityAction) throws {
        guard [.admitHost,.authenticateHost].contains(action.operation) else { throw AuthorityError.scope }
        try action.check(scope:scope,operation:action.operation)
        let files=try StoreFileSystem(path:path,create:false); defer { files.close() }
        try action.check(scope:scope,operation:action.operation)
        try checkEmptyAuthority(files,identity:identity,keys:keys,scope:scope)
        try action.check(scope:scope,operation:action.operation)
    }
    private static func checkEmptyAuthority(_ files: StoreFileSystem, identity: StoreIdentity, keys: StoreKeys, scope: AuthorityScope) throws {
        guard identity.authority == (try scope.digest), identity.bootID == scope.host.boot,
              Set(try files.scan().keys) == Set(["current","lock"]) else { throw AuthorityError.state }
        let bytes=try files.read("current",maximum:StoreLimits.manifest+StoreCrypto.overhead)
        let plain=try StoreCrypto.open(bytes,identity:identity,role:"manifest",epoch:nil,keys:keys)
        let m=try JSONDecoder().decode(StoreManifest.self,from:plain)
        guard try storeEncode(m) == plain, m.version == 2, m.authority == (try scope.digest), m.storeID == identity.storeID,
              m.bootID == identity.bootID, m.bindingDigest == (try identity.bindingDigest), m.epoch == 1,
              m.commit == nil, m.candidate == nil, m.replay == nil, m.high == 0, m.batches == 0, m.terminal == nil
        else { throw AuthorityError.state }
    }
}
