import Foundation
import ResumableMLXProvider
import RecoveryAuthorityContract

extension DurableHostStore {
    func checkNative(operations: [GenerationOperation] = [.admitHost,.reopen,.prepare,.advance,.delivery,.terminalReplay]) throws {
        if identity.native {
            guard let nativeAdmission, let nativeAction, let nativeAuthorityBinding else { throw AuthorityError.scope }
            try nativeAuthorityBinding.validate(nativeAction,permitting:operations)
            try nativeAction.publication(nativeAdmission)
        } else { guard nativeAdmission == nil, nativeAction == nil, nativeAuthorityBinding == nil else { throw AuthorityError.scope } }
    }
    public func authorize(_ action: GenerationAuthorityAction) throws {
        try authorize(action,operations:[.reopen,.prepare,.advance,.delivery,.terminalReplay])
    }
    func authorize(_ action: GenerationAuthorityAction, operations: [GenerationOperation]) throws {
        guard identity.native, let nativeAdmission, let nativeAuthorityBinding, nativeAdmission.store == identity.storeID,
              nativeAdmission.scope == action.scope else { throw AuthorityError.scope }
        try nativeAuthorityBinding.validate(action,permitting:operations)
        try action.bindAuthenticated(nativeAdmission); try action.publication(nativeAdmission); nativeAction=action
    }
    public static func initializeNative(at path: String, identity: StoreIdentity, keys: StoreKeys,
        admission: AuthorityAdmission, action: GenerationAuthorityAction) throws -> DurableHostStore {
        try action.check(scope:admission.scope,operation:.admitHost)
        guard identity.native, identity.authority == (try admission.scope.digest), identity.storeID == admission.store,
              identity.bootID == (try StoreEnvironment.bootIdentity()) else { throw AuthorityError.scope }
        try action.bindAuthenticated(admission)
        let fs=try StoreFileSystem(path:path,create:true)
        let store=DurableHostStore(identity:identity,keys:keys,files:fs,epoch:1,fault:{_ in},nativeAuthorityBinding:try action.bindResource())
        store.nativeAdmission=admission; store.nativeAction=action
        do {
            let m=try StoreManifest(version:3,authority:admission.scope.digest,storeID:identity.storeID,bootID:identity.bootID,bindingDigest:identity.bindingDigest,epoch:1)
            try store.replace(m); _=try store.load(); return store
        } catch { store.close(); throw error }
    }
    public static func reopenNative(at path: String, identity: StoreIdentity, keys: StoreKeys,
        admission: AuthorityAdmission, action: GenerationAuthorityAction, fault: @escaping StoreFaultHook = {_ in}) throws -> DurableHostStore {
        try action.check(scope:admission.scope,operation:.reopen)
        guard identity.native, identity.authority == (try admission.scope.digest), identity.storeID == admission.store else { throw AuthorityError.scope }
        try action.bindAuthenticated(admission)
        let fs=try StoreFileSystem(path:path,create:false)
        do {
            try action.publication(admission)
            let old=try readAuthority(files:fs,identity:identity,keys:keys); try action.publication(admission)
            let next=old.manifest.epoch.addingReportingOverflow(1); guard !next.overflow else { throw StoreError.stale }
            let store=DurableHostStore(identity:identity,keys:keys,files:fs,epoch:next.partialValue,fault:fault,nativeAuthorityBinding:try action.bindResource())
            store.nativeAdmission=admission; store.nativeAction=action
            try store.cleanup(old)
            var m=old.manifest; m.epoch=next.partialValue
            try store.replace(m); _=try store.load(); return store
        } catch { fs.close(); throw error }
    }
}
/// One ordinary native unit per guarded call. Original input fits one prefill
/// chunk; restore has no prefill. All native algorithms remain in the provider.
public final class GuardedNativeGeneration {
    public let store: DurableHostStore
    private var provider: ResumableMLXProvider?
    public private(set) var deliveredThrough: UInt64=0
    private var failed=false
    private init(store: DurableHostStore, provider: ResumableMLXProvider?) { self.store=store; self.provider=provider }
    public static func start(store: DurableHostStore, action: GenerationAuthorityAction,
        runtime: () throws -> ProviderRuntime) throws -> GuardedNativeGeneration {
        try store.authorize(action,operations:[.prepare])
        guard try store.snapshot().candidate == nil else { throw StoreError.stale }
        try store.reserve()
        let native=try runtime(); try store.checkNative()
        let live=try ResumableMLXProvider.prepare(binding:store.identity.provider,runtime:native,owner:store.ownerToken,credit:ResumableMLXProvider.reservationBytes)
        let g=GuardedNativeGeneration(store:store,provider:live)
        do { try store.checkNative(); guard let c=try live.pendingCandidate() else { throw StoreError.stale }; try g.commit(c); return g }
        catch { g.close(); throw error }
    }
    public static func restore(store: DurableHostStore, action: GenerationAuthorityAction,
        runtime: () throws -> ProviderRuntime) throws -> GuardedNativeGeneration {
        try store.authorize(action,operations:[.reopen])
        let s=try store.snapshot(); guard let c=s.candidate else { throw StoreError.noCommittedGeneration }
        if s.terminal { return .init(store:store,provider:nil) }
        try store.reserve(); let native=try runtime(); try store.checkNative()
        let live=try ResumableMLXProvider.restore(committed:c,expected:store.identity.provider,runtime:native,owner:store.ownerToken)
        do { try store.checkNative(); return .init(store:store,provider:live) }
        catch { live.close(); throw error }
    }
    public func acknowledgeDelivery(through cursor: UInt64, action: GenerationAuthorityAction) throws {
        try store.authorize(action); let s=try store.snapshot()
        guard cursor >= deliveredThrough, cursor == s.high else { throw StoreError.replayRequired }
        try store.checkNative(); deliveredThrough=cursor
    }
    public func advance(action: GenerationAuthorityAction) throws {
        try store.authorize(action,operations:[.advance])
        guard !failed, let provider else { throw StoreError.closed }
        let s=try store.snapshot(); guard !s.terminal, s.high == deliveredThrough,
            let commit=s.candidate?.commit, provider.acceptedCommit == commit else { throw StoreError.replayRequired }
        try store.reserve(); try store.checkNative()
        do {
            guard let c=try provider.advance(owner:store.ownerToken,current:commit,credit:ResumableMLXProvider.reservationBytes) else { throw StoreError.stale }
            try store.fault(.afterNativeBeforeCommit); try store.checkNative(); try self.commit(c)
        } catch { close(); throw error }
    }
    private func commit(_ candidate: ProviderCandidate) throws {
        try store.checkNative(); try store.commit(candidate)
        try store.fault(.afterCommitBeforeAck); try store.checkNative()
        guard let provider else { throw StoreError.closed }
        try provider.acceptCommit(candidate.commit,owner:store.ownerToken)
        try store.fault(.afterAckBeforePublication); try store.checkNative()
    }
    public func close() { failed=true; provider?.close(); provider=nil }
    deinit { close() }
}
