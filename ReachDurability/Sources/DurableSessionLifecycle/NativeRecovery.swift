import Foundation
import Darwin
import CryptoKit
import DurableHostStore
import DurableClientReceipts
import HostClientContract
import ResumableMLXProvider
import RecoveryAuthorityContract

extension DurableSessionLifecycle {
    /// Initializes the real catalog under the original root. No clock adapter,
    /// maintenance, session owner or provider is constructed for this lane.
    public static func initializeNativeRecovery(at path: String, identity: LifecycleIdentity, keys: LifecycleKeys) throws {
        guard let original=identity.authority, original.provision.native else { throw AuthorityError.scope }
        try original.validate()
        let fs=try LifecycleFileSystem(path:path,create:true); defer { fs.close() }
        let d=try CatalogDocument(version:3,authority:original.digest,incarnation:identity.incarnation,boot:identity.boot,
            clockPolicy:identity.clockPolicy,quota:identity.quota,epoch:1,lastObserved:original.anchor)
        try selectNativeCatalog(d,files:fs,identity:identity,keys:keys,check:{})
    }
    static func selectNativeCatalog(_ d: CatalogDocument, files: LifecycleFileSystem,
        identity: LifecycleIdentity, keys: LifecycleKeys, check: () throws -> Void) throws {
        try check(); try d.validate(identity)
        guard !(try files.root.exists("prepared")) else { throw AuthorityError.partial }
        let bytes=try lcEncode(d)
        let cipher=try LifecycleCrypto.seal(bytes,role:"catalog",record:UUID().uuidString.lowercased(),identity:identity,key:keys.catalog)
        try check(); try files.root.writeNew("prepared",bytes:cipher,maximum:LifecycleLimits.catalog+LifecycleCrypto.overhead)
        try check()
        guard renameat(files.root.fd,"prepared",files.root.fd,"current") == 0 else { throw LifecycleError.io("authority-catalog-select",errno) }
        try files.root.sync(); try check()
        guard try lcEncode(LifecycleCatalog.read(files,identity:identity,keys:keys)) == bytes else { throw AuthorityError.invalid }
        try check()
    }
    public static func admitNativeRecovery(at path: String, identity: LifecycleIdentity, keys: LifecycleKeys,
        scope: AuthorityScope, caller: CallerIdentity, provider: ProviderBinding, action: GenerationAuthorityAction,
        fault: LifecycleFaultHook = { _ in }) throws -> AuthorityIssued {
        guard let original=identity.authority, original.provision.native else { throw AuthorityError.scope }
        try original.check(scope,role:"host")
        guard scope.provision.execution?.provider == (try lcEncode(provider)), scope.provision.execution?.operation == provider.operationID else { throw AuthorityError.scope }
        try NativeRecoveryBinding.validate(provider)
        func check() throws { try action.check(scope:scope,operation:.admitHost) }
        try check()
        guard scope.host.boot == (try StoreEnvironment.bootIdentity()) else { throw AuthorityError.scope }
        let files=try LifecycleFileSystem(path:path,create:false); defer { files.close() }; try check()
        var d=try LifecycleCatalog.read(files,identity:identity,keys:keys); try check()
        let request=try LifecycleRequest(version:3,authority:scope.digest,namespace:scope.namespace,generation:scope.generation,caller:caller,provider:provider)
        try request.validate(); let requestBytes=try lcEncode(request)
        if let issued=d.admission {
            let a=try readNativeAdmission(d,files:files,identity:identity,keys:keys,scope:scope,action:action).0
            guard d.records.first?.phase == .preparing, a.requestDigest == lcHash(requestBytes) else { throw AuthorityError.partial }
            try action.publication(a); return issued
        }
        guard d.records.isEmpty, d.epoch == 1, d.lastObserved == (try original.anchor),
              !(try files.root.exists("prepared")), try files.requests.names(maximum:65,allowed:LifecycleFileSystem.requestRole).isEmpty,
              try files.children.names(maximum:64,allowed:LifecycleFileSystem.childRole).isEmpty else { throw AuthorityError.partial }
        try files.reserve(quota:identity.quota,child:true,request:true); try check()
        let ticket=try TicketCodec.issueAuthority(scope:scope,keys:keys,caller:caller)
        let claims=try TicketCodec.authorityClaims(scope:scope,caller:caller)
        let requestID=UUID().uuidString.lowercased(), childID=UUID().uuidString.lowercased(), recordID=UUID().uuidString.lowercased()
        let secrets=try GenerationSecrets(), requestDigest=lcHash(requestBytes), providerDigest=lcHash(try lcEncode(provider))
        let upstream=try AuthorityCodec.digest([scope.digest,childID,requestDigest,providerDigest])
        let context=try ClientAuthority(.init(caller:.init(principal:caller.principal,device:caller.device,app:caller.app),
            host:identity.incarnation,store:identity.incarnation,namespace:scope.namespace,generation:scope.generation,
            request:provider.requestID,operation:provider.operationID,upstreamDigest:upstream,route:provider.lane.route.rawValue,
            revision:HandoffContract.nativeRevision,issued:claims.issued,expires:claims.expires,authority:scope.digest))
        let admission=try AuthorityAdmission(scope:scope,ticket:ticket.data,context:context.bytes,requestDigest:requestDigest,
            providerDigest:providerDigest,record:recordID,store:childID)
        let issued=try keys.ticket.withUnsafeBytes { try AuthorityIssued(admission,ticketKey:Data($0)) }
        let cipher=try LifecycleCrypto.seal(requestBytes,role:"request",record:requestID,identity:identity,key:SymmetricKey(data:secrets.content))
        try check(); try files.requests.writeNew(LifecycleFileSystem.requestName(requestID),bytes:cipher,maximum:LifecycleLimits.request+LifecycleCrypto.overhead)
        try files.requests.sync(); try check()
        let times=LifecycleTimes(admitted:claims.issued,queueUntil:claims.expires,absoluteUntil:claims.expires,lastContact:claims.issued)
        d.records=[LifecycleRecord(id:recordID,identity:.init(namespace:scope.namespace,generation:scope.generation,caller:caller,
            ticketExpiry:claims.expires,requestDigest:requestDigest,operationDigest:lcHash(Data(provider.operationID.utf8))),phase:.allocating,
            work:.init(request:requestID,child:childID,keys:secrets,times:times))]
        d.admission=issued
        try selectNativeCatalog(d,files:files,identity:identity,keys:keys,check:check)
        try fault(.afterAllocating); try check()
        let childIdentity=try StoreIdentity(native:scope,storeID:childID,provider:provider)
        let child=try DurableHostStore.initializeNative(at:files.childPath(childID),identity:childIdentity,keys:secrets.storeKeys(),admission:admission,action:action); child.close()
        try fault(.afterEmptyChild); try check()
        d.records[0].phase = .preparing
        try selectNativeCatalog(d,files:files,identity:identity,keys:keys,check:check)
        try fault(.afterPreparing); try check()
        _=try readNativeAdmission(d,files:files,identity:identity,keys:keys,scope:scope,action:action)
        try action.publication(admission); return issued
    }
    static func readNativeAdmission(_ d: CatalogDocument, files: LifecycleFileSystem, identity: LifecycleIdentity,
        keys: LifecycleKeys, scope: AuthorityScope, action: GenerationAuthorityAction) throws -> (AuthorityAdmission, LifecycleRequest) {
        guard let original=identity.authority else { throw AuthorityError.scope }; try original.check(scope,role:"host")
        guard original.provision.native else { throw AuthorityError.scope }
        func check() throws { try action.check(scope:scope,operation:action.operation) }
        try check()
        guard d.version == 3, d.epoch > 0, d.lastObserved == (try original.anchor), d.records.count == 1,
              let issued=d.admission else { throw AuthorityError.partial }
        let issuer=try keys.ticket.withUnsafeBytes { try AuthorityIssued.issuerKey(ticketKey:Data($0),native:true).publicKey.rawRepresentation }
        let a=try issued.verify(issuer:issuer,expectedDigest:AuthorityCodec.digest(issued))
        guard a.scope == scope else { throw AuthorityError.scope }
        let r=d.records[0]
        guard [.allocating,.preparing,.active,.recovering,.terminal].contains(r.phase), r.id == a.record, let id=r.identity, let work=r.work,
              r.cleanup == nil, r.disposition == nil, !r.nonResumable,
              work.child == a.store, id.requestDigest == a.requestDigest, id.namespace == scope.namespace, id.generation == scope.generation,
              work.times.admitted == (try original.anchor), work.times.lastContact == (try original.anchor),
              work.times.queueUntil == (try original.deadline), work.times.absoluteUntil == (try original.deadline),
              work.times.attached, work.times.attachmentEpoch > 0, work.times.detachedUntil == nil,
              work.times.transitionStartedAt == (r.phase == .terminal ? try original.anchor : nil),
              work.times.terminalUntil == (r.phase == .terminal ? try original.deadline : nil) else { throw AuthorityError.state }
        let claims=try TicketCodec.verifyAuthority(a.ticket,scope:scope,keys:keys,caller:id.caller)
        guard id.ticketExpiry == claims.expires else { throw AuthorityError.invalid }
        guard Set(try files.requests.names(maximum:65,allowed:LifecycleFileSystem.requestRole)) == Set([LifecycleFileSystem.requestName(work.request)]) else { throw AuthorityError.partial }
        try check()
        let cipher=try files.requests.read(LifecycleFileSystem.requestName(work.request),maximum:LifecycleLimits.request+LifecycleCrypto.overhead)
        try check()
        let bytes=try LifecycleCrypto.open(cipher,role:"request",record:work.request,identity:identity,key:SymmetricKey(data:work.keys.content))
        let request=try JSONDecoder().decode(LifecycleRequest.self,from:bytes); try request.validate()
        guard try lcEncode(request) == bytes, lcHash(bytes) == a.requestDigest, request.authority == (try scope.digest), request.version == 3,
              scope.provision.execution?.provider == (try lcEncode(request.provider)), scope.provision.execution?.operation == request.provider.operationID,
              request.namespace == scope.namespace, request.generation == scope.generation, request.caller == id.caller,
              lcHash(try lcEncode(request.provider)) == a.providerDigest, lcHash(Data(request.provider.operationID.utf8)) == id.operationDigest else { throw AuthorityError.invalid }
        let context=try AuthorityCodec.decode(ClientContext.self,a.context)
        let expected=try ClientAuthority(.init(caller:.init(principal:id.caller.principal,device:id.caller.device,app:id.caller.app),
            host:identity.incarnation,store:identity.incarnation,namespace:scope.namespace,generation:scope.generation,
            request:request.provider.requestID,operation:request.provider.operationID,
            upstreamDigest:AuthorityCodec.digest([scope.digest,work.child,a.requestDigest,a.providerDigest]),route:request.provider.lane.route.rawValue,
            revision:HandoffContract.nativeRevision,issued:claims.issued,expires:claims.expires,authority:scope.digest))
        guard try AuthorityCodec.encode(context) == expected.bytes else { throw AuthorityError.invalid }
        try check()
        let children=try files.children.names(maximum:64,allowed:LifecycleFileSystem.childRole)
        guard r.phase != .allocating, children == [LifecycleFileSystem.childName(work.child)] else { throw AuthorityError.partial }
        _=try StoreIdentity(native:scope,storeID:work.child,provider:request.provider)
        try check(); try action.bindAuthenticated(a); return (a,request)
    }
}

/// A single selected generation; no clock, queue maintenance, contact refresh,
/// new admission, effect executor or replacement request API exists here.
public final class NativeLifecycleOwner {
    public let admission: AuthorityAdmission, provider: ProviderBinding, store: DurableHostStore
    private let files: LifecycleFileSystem, identity: LifecycleIdentity, keys: LifecycleKeys
    private let epoch: UInt64
    private let authorityBinding: GenerationAuthorityBinding
    public var fault: LifecycleFaultHook = {_ in}
    public init(path: String, identity: LifecycleIdentity, keys: LifecycleKeys, scope: AuthorityScope,
        action: GenerationAuthorityAction, storeFault: @escaping StoreFaultHook = {_ in}) throws {
        try action.check(scope:scope,operation:.reopen)
        authorityBinding=try action.bindResource()
        let fs=try LifecycleFileSystem(path:path,create:false)
        do {
            try action.check(); var d=try LifecycleCatalog.read(fs,identity:identity,keys:keys); try action.check()
            let (a,request)=try DurableSessionLifecycle.readNativeAdmission(d,files:fs,identity:identity,keys:keys,scope:scope,action:action)
            let w=d.records[0].work!
            let child=try DurableHostStore.reopenNative(at:fs.childPath(w.child),identity:.init(native:scope,storeID:w.child,provider:request.provider),keys:w.keys.storeKeys(),admission:a,action:action,fault:storeFault)
            files=fs; self.identity=identity; self.keys=keys; admission=a; provider=request.provider; store=child
            epoch=try lcAdd(d.epoch,1); d.epoch=epoch
            d.records[0].work!.times.attachmentEpoch=try lcAdd(w.times.attachmentEpoch,1)
            try reconcilePrepared(action)
            try project(&d,action:action); try select(d,action:action)
        } catch { fs.close(); throw error }
    }
    private func check(_ action: GenerationAuthorityAction) throws {
        try authorityBinding.validate(action,permitting:[.reopen,.prepare,.advance,.delivery,.terminalReplay])
        try action.publication(admission)
    }
    private func read(_ action: GenerationAuthorityAction) throws -> CatalogDocument {
        try check(action); try files.ensure()
        let d=try LifecycleCatalog.read(files,identity:identity,keys:keys); try check(action)
        guard d.epoch == epoch else { throw LifecycleError.stale }
        let (a,_)=try DurableSessionLifecycle.readNativeAdmission(d,files:files,identity:identity,keys:keys,scope:admission.scope,action:action)
        guard a == admission else { throw AuthorityError.scope }; return d
    }
    private func reconcilePrepared(_ action: GenerationAuthorityAction) throws {
        try check(action)
        if try files.root.exists("prepared") {
            let bytes=try LifecycleCrypto.open(files.root.read("prepared",maximum:LifecycleLimits.catalog+LifecycleCrypto.overhead),role:"catalog",identity:identity,key:keys.catalog)
            try check(action)
            let d=try JSONDecoder().decode(CatalogDocument.self,from:bytes); try d.validate(identity)
            guard try lcEncode(d) == bytes, d.admission == (try LifecycleCatalog.read(files,identity:identity,keys:keys)).admission else { throw AuthorityError.partial }
            try check(action); try files.root.unlink("prepared",maximum:LifecycleLimits.catalog+LifecycleCrypto.overhead)
        }
        try files.root.sync(); try check(action)
    }
    private func project(_ d: inout CatalogDocument, action: GenerationAuthorityAction) throws {
        try check(action)
        try store.authorize(action); let s=try store.snapshot()
        guard d.records[0].high <= s.high, d.records[0].phase != .terminal || s.terminal else { throw AuthorityError.state }
        d.records[0].high=s.high
        if s.terminal {
            struct Ending: Decodable { let terminal: ReachWire.WireFinishReason? }
            guard let c=s.candidate, let end=try JSONDecoder().decode(Ending.self,from:c.commit.data).terminal else { throw AuthorityError.state }
            d.records[0].phase = .terminal; d.records[0].ending=end
            d.records[0].work!.times.transitionStartedAt=try identity.authority!.anchor
            d.records[0].work!.times.terminalUntil=try identity.authority!.deadline
        } else { d.records[0].phase=s.candidate == nil ? .preparing : .active }
    }
    private func select(_ d: CatalogDocument, action: GenerationAuthorityAction) throws {
        try check(action)
        try fault(.beforeCatalogRename); try check(action)
        try DurableSessionLifecycle.selectNativeCatalog(d,files:files,identity:identity,keys:keys,check:{ try self.check(action) })
        try fault(.afterCatalogRename); try check(action)
    }
    public func synchronize(action: GenerationAuthorityAction) throws {
        var d=try read(action); try reconcilePrepared(action); try project(&d,action:action); try select(d,action:action)
    }
    public func acceptReceipt(_ witness: HandoffWitness, action: GenerationAuthorityAction) throws {
        guard [.delivery,.terminalReplay,.reopen,.advance,.prepare].contains(action.operation) else { throw AuthorityError.scope }
        try store.authorize(action); var d=try read(action)
        try witness.validate(expectedRoot:admission.scope.client.localID)
        let state=try store.snapshot()
        guard witness.high <= state.high, witness.context == AuthorityCodec.hash(admission.context), witness.registrations == 0 else { throw AuthorityError.scope }
        var prefix=HandoffPrefix(context:admission.context)
        for frame in try store.replay(after:0) {
            let batch=HandoffBatch(first:frame.firstSequence,count:frame.count,commit:frame.providerCommit,bytes:frame.eventBytes)
            if try batch.last() <= witness.high { try prefix.append(batch) }
        }
        let digests=prefix.digests()
        guard prefix.high == witness.high, witness.prefix == digests.0, witness.calls == digests.1,
              !witness.terminal || state.terminal && witness.high == state.high else { throw AuthorityError.state }
        if let old=d.nativeReceipt {
            guard witness.revision >= old.revision, witness.high >= old.high,
                  witness.revision != old.revision || witness == old else { throw AuthorityError.state }
        }
        d.nativeReceipt=witness; try reconcilePrepared(action); try project(&d,action:action); try select(d,action:action)
    }
    public func timerBytes(action: GenerationAuthorityAction) throws -> Data {
        let d=try read(action), result=try lcEncode(d.records[0].work!.times)
        try check(action); return result
    }
    public func close() { store.close(); files.close() }
    deinit { close() }
}

import ReachWire
