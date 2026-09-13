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
    public static func initializeRecoveryAuthority(at path: String, identity: LifecycleIdentity, keys: LifecycleKeys) throws {
        guard let original=identity.authority else { throw AuthorityError.scope }
        try original.validate()
        let fs=try LifecycleFileSystem(path:path,create:true); defer { fs.close() }
        let d=try CatalogDocument(version:2,authority:original.digest,incarnation:identity.incarnation,boot:identity.boot,
            clockPolicy:identity.clockPolicy,quota:identity.quota,epoch:1,lastObserved:original.anchor)
        try selectAuthorityCatalog(d,files:fs,identity:identity,keys:keys,check:{})
    }
    private static func selectAuthorityCatalog(_ d: CatalogDocument, files: LifecycleFileSystem,
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
    public static func admitRecoveryAuthority(at path: String, identity: LifecycleIdentity, keys: LifecycleKeys,
        scope: AuthorityScope, caller: CallerIdentity, provider: ProviderBinding, action: RecoveryAuthorityAction,
        fault: LifecycleFaultHook = { _ in }) throws -> AuthorityIssued {
        guard let original=identity.authority else { throw AuthorityError.scope }
        try original.check(scope,role:"host")
        func check() throws { try action.check(scope:scope,operation:.admitHost) }
        try check()
        guard scope.host.boot == (try StoreEnvironment.bootIdentity()) else { throw AuthorityError.scope }
        let files=try LifecycleFileSystem(path:path,create:false); defer { files.close() }; try check()
        var d=try LifecycleCatalog.read(files,identity:identity,keys:keys); try check()
        let request=try LifecycleRequest(version:2,authority:scope.digest,namespace:scope.namespace,generation:scope.generation,caller:caller,provider:provider)
        try request.validate(); let requestBytes=try lcEncode(request)
        if let issued=d.admission {
            let a=try readAuthorityAdmission(d,files:files,identity:identity,keys:keys,scope:scope,action:action)
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
            revision:HandoffContract.authorityRevision,issued:claims.issued,expires:claims.expires,authority:scope.digest))
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
        try selectAuthorityCatalog(d,files:files,identity:identity,keys:keys,check:check)
        try fault(.afterAllocating); try check()
        let childIdentity=try StoreIdentity(authority:scope,storeID:childID,provider:provider)
        try DurableHostStore.initializeEmptyAuthority(at:files.childPath(childID),identity:childIdentity,keys:secrets.storeKeys(),scope:scope,action:action)
        try fault(.afterEmptyChild); try check()
        d.records[0].phase = .preparing
        try selectAuthorityCatalog(d,files:files,identity:identity,keys:keys,check:check)
        try fault(.afterPreparing); try check()
        _=try readAuthorityAdmission(d,files:files,identity:identity,keys:keys,scope:scope,action:action)
        try action.publication(admission); return issued
    }
    private static func readAuthorityAdmission(_ d: CatalogDocument, files: LifecycleFileSystem, identity: LifecycleIdentity,
        keys: LifecycleKeys, scope: AuthorityScope, action: RecoveryAuthorityAction) throws -> AuthorityAdmission {
        guard let original=identity.authority else { throw AuthorityError.scope }; try original.check(scope,role:"host")
        guard [.admitHost,.authenticateHost].contains(action.operation) else { throw AuthorityError.scope }
        func check() throws { try action.check(scope:scope,operation:action.operation) }
        try check()
        guard d.version == 2, d.epoch == 1, d.lastObserved == (try original.anchor), d.records.count == 1,
              let issued=d.admission, !(try files.root.exists("prepared")) else { throw AuthorityError.partial }
        let issuer=try keys.ticket.withUnsafeBytes { try AuthorityIssued.issuerKey(ticketKey:Data($0)).publicKey.rawRepresentation }
        let a=try issued.verify(issuer:issuer,expectedDigest:AuthorityCodec.digest(issued))
        guard a.scope == scope else { throw AuthorityError.scope }
        let r=d.records[0]
        guard [.allocating,.preparing].contains(r.phase), r.id == a.record, let id=r.identity, let work=r.work,
              r.cleanup == nil, r.ending == nil, r.disposition == nil, r.high == 0, !r.nonResumable,
              work.child == a.store, id.requestDigest == a.requestDigest, id.namespace == scope.namespace, id.generation == scope.generation,
              work.times.admitted == (try original.anchor), work.times.lastContact == (try original.anchor),
              work.times.queueUntil == (try original.deadline), work.times.absoluteUntil == (try original.deadline),
              work.times.attached, work.times.attachmentEpoch == 1, work.times.detachedUntil == nil,
              work.times.transitionStartedAt == nil, work.times.terminalUntil == nil else { throw AuthorityError.state }
        let claims=try TicketCodec.verifyAuthority(a.ticket,scope:scope,keys:keys,caller:id.caller)
        guard id.ticketExpiry == claims.expires else { throw AuthorityError.invalid }
        guard Set(try files.requests.names(maximum:65,allowed:LifecycleFileSystem.requestRole)) == Set([LifecycleFileSystem.requestName(work.request)]) else { throw AuthorityError.partial }
        try check()
        let cipher=try files.requests.read(LifecycleFileSystem.requestName(work.request),maximum:LifecycleLimits.request+LifecycleCrypto.overhead)
        try check()
        let bytes=try LifecycleCrypto.open(cipher,role:"request",record:work.request,identity:identity,key:SymmetricKey(data:work.keys.content))
        let request=try JSONDecoder().decode(LifecycleRequest.self,from:bytes); try request.validate()
        guard try lcEncode(request) == bytes, lcHash(bytes) == a.requestDigest, request.authority == (try scope.digest),
              request.namespace == scope.namespace, request.generation == scope.generation, request.caller == id.caller,
              lcHash(try lcEncode(request.provider)) == a.providerDigest, lcHash(Data(request.provider.operationID.utf8)) == id.operationDigest else { throw AuthorityError.invalid }
        let context=try AuthorityCodec.decode(ClientContext.self,a.context)
        let expected=try ClientAuthority(.init(caller:.init(principal:id.caller.principal,device:id.caller.device,app:id.caller.app),
            host:identity.incarnation,store:identity.incarnation,namespace:scope.namespace,generation:scope.generation,
            request:request.provider.requestID,operation:request.provider.operationID,
            upstreamDigest:AuthorityCodec.digest([scope.digest,work.child,a.requestDigest,a.providerDigest]),route:request.provider.lane.route.rawValue,
            revision:HandoffContract.authorityRevision,issued:claims.issued,expires:claims.expires,authority:scope.digest))
        guard try AuthorityCodec.encode(context) == expected.bytes else { throw AuthorityError.invalid }
        try check()
        let children=try files.children.names(maximum:64,allowed:LifecycleFileSystem.childRole)
        if r.phase == .preparing {
            guard children == [LifecycleFileSystem.childName(work.child)] else { throw AuthorityError.state }
            try DurableHostStore.authenticateEmptyAuthority(at:files.childPath(work.child),
                identity:StoreIdentity(authority:scope,storeID:work.child,provider:request.provider),keys:work.keys.storeKeys(),scope:scope,action:action)
        } else { guard children.isEmpty else { throw AuthorityError.partial } }
        try action.bindAuthenticated(a); return a
    }
    public static func authenticateRecoveryAuthority(at path: String, identity: LifecycleIdentity, keys: LifecycleKeys,
        scope: AuthorityScope, action: RecoveryAuthorityAction, blocking: () throws -> Void = {}) throws -> AuthorityDiagnostic {
        try action.check(scope:scope,operation:.authenticateHost)
        let files=try LifecycleFileSystem(path:path,create:false); defer { files.close() }
        try action.check(scope:scope,operation:.authenticateHost)
        let d=try LifecycleCatalog.read(files,identity:identity,keys:keys)
        try action.check(scope:scope,operation:.authenticateHost)
        let a=try readAuthorityAdmission(d,files:files,identity:identity,keys:keys,scope:scope,action:action)
        try blocking()
        return try AuthorityDiagnostic(admission:a,phase:d.records[0].phase.rawValue,action:action)
    }
}
